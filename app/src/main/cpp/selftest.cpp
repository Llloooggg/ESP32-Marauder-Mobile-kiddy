// Known-answer self-test for the native crypto core.
//
// Why this exists: the app runs the native engine only after this gate passes, and
// falls back to the JVM implementation when it does not. A crypto core that is
// silently wrong on one ABI would report "not cracked" for a password that really is
// correct, which is the one failure mode this app must never present as a result.
//
// Every vector below comes from outside this code: published algorithm test vectors,
// hashcat's mode-22000 PMKID self-test (essid "hashcat-essid", password "hashcat!"),
// and hashcat's published example handshake (essid "TP-LINK_HASHCAT_TEST", password
// "hashcat!"). The same vectors are checked by the JVM tests, so the two engines are
// held to the same evidence.
//
// Compile standalone (`-DMK_SELFTEST_MAIN`) to run on a development host:
//   g++ -std=c++17 -O2 -pthread -DMK_SELFTEST_MAIN wpa_crypto.cpp selftest.cpp -o selftest
// `-pthread` is needed because the core spreads a batch over the machine's cores.
#include "wpa_crypto.h"

#include <cstdio>
#include <cstring>
#include <iterator>
#include <string>
#include <utility>
#include <vector>

#ifdef MK_SELFTEST_MAIN
#define MK_TEST_MAIN_DEFINED
#endif

namespace mktest {

// The core lives in namespace `mk`; the self-test deliberately uses it the way a
// consumer would, with no qualifications, so any name mismatch shows up here.
using namespace mk;

namespace {

std::vector<uint8_t> unhex(const std::string& s) {
    std::vector<uint8_t> out;
    out.reserve(s.size() / 2);
    for (size_t i = 0; i + 1 < s.size(); i += 2) {
        out.push_back(static_cast<uint8_t>(std::stoi(s.substr(i, 2), nullptr, 16)));
    }
    return out;
}

std::string toHex(const uint8_t* p, size_t n) {
    static const char* kDigits = "0123456789abcdef";
    std::string s;
    s.reserve(n * 2);
    for (size_t i = 0; i < n; i++) {
        s.push_back(kDigits[p[i] >> 4]);
        s.push_back(kDigits[p[i] & 0xF]);
    }
    return s;
}

bool eqHex(const char* want, const uint8_t* got, size_t n, std::string& detail) {
    const std::string hex = toHex(got, n);
    if (hex == want) return true;
    detail = std::string("want ") + want + ", got " + hex;
    return false;
}

int cmpBytes(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b) {
    const size_t n = a.size() < b.size() ? a.size() : b.size();
    for (size_t i = 0; i < n; i++) {
        if (a[i] != b[i]) return a[i] < b[i] ? -1 : 1;
    }
    return a.size() < b.size() ? -1 : (a.size() > b.size() ? 1 : 0);
}

/** Same pairwise-key-expansion buffers Kotlin's CrackCore builds. */
void buildPkeSets(const std::vector<uint8_t>& aa, const std::vector<uint8_t>& spa,
                  const std::vector<uint8_t>& anonce, const std::vector<uint8_t>& snonce,
                  PkeSet& out) {
    const bool apFirst = cmpBytes(aa, spa) <= 0;
    const std::vector<uint8_t>& macLow = apFirst ? aa : spa;
    const std::vector<uint8_t>& macHigh = apFirst ? spa : aa;
    const bool anFirst = cmpBytes(anonce, snonce) <= 0;
    const std::vector<uint8_t>& nonLow = anFirst ? anonce : snonce;
    const std::vector<uint8_t>& nonHigh = anFirst ? snonce : anonce;

    static const char kLabel[] = "Pairwise key expansion";   // 22 chars

    out.p100.assign(100, 0);
    std::memcpy(out.p100.data(), kLabel, 22);                 // label + NUL = 23 bytes
    std::memcpy(out.p100.data() + 23, macLow.data(), 6);
    std::memcpy(out.p100.data() + 29, macHigh.data(), 6);
    std::memcpy(out.p100.data() + 35, nonLow.data(), 32);
    std::memcpy(out.p100.data() + 67, nonHigh.data(), 32);

    out.p102.assign(102, 0);
    out.p102[0] = 1;
    std::memcpy(out.p102.data() + 2, kLabel, 22);
    std::memcpy(out.p102.data() + 24, macLow.data(), 6);
    std::memcpy(out.p102.data() + 30, macHigh.data(), 6);
    std::memcpy(out.p102.data() + 36, nonLow.data(), 32);
    std::memcpy(out.p102.data() + 68, nonHigh.data(), 32);
    out.p102[100] = 0x80;
    out.p102[101] = 1;

    out.pstd.assign(100, 0);
    out.pstd[0] = 0;                                         // PRF-384 block counter
    std::memcpy(out.pstd.data() + 1, kLabel, 22);
    out.pstd[23] = 0;
    std::memcpy(out.pstd.data() + 24, macLow.data(), 6);
    std::memcpy(out.pstd.data() + 30, macHigh.data(), 6);
    std::memcpy(out.pstd.data() + 36, nonLow.data(), 32);
    std::memcpy(out.pstd.data() + 68, nonHigh.data(), 32);
}

// --- the two published vectors, named once -----------------------------------------
//
// Both the known-answer checks and the batch test below use these. Copying the
// 242-character EAPOL literal into a second place is exactly how the two would drift
// apart and quietly stop proving the same thing — it already gained nine stray zero
// bytes once.

// hashcat's mode-22000 PMKID self-test: essid "hashcat-essid", password "hashcat!".
const char kPmkidEssid[] = "hashcat-essid";
const char kPmkidPassword[] = "hashcat!";
const char kPmkidAa[] = "fc690c158264";
const char kPmkidSpa[] = "f4747f87f9f4";
const char kPmkidTag[] = "4d4fe7aac3a2cecab195321ceb99a7d0";

// hashcat's published example handshake: essid "TP-LINK_HASHCAT_TEST", password
// "hashcat!", keyver 2. Its stored EAPOL-Key frame carries the supplicant nonce at
// 17..49 and an empty standard KEY NONCE field at 49..81 — verified independently by
// recomputing this line's MIC with the JDK's own PBKDF2/HMAC.
const char kHsEssid[] = "TP-LINK_HASHCAT_TEST";
const char kHsPassword[] = "hashcat!";
const char kHsAa[] = "6466b38ec3fc";
const char kHsSpa[] = "225edc49b7aa";
const char kHsAnonce[] = "10e3be3b005a629e89de088d6a2fdc489db83ad4764f2d186b9cde15446e972e";
const char kHsSnonce[] = "48ce2ccba9c1fda130ff2fbbfb4fd3b063d1a93920b0f7df54a5cbf787b16171";
const char kHsEapol[] =
    "0103007502010a0000000000000000000148ce2ccba9c1fda130ff2f"
    "bbfb4fd3b063d1a93920b0f7df54a5cbf787b1617100000000000000"
    "00000000000000000000000000000000000000000000000000000000"
    "00000000000000000000000000001630140100000fac040100000fac"
    "040100000fac028000";
const char kHsMic[] = "024022795224bffca545276c3762686f";

/** The published PMKID target: kind 1, salt = raw ESSID, tag compared against `kPmkidTag`. */
Target makePmkidTarget() {
    Target t;
    t.kind = 1;
    t.keyver = 0;
    t.salt.assign(std::begin(kPmkidEssid), std::end(kPmkidEssid) - 1);
    t.pmkidData.assign(reinterpret_cast<const uint8_t*>("PMK Name"),
                       reinterpret_cast<const uint8_t*>("PMK Name") + 8);
    const std::vector<uint8_t> aa = unhex(kPmkidAa);
    const std::vector<uint8_t> spa = unhex(kPmkidSpa);
    t.pmkidData.insert(t.pmkidData.end(), aa.begin(), aa.end());
    t.pmkidData.insert(t.pmkidData.end(), spa.begin(), spa.end());
    const std::vector<uint8_t> want = unhex(kPmkidTag);
    std::memcpy(t.expected, want.data(), 16);
    return t;
}

/**
 * The published handshake target, with the nonce at 17..49 — i.e. what CrackCore builds
 * for that 22000 line. Built from the constants above so the batch test below verifies
 * the very same target the known-answer check verifies.
 */
Target makeHandshakeTarget(const std::vector<uint8_t>& eapol) {
    const std::vector<uint8_t> aa = unhex(kHsAa);
    const std::vector<uint8_t> spa = unhex(kHsSpa);
    const std::vector<uint8_t> anonce = unhex(kHsAnonce);
    const std::vector<uint8_t> snonce(eapol.begin() + 17, eapol.begin() + 49);

    PkeSet set;
    buildPkeSets(aa, spa, anonce, snonce, set);

    Target t;
    t.kind = 2;
    t.keyver = 2;
    t.salt.assign(std::begin(kHsEssid), std::end(kHsEssid) - 1);
    const std::vector<uint8_t> want = unhex(kHsMic);
    std::memcpy(t.expected, want.data(), 16);
    t.pkes.push_back(set);
    t.micMsgs.push_back(eapol);
    return t;
}

// --- TLV writer mirroring Kotlin's Material.write (v2) ------------------------------

void putU32(std::vector<uint8_t>& out, uint32_t v) {
    out.push_back(static_cast<uint8_t>(v >> 24));
    out.push_back(static_cast<uint8_t>(v >> 16));
    out.push_back(static_cast<uint8_t>(v >> 8));
    out.push_back(static_cast<uint8_t>(v));
}

void putVec(std::vector<uint8_t>& out, const std::vector<uint8_t>& v) {
    putU32(out, static_cast<uint32_t>(v.size()));
    out.insert(out.end(), v.begin(), v.end());
}

void putTarget(std::vector<uint8_t>& out, const Target& t) {
    out.push_back(t.kind);
    out.push_back(t.keyver);
    putVec(out, t.salt);
    out.insert(out.end(), t.expected, t.expected + 16);
    putVec(out, t.pmkidData);
    putU32(out, static_cast<uint32_t>(t.pkes.size()));
    for (const auto& pk : t.pkes) {
        putVec(out, pk.p100);
        putVec(out, pk.p102);
        putVec(out, pk.pstd);
    }
    putU32(out, static_cast<uint32_t>(t.micMsgs.size()));
    for (const auto& m : t.micMsgs) putVec(out, m);
}

/** The whole v2 blob, exactly as Kotlin's Material.write produces it. */
std::vector<uint8_t> writeMaterial(const std::vector<Target>& targets) {
    std::vector<uint8_t> blob;
    blob.insert(blob.end(), {'M', 'K', 'M', 'T'});
    putU32(blob, 2);
    putU32(blob, static_cast<uint32_t>(targets.size()));
    for (const auto& t : targets) putTarget(blob, t);
    return blob;
}

/** One candidate record: big-endian u32 length, then the bytes. */
void putWord(std::vector<uint8_t>& out, const std::string& word) {
    putU32(out, static_cast<uint32_t>(word.size()));
    out.insert(out.end(), word.begin(), word.end());
}

std::string describePairs(const std::vector<std::pair<int, int>>& pairs) {
    std::string s;
    for (const auto& p : pairs) {
        if (!s.empty()) s += ", ";
        s += "(" + std::to_string(p.first) + "," + std::to_string(p.second) + ")";
    }
    return s;
}

}  // namespace

/** Returns true when every known-answer check passed; otherwise `fail` says which one. */
bool self_test(std::string& fail) {
    // --- hash primitives -----------------------------------------------------------
    //
    // The MD5 list is RFC 1321 appendix A.5 verbatim. Its lengths (0, 1, 3, 14, 26,
    // 62, 80) cross the padding boundary at 56 bytes, which matters because MD5 stores
    // the padded message length little-endian while SHA-1/SHA-256 store it big-endian.
    // A build that used one convention for all three passed MD5("abc") and was wrong
    // for anything 56 bytes or longer — exactly the kind of "it looks fine" bug these
    // vectors exist to make impossible.
    {
        std::vector<std::pair<std::string, const char*>> md5Suite{
            {"", "d41d8cd98f00b204e9800998ecf8427e"},
            {"a", "0cc175b9c0f1b6a831c399e269772661"},
            {"abc", "900150983cd24fb0d6963f7d28e17f72"},
            {"message digest", "f96b697d7cb7938d525a2f31aaf161d0"},
            {"abcdefghijklmnopqrstuvwxyz", "c3fcd3d76192e4007dfb496cca67e13b"},
            {"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
             "d174ab98d277d9f5a5611c2c9f419d9f"},
        };
        // Built rather than copied: the RFC's own display of this one wraps across
        // lines, and a hand-copied 80-character literal is 70 characters waiting to
        // happen (it was, here). Repeating "1234567890" eight times cannot drift.
        std::string digits;
        for (int i = 0; i < 8; i++) digits += "1234567890";
        md5Suite.emplace_back(digits, "57edf4a22be3c955ac49da2e2107b67a");

        uint8_t d[32];
        std::string detail;
        for (const auto& c : md5Suite) {
            md5(reinterpret_cast<const uint8_t*>(c.first.data()), c.first.size(), d);
            if (!eqHex(c.second, d, 16, detail)) {
                fail = "MD5 RFC1321 A.5 (len " + std::to_string(c.first.size()) + "): " + detail;
                return false;
            }
        }

        sha1(reinterpret_cast<const uint8_t*>("abc"), 3, d);
        if (!eqHex("a9993e364706816aba3e25717850c26c9cd0d89d", d, 20, detail)) {
            fail = "SHA-1(\"abc\") FIPS 180-4: " + detail;
            return false;
        }
        sha256(reinterpret_cast<const uint8_t*>("abc"), 3, d);
        if (!eqHex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", d, 32, detail)) {
            fail = "SHA-256(\"abc\") FIPS 180-4: " + detail;
            return false;
        }
    }

    // --- HMAC ----------------------------------------------------------------------
    //
    // RFC 2202 (MD5, SHA-1) and RFC 4231 (SHA-256) cases 1, 2 and 6. The key length
    // matters: RFC 2202's MD5 case 1 uses 16 bytes of 0x0b while RFC 4231's case 1 uses
    // 20 — a detail this test itself got wrong at first, which is worth recording
    // because the failure it produced looked like an implementation bug.
    // Case 6 (key longer than the hash block size) covers the hash-the-key-first path.
    {
        struct HmacCase {
            HashId id; std::vector<uint8_t> key; const char* data; const char* want; size_t outLen;
        };
        // Built, not written as hex: RFC 4231 case 6's key is 131 bytes of 0xaa, and a
        // hand-counted hex literal is exactly where that would go quietly wrong.
        auto rep = [](int byte, size_t n) { return std::vector<uint8_t>(n, uint8_t(byte)); };
        const char* const jefe = "what do ya want for nothing?";
        const std::vector<uint8_t> keyJefe = unhex("4a656665");
        const char* const longData =
            "This is a test using a larger than block-size key and a larger than "
            "block-size data. The key needs to be hashed before being used by the HMAC "
            "algorithm.";
        std::vector<HmacCase> cases;
        cases.push_back({ H_MD5,    rep(0x0b, 16),  "Hi There",
                          "9294727a3638bb1c13f48ef8158bfc9d", 16 });
        cases.push_back({ H_MD5,    keyJefe,        jefe,
                          "750c783e6ab0b503eaa86e310a5db738", 16 });
        cases.push_back({ H_MD5,    rep(0xaa, 80),
                          "Test Using Larger Than Block-Size Key - Hash Key First",
                          "6b1ab7fe4bd7bf8f0b62e6ce61b9d0cd", 16 });
        cases.push_back({ H_SHA1,   rep(0x0b, 20),  "Hi There",
                          "b617318655057264e28bc0b6fb378c8ef146be00", 20 });
        cases.push_back({ H_SHA1,   keyJefe,        jefe,
                          "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79", 20 });
        cases.push_back({ H_SHA1,   rep(0xaa, 80),
                          "Test Using Larger Than Block-Size Key - Hash Key First",
                          "aa4ae5e15272d00e95705637ce8a3b55ed402112", 20 });
        cases.push_back({ H_SHA256, rep(0x0b, 20),  "Hi There",
                          "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7", 32 });
        cases.push_back({ H_SHA256, keyJefe,        jefe,
                          "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843", 32 });
        cases.push_back({ H_SHA256, rep(0xaa, 131),
                          "Test Using Larger Than Block-Size Key - Hash Key First",
                          "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54", 32 });
        // Case 7: both key and data exceed the block size, so the outer hash sees more
        // than one block. That path is not covered by the three cases above.
        cases.push_back({ H_SHA256, rep(0xaa, 131), longData,
                          "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2", 32 });

        for (const auto& c : cases) {
            uint8_t out[32] = {};
            hmac(c.id, c.key.data(), c.key.size(), reinterpret_cast<const uint8_t*>(c.data),
                 std::strlen(c.data), out);
            std::string detail;
            if (!eqHex(c.want, out, c.outLen, detail)) {
                fail = std::string("HMAC case (key ") + std::to_string(c.key.size()) +
                       " bytes, data \"" + c.data + "\"): " + detail;
                return false;
            }
        }
    }

    // --- AES-128 (FIPS-197 appendix C.1) and AES-CMAC (RFC 4493 section 4) ----------
    //
    // All four RFC 4493 lengths are checked: 0 and 64 exercise the empty-message and
    // complete-final-block paths, 16 and 40 the single- and multi-block incomplete
    // paths. hashcat's keyver 3/5 MIC is AES-CMAC, so a wrong branch here means every
    // CCMP handshake reports "not found".
    {
        const std::vector<uint8_t> key = unhex("000102030405060708090a0b0c0d0e0f");
        const std::vector<uint8_t> pt = unhex("00112233445566778899aabbccddeeff");
        uint8_t ct[16];
        std::string detail;
        aes128_encrypt_block(key.data(), pt.data(), ct);
        if (!eqHex("69c4e0d86a7b0430d8cdb78070b4c55a", ct, 16, detail)) {
            fail = "AES-128 FIPS-197 C.1: " + detail;
            return false;
        }

        const std::vector<uint8_t> cmacKey = unhex("2b7e151628aed2a6abf7158809cf4f3c");
        uint8_t zeroBlock[16] = {};
        uint8_t l[16];
        aes128_encrypt_block(cmacKey.data(), zeroBlock, l);
        if (!eqHex("7df76b0c1ab899b33e42f047b91b546f", l, 16, detail)) {
            fail = "AES-CMAC subkey L (RFC 4493): " + detail;
            return false;
        }

        const std::vector<uint8_t> m64 = unhex(
            "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51"
            "30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710");
        struct CmacCase { size_t len; const char* want; };
        const CmacCase cmacCases[] = {
            { 0,  "bb1d6929e95937287fa37d129b756746" },
            { 16, "070a16b46b4d4144f79bdd9dd04a287c" },
            { 40, "dfa66747de9ae63030ca32611497c827" },
            { 64, "51f0bebf7e3b9d92fc49741779363cfe" },
        };
        for (const auto& c : cmacCases) {
            aes_cmac(cmacKey.data(), m64.data(), c.len, ct);
            if (!eqHex(c.want, ct, 16, detail)) {
                fail = "AES-CMAC RFC4493 len=" + std::to_string(c.len) + ": " + detail;
                return false;
            }
        }
    }

    // --- PBKDF2 + the official hashcat PMKID self-test ------------------------------
    //
    // This is the pair that makes the whole crack path meaningful: PBKDF2 is the cost,
    // and the PMKID tag is what a candidate is compared against.
    {
        const std::string essid = "hashcat-essid";
        const std::vector<uint8_t> aa = unhex("fc690c158264");
        const std::vector<uint8_t> spa = unhex("f4747f87f9f4");
        uint8_t pmk[32];
        pbkdf2_sha1_32(reinterpret_cast<const uint8_t*>("hashcat!"), 8,
                       reinterpret_cast<const uint8_t*>(essid.data()), essid.size(), 4096, pmk);

        std::vector<uint8_t> msg = std::vector<uint8_t>(reinterpret_cast<const uint8_t*>("PMK Name"),
                                                        reinterpret_cast<const uint8_t*>("PMK Name") + 8);
        msg.insert(msg.end(), aa.begin(), aa.end());
        msg.insert(msg.end(), spa.begin(), spa.end());
        uint8_t tag[20];
        hmac(H_SHA1, pmk, 32, msg.data(), msg.size(), tag);
        std::string detail;
        if (!eqHex("4d4fe7aac3a2cecab195321ceb99a7d0", tag, 16, detail)) {
            fail = "hashcat PMKID self-test: " + detail;
            return false;
        }

        // The TLV round trip: serialise this target, parse it back, verify both ways.
        Target t;
        t.kind = 1;
        t.keyver = 0;
        t.salt.assign(essid.begin(), essid.end());
        std::memcpy(t.expected, tag, 16);
        t.pmkidData = msg;
        std::vector<uint8_t> blob;
        blob.insert(blob.end(), {'M', 'K', 'M', 'T'});
        putU32(blob, 2);
        putU32(blob, 1);
        putTarget(blob, t);

        std::vector<Target> parsed;
        std::string err;
        if (!parse_material(blob.data(), blob.size(), parsed, err)) {
            fail = "material v2 parse: " + err;
            return false;
        }
        if (parsed.size() != 1 || parsed[0].kind != 1 || parsed[0].salt != t.salt ||
            std::memcmp(parsed[0].expected, t.expected, 16) != 0 || parsed[0].pmkidData != msg) {
            fail = "material v2 round trip changed the target";
            return false;
        }
        if (!verify_with_pmk(parsed[0], pmk)) {
            fail = "material v2 verify rejected the known password";
            return false;
        }
        uint8_t wrong[32];
        pbkdf2_sha1_32(reinterpret_cast<const uint8_t*>("hashcat"), 7,
                       reinterpret_cast<const uint8_t*>(essid.data()), essid.size(), 4096, wrong);
        if (verify_with_pmk(parsed[0], wrong)) {
            fail = "material v2 verify accepted a near-miss password";
            return false;
        }

        // Transport must refuse a v1 blob rather than guess at it: v1 carried one pke
        // set, and re-reading it under v2 would hide the other nonce placement.
        std::vector<uint8_t> v1 = blob;
        v1[7] = 1;
        if (parse_material(v1.data(), v1.size(), parsed, err)) {
            fail = "material v1 blob was accepted; it cannot be re-read safely";
            return false;
        }
        if (parse_material(blob.data(), blob.size() - 4, parsed, err)) {
            fail = "truncated material blob was accepted";
            return false;
        }
    }

    // --- handshake KAT: hashcat's published example handshake ------------------------
    //
    // Same line the JVM tests use. The stored blob carries its supplicant nonce at
    // 17..49 (the layout that reproduces this line's MIC — verified against the JDK's
    // own PBKDF2/HMAC), so that is the placement the buffers are built for here.
    {
        const std::string essid = kHsEssid;
        const std::vector<uint8_t> eapol = unhex(kHsEapol);
        // The blob is checked against its own EAPOL-Key header rather than taken on
        // trust: a hand-copied 242-character hex string is nine stray zero bytes waiting
        // to happen (it happened, here), and a corrupted blob still looks like an EAPOL
        // frame while verifying nothing.
        if (eapol.size() != 121) {
            fail = "handshake KAT: stored EAPOL is " + std::to_string(eapol.size()) +
                   " bytes; its own body-length field says 117 + 4";
            return false;
        }
        if (((eapol[2] << 8) | eapol[3]) != 117 || eapol[97] != 0 || eapol[98] != 22) {
            fail = "handshake KAT: EAPOL body length / key-data length do not match the published vector";
            return false;
        }
        const std::vector<uint8_t> snonce(eapol.begin() + 17, eapol.begin() + 49);
        if (toHex(snonce.data(), snonce.size()) != kHsSnonce) {
            fail = "handshake KAT: the supplicant nonce is not where this vector puts it";
            return false;
        }
        for (size_t i = 49; i < 81; i++) {
            if (eapol[i] != 0) {
                fail = "handshake KAT: the standard KEY NONCE field is not empty in this vector";
                return false;
            }
        }

        const Target t = makeHandshakeTarget(eapol);

        uint8_t pmk[32];
        pbkdf2_sha1_32(reinterpret_cast<const uint8_t*>(kHsPassword), std::strlen(kHsPassword),
                       reinterpret_cast<const uint8_t*>(essid.data()), essid.size(), 4096, pmk);
        if (!verify_with_pmk(t, pmk)) {
            fail = "handshake KAT: the known password did not verify (pke layout or MIC variants)";
            return false;
        }
        uint8_t wrong[32];
        pbkdf2_sha1_32(reinterpret_cast<const uint8_t*>("hashcat1"), 8,
                       reinterpret_cast<const uint8_t*>(essid.data()), essid.size(), 4096, wrong);
        if (verify_with_pmk(t, wrong)) {
            fail = "handshake KAT: a near-miss password verified";
            return false;
        }

        // The same line read with the nonce in the standard's KEY NONCE field (49..81)
        // must NOT verify: that pins the layout distinction rather than hiding it.
        Target other = t;
        PkeSet set2;
        const std::vector<uint8_t> snonceOther(eapol.begin() + 49, eapol.begin() + 81);
        buildPkeSets(unhex(kHsAa), unhex(kHsSpa), unhex(kHsAnonce), snonceOther, set2);
        other.pkes.assign(1, set2);
        if (verify_with_pmk(other, pmk)) {
            fail = "handshake KAT: the other nonce placement also verified, so the test proves nothing";
            return false;
        }
    }

    // --- batch cracking: the plumbing the engines are built on -----------------------
    //
    // Everything above pins the primitives. This pins the loop that turns them into a
    // crack run, and it lives in the core rather than in the JNI wrapper so it can be run
    // here at all — a batch loop in a wrapper is only ever exercised on a phone, which is
    // the worst possible place to find such a bug. What has to hold:
    //
    //  * every candidate is tried against every target, including the ones that share a
    //    PBKDF2 salt (one derivation feeding several targets is the whole point of
    //    grouping, and a wrong group assignment shows up here as a missed target);
    //  * the reported (wordIndex, targetIndex) pairs are exact, and in word order, so the
    //    UI attributes a recovered password to the right hash line;
    //  * the answer does not depend on how many cores ran the batch;
    //  * malformed input is reported as a failure, never as an empty result — "nothing
    //    matched" and "could not run" must not look the same to the caller.
    //
    // Targets 0 and 1 are the published vectors checked above. Targets 2 and 3 are derived
    // with the primitives already pinned there, because attribution and ordering are what
    // is under test here, not the hashes.
    {
        auto pmkidTargetFor = [](const std::string& essid, const std::string& password,
                                 const std::string& aaHex, const std::string& spaHex) {
            Target t;
            t.kind = 1;
            t.keyver = 0;
            t.salt.assign(essid.begin(), essid.end());
            const std::vector<uint8_t> aa = unhex(aaHex);
            const std::vector<uint8_t> spa = unhex(spaHex);
            t.pmkidData.assign(reinterpret_cast<const uint8_t*>("PMK Name"),
                               reinterpret_cast<const uint8_t*>("PMK Name") + 8);
            t.pmkidData.insert(t.pmkidData.end(), aa.begin(), aa.end());
            t.pmkidData.insert(t.pmkidData.end(), spa.begin(), spa.end());
            uint8_t pmk[32];
            pbkdf2_sha1_32(reinterpret_cast<const uint8_t*>(password.data()), password.size(),
                           t.salt.data(), t.salt.size(), 4096, pmk);
            uint8_t tag[20];
            hmac(H_SHA1, pmk, 32, t.pmkidData.data(), t.pmkidData.size(), tag);
            std::memcpy(t.expected, tag, 16);
            return t;
        };

        // A second client of the same network: same salt, so the same PBKDF2 output, and
        // the group logic has to serve it from that one derivation.
        const std::string essidA = kPmkidEssid;
        const std::string essidC = "another-network";

        std::vector<Target> targets;
        targets.push_back(makePmkidTarget());                              // 0, published
        targets.push_back(makeHandshakeTarget(unhex(kHsEapol)));           // 1, published
        targets.push_back(pmkidTargetFor(essidA, kPmkidPassword, "000e9004aaaa", "001132aa64c8"));
        targets.push_back(pmkidTargetFor(essidC, "alpha-only", "000e90041234", "001132aabbcc"));

        const std::vector<std::string> words = {
            "hashcat",     // right network, wrong password
            "alpha-only",  // target 3
            "hashcat!!",   // near miss everywhere
            kPmkidPassword, // targets 0, 1 and 2
            "short",       // below the 8-char WPA minimum: must not upset the packing
        };

        std::vector<uint8_t> packed;
        for (const auto& w : words) putWord(packed, w);
        const std::vector<uint8_t> blob = writeMaterial(targets);

        const std::vector<std::pair<int, int>> want = {
            {1, 3}, {3, 0}, {3, 1}, {3, 2},
        };

        // threads=0 means "however many cores this machine reports", so this loop also
        // covers the auto-selected split without the test hard-coding a core count.
        const int threadCounts[] = { 1, 2, 3, 4, 16, 0 };
        for (const int count : threadCounts) {
            std::vector<std::pair<int, int>> found;
            std::string err;
            if (!crack_batch(blob.data(), blob.size(), packed.data(), packed.size(),
                             count, found, err)) {
                fail = "crack_batch(threads=" + std::to_string(count) + "): " + err;
                return false;
            }
            if (found != want) {
                fail = "crack_batch(threads=" + std::to_string(count) + "): got [" +
                       describePairs(found) + "], want [" + describePairs(want) + "]";
                return false;
            }
        }

        // An empty batch is a legitimate call with an empty answer, not a failure. The
        // vectors here are empty on purpose: an empty std::vector's data() may be null,
        // and that must not be read as a truncated buffer.
        {
            const std::vector<uint8_t> noCandidates;
            std::vector<std::pair<int, int>> found;
            std::string err;
            if (!crack_batch(blob.data(), blob.size(), noCandidates.data(), noCandidates.size(),
                             4, found, err) || !found.empty()) {
                fail = "crack_batch with no candidates should succeed and find nothing";
                return false;
            }
        }

        // Malformed input must come back as a failure. If any of these returned true with
        // an empty list, the app would tell the user the password is not in the wordlist.
        struct BadCase { const char* what; std::vector<uint8_t> bytes; };
        std::vector<BadCase> bad;
        {
            std::vector<uint8_t> truncated = packed;
            truncated.resize(truncated.size() - 3);           // ends inside a candidate
            bad.push_back({ "candidate buffer truncated mid-word", truncated });
        }
        {
            std::vector<uint8_t> midHeader = packed;
            midHeader.resize(midHeader.size() - 1);           // ends inside a length field
            bad.push_back({ "candidate buffer ends inside a length header", midHeader });
        }
        {
            std::vector<uint8_t> zeroLen = packed;
            for (size_t i = 0; i + 3 < zeroLen.size(); i++) zeroLen[i] = 0;  // u32 length 0
            bad.push_back({ "zero-length candidate", zeroLen });
        }
        {
            std::vector<uint8_t> hugeLen = packed;
            hugeLen[0] = 0xFF; hugeLen[1] = 0xFF;             // length far past any word
            bad.push_back({ "implausible candidate length", hugeLen });
        }
        {
            std::vector<uint8_t> v1 = blob;
            v1[7] = 1;                                        // material protocol v1
            bad.push_back({ "material v1 blob", v1 });
        }
        {
            std::vector<uint8_t> cut = blob;
            cut.resize(cut.size() - 4);
            bad.push_back({ "truncated material blob", cut });
        }
        for (const auto& c : bad) {
            std::vector<std::pair<int, int>> found;
            std::string err;
            const bool ok = crack_batch(c.bytes.data(), c.bytes.size(),
                                        packed.data(), packed.size(), 2, found, err);
            if (ok) {
                fail = std::string("crack_batch accepted ") + c.what +
                       " and reported [found " + describePairs(found) + "]";
                return false;
            }
            if (err.empty()) fail = std::string("crack_batch(") + c.what + ") failed without a reason";
        }
    }

    return true;
}

}  // namespace mktest

#ifdef MK_SELFTEST_MAIN
int main() {
    std::string fail;
    if (mktest::self_test(fail)) {
        std::puts("SELFTEST OK");
        return 0;
    }
    std::printf("SELFTEST FAILED: %s\n", fail.c_str());
    return 1;
}
#endif
