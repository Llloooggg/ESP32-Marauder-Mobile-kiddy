// Shared fixtures for the native cracking tests: the CPU known-answer test
// (selftest.cpp) and the Vulkan host test (gpu_host_test.cpp).
//
// Both need the same published vectors and the same idea of what a session's material
// looks like, and they have to mean exactly the same thing by it: the claim under test is
// that the CPU engine and the Vulkan engine agree about a hash, and that claim is worthless
// if each test builds its own target. One fixture, two engines.
//
// Header-only and test-only: nothing in the shipping engines includes it.
#pragma once

#include "wpa_crypto.h"

#include <cstring>
#include <iterator>
#include <string>
#include <utility>
#include <vector>

namespace mktest {

inline std::vector<uint8_t> unhex(const std::string& s) {
    std::vector<uint8_t> out;
    out.reserve(s.size() / 2);
    for (size_t i = 0; i + 1 < s.size(); i += 2) {
        out.push_back(static_cast<uint8_t>(std::stoi(s.substr(i, 2), nullptr, 16)));
    }
    return out;
}

inline std::string toHex(const uint8_t* p, size_t n) {
    static const char* kDigits = "0123456789abcdef";
    std::string s;
    s.reserve(n * 2);
    for (size_t i = 0; i < n; i++) {
        s.push_back(kDigits[p[i] >> 4]);
        s.push_back(kDigits[p[i] & 0xF]);
    }
    return s;
}

inline bool eqHex(const char* want, const uint8_t* got, size_t n, std::string& detail) {
    const std::string hex = toHex(got, n);
    if (hex == want) return true;
    detail = std::string("want ") + want + ", got " + hex;
    return false;
}

inline int cmpBytes(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b) {
    const size_t n = a.size() < b.size() ? a.size() : b.size();
    for (size_t i = 0; i < n; i++) {
        if (a[i] != b[i]) return a[i] < b[i] ? -1 : 1;
    }
    return a.size() < b.size() ? -1 : (a.size() > b.size() ? 1 : 0);
}

/** The pairwise-key-expansion buffers, built the way Kotlin's CrackCore builds them. */
inline void buildPkeSets(const std::vector<uint8_t>& aa, const std::vector<uint8_t>& spa,
                         const std::vector<uint8_t>& anonce, const std::vector<uint8_t>& snonce,
                         mk::PkeSet& out) {
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
// Used by the known-answer checks, the batch test and the Vulkan test. Copying the
// 242-character EAPOL literal into a second place is how two tests would drift apart and
// quietly stop proving the same thing — it already gained nine stray zero bytes once.

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

inline std::vector<uint8_t> handshakeEapol() { return unhex(kHsEapol); }

/** The published PMKID target: kind 1, salt = raw ESSID, tag compared against kPmkidTag. */
inline mk::Target makePmkidTarget() {
    mk::Target t;
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
 * The published handshake target, with the nonce at 17..49 — i.e. what CrackCore builds for
 * that 22000 line. Every test that needs a handshake target gets it from here, so a fix to
 * the vector fixes all of them at once.
 */
inline mk::Target makeHandshakeTarget(const std::vector<uint8_t>& eapol) {
    const std::vector<uint8_t> aa = unhex(kHsAa);
    const std::vector<uint8_t> spa = unhex(kHsSpa);
    const std::vector<uint8_t> anonce = unhex(kHsAnonce);
    const std::vector<uint8_t> snonce(eapol.begin() + 17, eapol.begin() + 49);

    mk::PkeSet set;
    buildPkeSets(aa, spa, anonce, snonce, set);

    mk::Target t;
    t.kind = 2;
    t.keyver = 2;
    t.salt.assign(std::begin(kHsEssid), std::end(kHsEssid) - 1);
    const std::vector<uint8_t> want = unhex(kHsMic);
    std::memcpy(t.expected, want.data(), 16);
    t.pkes.push_back(set);
    t.micMsgs.push_back(eapol);
    return t;
}

// --- session material, mirroring Kotlin's Material.write (v2) ----------------------

inline void putU32(std::vector<uint8_t>& out, uint32_t v) {
    out.push_back(static_cast<uint8_t>(v >> 24));
    out.push_back(static_cast<uint8_t>(v >> 16));
    out.push_back(static_cast<uint8_t>(v >> 8));
    out.push_back(static_cast<uint8_t>(v));
}

inline void putVec(std::vector<uint8_t>& out, const std::vector<uint8_t>& v) {
    putU32(out, static_cast<uint32_t>(v.size()));
    out.insert(out.end(), v.begin(), v.end());
}

inline void putTarget(std::vector<uint8_t>& out, const mk::Target& t) {
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
inline std::vector<uint8_t> writeMaterial(const std::vector<mk::Target>& targets) {
    std::vector<uint8_t> blob;
    blob.insert(blob.end(), {'M', 'K', 'M', 'T'});
    putU32(blob, 2);
    putU32(blob, static_cast<uint32_t>(targets.size()));
    for (const auto& t : targets) putTarget(blob, t);
    return blob;
}

/** One candidate record: big-endian u32 length, then the bytes. */
inline void putWord(std::vector<uint8_t>& out, const std::string& word) {
    putU32(out, static_cast<uint32_t>(word.size()));
    out.insert(out.end(), word.begin(), word.end());
}

inline std::string describePairs(const std::vector<std::pair<int, int>>& pairs) {
    std::string s;
    for (const auto& p : pairs) {
        if (!s.empty()) s += ", ";
        s += "(" + std::to_string(p.first) + "," + std::to_string(p.second) + ")";
    }
    return s;
}

/** A PMKID target whose expected tag is derived with the primitives pinned elsewhere. */
inline mk::Target makeDerivedPmkidTarget(const std::string& essid, const std::string& password,
                                         const std::string& aaHex, const std::string& spaHex) {
    mk::Target t;
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
    mk::pbkdf2_sha1_32(reinterpret_cast<const uint8_t*>(password.data()), password.size(),
                       t.salt.data(), t.salt.size(), 4096, pmk);
    uint8_t tag[20];
    mk::hmac(mk::H_SHA1, pmk, 32, t.pmkidData.data(), t.pmkidData.size(), tag);
    std::memcpy(t.expected, tag, 16);
    return t;
}

// --- one batch case both engines must solve identically ----------------------------
//
// Four targets and five candidates, chosen so that a batch loop cannot pass by accident:
//
//  * two targets on one ESSID (a second client of the same network), which is what the
//    salt grouping exists to share, and which is missed if grouping is wrong;
//  * one target on a second ESSID, crackable by a different candidate, so the grouping has
//    to be right rather than merely fast;
//  * a published PMKID and a published handshake in the same batch, so kind 1 and kind 2
//    are both exercised together;
//  * candidates that are near misses everywhere ("hashcat", "hashcat!!") and one below the
//    WPA minimum length, so attribution has to be exact rather than "found something".
//
// The published vectors' expected tags come from hashcat; the two derived targets' tags come
// from the primitives this file's other sections pin to RFC/published answers, so what the
// batch case adds is attribution and ordering, not more hashing evidence.
struct BatchCase {
    std::vector<mk::Target> targets;
    std::vector<std::string> words;
    std::vector<uint8_t> material;
    std::vector<uint8_t> packedWords;
    std::vector<std::pair<int, int>> expect;
};

inline BatchCase makeBatchCase() {
    BatchCase c;
    c.targets.push_back(makePmkidTarget());                              // 0, published
    c.targets.push_back(makeHandshakeTarget(handshakeEapol()));           // 1, published
    c.targets.push_back(makeDerivedPmkidTarget(kPmkidEssid, kPmkidPassword,
                                               "000e9004aaaa", "001132aa64c8"));
    c.targets.push_back(makeDerivedPmkidTarget("another-network", "alpha-only",
                                               "000e90041234", "001132aabbcc"));

    c.words = {
        "hashcat",        // right network, wrong password
        "alpha-only",     // target 3
        "hashcat!!",      // near miss everywhere
        kPmkidPassword,   // targets 0, 1 and 2
        "short",          // below the 8-char WPA minimum: must not upset the packing
    };

    c.material = writeMaterial(c.targets);
    for (const auto& w : c.words) putWord(c.packedWords, w);

    // (word index, target index), in word order.
    c.expect = { {1, 3}, {3, 0}, {3, 1}, {3, 2} };
    return c;
}
}  // namespace mktest
