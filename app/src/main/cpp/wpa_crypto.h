// WPA2-PSK (hashcat mode 22000) crypto core for the native cracking engines.
//
// Everything here is deliberately self-contained: no OpenSSL, no JNI types, no
// Android dependencies, so the exact same code can be unit-tested, and the same
// semantics as `extractor/CrackCore.verifyWithPmk` are reproduced byte for byte.
//
// The variant superset mirrors hashcat v6.2.6 module_22000: its deep-compute aux
// kernels all run for one hash (their guards are `type != 2 && keyver != N`), so
// keyver only selects the byte-swap convention, not one MIC algorithm. A candidate
// is accepted when ANY variant matches, each tag truncated to 16 bytes.
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace mk {

enum HashId { H_SHA1 = 0, H_MD5 = 1, H_SHA256 = 2 };

void sha1(const uint8_t* msg, size_t len, uint8_t out[20]);
void md5(const uint8_t* msg, size_t len, uint8_t out[16]);
void sha256(const uint8_t* msg, size_t len, uint8_t out[32]);

/** Raw HMAC of one message. `out` must hold the hash's own length (20/16/32). */
void hmac(HashId id, const uint8_t* key, size_t keyLen,
          const uint8_t* msg, size_t msgLen, uint8_t* out);

/**
 * HMAC kept to its first `outLen` bytes, which is how the WPA key-derivation
 * functions use it (KCK/TEK = first 16 bytes of a 20- or 32-byte digest).
 *
 * This exists because calling the raw `hmac` with a 16-byte buffer is a buffer
 * overflow, not a truncation: SHA-1 writes 20 bytes and SHA-256 writes 32 past the
 * end of the array. That happened here, and it produced wrong MICs rather than a
 * crash — the handshake known-answer test is what caught it.
 */
void hmac_truncated(HashId id, const uint8_t* key, size_t keyLen,
                    const uint8_t* msg, size_t msgLen, uint8_t* out, size_t outLen);

/**
 * PBKDF2-HMAC-SHA1 for exactly 32 output bytes, i.e. the two WPA-PSK blocks.
 * This is what dominates cracking cost, so it is written as a rolling HMAC
 * (no per-iteration buffers) and it is the part the GPU kernel replicates.
 */
void pbkdf2_sha1_32(const uint8_t* pass, size_t passLen,
                    const uint8_t* salt, size_t saltLen,
                    uint32_t iterations, uint8_t out[32]);

void aes128_encrypt_block(const uint8_t key[16], const uint8_t in[16], uint8_t out[16]);

/** RFC 4493 / SP 800-38B AES-128 CMAC (what hashcat's keyver-2 aux3 kernel uses). */
void aes_cmac(const uint8_t key[16], const uint8_t* msg, size_t len, uint8_t out[16]);

/** Length-independent compare (crack loops compare public tags, but keep it simple). */
bool ct_equal(const uint8_t* a, const uint8_t* b, size_t n);

/**
 * One batch of a crack run: verify candidate words against the targets in a material
 * blob, and report which (word, target) pairs verified.
 *
 * `packedWords` is a sequence of records: big-endian u32 length, then that many bytes —
 * the same length-prefix convention the material TLV uses for its buffers.
 *
 * This lives in the core rather than in the JNI wrapper so that the part with real
 * logic (salt grouping, PBKDF2 reuse across targets of one network, thread splitting,
 * result ordering) is the part the host known-answer test exercises. The JNI layer is
 * then only array marshalling, which is the least likely place to be wrong and the
 * easiest to see wrong on a device.
 *
 * `threads` <= 0 means "use every core the device reports".
 * Returns false with `err` set when the inputs cannot be read; that is deliberately not
 * the same as an empty `found`, because "nothing matched" and "could not run" must not
 * look identical to the caller.
 */
bool crack_batch(const uint8_t* material, size_t materialLen,
                 const uint8_t* packedWords, size_t wordsLen,
                 int threads,
                 std::vector<std::pair<int, int>>& found,
                 std::string& err);

// --- session material -------------------------------------------------------------

/** One pairwise-key-expansion buffer set: one placement of the SNonce. */
struct PkeSet {
    std::vector<uint8_t> p100;   // HMAC-SHA1 key-expansion input
    std::vector<uint8_t> p102;   // HMAC-SHA256 key-expansion input
    std::vector<uint8_t> pstd;   // 802.11 PRF-384 (KCKstd) input
};

/**
 * One parsed 22000 record with everything password-independent pre-computed,
 * exactly as `WpaTarget` does it in Kotlin. The app serialises the session's
 * targets once (TLV, see `Material.write`) and the native side parses that into
 * these structs, so parsing/hex handling lives in one place only.
 */
struct Target {
    uint8_t kind = 0;              // 1 = PMKID (WPA*01), 2 = handshake (WPA*02)
    uint8_t keyver = 0;            // informational: matches the Kotlin parse
    std::vector<uint8_t> salt;     // PBKDF2 salt == raw SSID bytes
    uint8_t expected[16] = {};     // PMKID or Key MIC we are looking for
    std::vector<uint8_t> pmkidData;  // "PMK Name" || AA || SPA (kind 1)
    /**
     * One entry per plausible placement of the supplicant nonce inside the stored
     * EAPOL blob (the 22000 line has two competing conventions). The Kotlin verifier
     * tries all of them, so the native one must too — otherwise the same hash cracks
     * on one engine and comes back "not found" on the other.
     */
    std::vector<PkeSet> pkes;
    std::vector<std::vector<uint8_t>> micMsgs;  // candidate MIC messages

    bool usable() const {
        if (salt.empty()) return false;
        if (kind == 1) return !pmkidData.empty();
        if (kind == 2) return !pkes.empty() && !micMsgs.empty();
        return false;
    }
};

/** Parses the app's TLV material blob. On failure returns false and sets `err`. */
bool parse_material(const uint8_t* buf, size_t len, std::vector<Target>& out, std::string& err);

/**
 * Verifies an already-derived PMK against one target — the same variant
 * combination `CrackCore.verifyWithPmk` runs, in the same order.
 */
bool verify_with_pmk(const Target& t, const uint8_t pmk[32]);
}  // namespace mk
