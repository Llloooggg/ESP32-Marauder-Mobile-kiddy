// Implementation of wpa_crypto.h. Written from the algorithm specifications
// (FIPS 180-4 SHA-1/SHA-256, RFC 1321 MD5, RFC 2104 HMAC, RFC 2898 PBKDF2,
// FIPS 197 AES, RFC 4493 AES-CMAC) and checked at runtime by selftest.cpp —
// the app refuses to use this code for real runs unless those known answers
// match, so a mistake here cannot produce a silent false negative.
#include "wpa_crypto.h"

#include <algorithm>   // std::min, std::sort
#include <cstring>
#include <system_error>  // the exception std::thread throws when it cannot start
#include <thread>

namespace mk {
namespace {

inline uint32_t load32be(const uint8_t* p) {
    return (uint32_t(p[0]) << 24) | (uint32_t(p[1]) << 16) | (uint32_t(p[2]) << 8) | p[3];
}
inline uint32_t load32le(const uint8_t* p) {
    return p[0] | (uint32_t(p[1]) << 8) | (uint32_t(p[2]) << 16) | (uint32_t(p[3]) << 24);
}
inline void store32be(uint8_t* p, uint32_t v) {
    p[0] = uint8_t(v >> 24); p[1] = uint8_t(v >> 16); p[2] = uint8_t(v >> 8); p[3] = uint8_t(v);
}
inline void store32le(uint8_t* p, uint32_t v) {
    p[0] = uint8_t(v); p[1] = uint8_t(v >> 8); p[2] = uint8_t(v >> 16); p[3] = uint8_t(v >> 24);
}
inline void store64be(uint8_t* p, uint64_t v) {
    for (int i = 0; i < 8; i++) p[i] = uint8_t(v >> (56 - 8 * i));
}
inline void store64le(uint8_t* p, uint64_t v) {
    for (int i = 0; i < 8; i++) p[i] = uint8_t(v >> (8 * i));
}

// ---- SHA-1 ---------------------------------------------------------------------

inline uint32_t rotl32(uint32_t v, int n) { return (v << n) | (v >> (32 - n)); }
/** SHA-256's Σ/σ functions are defined as right rotations (FIPS 180-4 section 4.1.2);
 *  SHA-1's are left rotations. They are not interchangeable, and a hash built with the
 *  wrong direction is still 32 hex characters, it is just not SHA-256. */
inline uint32_t rotr32(uint32_t v, int n) { return (v >> n) | (v << (32 - n)); }

void sha1_compress(uint32_t h[5], const uint8_t block[64]) {
    uint32_t w[80];
    for (int i = 0; i < 16; i++) w[i] = load32be(block + 4 * i);
    for (int i = 16; i < 80; i++) w[i] = rotl32(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);

    uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4];
    for (int i = 0; i < 80; i++) {
        uint32_t f, k;
        if (i < 20)      { f = (b & c) | ((~b) & d);            k = 0x5A827999u; }
        else if (i < 40) { f = b ^ c ^ d;                       k = 0x6ED9EBA1u; }
        else if (i < 60) { f = (b & c) | (b & d) | (c & d);     k = 0x8F1BBCDCu; }
        else             { f = b ^ c ^ d;                       k = 0xCA62C1D6u; }
        const uint32_t tmp = rotl32(a, 5) + f + e + k + w[i];
        e = d; d = c; c = rotl32(b, 30); b = a; a = tmp;
    }
    h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e;
}

// ---- MD5 -----------------------------------------------------------------------

const uint32_t MD5_K[64] = {
    0xd76aa478u, 0xe8c7b756u, 0x242070dbu, 0xc1bdceeeu, 0xf57c0fafu, 0x4787c62au, 0xa8304613u, 0xfd469501u,
    0x698098d8u, 0x8b44f7afu, 0xffff5bb1u, 0x895cd7beu, 0x6b901122u, 0xfd987193u, 0xa679438eu, 0x49b40821u,
    0xf61e2562u, 0xc040b340u, 0x265e5a51u, 0xe9b6c7aau, 0xd62f105du, 0x02441453u, 0xd8a1e681u, 0xe7d3fbc8u,
    0x21e1cde6u, 0xc33707d6u, 0xf4d50d87u, 0x455a14edu, 0xa9e3e905u, 0xfcefa3f8u, 0x676f02d9u, 0x8d2a4c8au,
    0xfffa3942u, 0x8771f681u, 0x6d9d6122u, 0xfde5380cu, 0xa4beea44u, 0x4bdecfa9u, 0xf6bb4b60u, 0xbebfbc70u,
    0x289b7ec6u, 0xeaa127fau, 0xd4ef3085u, 0x04881d05u, 0xd9d4d039u, 0xe6db99e5u, 0x1fa27cf8u, 0xc4ac5665u,
    0xf4292244u, 0x432aff97u, 0xab9423a7u, 0xfc93a039u, 0x655b59c3u, 0x8f0ccc92u, 0xffeff47du, 0x85845dd1u,
    0x6fa87e4fu, 0xfe2ce6e0u, 0xa3014314u, 0x4e0811a1u, 0xf7537e82u, 0xbd3af235u, 0x2ad7d2bbu, 0xeb86d391u,
};

const int MD5_S[64] = {
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
    5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
};

void md5_compress(uint32_t h[4], const uint8_t block[64]) {
    uint32_t m[16];
    for (int i = 0; i < 16; i++) m[i] = load32le(block + 4 * i);
    uint32_t a = h[0], b = h[1], c = h[2], d = h[3];
    for (int i = 0; i < 64; i++) {
        uint32_t f;
        int g;
        if (i < 16)      { f = (b & c) | ((~b) & d);            g = i; }
        else if (i < 32) { f = (d & b) | ((~d) & c);            g = (5 * i + 1) & 15; }
        else if (i < 48) { f = b ^ c ^ d;                       g = (3 * i + 5) & 15; }
        else             { f = c ^ (b | (~d));                  g = (7 * i) & 15; }
        f += a + MD5_K[i] + m[g];
        a = d; d = c; c = b;
        b += rotl32(f, MD5_S[i]);
    }
    h[0] += a; h[1] += b; h[2] += c; h[3] += d;
}

// ---- SHA-256 -------------------------------------------------------------------

const uint32_t SHA256_K[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
    0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u, 0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
    0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
    0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u, 0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u, 0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u,
};

void sha256_compress(uint32_t h[8], const uint8_t block[64]) {
    uint32_t w[64];
    for (int i = 0; i < 16; i++) w[i] = load32be(block + 4 * i);
    for (int i = 16; i < 64; i++) {
        const uint32_t s0 = rotr32(w[i - 15], 7) ^ rotr32(w[i - 15], 18) ^ (w[i - 15] >> 3);
        const uint32_t s1 = rotr32(w[i - 2], 17) ^ rotr32(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];
    for (int i = 0; i < 64; i++) {
        const uint32_t S1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
        const uint32_t ch = (e & f) ^ ((~e) & g);
        const uint32_t t1 = hh + S1 + ch + SHA256_K[i] + w[i];
        const uint32_t S0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
        const uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        const uint32_t t2 = S0 + maj;
        hh = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }
    h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
}

// ---- generic merkle-damgard hashing over an in-memory message --------------------

constexpr size_t BLOCK = 64;  // all three hashes share a 64-byte block

/**
 * Merkle–Damgård hashing over an in-memory message, with the padding conventions
 * supplied by the policy.
 *
 * MD5 differs from SHA-1/SHA-256 in BOTH places a hash's bytes are read or written:
 * its block words are little-endian (that is inside its compress function), its
 * 64-bit message-length field is little-endian, and its digest words are
 * little-endian. Getting either of the last two wrong produces a digest that looks
 * like a digest and is simply wrong — the RFC 1321 / FIPS 180-4 known answers in
 * `selftest.cpp` are what keep this honest.
 */
template <typename H>
void hash_generic(const uint8_t* msg, size_t len, uint8_t* out, uint32_t init[8], size_t digestWords) {
    uint32_t h[8];
    std::memcpy(h, init, digestWords * sizeof(uint32_t));

    size_t off = 0;
    while (len - off >= BLOCK) {
        H::compress(h, msg + off);
        off += BLOCK;
    }
    const size_t rem = len - off;

    uint8_t tail[128];
    std::memset(tail, 0, sizeof(tail));
    std::memcpy(tail, msg + off, rem);
    tail[rem] = 0x80;
    const size_t total = (rem + 1 + 8 <= BLOCK) ? BLOCK : 2 * BLOCK;
    if constexpr (H::kLittleEndianLength) {
        store64le(tail + total - 8, uint64_t(len) * 8u);
    } else {
        store64be(tail + total - 8, uint64_t(len) * 8u);
    }
    for (size_t i = 0; i < total; i += BLOCK) H::compress(h, tail + i);

    for (size_t i = 0; i < digestWords; i++) {
        if constexpr (H::kLittleEndianDigest) store32le(out + 4 * i, h[i]);
        else store32be(out + 4 * i, h[i]);
    }
}

struct Sha1Policy  {
    static void compress(uint32_t* h, const uint8_t* b) { sha1_compress(h, b); }
    static constexpr bool kLittleEndianLength = false;
    static constexpr bool kLittleEndianDigest = false;
};
struct Md5Policy   {
    static void compress(uint32_t* h, const uint8_t* b) { md5_compress(h, b); }
    static constexpr bool kLittleEndianLength = true;   // RFC 1321 section 3.2
    static constexpr bool kLittleEndianDigest = true;   // RFC 1321 section 3.4
};
struct Sha256Policy{
    static void compress(uint32_t* h, const uint8_t* b) { sha256_compress(h, b); }
    static constexpr bool kLittleEndianLength = false;
    static constexpr bool kLittleEndianDigest = false;
};

const uint32_t SHA1_INIT[8]   = {0x67452301u, 0xefcdab89u, 0x98badcfeu, 0x10325476u, 0xc3d2e1f0u};
const uint32_t MD5_INIT[8]    = {0x67452301u, 0xefcdab89u, 0x98badcfeu, 0x10325476u};
const uint32_t SHA256_INIT[8] = {0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
                                 0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u};

size_t digest_len(HashId id) { return id == H_MD5 ? 16 : (id == H_SHA1 ? 20 : 32); }

}  // namespace

void sha1(const uint8_t* msg, size_t len, uint8_t out[20]) {
    uint32_t init[8];
    std::memcpy(init, SHA1_INIT, sizeof(uint32_t) * 5);
    hash_generic<Sha1Policy>(msg, len, out, init, 5);
}

void md5(const uint8_t* msg, size_t len, uint8_t out[16]) {
    uint32_t init[8];
    std::memcpy(init, MD5_INIT, sizeof(uint32_t) * 4);
    // The little-endian length field and the little-endian digest words both come
    // from Md5Policy; an extra byte-swap pass here would undo them.
    hash_generic<Md5Policy>(msg, len, out, init, 4);
}

void sha256(const uint8_t* msg, size_t len, uint8_t out[32]) {
    hash_generic<Sha256Policy>(msg, len, out, const_cast<uint32_t*>(SHA256_INIT), 8);
}

void hmac(HashId id, const uint8_t* key, size_t keyLen,
          const uint8_t* msg, size_t msgLen, uint8_t* out) {
    const size_t dlen = digest_len(id);

    uint8_t keyBlock[BLOCK];
    std::memset(keyBlock, 0, BLOCK);
    if (keyLen > BLOCK) {
        uint8_t hashed[32];
        switch (id) {
            case H_MD5:    md5(key, keyLen, hashed); break;
            case H_SHA256: sha256(key, keyLen, hashed); break;
            default:       sha1(key, keyLen, hashed); break;
        }
        std::memcpy(keyBlock, hashed, dlen);
    } else {
        std::memcpy(keyBlock, key, keyLen);
    }

    uint8_t ipad[BLOCK], opad[BLOCK];
    for (size_t i = 0; i < BLOCK; i++) {
        ipad[i] = uint8_t(keyBlock[i] ^ 0x36);
        opad[i] = uint8_t(keyBlock[i] ^ 0x5c);
    }

    // inner = H(ipad || msg), outer = H(opad || inner). Concatenated into one pass
    // when the message is small, which it always is here (< a few hundred bytes).
    std::vector<uint8_t> innerIn(BLOCK + msgLen);
    std::memcpy(innerIn.data(), ipad, BLOCK);
    if (msgLen) std::memcpy(innerIn.data() + BLOCK, msg, msgLen);
    uint8_t inner[32];
    switch (id) {
        case H_MD5:    md5(innerIn.data(), innerIn.size(), inner); break;
        case H_SHA256: sha256(innerIn.data(), innerIn.size(), inner); break;
        default:       sha1(innerIn.data(), innerIn.size(), inner); break;
    }

    std::vector<uint8_t> outerIn(BLOCK + dlen);
    std::memcpy(outerIn.data(), opad, BLOCK);
    std::memcpy(outerIn.data() + BLOCK, inner, dlen);
    switch (id) {
        case H_MD5:    md5(outerIn.data(), outerIn.size(), out); break;
        case H_SHA256: sha256(outerIn.data(), outerIn.size(), out); break;
        default:       sha1(outerIn.data(), outerIn.size(), out); break;
    }
}

void hmac_truncated(HashId id, const uint8_t* key, size_t keyLen,
                    const uint8_t* msg, size_t msgLen, uint8_t* out, size_t outLen) {
    uint8_t full[32];
    hmac(id, key, keyLen, msg, msgLen, full);
    const size_t dlen = digest_len(id);
    std::memcpy(out, full, outLen < dlen ? outLen : dlen);
    // A prefix, matching Kotlin's `hmac(...).copyOfRange(0, 16)` in CrackCore.
}

void pbkdf2_sha1_32(const uint8_t* pass, size_t passLen,
                    const uint8_t* salt, size_t saltLen,
                    uint32_t iterations, uint8_t out[32]) {
    // Two 20-byte blocks concatenated: WPA-PSK takes the first 32 of 40 bytes.
    for (uint32_t block = 1; block <= 2; block++) {
        std::vector<uint8_t> first(saltLen + 4);
        if (saltLen) std::memcpy(first.data(), salt, saltLen);
        store32be(first.data() + saltLen, block);

        uint8_t u[20], t[20];
        hmac(H_SHA1, pass, passLen, first.data(), first.size(), u);
        std::memcpy(t, u, 20);
        for (uint32_t i = 1; i < iterations; i++) {
            hmac(H_SHA1, pass, passLen, u, 20, u);
            for (int j = 0; j < 20; j++) t[j] ^= u[j];
        }
        std::memcpy(out + 20 * (block - 1), t, block == 2 ? 12 : 20);
    }
}

// ---- AES-128 (encryption only, which is all CMAC needs) ---------------------------

const uint8_t SBOX[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
};

const uint8_t RCON[11] = {0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36};

inline uint8_t xtime(uint8_t v) { return uint8_t((v << 1) ^ ((v & 0x80) ? 0x1b : 0x00)); }

inline uint8_t gmul(uint8_t a, uint8_t b) {
    uint8_t r = 0;
    for (int i = 0; i < 8; i++) {
        if (b & 1) r ^= a;
        b >>= 1;
        a = xtime(a);
    }
    return r;
}

void aes128_expand(const uint8_t key[16], uint8_t roundKeys[176]) {
    std::memcpy(roundKeys, key, 16);
    for (int i = 4; i < 44; i++) {
        uint8_t t[4];
        std::memcpy(t, roundKeys + 4 * (i - 1), 4);
        if (i % 4 == 0) {
            const uint8_t tmp = t[0];
            t[0] = uint8_t(SBOX[t[1]] ^ RCON[i / 4]);
            t[1] = SBOX[t[2]];
            t[2] = SBOX[t[3]];
            t[3] = SBOX[tmp];
        }
        for (int j = 0; j < 4; j++) roundKeys[4 * i + j] = uint8_t(roundKeys[4 * (i - 4) + j] ^ t[j]);
    }
}

/**
 * AES-128 block encryption, textbook round structure (FIPS-197 section 5.1):
 * AddRoundKey(0), then rounds 1..9 of SubBytes/ShiftRows/MixColumns/AddRoundKey,
 * then the final round without MixColumns.
 *
 * An earlier version of this loop ran 16 rounds and indexed roundKeys up to
 * `16*15+15` while the schedule holds 11 round keys (176 bytes) — out of bounds and
 * wrong output. The FIPS-197 known-answer test in `selftest.cpp` is what proves the
 * current form; without that test the mistake would have silently mis-MIC'd every
 * handshake on every device.
 */
void aes128_encrypt_block(const uint8_t key[16], const uint8_t in[16], uint8_t out[16]) {
    uint8_t roundKeys[176];
    aes128_expand(key, roundKeys);
    uint8_t s[16];
    std::memcpy(s, in, 16);

    // ShiftRows on the column-major AES state: byte i is row i%4, column i/4.
    auto addRoundKey = [&](int r) {
        for (int i = 0; i < 16; i++) s[i] ^= roundKeys[16 * r + i];
    };
    auto subAndShift = [&] {
        for (int i = 0; i < 16; i++) s[i] = SBOX[s[i]];
        uint8_t t[16];
        std::memcpy(t, s, 16);
        for (int c = 0; c < 4; c++)
            for (int row = 0; row < 4; row++)
                s[4 * c + row] = t[4 * ((c + row) & 3) + row];
    };
    auto mixColumns = [&] {
        for (int c = 0; c < 4; c++) {
            const uint8_t a0 = s[4 * c], a1 = s[4 * c + 1], a2 = s[4 * c + 2], a3 = s[4 * c + 3];
            s[4 * c]     = uint8_t(gmul(a0, 2) ^ gmul(a1, 3) ^ a2 ^ a3);
            s[4 * c + 1] = uint8_t(a0 ^ gmul(a1, 2) ^ gmul(a2, 3) ^ a3);
            s[4 * c + 2] = uint8_t(a0 ^ a1 ^ gmul(a2, 2) ^ gmul(a3, 3));
            s[4 * c + 3] = uint8_t(gmul(a0, 3) ^ a1 ^ a2 ^ gmul(a3, 2));
        }
    };

    addRoundKey(0);
    for (int r = 1; r < 10; r++) {
        subAndShift();
        mixColumns();
        addRoundKey(r);
    }
    subAndShift();
    addRoundKey(10);

    std::memcpy(out, s, 16);
}

void aes_cmac(const uint8_t key[16], const uint8_t* msg, size_t len, uint8_t out[16]) {
    uint8_t zero[16] = {};
    uint8_t L[16];
    aes128_encrypt_block(key, zero, L);

    uint8_t K1[16], K2[16];
    // GF(2^128) doubling: shift left by one, and reduce by Rb = 0x87 only when the
    // bit shifted out of the most significant byte was set (RFC 4493 section 5.3).
    uint8_t carry = 0;
    for (int i = 15; i >= 0; i--) {
        const uint8_t next = uint8_t((L[i] & 0x80) ? 1 : 0);
        K1[i] = uint8_t((L[i] << 1) | carry);
        carry = next;
    }
    if (carry) K1[15] ^= 0x87;
    carry = 0;
    for (int i = 15; i >= 0; i--) {
        const uint8_t next = uint8_t((K1[i] & 0x80) ? 1 : 0);
        K2[i] = uint8_t((K1[i] << 1) | carry);
        carry = next;
    }
    if (carry) K2[15] ^= 0x87;

    const size_t nBlocks = (len == 0) ? 1 : (len + 15) / 16;
    const bool complete = (len != 0) && (len % 16 == 0);

    uint8_t chain[16] = {};
    for (size_t b = 0; b < nBlocks; b++) {
        uint8_t block[16];
        const size_t off = b * 16;
        const size_t take = (len - off < 16) ? (len - off) : 16;
        std::memset(block, 0, 16);
        if (take) std::memcpy(block, msg + off, take);
        if (b + 1 == nBlocks) {
            // RFC 4493 step 4: a complete last block is XORed with K1; otherwise the
            // partial block is padded 10^i (a single 0x80 bit, then zeros) and XORed
            // with K2. For the empty message n == 1 and the block is just 0x80||0^120.
            if (!complete) block[take] = 0x80;
            const uint8_t* subkey = complete ? K1 : K2;
            for (int i = 0; i < 16; i++) block[i] ^= subkey[i];
        }
        uint8_t in[16];
        for (int i = 0; i < 16; i++) in[i] = uint8_t(chain[i] ^ block[i]);
        aes128_encrypt_block(key, in, chain);
    }
    std::memcpy(out, chain, 16);
}

bool ct_equal(const uint8_t* a, const uint8_t* b, size_t n) {
    uint8_t diff = 0;
    for (size_t i = 0; i < n; i++) diff = uint8_t(diff | (a[i] ^ b[i]));
    return diff == 0;
}

// --- material TLV ------------------------------------------------------------------

namespace {
uint32_t rd32(const uint8_t* p) { return load32be(p); }

bool rdVec(const uint8_t*& p, const uint8_t* end, std::vector<uint8_t>& out) {
    if (p + 4 > end) return false;
    const uint32_t n = rd32(p);
    p += 4;
    if (n > (1u << 20) || p + n > end) return false;
    out.assign(p, p + n);
    p += n;
    return true;
}
}  // namespace

bool parse_material(const uint8_t* buf, size_t len, std::vector<Target>& out, std::string& err) {
    if (len < 12) { err = "material blob too short"; return false; }
    if (std::memcmp(buf, "MKMT", 4) != 0) { err = "material blob: bad magic"; return false; }
    const uint32_t version = rd32(buf + 4);
    // v1 carried a single pke triple, which silently dropped the other EAPOL nonce
    // layout; accepting it would let a native run report "not found" for a hash the
    // app's own verifier cracks. Re-jet it and let the caller re-serialise.
    if (version != 2) { err = "material blob: unsupported version " + std::to_string(version) + " (this build reads v2)"; return false; }
    const uint32_t count = rd32(buf + 8);
    if (count == 0 || count > 4096) { err = "material blob: implausible target count"; return false; }

    const uint8_t* p = buf + 12;
    const uint8_t* end = buf + len;
    out.clear();
    out.reserve(count);
    for (uint32_t i = 0; i < count; i++) {
        if (p + 2 > end) { err = "material blob: truncated target header"; return false; }
        Target t;
        t.kind = *p++;
        t.keyver = *p++;
        if (!rdVec(p, end, t.salt)) { err = "material blob: truncated salt"; return false; }
        if (p + 16 > end) { err = "material blob: truncated tag"; return false; }
        std::memcpy(t.expected, p, 16);
        p += 16;
        if (!rdVec(p, end, t.pmkidData)) { err = "material blob: truncated pmkid data"; return false; }
        if (p + 4 > end) { err = "material blob: truncated pke set count"; return false; }
        const uint32_t sets = rd32(p);
        p += 4;
        if (sets > 8) { err = "material blob: implausible pke set count"; return false; }
        for (uint32_t s = 0; s < sets; s++) {
            PkeSet set;
            if (!rdVec(p, end, set.p100)) { err = "material blob: truncated pke100"; return false; }
            if (!rdVec(p, end, set.p102)) { err = "material blob: truncated pke102"; return false; }
            if (!rdVec(p, end, set.pstd)) { err = "material blob: truncated pke_std"; return false; }
            t.pkes.push_back(std::move(set));
        }
        if (p + 4 > end) { err = "material blob: truncated message count"; return false; }
        const uint32_t msgs = rd32(p);
        p += 4;
        if (msgs > 64) { err = "material blob: implausible message count"; return false; }
        for (uint32_t m = 0; m < msgs; m++) {
            std::vector<uint8_t> msg;
            if (!rdVec(p, end, msg)) { err = "material blob: truncated mic message"; return false; }
            t.micMsgs.push_back(std::move(msg));
        }
        if (!t.usable()) { err = "material blob: target " + std::to_string(i) + " is missing required fields"; return false; }
        out.push_back(std::move(t));
    }
    return true;
}

bool verify_with_pmk(const Target& t, const uint8_t pmk[32]) {
    uint8_t tag[32];
    if (t.kind == 1) {
        hmac(H_SHA1, pmk, 32, t.pmkidData.data(), t.pmkidData.size(), tag);
        return ct_equal(tag, t.expected, 16);
    }

    // Same order as CrackCore.verifyWithPmk: for every nonce placement, expand the
    // key material, then try each MIC message against every variant.
    for (const auto& pk : t.pkes) {
        // Every KCK here is the first 16 bytes of a longer HMAC, the same truncation
        // CrackCore.verifyWithPmk applies with copyOfRange(0, 16). Passing these
        // 16-byte buffers to the raw hmac() would overflow them by 4 or 16 bytes.
        uint8_t kde100[16], kde100md5[16], kde102[16], kckStd[16];
        hmac_truncated(H_SHA1,   pmk, 32, pk.p100.data(), pk.p100.size(), kde100, 16);
        hmac_truncated(H_MD5,    pmk, 32, pk.p100.data(), pk.p100.size(), kde100md5, 16);
        hmac_truncated(H_SHA256, pmk, 32, pk.p102.data(), pk.p102.size(), kde102, 16);
        hmac_truncated(H_SHA1,   pmk, 32, pk.pstd.data(), pk.pstd.size(), kckStd, 16);

        for (const auto& msg : t.micMsgs) {
            hmac(H_MD5, kde100, 16, msg.data(), msg.size(), tag);
            if (ct_equal(tag, t.expected, 16)) return true;
            hmac(H_SHA1, kde100, 16, msg.data(), msg.size(), tag);
            if (ct_equal(tag, t.expected, 16)) return true;
            aes_cmac(kde102, msg.data(), msg.size(), tag);
            if (ct_equal(tag, t.expected, 16)) return true;
            aes_cmac(kckStd, msg.data(), msg.size(), tag);
            if (ct_equal(tag, t.expected, 16)) return true;
            hmac(H_MD5, kde100md5, 16, msg.data(), msg.size(), tag);
            if (ct_equal(tag, t.expected, 16)) return true;
        }
    }
    return false;
}

// ---- batch input handling, shared by the CPU and Vulkan back ends ------------------

bool unpack_candidates(const uint8_t* buf, size_t len, std::vector<Candidate>& out,
                       std::string& err) {
    // An empty vector's data() may be null, and `null + 0` is not a pointer worth
    // forming, so the no-candidate case returns here rather than through the loop.
    if (len == 0) return true;
    const uint8_t* p = buf;
    const uint8_t* end = buf + len;
    while (p < end) {
        if (p + 4 > end) { err = "word buffer ends inside a length field"; return false; }
        const uint32_t n = (uint32_t(p[0]) << 24) | (uint32_t(p[1]) << 16) |
                           (uint32_t(p[2]) << 8) | p[3];
        p += 4;
        if (n == 0 || n > kMaxCandidateLength) {
            err = "implausible candidate length " + std::to_string(n);
            return false;
        }
        if (p + n > end) { err = "word buffer truncated mid-word"; return false; }
        out.push_back(Candidate{ p, n });
        p += n;
    }
    return true;
}

std::vector<SaltGroup> group_targets_by_salt(const std::vector<Target>& targets) {
    std::vector<SaltGroup> groups;
    for (size_t i = 0; i < targets.size(); i++) {
        bool placed = false;
        for (auto& g : groups) {
            if (g.salt == targets[i].salt) { g.targets.push_back(int(i)); placed = true; break; }
        }
        if (!placed) groups.push_back(SaltGroup{ targets[i].salt, { int(i) } });
    }
    return groups;
}

// ---- one batch of a crack run ----------------------------------------------------
//
// Kept in the core (not in the JNI wrapper) so the logic that can actually go wrong —
// grouping targets by PBKDF2 salt, reusing one derivation across them, splitting work
// across cores, ordering results — is the logic the host known-answer test runs. The
// wrapper is left doing nothing but copying arrays.

bool crack_batch(const uint8_t* material, size_t materialLen,
                 const uint8_t* packedWords, size_t wordsLen,
                 int threads,
                 std::vector<std::pair<int, int>>& found,
                 std::string& err) {
    found.clear();
    std::vector<Target> targets;
    if (!parse_material(material, materialLen, targets, err)) return false;

    std::vector<Candidate> candidates;
    if (!unpack_candidates(packedWords, wordsLen, candidates, err)) return false;

    const std::vector<SaltGroup> groups = group_targets_by_salt(targets);

    const unsigned hw = std::thread::hardware_concurrency();
    int workers = threads > 0 ? threads : int(hw > 0 ? hw : 1u);
    if (workers < 1) workers = 1;
    if (workers > int(candidates.size())) workers = int(candidates.size());
    if (workers < 1) workers = 1;

    // One result list per thread: no shared writes in the hot loop. The merged list is
    // sorted afterwards, so the caller sees wordlist order regardless of how the words
    // happened to land.
    std::vector<std::vector<int>> foundPerThread;
    foundPerThread.resize(size_t(workers));
    const size_t per = (candidates.size() + size_t(workers) - 1) / size_t(workers);

    // A worker's entire job, as one function both the threaded path and the fallback
    // below call. Two copies of this loop is how one half of them would end up disagreeing
    // about which candidates were tried.
    auto scan = [&](size_t from, size_t to, std::vector<int>& local) {
        uint8_t pmk[32];
        for (size_t w = from; w < to; w++) {
            const Candidate& word = candidates[w];
            for (const auto& g : groups) {
                pbkdf2_sha1_32(word.bytes, word.len, g.salt.data(), g.salt.size(), 4096, pmk);
                for (int t : g.targets) {
                    if (verify_with_pmk(targets[size_t(t)], pmk)) {
                        local.push_back(int(w));
                        local.push_back(t);
                    }
                }
            }
        }
    };

    auto worker = [&](int index) {
        const size_t from = size_t(index) * per;
        scan(from, std::min(candidates.size(), from + per), foundPerThread[size_t(index)]);
    };

    std::vector<std::thread> pool;
    pool.reserve(size_t(workers));
    int launched = 0;
    try {
        for (int i = 0; i < workers; i++) {
            pool.emplace_back(worker, i);
            launched = i + 1;
        }
    } catch (const std::system_error& /*e*/) {
        // Thread creation failed (a tight process limit, an absurd request). The workers
        // that did start own the ranges [0, launched*per) and are still running, so this
        // thread finishes the ranges nobody was given. Every range is independent and
        // writes only to its own slot, so nothing here is tried twice or skipped — the
        // batch still covers every candidate, which is why no error is reported: the
        // answer it produces is the same answer the threaded path would have produced.
        for (int i = launched; i < workers; i++) worker(i);
    }
    for (auto& t : pool) t.join();

    std::vector<std::pair<int, int>> ordered;
    for (const auto& local : foundPerThread) {
        for (size_t i = 0; i + 1 < local.size(); i += 2) ordered.emplace_back(local[i], local[i + 1]);
    }
    std::sort(ordered.begin(), ordered.end());
    found = ordered;
    return true;
}

}  // namespace mk
