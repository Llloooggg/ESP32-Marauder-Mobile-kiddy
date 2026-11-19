// Vulkan compute back end for the PBKDF2 half of a WPA2-PSK guess.
//
// The split is deliberate: the GPU does the 4096 HMAC-SHA1 rounds per guess (the entire
// cost), and the CPU does the MIC/PMKID comparison with the same `mk::verify_with_pmk`
// the CPU engine uses. Two implementations of "is this a match" is how a GPU run and a
// CPU run end up disagreeing about the same hash, so there is only one.
//
// The header deliberately keeps Vulkan out of `wpa_crypto.h`: the core is what the host
// known-answer test builds with plain g++, and it must stay free of driver dependencies.
//
// On a development machine this file is exercised by gpu_host_test.cpp, which calls the
// same self_test() through the same code path on a software Vulkan driver.
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#include "wpa_crypto.h"

namespace mkgpu {

/**
 * False + a human-readable reason when this machine has no Vulkan compute device the
 * engine can use. The probe result is cached: it is what the crack screen shows next to
 * the backend choice, so it has to be cheap enough to ask on every screen update.
 */
bool available(std::string& reason);

/** The compute device that would be used ("Adreno (TM) 740"), empty when none is usable. */
std::string deviceName();

/**
 * Derives 32-byte PMKs for candidates [from, to) against every salt, on the GPU.
 *
 * `pmksOut` is (to-from) * salts.size() * 32 bytes, candidate-major: pair index is
 * (candidate - from) * salts.size() + saltIndex, the same order the shader uses.
 *
 * Returns false with `err` when the dispatch could not be set up or run. An empty result
 * is never returned for a failure: "no candidate matched" and "the GPU could not run"
 * must not look the same to the caller.
 */
bool derive_pmks(const std::vector<mk::Candidate>& candidates, size_t from, size_t to,
                 const std::vector<std::vector<uint8_t>>& salts, uint32_t iterations,
                 std::vector<uint8_t>& pmksOut, std::string& err);

/**
 * A whole batch: GPU PBKDF2, then the CPU's own verification of every resulting PMK.
 * Returns the same (wordIndex, targetIndex) pairs, in the same order, as
 * `mk::crack_batch` does for the same inputs — the two engines differ only in where the
 * PBKDF2 rounds run, which is what lets the GPU path be checked against the CPU path.
 */
bool crack_batch_gpu(const uint8_t* material, size_t materialLen,
                     const uint8_t* packedWords, size_t wordsLen,
                     std::vector<std::pair<int, int>>& found, std::string& err);

/**
 * Known-answer gate for this device's driver. Runs hashcat's published PMKID vector
 * through the shader and compares the tag the CPU derives from the resulting PMK against
 * the published value, then checks the shader's PMKs against this repo's own CPU PBKDF2
 * over inputs chosen to cover the cases that single vector does not.
 *
 * Returns true when every check passed. The app runs this before it will use the GPU at
 * all, because a shader that is subtly wrong on one driver reports "password not found"
 * for a password that is in the wordlist.
 */
bool self_test(std::string& err);
}  // namespace mkgpu
