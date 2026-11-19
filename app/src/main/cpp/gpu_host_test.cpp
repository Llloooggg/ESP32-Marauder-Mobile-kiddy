/* Vulkan known-answer test, built and run on a development machine.

     g++ -std=c++17 -O2 -Wall -Wextra -pthread -DMK_GPU_HOST_TEST \
         wpa_crypto.cpp vulkan_engine.cpp gpu_host_test.cpp -o gpu_host_test -lvulkan
     ./gpu_host_test
*/
//
// Why a host test for a GPU path at all: the shader is compiled by the NDK's glslc and then
// run by whatever driver the phone happens to have, and neither of those is this machine.
// Running the production code here — Session, device selection, pipeline, dispatch,
// readback, the same self_test() the app calls on the phone — against a software Vulkan
// driver is what proves the harness and the shader agree with the published vectors. The
// phone then only has to answer "does THIS driver also agree", which is the question that
// can only be asked on the phone.
//
// A Debian/WSL container gets a driver from `mesa-vulkan-drivers` (llvmpipe, ICD in
// /usr/share/vulkan/icd.d/lvp_icd.json) and headers from `libvulkan-dev`.
#include "mk_test_fixtures.h"
#include "vulkan_engine.h"
#include "wpa_crypto.h"

#ifdef MK_GPU_HOST_TEST
#include <cstdio>
#include <string>
#include <vector>

namespace {

bool samePairs(const std::vector<std::pair<int, int>>& a, const std::vector<std::pair<int, int>>& b) {
    return a == b;
}

int report(const char* message) {
    std::printf("GPU HOST TEST FAILED: %s\n", message);
    return 1;
}

}  // namespace

int main() {
    std::string reason;
    if (!mkgpu::available(reason)) return report(("no usable Vulkan device: " + reason).c_str());
    std::printf("vulkan device under test: %s\n", mkgpu::deviceName().c_str());

    std::string err;
    if (!mkgpu::self_test(err)) return report(err.c_str());
    std::printf("published PMKID vector and CPU-agreement cross-check: OK\n");

    // The CPU engine and the GPU engine, same material, same candidates, one expected
    // answer. If these ever differ, the backend the user picked is not the backend whose
    // behaviour the test suite describes, and that is the failure this whole split is not
    // allowed to have.
    const mktest::BatchCase c = mktest::makeBatchCase();
    std::vector<std::pair<int, int>> cpuPairs;
    if (!mk::crack_batch(c.material.data(), c.material.size(), c.packedWords.data(),
                         c.packedWords.size(), 4, cpuPairs, err)) {
        return report(("CPU batch: " + err).c_str());
    }
    std::vector<std::pair<int, int>> gpuPairs;
    if (!mkgpu::crack_batch_gpu(c.material.data(), c.material.size(), c.packedWords.data(),
                                c.packedWords.size(), gpuPairs, err)) {
        return report(("GPU batch: " + err).c_str());
    }
    if (!samePairs(cpuPairs, c.expect)) {
        return report(("CPU pairs [" + mktest::describePairs(cpuPairs) + "] != expected [" +
                       mktest::describePairs(c.expect) + "]").c_str());
    }
    if (!samePairs(gpuPairs, cpuPairs)) {
        return report(("GPU pairs [" + mktest::describePairs(gpuPairs) + "] != CPU pairs [" +
                       mktest::describePairs(cpuPairs) + "]").c_str());
    }
    std::printf("batch agreement: OK (%zu pairs: %s)\n", gpuPairs.size(),
                mktest::describePairs(gpuPairs).c_str());

    // A salt longer than an ESSID can be must be refused, not derived: hashing a truncated
    // salt would report "password not in this wordlist" for a password that might be in it.
    {
        std::vector<mk::Target> targets{ mktest::makePmkidTarget() };
        targets[0].salt.assign(40, 'x');
        const std::vector<uint8_t> material = mktest::writeMaterial(targets);
        std::vector<std::pair<int, int>> found;
        std::string saltErr;
        if (mkgpu::crack_batch_gpu(material.data(), material.size(), c.packedWords.data(),
                                   c.packedWords.size(), found, saltErr)) {
            return report("a 40-byte salt was accepted; the kernel would derive the wrong key");
        }
        std::printf("oversized salt refused as expected: %s\n", saltErr.c_str());
    }

    std::printf("GPU HOST TEST OK\n");
    return 0;
}
#endif
