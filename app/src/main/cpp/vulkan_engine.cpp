// Implementation of vulkan_engine.h against core Vulkan 1.0, with no extensions and no
// loader wrappers, so the same source builds against the NDK's libvulkan on Android and
// against the desktop loader in a development container.
#include "vulkan_engine.h"

#include <vulkan/vulkan.h>

#include "pbkdf2_sha1_spv.h"

#include <algorithm>
#include <cstring>
#include <mutex>

namespace mkgpu {
namespace {

// Must agree with local_size_x in shader/pbkdf2_sha1.comp. The dispatch size is derived
// from it, so a shader that changes its workgroup size without this constant being
// changed would process the wrong number of candidates - a mistake the self-test would
// catch, but not one worth leaving to chance.
constexpr uint32_t kWorkgroupSize = 32;

// Pairs per dispatch. 16k candidates x 32 bytes of output is 512 KiB, which every driver
// seen accepts as a storage buffer, and one dispatch at that size is already far more
// work than the launch overhead it amortises.
constexpr size_t kMaxPairsPerDispatch = 1u << 14;

// An ESSID is at most 32 octets, which is also the most the 22000 salt field can carry,
// so a longer salt means the input is not what this app believes it to be. Refusing is
// better than deriving against a salt the kernel would truncate: that would report
// "password not in this wordlist" for a password that may well be in it.
constexpr size_t kMaxSaltLength = 32;

constexpr uint32_t kSpiRV = 0x07230203u;   // SPIR-V magic, little-endian image

constexpr uint32_t kIterationsWpa2Psk = 4096;

struct PushConstants {
    uint32_t iterations;
    uint32_t saltCount;
    uint32_t pairCount;
};

const char* resultName(VkResult r) {
    switch (r) {
        case VK_SUCCESS: return "VK_SUCCESS";
        case VK_ERROR_INITIALIZATION_FAILED: return "VK_ERROR_INITIALIZATION_FAILED";
        case VK_ERROR_INCOMPATIBLE_DRIVER: return "VK_ERROR_INCOMPATIBLE_DRIVER";
        case VK_ERROR_OUT_OF_HOST_MEMORY: return "VK_ERROR_OUT_OF_HOST_MEMORY";
        case VK_ERROR_OUT_OF_DEVICE_MEMORY: return "VK_ERROR_OUT_OF_DEVICE_MEMORY";
        case VK_ERROR_DEVICE_LOST: return "VK_ERROR_DEVICE_LOST";
        case VK_ERROR_EXTENSION_NOT_PRESENT: return "VK_ERROR_EXTENSION_NOT_PRESENT";
        case VK_INCOMPLETE: return "VK_INCOMPLETE";
        default: return "VkResult(other)";
    }
}

struct Buffer {
    VkBuffer handle = VK_NULL_HANDLE;
    VkDeviceMemory memory = VK_NULL_HANDLE;
    VkDeviceSize size = 0;
    void* mapped = nullptr;
};

/**
 * One GPU session: instance, device, pipeline. Created per dispatch on purpose. Device
 * creation costs tens of milliseconds, which is noise next to the 4096-round PBKDF2 work
 * a batch does (a batch is thousands of guesses), and it keeps there's no long-lived
 * device to reason about across threads, suspend/resume or a driver that goes away.
 */
struct Session {
    VkInstance instance = VK_NULL_HANDLE;
    VkPhysicalDevice physical = VK_NULL_HANDLE;
    VkDevice device = VK_NULL_HANDLE;
    VkQueue queue = VK_NULL_HANDLE;
    uint32_t queueFamily = 0;
    bool haveQueueFamily = false;
    VkCommandPool pool = VK_NULL_HANDLE;
    VkDescriptorPool descriptorPool = VK_NULL_HANDLE;
    VkDescriptorSetLayout setLayout = VK_NULL_HANDLE;
    VkPipelineLayout pipelineLayout = VK_NULL_HANDLE;
    VkShaderModule shader = VK_NULL_HANDLE;
    VkPipeline pipeline = VK_NULL_HANDLE;
    VkPhysicalDeviceLimits limits{};
    VkPhysicalDeviceMemoryProperties memoryProps{};
    std::string name;

    ~Session() { release(); }

    Session() = default;
    Session(const Session&) = delete;
    Session& operator=(const Session&) = delete;

    void release() {
        if (device != VK_NULL_HANDLE) vkDeviceWaitIdle(device);
        if (pipeline != VK_NULL_HANDLE) vkDestroyPipeline(device, pipeline, nullptr);
        if (shader != VK_NULL_HANDLE) vkDestroyShaderModule(device, shader, nullptr);
        if (pipelineLayout != VK_NULL_HANDLE) vkDestroyPipelineLayout(device, pipelineLayout, nullptr);
        if (setLayout != VK_NULL_HANDLE) vkDestroyDescriptorSetLayout(device, setLayout, nullptr);
        if (descriptorPool != VK_NULL_HANDLE) vkDestroyDescriptorPool(device, descriptorPool, nullptr);
        if (pool != VK_NULL_HANDLE) vkDestroyCommandPool(device, pool, nullptr);
        if (device != VK_NULL_HANDLE) vkDestroyDevice(device, nullptr);
        if (instance != VK_NULL_HANDLE) vkDestroyInstance(instance, nullptr);
        pipeline = VK_NULL_HANDLE;
        shader = VK_NULL_HANDLE;
        pipelineLayout = VK_NULL_HANDLE;
        setLayout = VK_NULL_HANDLE;
        descriptorPool = VK_NULL_HANDLE;
        pool = VK_NULL_HANDLE;
        device = VK_NULL_HANDLE;
        instance = VK_NULL_HANDLE;
    }

    bool pickMemoryType(uint32_t typeBits, VkMemoryPropertyFlags want, uint32_t& out,
                        std::string& err) const {
        for (uint32_t i = 0; i < memoryProps.memoryTypeCount; i++) {
            if ((typeBits & (1u << i)) &&
                (memoryProps.memoryTypes[i].propertyFlags & want) == want) {
                out = i;
                return true;
            }
        }
        err = "no device memory type for the requested properties";
        return false;
    }

    bool createBuffer(VkDeviceSize size, VkBufferUsageFlags usage,
                      VkMemoryPropertyFlags preferred, VkMemoryPropertyFlags fallback,
                      Buffer& out, std::string& err) {
        if (size == 0) { err = "zero-sized buffer requested"; return false; }
        if (size > limits.maxStorageBufferRange) {
            err = "buffer of " + std::to_string(size) + " bytes exceeds this device's " +
                  "maxStorageBufferRange (" + std::to_string(limits.maxStorageBufferRange) + ")";
            return false;
        }

        VkBufferCreateInfo bi{};
        bi.sType = VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO;
        bi.size = size;
        bi.usage = usage;
        bi.sharingMode = VK_SHARING_MODE_EXCLUSIVE;
        VkResult r = vkCreateBuffer(device, &bi, nullptr, &out.handle);
        if (r != VK_SUCCESS) {
            err = std::string("vkCreateBuffer: ") + resultName(r);
            return false;
        }
        out.size = size;

        VkMemoryRequirements req{};
        vkGetBufferMemoryRequirements(device, out.handle, &req);

        uint32_t type = 0;
        if (!pickMemoryType(req.memoryTypeBits, preferred, type, err) &&
            !pickMemoryType(req.memoryTypeBits, fallback, type, err)) {
            vkDestroyBuffer(device, out.handle, nullptr);
            out.handle = VK_NULL_HANDLE;
            return false;
        }

        VkMemoryAllocateInfo ai{};
        ai.sType = VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO;
        ai.allocationSize = req.size;
        ai.memoryTypeIndex = type;
        r = vkAllocateMemory(device, &ai, nullptr, &out.memory);
        if (r != VK_SUCCESS) {
            vkDestroyBuffer(device, out.handle, nullptr);
            out.handle = VK_NULL_HANDLE;
            err = std::string("vkAllocateMemory: ") + resultName(r);
            return false;
        }
        r = vkBindBufferMemory(device, out.handle, out.memory, 0);
        if (r != VK_SUCCESS) {
            vkFreeMemory(device, out.memory, nullptr);
            vkDestroyBuffer(device, out.handle, nullptr);
            out.handle = VK_NULL_HANDLE;
            out.memory = VK_NULL_HANDLE;
            err = std::string("vkBindBufferMemory: ") + resultName(r);
            return false;
        }

        if (preferred & VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT) {
            r = vkMapMemory(device, out.memory, 0, size, 0, &out.mapped);
            if (r != VK_SUCCESS) {
                err = std::string("vkMapMemory: ") + resultName(r);
                return false;
            }
        }
        return true;
    }

    void destroyBuffer(Buffer& b) {
        if (b.mapped != nullptr) { vkUnmapMemory(device, b.memory); b.mapped = nullptr; }
        if (b.memory != VK_NULL_HANDLE) { vkFreeMemory(device, b.memory, nullptr); b.memory = VK_NULL_HANDLE; }
        if (b.handle != VK_NULL_HANDLE) { vkDestroyBuffer(device, b.handle, nullptr); b.handle = VK_NULL_HANDLE; }
    }

    bool init(std::string& err) {
        VkApplicationInfo app{};
        app.sType = VK_STRUCTURE_TYPE_APPLICATION_INFO;
        app.pApplicationName = "marauder-crack";
        app.apiVersion = VK_MAKE_VERSION(1, 0, 0);

        VkInstanceCreateInfo ici{};
        ici.sType = VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO;
        ici.pApplicationInfo = &app;
        VkResult r = vkCreateInstance(&ici, nullptr, &instance);
        if (r == VK_ERROR_INCOMPATIBLE_DRIVER) { err = "no Vulkan driver on this device"; return false; }
        if (r != VK_SUCCESS && r != VK_INCOMPLETE) {
            err = std::string("vkCreateInstance: ") + resultName(r);
            return false;
        }

        uint32_t count = 0;
        r = vkEnumeratePhysicalDevices(instance, &count, nullptr);
        if (r != VK_SUCCESS && r != VK_INCOMPLETE) {
            err = std::string("vkEnumeratePhysicalDevices: ") + resultName(r);
            return false;
        }
        if (count == 0) { err = "the Vulkan driver reports no physical device"; return false; }
        std::vector<VkPhysicalDevice> devices(count);
        r = vkEnumeratePhysicalDevices(instance, &count, devices.data());
        if (r != VK_SUCCESS && r != VK_INCOMPLETE) {
            err = std::string("vkEnumeratePhysicalDevices: ") + resultName(r);
            return false;
        }

        // Two passes: prefer a discrete GPU (the one worth cracking on), then accept any
        // device that has a compute queue. Integrated graphics and software drivers land
        // in the second pass, which is still honest work as long as the UI says which
        // device ran.
        size_t chosen = devices.size();
        for (int pass = 0; pass < 2 && chosen == devices.size(); pass++) {
            for (size_t i = 0; i < devices.size(); i++) {
                VkPhysicalDeviceProperties props{};
                vkGetPhysicalDeviceProperties(devices[i], &props);
                if (pass == 0 && props.deviceType != VK_PHYSICAL_DEVICE_TYPE_DISCRETE_GPU) continue;

                uint32_t families = 0;
                vkGetPhysicalDeviceQueueFamilyProperties(devices[i], &families, nullptr);
                std::vector<VkQueueFamilyProperties> fp(families);
                vkGetPhysicalDeviceQueueFamilyProperties(devices[i], &families, fp.data());
                for (uint32_t f = 0; f < families; f++) {
                    if ((fp[f].queueFlags & VK_QUEUE_COMPUTE_BIT) && fp[f].queueCount > 0) {
                        chosen = i;
                        queueFamily = f;
                        haveQueueFamily = true;
                        break;
                    }
                }
            }
        }
        if (chosen == devices.size()) { err = "no Vulkan device with a compute queue"; return false; }

        physical = devices[chosen];
        VkPhysicalDeviceProperties props{};
        vkGetPhysicalDeviceProperties(physical, &props);
        vkGetPhysicalDeviceMemoryProperties(physical, &memoryProps);
        limits = props.limits;
        name = props.deviceName;

        float priority = 1.0f;
        VkDeviceQueueCreateInfo qci{};
        qci.sType = VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO;
        qci.queueFamilyIndex = queueFamily;
        qci.queueCount = 1;
        qci.pQueuePriorities = &priority;

        VkDeviceCreateInfo dci{};
        dci.sType = VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO;
        dci.queueCreateInfoCount = 1;
        dci.pQueueCreateInfos = &qci;
        r = vkCreateDevice(physical, &dci, nullptr, &device);
        if (r != VK_SUCCESS) { err = std::string("vkCreateDevice: ") + resultName(r); return false; }
        vkGetDeviceQueue(device, queueFamily, 0, &queue);

        if (limits.maxPushConstantsSize < sizeof(PushConstants)) {
            err = "device push-constant space is too small";
            return false;
        }
        if (limits.maxComputeWorkGroupCount[0] < 1) {
            err = "device reports no compute workgroups";
            return false;
        }

        // The generated header is the SPIR-V image verbatim, so its magic number is checked
        // here: a stale or truncated header should produce a clear refusal telling the
        // developer to regenerate it, not a driver error from deep inside
        // vkCreateShaderModule.
        if (mkshader::pbkdf2_sha1_spv_len % 4 != 0 ||
            mkshader::pbkdf2_sha1_spv[0] != kSpiRV) {
            err = "the compiled shader header is not a SPIR-V image (regenerate it with "
                  "tools/regen_shaders.ps1)";
            return false;
        }

        VkShaderModuleCreateInfo smci{};
        smci.sType = VK_STRUCTURE_TYPE_SHADER_MODULE_CREATE_INFO;
        smci.codeSize = mkshader::pbkdf2_sha1_spv_len;
        smci.pCode = mkshader::pbkdf2_sha1_spv;
        r = vkCreateShaderModule(device, &smci, nullptr, &shader);
        if (r != VK_SUCCESS) {
            err = std::string("vkCreateShaderModule on ") + name + ": " + resultName(r) +
                  " (shader/driver combination rejected)";
            return false;
        }

        VkDescriptorSetLayoutBinding bindings[5];
        for (uint32_t i = 0; i < 5; i++) {
            bindings[i].binding = i;
            bindings[i].descriptorType = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;
            bindings[i].descriptorCount = 1;
            bindings[i].stageFlags = VK_SHADER_STAGE_COMPUTE_BIT;
            bindings[i].pImmutableSamplers = nullptr;
        }
        VkDescriptorSetLayoutCreateInfo dslci{};
        dslci.sType = VK_STRUCTURE_TYPE_DESCRIPTOR_SET_LAYOUT_CREATE_INFO;
        dslci.bindingCount = 5;
        dslci.pBindings = bindings;
        r = vkCreateDescriptorSetLayout(device, &dslci, nullptr, &setLayout);
        if (r != VK_SUCCESS) { err = std::string("vkCreateDescriptorSetLayout: ") + resultName(r); return false; }

        VkPushConstantRange pcr{};
        pcr.stageFlags = VK_SHADER_STAGE_COMPUTE_BIT;
        pcr.offset = 0;
        pcr.size = sizeof(PushConstants);
        VkPipelineLayoutCreateInfo plci{};
        plci.sType = VK_STRUCTURE_TYPE_PIPELINE_LAYOUT_CREATE_INFO;
        plci.setLayoutCount = 1;
        plci.pSetLayouts = &setLayout;
        plci.pushConstantRangeCount = 1;
        plci.pPushConstantRanges = &pcr;
        r = vkCreatePipelineLayout(device, &plci, nullptr, &pipelineLayout);
        if (r != VK_SUCCESS) { err = std::string("vkCreatePipelineLayout: ") + resultName(r); return false; }

        VkPipelineShaderStageCreateInfo stage{};
        stage.sType = VK_STRUCTURE_TYPE_PIPELINE_SHADER_STAGE_CREATE_INFO;
        stage.stage = VK_SHADER_STAGE_COMPUTE_BIT;
        stage.module = shader;
        stage.pName = "main";
        VkComputePipelineCreateInfo cpci{};
        cpci.sType = VK_STRUCTURE_TYPE_COMPUTE_PIPELINE_CREATE_INFO;
        cpci.stage = stage;
        cpci.layout = pipelineLayout;
        r = vkCreateComputePipelines(device, VK_NULL_HANDLE, 1, &cpci, nullptr, &pipeline);
        if (r != VK_SUCCESS) { err = std::string("vkCreateComputePipelines: ") + resultName(r); return false; }

        VkCommandPoolCreateInfo cpci2{};
        cpci2.sType = VK_STRUCTURE_TYPE_COMMAND_POOL_CREATE_INFO;
        cpci2.queueFamilyIndex = queueFamily;
        cpci2.flags = VK_COMMAND_POOL_CREATE_RESET_COMMAND_BUFFER_BIT;
        r = vkCreateCommandPool(device, &cpci2, nullptr, &pool);
        if (r != VK_SUCCESS) { err = std::string("vkCreateCommandPool: ") + resultName(r); return false; }

        VkDescriptorPoolSize poolSize{};
        poolSize.type = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;
        poolSize.descriptorCount = 5;
        VkDescriptorPoolCreateInfo dpci{};
        dpci.sType = VK_STRUCTURE_TYPE_DESCRIPTOR_POOL_CREATE_INFO;
        dpci.maxSets = 1;
        dpci.poolSizeCount = 1;
        dpci.pPoolSizes = &poolSize;
        r = vkCreateDescriptorPool(device, &dpci, nullptr, &descriptorPool);
        if (r != VK_SUCCESS) err = std::string("vkCreateDescriptorPool: ") + resultName(r);
        return r == VK_SUCCESS;
    }
};

/**
 * Packs byte entries into the word layout the shader reads: each entry's four bytes become
 * one uint in SHA-1 message-word order (most significant byte first), every entry starts on
 * a 4-byte boundary, the unused low bytes of a short final word are zero, plus a table of
 * (byte offset, byte length) pairs.
 *
 * The host writes these words natively, and the shader reads them natively, so the two sides
 * agree on one rule and there is no byte swap left for a reader to get wrong.
 */
void packEntries(const std::vector<const uint8_t*>& bytes, const std::vector<size_t>& lengths,
                 std::vector<uint32_t>& dataOut, std::vector<uint32_t>& tableOut) {
    dataOut.clear();
    tableOut.clear();
    for (size_t i = 0; i < bytes.size(); i++) {
        tableOut.push_back(static_cast<uint32_t>(dataOut.size() * 4));   // offset in bytes
        tableOut.push_back(static_cast<uint32_t>(lengths[i]));
        size_t n = 0;
        while (n < lengths[i]) {
            uint32_t word = 0;
            uint32_t got = 0;
            for (; got < 4 && n < lengths[i]; got++, n++) {
                word = (word << 8) | bytes[i][n];
            }
            dataOut.push_back(word << (8u * (4u - got)));   // short group: bytes sit high
        }
    }
    if (dataOut.empty()) dataOut.push_back(0);   // a zero-sized buffer is not allowed
}

/** The same words as the bytes a VkBuffer memcpy wants, on a little-endian host. */
const uint8_t* asBytes(const std::vector<uint32_t>& words) {
    return reinterpret_cast<const uint8_t*>(words.data());
}

/**
 * Turns the shader's output words back into PMK bytes. The GPU wrote SHA-1-order words; the
 * CPU's verify_with_pmk wants bytes in the order the published vectors write them, so this
 * is the one place the convention is undone - and the CPU/GPU agreement check in the host
 * test is what proves it is undone correctly.
 */
void pmkWordsToBytes(const uint8_t* raw, size_t wordCount, std::vector<uint8_t>& out) {
    out.resize(wordCount * 4);
    for (size_t i = 0; i < wordCount; i++) {
        const uint32_t v = uint32_t(raw[i * 4]) | (uint32_t(raw[i * 4 + 1]) << 8) |
                           (uint32_t(raw[i * 4 + 2]) << 16) | (uint32_t(raw[i * 4 + 3]) << 24);
        out[i * 4] = uint8_t(v >> 24);
        out[i * 4 + 1] = uint8_t(v >> 16);
        out[i * 4 + 2] = uint8_t(v >> 8);
        out[i * 4 + 3] = uint8_t(v);
    }
}

/**
 * One probe of this machine's Vulkan support, shared by available() and deviceName(). It
 * is deliberately done once: the crack screen asks on every update, and opening a Vulkan
 * device on every ask would be silly.
 */
struct Probe {
    bool ok = false;
    std::string name;
    std::string reason;
};

const Probe& probe() {
    static Probe cached;
    static std::once_flag once;
    std::call_once(once, [] {
        Session session;
        std::string err;
        if (session.init(err)) {
            cached.ok = true;
            cached.name = session.name;
        } else {
            cached.reason = err;
        }
    });
    return cached;
}

}  // namespace

bool available(std::string& reason) {
    const Probe& p = probe();
    reason = p.reason;
    return p.ok;
}

std::string deviceName() { return probe().name; }

bool derive_pmks(const std::vector<mk::Candidate>& candidates, size_t from, size_t to,
                 const std::vector<std::vector<uint8_t>>& salts, uint32_t iterations,
                 std::vector<uint8_t>& pmksOut, std::string& err) {
    pmksOut.clear();
    if (from >= to || salts.empty()) return true;      // nothing to do, not a failure

    const size_t pairCount = (to - from) * salts.size();
    if (pairCount > kMaxPairsPerDispatch) {
        err = "internal error: " + std::to_string(pairCount) +
              " pairs in one dispatch (caller must chunk)";
        return false;
    }

    Session session;
    if (!session.init(err)) return false;

    std::vector<const uint8_t*> wordPtrs;
    std::vector<size_t> wordLens;
    wordPtrs.reserve(to - from);
    wordLens.reserve(to - from);
    for (size_t i = from; i < to; i++) {
        wordPtrs.push_back(candidates[i].bytes);
        wordLens.push_back(candidates[i].len);
    }
    std::vector<const uint8_t*> saltPtrs;
    std::vector<size_t> saltLens;
    saltPtrs.reserve(salts.size());
    saltLens.reserve(salts.size());
    for (const auto& s : salts) { saltPtrs.push_back(s.data()); saltLens.push_back(s.size()); }

    std::vector<uint32_t> wordData, saltData;
    std::vector<uint32_t> wordTable, saltTable;
    packEntries(wordPtrs, wordLens, wordData, wordTable);
    packEntries(saltPtrs, saltLens, saltData, saltTable);

    const size_t outBytes = pairCount * 32;
    const VkDeviceSize wordTableBytes = wordTable.size() * sizeof(uint32_t);
    const VkDeviceSize saltTableBytes = saltTable.size() * sizeof(uint32_t);

    // Staging (host visible, written by the CPU) and device buffers, per the five bindings
    // the shader declares, in binding order.
    Buffer stage[5];
    Buffer deviceBuf[5];
    const VkDeviceSize sizes[5] = {
        wordData.size() * sizeof(uint32_t), wordTableBytes,
        saltData.size() * sizeof(uint32_t), saltTableBytes, outBytes,
    };
    const void* srcs[5] = {
        asBytes(wordData), wordTable.data(), asBytes(saltData), saltTable.data(), nullptr,
    };

    for (int i = 0; i < 5; i++) {
        const bool out = (i == 4);
        if (!session.createBuffer(sizes[i],
                                  out ? (VK_BUFFER_USAGE_TRANSFER_SRC_BIT |
                                         VK_BUFFER_USAGE_STORAGE_BUFFER_BIT)
                                      : VK_BUFFER_USAGE_TRANSFER_SRC_BIT,
                                  VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT |
                                      VK_MEMORY_PROPERTY_HOST_COHERENT_BIT,
                                  VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT |
                                      VK_MEMORY_PROPERTY_HOST_COHERENT_BIT,
                                  stage[i], err)) {
            for (int j = 0; j < 5; j++) session.destroyBuffer(stage[j]);
            return false;
        }
        if (!session.createBuffer(sizes[i],
                                  VK_BUFFER_USAGE_TRANSFER_DST_BIT | VK_BUFFER_USAGE_STORAGE_BUFFER_BIT,
                                  VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT,
                                  VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT |
                                      VK_MEMORY_PROPERTY_HOST_COHERENT_BIT,
                                  deviceBuf[i], err)) {
            for (int j = 0; j < 5; j++) { session.destroyBuffer(stage[j]); session.destroyBuffer(deviceBuf[j]); }
            return false;
        }
        if (!out && srcs[i] != nullptr) std::memcpy(stage[i].mapped, srcs[i], sizes[i]);
    }

    bool ok = true;
    do {
        VkDescriptorSet set = VK_NULL_HANDLE;
        VkDescriptorSetAllocateInfo dsai{};
        dsai.sType = VK_STRUCTURE_TYPE_DESCRIPTOR_SET_ALLOCATE_INFO;
        dsai.descriptorPool = session.descriptorPool;
        dsai.descriptorSetCount = 1;
        dsai.pSetLayouts = &session.setLayout;
        VkResult r = vkAllocateDescriptorSets(session.device, &dsai, &set);
        if (r != VK_SUCCESS) { err = std::string("vkAllocateDescriptorSets: ") + resultName(r); ok = false; break; }

        // Both arrays are value-initialized, and that is not style: `VkWriteDescriptorSet` has a
        // `pNext` chain, and a driver is allowed to walk it. Left as raw stack memory, `pNext`
        // holds whatever the last call put there - the Adreno driver on this phone (the compute
        // device names itself "Adreno (TM) 725") does walk
        // it, and dereferencing that garbage killed the process inside vkUpdateDescriptorSets:
        //
        //   signal 11 (SIGSEGV), code 1 (SEGV_MAPERR), fault addr 0x006d93715633ec78
        //     #00 vulkan.adreno.so qglinternal::vkUpdateDescriptorSets(...)+696
        //     #01 libmarauder_crypto.so mkgpu::derive_pmks(...)+3456
        //     #02 libmarauder_crypto.so mkgpu::self_test(...)+472
        //
        // Every other Vulkan struct here is written as `X x{}` for the same reason. A host-side
        // driver happened to ignore the field, so the host test could not have caught this:
        // uninitialized memory is a coin flip, which is exactly why it must not exist.
        VkDescriptorBufferInfo infos[5]{};
        VkWriteDescriptorSet writes[5]{};
        for (int i = 0; i < 5; i++) {
            infos[i].buffer = deviceBuf[i].handle;
            infos[i].offset = 0;
            infos[i].range = deviceBuf[i].size;
            writes[i].sType = VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET;
            writes[i].pNext = nullptr;
            writes[i].dstSet = set;
            writes[i].dstBinding = static_cast<uint32_t>(i);
            writes[i].dstArrayElement = 0;
            writes[i].descriptorCount = 1;
            writes[i].descriptorType = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;
            writes[i].pBufferInfo = &infos[i];
        }
        vkUpdateDescriptorSets(session.device, 5, writes, 0, nullptr);

        VkCommandBufferAllocateInfo cbai{};
        cbai.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO;
        cbai.commandPool = session.pool;
        cbai.level = VK_COMMAND_BUFFER_LEVEL_PRIMARY;
        cbai.commandBufferCount = 1;
        VkCommandBuffer cmd = VK_NULL_HANDLE;
        r = vkAllocateCommandBuffers(session.device, &cbai, &cmd);
        if (r != VK_SUCCESS) { err = std::string("vkAllocateCommandBuffers: ") + resultName(r); ok = false; break; }

        VkCommandBufferBeginInfo begin{};
        begin.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO;
        begin.flags = VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT;
        r = vkBeginCommandBuffer(cmd, &begin);
        if (r != VK_SUCCESS) { err = std::string("vkBeginCommandBuffer: ") + resultName(r); ok = false; break; }

        for (int i = 0; i < 4; i++) {
            VkBufferCopy copy{};
            copy.size = sizes[i];
            vkCmdCopyBuffer(cmd, stage[i].handle, deviceBuf[i].handle, 1, &copy);
        }

        // Inputs were written by transfer commands and are read by the shader; the output
        // is written by the shader and read back by a transfer command. Both directions
        // need an explicit execution+memory dependency, which is not something a driver is
        // allowed to guess at.
        VkMemoryBarrier toShader{};
        toShader.sType = VK_STRUCTURE_TYPE_MEMORY_BARRIER;
        toShader.srcAccessMask = VK_ACCESS_TRANSFER_WRITE_BIT;
        toShader.dstAccessMask = VK_ACCESS_SHADER_READ_BIT;
        vkCmdPipelineBarrier(cmd, VK_PIPELINE_STAGE_TRANSFER_BIT, VK_PIPELINE_STAGE_COMPUTE_SHADER_BIT,
                             0, 1, &toShader, 0, nullptr, 0, nullptr);

        vkCmdBindPipeline(cmd, VK_PIPELINE_BIND_POINT_COMPUTE, session.pipeline);
        vkCmdBindDescriptorSets(cmd, VK_PIPELINE_BIND_POINT_COMPUTE, session.pipelineLayout,
                                0, 1, &set, 0, nullptr);

        PushConstants pc{};
        pc.iterations = iterations;
        pc.saltCount = static_cast<uint32_t>(salts.size());
        pc.pairCount = static_cast<uint32_t>(pairCount);
        vkCmdPushConstants(cmd, session.pipelineLayout, VK_SHADER_STAGE_COMPUTE_BIT, 0,
                           sizeof(pc), &pc);

        const uint32_t groups = static_cast<uint32_t>((pairCount + kWorkgroupSize - 1) / kWorkgroupSize);
        if (groups > session.limits.maxComputeWorkGroupCount[0]) {
            err = "dispatch needs " + std::to_string(groups) + " workgroups, this device allows " +
                  std::to_string(session.limits.maxComputeWorkGroupCount[0]);
            ok = false;
            break;
        }
        vkCmdDispatch(cmd, groups, 1, 1);

        VkMemoryBarrier toTransfer{};
        toTransfer.sType = VK_STRUCTURE_TYPE_MEMORY_BARRIER;
        toTransfer.srcAccessMask = VK_ACCESS_SHADER_WRITE_BIT;
        toTransfer.dstAccessMask = VK_ACCESS_TRANSFER_READ_BIT;
        vkCmdPipelineBarrier(cmd, VK_PIPELINE_STAGE_COMPUTE_SHADER_BIT, VK_PIPELINE_STAGE_TRANSFER_BIT,
                             0, 1, &toTransfer, 0, nullptr, 0, nullptr);

        VkBufferCopy readBack{};
        readBack.size = outBytes;
        vkCmdCopyBuffer(cmd, deviceBuf[4].handle, stage[4].handle, 1, &readBack);

        r = vkEndCommandBuffer(cmd);
        if (r != VK_SUCCESS) { err = std::string("vkEndCommandBuffer: ") + resultName(r); ok = false; break; }

        VkSubmitInfo submit{};
        submit.sType = VK_STRUCTURE_TYPE_SUBMIT_INFO;
        submit.commandBufferCount = 1;
        submit.pCommandBuffers = &cmd;
        r = vkQueueSubmit(session.queue, 1, &submit, VK_NULL_HANDLE);
        if (r != VK_SUCCESS) { err = std::string("vkQueueSubmit: ") + resultName(r); ok = false; break; }
        r = vkQueueWaitIdle(session.queue);
        if (r != VK_SUCCESS) { err = std::string("vkQueueWaitIdle: ") + resultName(r); ok = false; break; }

        // The GPU wrote SHA-1-order words; the CPU verifier wants PMK bytes. One undo, here.
        pmkWordsToBytes(static_cast<const uint8_t*>(stage[4].mapped), pairCount * 8, pmksOut);
    } while (false);

    for (int i = 0; i < 5; i++) { session.destroyBuffer(stage[i]); session.destroyBuffer(deviceBuf[i]); }
    if (!ok) pmksOut.clear();
    return ok;
}

bool crack_batch_gpu(const uint8_t* material, size_t materialLen,
                     const uint8_t* packedWords, size_t wordsLen,
                     std::vector<std::pair<int, int>>& found, std::string& err) {
    found.clear();

    // Same parse, same candidate unpacking, same salt grouping as the CPU batch, shared on
    // purpose: if these diverged, the GPU run and the CPU run would report different
    // results for one identical hash line.
    std::vector<mk::Target> targets;
    if (!mk::parse_material(material, materialLen, targets, err)) return false;

    std::vector<mk::Candidate> candidates;
    if (!mk::unpack_candidates(packedWords, wordsLen, candidates, err)) return false;

    const std::vector<mk::SaltGroup> groups = mk::group_targets_by_salt(targets);
    if (groups.empty() || candidates.empty()) return true;

    for (const auto& g : groups) {
        if (g.salt.empty() || g.salt.size() > kMaxSaltLength) {
            err = "salt of " + std::to_string(g.salt.size()) +
                  " bytes is outside the 1..32 octets an ESSID can be; the GPU kernel "
                  "would derive the wrong key, so this hash is refused rather than guessed at";
            return false;
        }
    }

    std::vector<std::vector<uint8_t>> salts;
    salts.reserve(groups.size());
    for (const auto& g : groups) salts.push_back(g.salt);

    const size_t chunkWords = std::max<size_t>(1, kMaxPairsPerDispatch / salts.size());
    std::vector<uint8_t> pmks;

    for (size_t from = 0; from < candidates.size(); from += chunkWords) {
        const size_t to = std::min(candidates.size(), from + chunkWords);
        if (!derive_pmks(candidates, from, to, salts, kIterationsWpa2Psk, pmks, err)) return false;

        const size_t stride = salts.size() * 32;
        for (size_t w = from; w < to; w++) {
            const uint8_t* row = pmks.data() + (w - from) * stride;
            for (size_t s = 0; s < salts.size(); s++) {
                const uint8_t* pmk = row + s * 32;
                for (int t : groups[s].targets) {
                    if (mk::verify_with_pmk(targets[size_t(t)], pmk)) {
                        found.emplace_back(int(w), t);
                    }
                }
            }
        }
    }

    std::sort(found.begin(), found.end());
    return true;
}

bool self_test(std::string& err) {
    Session session;
    if (!session.init(err)) {
        err = "GPU self-test could not open a device: " + err;
        return false;
    }

    // --- published vector, end to end ------------------------------------------------
    //
    // The GPU derives the PMK; the PMKID tag is computed on the CPU with the same HMAC the
    // CPU engine uses, and compared against hashcat's published 16 bytes. That one check
    // covers the shader's SHA-1, its ipad/opad handling, the salt-and-counter block,
    // PBKDF2's 4096 rounds, both output blocks and the 32-byte truncation WPA2 uses.
    {
        const std::string essid = "hashcat-essid";
        const std::string password = "hashcat!";
        std::vector<mk::Candidate> words{ mk::Candidate{
            reinterpret_cast<const uint8_t*>(password.data()), password.size() } };
        std::vector<std::vector<uint8_t>> salts{ std::vector<uint8_t>(essid.begin(), essid.end()) };

        std::vector<uint8_t> pmks;
        if (!derive_pmks(words, 0, words.size(), salts, kIterationsWpa2Psk, pmks, err)) {
            err = "GPU self-test: dispatch failed: " + err;
            return false;
        }
        if (pmks.size() != 32) {
            err = "GPU self-test: expected 32 bytes of PMK, got " + std::to_string(pmks.size());
            return false;
        }

        std::vector<uint8_t> msg(reinterpret_cast<const uint8_t*>("PMK Name"),
                                 reinterpret_cast<const uint8_t*>("PMK Name") + 8);
        const uint8_t aa[6] = { 0xfc, 0x69, 0x0c, 0x15, 0x82, 0x64 };
        const uint8_t spa[6] = { 0xf4, 0x74, 0x7f, 0x87, 0xf9, 0xf4 };
        msg.insert(msg.end(), aa, aa + 6);
        msg.insert(msg.end(), spa, spa + 6);

        uint8_t tag[20];
        mk::hmac(mk::H_SHA1, pmks.data(), 32, msg.data(), msg.size(), tag);
        char hex[41];
        for (int i = 0; i < 16; i++) {
            static const char* digits = "0123456789abcdef";
            hex[i * 2] = digits[tag[i] >> 4];
            hex[i * 2 + 1] = digits[tag[i] & 15];
        }
        hex[32] = '\0';
        if (std::strcmp(hex, "4d4fe7aac3a2cecab195321ceb99a7d0") != 0) {
            err = std::string("GPU self-test: hashcat's published PMKID vector gave ") + hex +
                  " on " + session.name + ", want 4d4fe7aac3a2cecab195321ceb99a7d0";
            return false;
        }
    }

    // --- agreement with this repo's own CPU PBKDF2 -----------------------------------
    //
    // The published vector has one ESSID length, so on its own it would not notice a shader
    // that handles only some salt alignments: when the ESSID is not a multiple of four the
    // block counter straddles two 32-bit words, and that is a separate code path. Every
    // remainder is covered here, along with the longest legal WPA2 passphrase and a
    // candidate long enough that RFC 2104 says the key must be hashed first.
    {
        const char* essids[] = {
            "abcd",                  // 4,  saltLen % 4 == 0
            "abcde",                 // 5,  straddles by 1
            "abcdefg",               // 7,  straddles by 3
            "hashcat-essid",         // 13, straddles by 1
            "TP-LINK_HASHCAT_TEST",  // 20, aligned
            "abcdefghijklmnopqrstuvwxyz012345",   // 32, the maximum
        };
        std::string longPass(100, 'k');          // > 64 bytes: hash-the-key-first path
        std::string maxPass(63, 'm');           // the longest legal WPA2 passphrase
        const char* words[] = { "hashcat!", "password123", longPass.c_str(), maxPass.c_str() };

        std::vector<mk::Candidate> candidates;
        std::vector<std::vector<uint8_t>> salts;
        for (const char* w : words) {
            candidates.push_back(mk::Candidate{ reinterpret_cast<const uint8_t*>(w), std::strlen(w) });
        }
        for (const char* e : essids) {
            const size_t len = std::strlen(e);
            salts.emplace_back(reinterpret_cast<const uint8_t*>(e),
                               reinterpret_cast<const uint8_t*>(e) + len);
        }

        std::vector<uint8_t> pmks;
        if (!derive_pmks(candidates, 0, candidates.size(), salts, kIterationsWpa2Psk, pmks, err)) {
            err = "GPU self-test: cross-check dispatch failed: " + err;
            return false;
        }
        if (pmks.size() != candidates.size() * salts.size() * 32) {
            err = "GPU self-test: cross-check returned " + std::to_string(pmks.size()) +
                  " bytes, expected " +
                  std::to_string(candidates.size() * salts.size() * 32);
            return false;
        }

        for (size_t w = 0; w < candidates.size(); w++) {
            for (size_t s = 0; s < salts.size(); s++) {
                uint8_t cpu[32];
                mk::pbkdf2_sha1_32(candidates[w].bytes, candidates[w].len,
                                   salts[s].data(), salts[s].size(), kIterationsWpa2Psk, cpu);
                const uint8_t* gpu = pmks.data() + (w * salts.size() + s) * 32;
                if (std::memcmp(cpu, gpu, 32) != 0) {
                    err = "GPU self-test: the shader disagrees with the CPU core for a " +
                          std::to_string(candidates[w].len) + "-byte candidate against a " +
                          std::to_string(salts[s].size()) + "-byte ESSID on " + session.name +
                          " (salt alignment or long-key path)";
                    return false;
                }
            }
        }
    }

    return true;
}
}  // namespace mkgpu
