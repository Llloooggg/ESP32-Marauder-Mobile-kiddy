// JNI bridge between the app's cracking UI and the native WPA2 core.
//
// Deliberately nothing but marshalling. The three entry points:
//
//   nativeSelfTest()          runs the known-answer gate in selftest.cpp. Returns
//                             nullptr when every vector passed, and the first failing
//                             vector's description otherwise. The app refuses to use the
//                             native engine when this fails: a crypto core that is wrong
//                             on one ABI would report "not cracked" for a password that
//                             really is correct, which is the one result this app must
//                             never present as an answer.
//
//   nativeMaterialVersion()   the material-protocol version this library reads, so
//                             Kotlin can refuse to hand it a blob whose layout it does
//                             not understand instead of letting it guess.
//
//   nativeCrackBatch()        copies the two byte arrays out of the JVM, calls
//                             mk::crack_batch (which does all of the work: TLV parse,
//                             candidate unpacking, salt grouping, thread splitting,
//                             result ordering) and copies the (word, target) pairs back.
//
// The logic lives in the core on purpose, because the core is what the host known-answer
// test runs on this machine; a wrapper is only ever exercised on a phone, which is the
// worst place to discover a bug in a batch loop.
//
// What the native side never does: parse a 22000 line, decide what a network is, or
// report success the caller cannot see.
#include <jni.h>

#include <string>
#include <utility>
#include <vector>

#include "wpa_crypto.h"

namespace mktest {
bool self_test(std::string& fail);
}

namespace {

void throwIse(JNIEnv* env, const std::string& message) {
    jclass cls = env->FindClass("java/lang/IllegalStateException");
    if (cls != nullptr) env->ThrowNew(cls, message.c_str());
}

/** Reads a Java byte[] into `out`. Returns false if the array could not be pinned. */
bool getBytes(JNIEnv* env, jbyteArray array, std::vector<uint8_t>& out) {
    if (array == nullptr) { out.clear(); return true; }
    const jsize len = env->GetArrayLength(array);
    jbyte* raw = env->GetByteArrayElements(array, nullptr);
    if (raw == nullptr) return false;
    out.assign(raw, raw + (len > 0 ? size_t(len) : 0));
    // JNI_ABORT: this is read-only input, nothing to copy back.
    env->ReleaseByteArrayElements(array, raw, JNI_ABORT);
    return true;
}

}  // namespace

extern "C" {

/** nullptr == every known-answer vector passed. Otherwise: what failed. */
JNIEXPORT jstring JNICALL
Java_com_marauder_mobile_crack_NativeCrypto_nativeSelfTest(JNIEnv* env, jobject) {
    std::string fail;
    if (mktest::self_test(fail)) return nullptr;
    return env->NewStringUTF(fail.c_str());
}

JNIEXPORT jint JNICALL
Java_com_marauder_mobile_crack_NativeCrypto_nativeMaterialVersion(JNIEnv*, jobject) {
    return 2;
}

/**
 * Verifies [packedWords] against the targets in [materialBlob].
 *
 * Returns (wordIndex, targetIndex) pairs sorted by word order, so the caller emits
 * results in the order the wordlist has them. An empty array means "none of these words
 * worked", never "something went wrong" — a real failure throws, because an empty result
 * and a wrong answer look identical to a user.
 */
JNIEXPORT jintArray JNICALL
Java_com_marauder_mobile_crack_NativeCrypto_nativeCrackBatch(
        JNIEnv* env, jobject, jbyteArray materialBlob, jbyteArray packedWords, jint threads) {

    std::vector<uint8_t> material;
    std::vector<uint8_t> words;
    if (!getBytes(env, materialBlob, material) || !getBytes(env, packedWords, words)) {
        throwIse(env, "native engine: could not read the batch buffers from the JVM");
        return nullptr;
    }

    std::vector<std::pair<int, int>> found;
    std::string err;
    if (!mk::crack_batch(material.data(), material.size(), words.data(), words.size(),
                         int(threads), found, err)) {
        throwIse(env, "native engine: " + err);
        return nullptr;
    }

    jintArray out = env->NewIntArray(int(found.size()) * 2);
    if (out == nullptr) return nullptr;   // allocation failure: JNI already reports it
    if (!found.empty()) {
        std::vector<jint> flat(found.size() * 2);
        for (size_t i = 0; i < found.size(); i++) {
            flat[2 * i] = jint(found[i].first);
            flat[2 * i + 1] = jint(found[i].second);
        }
        env->SetIntArrayRegion(out, 0, int(flat.size()), flat.data());
    }
    return out;
}

}  // extern "C"
