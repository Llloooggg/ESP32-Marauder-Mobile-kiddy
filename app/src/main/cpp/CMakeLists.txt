# Native WPA2-PSK cracking core for the built-in cracker.
#
# Everything here is self-contained (no OpenSSL, no external sources) so the exact
# bytes that run on a phone are the same bytes the host known-answer test checks:
#
#   g++ -std=c++17 -O2 -pthread -DMK_SELFTEST_MAIN wpa_crypto.cpp selftest.cpp -o selftest && ./selftest
#
# The app runs that same self_test() at startup through nativeSelfTest() and only uses
# this library when it passes, falling back to the JVM implementation otherwise. A
# crypto core that is subtly wrong on one ABI would report "not cracked" for the right
# password, and the app must not present that as a result.
cmake_minimum_required(VERSION 3.22.1)
project(marauder_crypto LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_library(marauder_crypto SHARED
        wpa_crypto.cpp
        selftest.cpp
        jni_bridge.cpp)

target_compile_options(marauder_crypto PRIVATE -Wall -Wextra)

# std::thread is used to spread one batch over the device's cores, and on bionic that
# means `-pthread` for the atomics/C++ threading support. Required rather than optional:
# a build that silently loses the flag is a build whose batch loop may not start its
# workers, which the code copes with but which nobody should discover by accident.
find_package(Threads REQUIRED)
target_link_libraries(marauder_crypto PRIVATE Threads::Threads)
