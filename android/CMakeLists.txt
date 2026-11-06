# slipstream-client for Android with the NDK's CMake toolchain:
#   cmake -S android -B <build> -DCMAKE_TOOLCHAIN_FILE=$NDK/build/cmake/android.toolchain.cmake -DANDROID_ABI=<abi> \
#     -DANDROID_PLATFORM=android-23 -DOPENSSL_ROOT_DIR=<OpenSSL for the ABI, .github/scripts/android-openssl.sh>
# The sources and picoquic are those of the meson build (meson.build); only the client, no logs, no demo, no tests.
cmake_minimum_required(VERSION 3.20)
project(slipstream_android C CXX)

set(ROOT ${CMAKE_CURRENT_SOURCE_DIR}/..)

# OpenSSL static, found under its own prefix (the toolchain looks in the NDK's sysroot only)
set(OPENSSL_USE_STATIC_LIBS TRUE)
set(OPENSSL_INCLUDE_DIR ${OPENSSL_ROOT_DIR}/include CACHE PATH "" FORCE)
set(OPENSSL_CRYPTO_LIBRARY ${OPENSSL_ROOT_DIR}/lib/libcrypto.a CACHE FILEPATH "" FORCE)
set(OPENSSL_SSL_LIBRARY ${OPENSSL_ROOT_DIR}/lib/libssl.a CACHE FILEPATH "" FORCE)
find_package(OpenSSL REQUIRED)

# picoquic and picotls (fetched at the commit picoquic pins) as the meson build sets them
set(PICOQUIC_FETCH_PTLS ON CACHE BOOL "" FORCE)
set(BUILD_DEMO OFF CACHE BOOL "" FORCE)
set(BUILD_HTTP OFF CACHE BOOL "" FORCE)
set(BUILD_LOGLIB OFF CACHE BOOL "" FORCE)
set(BUILD_LOGREADER OFF CACHE BOOL "" FORCE)
set(BUILD_TESTING OFF CACHE BOOL "" FORCE)
set(picoquic_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(DISABLE_DEBUG_PRINTF ON CACHE BOOL "" FORCE)
set(ENABLE_ASAN OFF CACHE BOOL "" FORCE)
set(ENABLE_UBSAN OFF CACHE BOOL "" FORCE)
# fusion is AES-NI on x86 only: OpenSSL's AES serves every ABI alike
set(WITH_FUSION OFF CACHE BOOL "" FORCE)
set(CMAKE_POLICY_VERSION_MINIMUM 3.5 CACHE STRING "" FORCE)
include(FetchContent)
add_subdirectory(${ROOT}/subprojects/picoquic picoquic EXCLUDE_FROM_ALL)
FetchContent_GetProperties(picotls)

find_package(Threads REQUIRED)

set(SRC ${ROOT}/src)
add_executable(slipstream-client
    ${SRC}/slipstream_client.c
    ${SRC}/slipstream_client_cli.cpp
    ${SRC}/slipstream_pin.c
    ${SRC}/slipstream_sockloop.c
    ${SRC}/slipstream_utils.c
    ${SRC}/slipstream_inline_dots.c
    ${ROOT}/extern/lua-resty-base-encoding/base32.c
    ${ROOT}/extern/SPCDNS/src/codec.c
    ${ROOT}/extern/SPCDNS/src/mappings.c
    ${ROOT}/extern/SPCDNS/src/netsimple.c
    ${ROOT}/extern/SPCDNS/src/output.c)
target_include_directories(slipstream-client PRIVATE
    ${ROOT}/include
    ${ROOT}/extern
    ${ROOT}/extern/quick_arg_parser
    ${ROOT}/extern/SPCDNS/src
    ${ROOT}/extern/lua-resty-base-encoding
    ${ROOT}/subprojects/picoquic/picoquic
    ${picotls_SOURCE_DIR}/include
    ${OPENSSL_INCLUDE_DIR})
set_target_properties(slipstream-client PROPERTIES
    C_STANDARD 11 C_EXTENSIONS ON CXX_STANDARD 11 CXX_EXTENSIONS ON)
target_link_libraries(slipstream-client PRIVATE
    picoquic-core picotls-openssl picotls-minicrypto picotls-core OpenSSL::SSL OpenSSL::Crypto Threads::Threads)
# with ANDROID_STL=c++_static the NDK's libc++ is inside; no symbols in the shipped file
target_link_options(slipstream-client PRIVATE -Wl,--gc-sections -s)
