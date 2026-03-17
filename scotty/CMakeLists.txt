cmake_minimum_required(VERSION 3.15)
project(scotty LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(OpenSSL REQUIRED)
find_package(yaml-cpp REQUIRED)
find_package(BLAKE3 REQUIRED)
find_package(TBB    REQUIRED)

# RPATH: TBB is a shared library; record its location so the binary finds it
# at runtime without requiring LD_LIBRARY_PATH.
get_target_property(_tbb_loc TBB::tbb IMPORTED_LOCATION_RELEASE)
if(NOT _tbb_loc)
    get_target_property(_tbb_loc TBB::tbb IMPORTED_LOCATION)
endif()
get_filename_component(_tbb_libdir "${_tbb_loc}" DIRECTORY)
set(CMAKE_BUILD_RPATH "${_tbb_libdir}")

# ── Library source directories ─────────────────────────────────────────────────
# CMakeLists.txt lives in pq/scotty/; kyber is at ../../kyber, dilithium at ../../dilithium
set(KYBER_REF_DIR     "${CMAKE_SOURCE_DIR}/../../kyber/ref")
set(DILITHIUM_REF_DIR "${CMAKE_SOURCE_DIR}/../../dilithium/ref")

# ── scrypt ─────────────────────────────────────────────────────────────────────
set(SCRYPT_DIR "${CMAKE_SOURCE_DIR}/../../scrypt")
get_filename_component(SCRYPT_DIR_ABS "${SCRYPT_DIR}" ABSOLUTE)

set(SCRYPT_SOURCES
    "${SCRYPT_DIR_ABS}/lib-platform/crypto/crypto_scrypt.c"
    "${SCRYPT_DIR_ABS}/lib/crypto/crypto_scrypt_smix.c"
    "${SCRYPT_DIR_ABS}/libcperciva/alg/sha256.c"
    "${SCRYPT_DIR_ABS}/libcperciva/util/insecure_memzero.c"
    "${SCRYPT_DIR_ABS}/libcperciva/util/warnp.c"
)

get_filename_component(KYBER_REF_DIR_ABS "${KYBER_REF_DIR}" ABSOLUTE)

# ── randombytes ────────────────────────────────────────────────────────────────
# The kyber and dilithium static archives leave randombytes undefined.
# Compile it into the binary from kyber/ref (works for both).
set(RANDOMBYTES_SRC "${KYBER_REF_DIR_ABS}/randombytes.c")

add_subdirectory(../../kyber/ref     kyber_ref_build)
add_subdirectory(../../dilithium/ref dilithium_ref_build)

# ── Sources ───────────────────────────────────────────────────────────────────
set(SOURCES
    src/main.cpp
    src/tray.cpp
    src/ec_ops.cpp
    src/kyber_ops.cpp
    src/dilithium_ops.cpp
    src/mceliece_ops.cpp
    src/slhdsa_ops.cpp
    src/mceliece_randombytes.c
    src/yaml_io.cpp
    src/base64.cpp
    src/secure_tray.cpp
    ${RANDOMBYTES_SRC}
    ${SCRYPT_SOURCES}
)

add_executable(scotty ${SOURCES})

target_include_directories(scotty PRIVATE
    src
    "${CMAKE_SOURCE_DIR}/../include"
    "${KYBER_REF_DIR_ABS}"                       # for randombytes.h
    /usr/local/include                            # for mceliece.h
    "${SCRYPT_DIR_ABS}"                          # config.h
    "${SCRYPT_DIR_ABS}/lib-platform"             # platform.h
    "${SCRYPT_DIR_ABS}/lib/crypto"               # crypto_scrypt_smix.h
    "${SCRYPT_DIR_ABS}/libcperciva/alg"          # sha256.h, sysendian.h
    "${SCRYPT_DIR_ABS}/libcperciva/util"         # warnp.h, insecure_memzero.h
    "${SCRYPT_DIR_ABS}/libcperciva/cpusupport"   # cpusupport.h
    "${SCRYPT_DIR_ABS}/libscrypt-kdf"            # scrypt-kdf.h
)

target_link_libraries(scotty PRIVATE
    pqcrystals_kyber512_ref
    pqcrystals_kyber768_ref
    pqcrystals_kyber1024_ref
    pqcrystals_kyber_fips202_ref
    pqcrystals_dilithium2_ref
    pqcrystals_dilithium3_ref
    pqcrystals_dilithium5_ref
    pqcrystals_dilithium_fips202_ref
    /usr/local/lib/libmceliece.a
    "${SCRYPT_DIR_ABS}/.libs/libscrypt_sse2.a"
    "${SCRYPT_DIR_ABS}/.libs/libcperciva_cpusupport_detect.a"
    "${SCRYPT_DIR_ABS}/.libs/libcperciva_shani.a"
    BLAKE3::blake3
    TBB::tbb
    OpenSSL::Crypto
    yaml-cpp
)

# ── Compiler flags ────────────────────────────────────────────────────────────
target_compile_options(scotty PRIVATE -O2 -Wall -Wextra)
target_compile_definitions(scotty PRIVATE HAVE_CONFIG_H)

# ── Install ───────────────────────────────────────────────────────────────────
install(TARGETS scotty DESTINATION bin)
