cmake_minimum_required(VERSION 3.15)
project(scotty LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(OpenSSL REQUIRED)
find_package(yaml-cpp REQUIRED)

# ── Library source directories ─────────────────────────────────────────────────
# CMakeLists.txt lives in pq/scotty/; kyber is at ../../kyber, dilithium at ../../dilithium
set(KYBER_REF_DIR     "${CMAKE_SOURCE_DIR}/../../kyber/ref")
set(DILITHIUM_REF_DIR "${CMAKE_SOURCE_DIR}/../../dilithium/ref")

# msgpack-c (header-only) and the shared tray_pack module
set(MSGPACK_SRC "${CMAKE_SOURCE_DIR}/../msgpack/src")
set(MSGPACK_INC "${CMAKE_SOURCE_DIR}/../../msgpack-c/include")

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
    src/yaml_io.cpp
    src/base64.cpp
    "${MSGPACK_SRC}/tray_pack.cpp"
    ${RANDOMBYTES_SRC}
)

add_executable(scotty ${SOURCES})

target_include_directories(scotty PRIVATE
    src
    "${CMAKE_SOURCE_DIR}/../include"
    "${KYBER_REF_DIR_ABS}"       # for randombytes.h
    "${MSGPACK_SRC}"             # for tray_pack.hpp
    "${MSGPACK_INC}"             # msgpack-c header-only library
)

target_compile_definitions(scotty PRIVATE MSGPACK_NO_BOOST)

target_link_libraries(scotty PRIVATE
    pqcrystals_kyber512_ref
    pqcrystals_kyber768_ref
    pqcrystals_kyber1024_ref
    pqcrystals_kyber_fips202_ref
    pqcrystals_dilithium2_ref
    pqcrystals_dilithium3_ref
    pqcrystals_dilithium5_ref
    pqcrystals_dilithium_fips202_ref
    OpenSSL::Crypto
    yaml-cpp
)

# ── Compiler flags ────────────────────────────────────────────────────────────
target_compile_options(scotty PRIVATE -O2 -Wall -Wextra)

# ── Install ───────────────────────────────────────────────────────────────────
install(TARGETS scotty DESTINATION bin)
