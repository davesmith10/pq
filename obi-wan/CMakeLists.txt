cmake_minimum_required(VERSION 3.16)
project(obi-wan LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(OpenSSL REQUIRED)
find_package(yaml-cpp REQUIRED)

# ── Library paths ─────────────────────────────────────────────────────────────
# CMakeLists.txt lives in pq/obi-wan/; kyber is at ../../kyber
set(KYBER_REF_DIR "${CMAKE_SOURCE_DIR}/../../kyber/ref")
set(XKCP_DIR      "${CMAKE_SOURCE_DIR}/../../XKCP")

get_filename_component(KYBER_REF_DIR_ABS "${KYBER_REF_DIR}" ABSOLUTE)
get_filename_component(XKCP_DIR_ABS      "${XKCP_DIR}"      ABSOLUTE)

set(KYBER_REF_LIBDIR "${KYBER_REF_DIR_ABS}/lib")
set(XKCP_LIBDIR      "${XKCP_DIR_ABS}/bin/x86-64")
set(XKCP_INC         "${XKCP_DIR_ABS}/bin/x86-64/libXKCP.so.headers")

# msgpack-c and tray_pack
set(MSGPACK_SRC "${CMAKE_SOURCE_DIR}/../msgpack/src")
set(MSGPACK_INC "${CMAKE_SOURCE_DIR}/../../msgpack-c/include")

# ── RPATH ─────────────────────────────────────────────────────────────────────
set(CMAKE_SKIP_BUILD_RPATH FALSE)
set(CMAKE_BUILD_WITH_INSTALL_RPATH FALSE)
set(CMAKE_BUILD_RPATH "${KYBER_REF_LIBDIR}:${XKCP_LIBDIR}")
set(CMAKE_INSTALL_RPATH "$ORIGIN/../lib/obi-wan")
set(CMAKE_INSTALL_RPATH_USE_LINK_PATH FALSE)

# ── randombytes ───────────────────────────────────────────────────────────────
set(RANDOMBYTES_SRC "${KYBER_REF_DIR_ABS}/randombytes.c")

# ── fips202 (kyber namespace only — no dilithium needed) ─────────────────────
# obi-wan uses Kyber ref only, so we need kyber's fips202 namespace.
# Compile fips202.c into an OBJECT library and export via -rdynamic.
add_library(kyber_fips202_obj OBJECT "${KYBER_REF_DIR_ABS}/fips202.c")
target_include_directories(kyber_fips202_obj PRIVATE "${KYBER_REF_DIR_ABS}")

# ── Sources ───────────────────────────────────────────────────────────────────
set(SOURCES
    src/main.cpp
    src/kyber_kem.cpp
    src/ec_kem.cpp
    src/tray_reader.cpp
    src/armor.cpp
    src/base64.cpp
    "${MSGPACK_SRC}/tray_pack.cpp"
    ${RANDOMBYTES_SRC}
)

add_executable(obi-wan
    ${SOURCES}
    $<TARGET_OBJECTS:kyber_fips202_obj>
)

target_include_directories(obi-wan PRIVATE
    src
    "${CMAKE_SOURCE_DIR}/../include"   # tray.hpp
    "${KYBER_REF_DIR_ABS}"             # randombytes.h
    "${XKCP_INC}"                      # SimpleFIPS202.h, SP800-185.h
    "${MSGPACK_SRC}"                   # tray_pack.hpp
    "${MSGPACK_INC}"                   # msgpack-c header-only
)

target_compile_definitions(obi-wan PRIVATE MSGPACK_NO_BOOST)

# Export symbols so Kyber .so files can resolve their fips202 dependencies
target_link_options(obi-wan PRIVATE -rdynamic)

# ── Link ──────────────────────────────────────────────────────────────────────
target_link_libraries(obi-wan PRIVATE
    "${KYBER_REF_LIBDIR}/libpqcrystals_kyber512_ref.so"
    "${KYBER_REF_LIBDIR}/libpqcrystals_kyber768_ref.so"
    "${KYBER_REF_LIBDIR}/libpqcrystals_kyber1024_ref.so"
    "${XKCP_LIBDIR}/libXKCP.so"
    OpenSSL::Crypto
    yaml-cpp
)

# ── Compiler flags ────────────────────────────────────────────────────────────
target_compile_options(obi-wan PRIVATE -O2 -Wall -Wextra)

# ── Install ───────────────────────────────────────────────────────────────────
install(TARGETS obi-wan DESTINATION bin)

install(FILES
    "${KYBER_REF_LIBDIR}/libpqcrystals_kyber512_ref.so"
    "${KYBER_REF_LIBDIR}/libpqcrystals_kyber768_ref.so"
    "${KYBER_REF_LIBDIR}/libpqcrystals_kyber1024_ref.so"
    "${KYBER_REF_LIBDIR}/libpqcrystals_fips202_ref.so"
    "${XKCP_LIBDIR}/libXKCP.so"
    DESTINATION lib/obi-wan
)
