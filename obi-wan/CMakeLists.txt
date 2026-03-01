cmake_minimum_required(VERSION 3.16)
project(obi-wan LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(OpenSSL REQUIRED)
find_package(yaml-cpp REQUIRED)
find_package(BLAKE3 REQUIRED)
find_package(TBB    REQUIRED)

# ── Library paths ─────────────────────────────────────────────────────────────
# CMakeLists.txt lives in pq/obi-wan/; kyber is at ../../kyber, dilithium at ../../dilithium
set(KYBER_REF_DIR "${CMAKE_SOURCE_DIR}/../../kyber/ref")
set(XKCP_DIR      "${CMAKE_SOURCE_DIR}/../../XKCP")

get_filename_component(KYBER_REF_DIR_ABS "${KYBER_REF_DIR}" ABSOLUTE)
get_filename_component(XKCP_DIR_ABS      "${XKCP_DIR}"      ABSOLUTE)

set(XKCP_LIBDIR "${XKCP_DIR_ABS}/bin/x86-64")
set(XKCP_INC    "${XKCP_DIR_ABS}/bin/x86-64/libXKCP.so.headers")

# msgpack-c and tray_pack
set(MSGPACK_SRC "${CMAKE_SOURCE_DIR}/../msgpack/src")
set(MSGPACK_INC "${CMAKE_SOURCE_DIR}/../../msgpack-c/include")

# ── RPATH ─────────────────────────────────────────────────────────────────────
set(CMAKE_SKIP_BUILD_RPATH FALSE)
set(CMAKE_BUILD_WITH_INSTALL_RPATH FALSE)
# Build RPATH: XKCP + TBB — kyber/dilithium are statically linked.
get_target_property(_tbb_loc TBB::tbb IMPORTED_LOCATION_RELEASE)
if(NOT _tbb_loc)
    get_target_property(_tbb_loc TBB::tbb IMPORTED_LOCATION)
endif()
get_filename_component(_tbb_libdir "${_tbb_loc}" DIRECTORY)
set(CMAKE_BUILD_RPATH "${XKCP_LIBDIR}" "${_tbb_libdir}")
# Install RPATH: relative so the installed binary is portable.
set(CMAKE_INSTALL_RPATH "$ORIGIN/../lib/obi-wan")
set(CMAKE_INSTALL_RPATH_USE_LINK_PATH FALSE)

# ── randombytes ───────────────────────────────────────────────────────────────
set(RANDOMBYTES_SRC "${KYBER_REF_DIR_ABS}/randombytes.c")

add_subdirectory(../../kyber/ref     kyber_ref_build)
add_subdirectory(../../dilithium/ref dilithium_ref_build)

# ── Sources ───────────────────────────────────────────────────────────────────
set(SOURCES
    src/main.cpp
    src/kyber_kem.cpp
    src/ec_kem.cpp
    src/ec_sig.cpp
    src/dilithium_sig.cpp
    src/tray_reader.cpp
    src/armor.cpp
    src/base64.cpp
    "${MSGPACK_SRC}/tray_pack.cpp"
    ${RANDOMBYTES_SRC}
)

add_executable(obi-wan ${SOURCES})

target_include_directories(obi-wan PRIVATE
    src
    "${CMAKE_SOURCE_DIR}/../include"   # tray.hpp
    "${KYBER_REF_DIR_ABS}"             # randombytes.h
    "${XKCP_INC}"                      # SimpleFIPS202.h, SP800-185.h
    "${MSGPACK_SRC}"                   # tray_pack.hpp
    "${MSGPACK_INC}"                   # msgpack-c header-only
)

target_compile_definitions(obi-wan PRIVATE MSGPACK_NO_BOOST)

# ── Link ──────────────────────────────────────────────────────────────────────
target_link_libraries(obi-wan PRIVATE
    pqcrystals_kyber512_ref
    pqcrystals_kyber768_ref
    pqcrystals_kyber1024_ref
    pqcrystals_kyber_fips202_ref
    pqcrystals_dilithium2_ref
    pqcrystals_dilithium3_ref
    pqcrystals_dilithium5_ref
    pqcrystals_dilithium_fips202_ref
    "${XKCP_LIBDIR}/libXKCP.so"
    BLAKE3::blake3
    TBB::tbb
    OpenSSL::Crypto
    yaml-cpp
)

# ── Compiler flags ────────────────────────────────────────────────────────────
target_compile_options(obi-wan PRIVATE -O2 -Wall -Wextra)

# ── Install ───────────────────────────────────────────────────────────────────
install(TARGETS obi-wan DESTINATION bin)

install(FILES
    "${XKCP_LIBDIR}/libXKCP.so"
    DESTINATION lib/obi-wan
)
