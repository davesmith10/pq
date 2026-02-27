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

get_filename_component(KYBER_REF_DIR_ABS     "${KYBER_REF_DIR}"     ABSOLUTE)
get_filename_component(DILITHIUM_REF_DIR_ABS "${DILITHIUM_REF_DIR}" ABSOLUTE)

set(KYBER_REF_LIBDIR "${KYBER_REF_DIR_ABS}/lib")

# ── RPATH settings ────────────────────────────────────────────────────────────
set(CMAKE_SKIP_BUILD_RPATH FALSE)
set(CMAKE_BUILD_WITH_INSTALL_RPATH FALSE)
# Build RPATH: absolute paths so build/scotty works in-place during development.
set(CMAKE_BUILD_RPATH "${KYBER_REF_LIBDIR}:${DILITHIUM_REF_DIR_ABS}")
# Install RPATH: relative so the installed binary is portable.
set(CMAKE_INSTALL_RPATH "$ORIGIN/../lib/scotty")
set(CMAKE_INSTALL_RPATH_USE_LINK_PATH FALSE)

# ── randombytes ────────────────────────────────────────────────────────────────
# The kyber and dilithium .so files leave randombytes undefined.
# Compile it into the binary from kyber/ref (works for both).
set(RANDOMBYTES_SRC "${KYBER_REF_DIR_ABS}/randombytes.c")

# ── fips202: compile both namespaces into the binary ──────────────────────────
#
# kyber .so files need pqcrystals_kyber_fips202_ref_* symbols.
# dilithium .so files need pqcrystals_dilithium_fips202_ref_* symbols.
# Both are implemented in identical fips202.c files compiled against different
# fips202.h headers that define the symbol namespace via macros.
#
# Solution: compile each fips202.c as an OBJECT library with its own include
# path, then link both into scotty.  Use -rdynamic so the .so files can resolve
# their fips202 dependencies against the main executable's symbol table.

add_library(kyber_fips202_obj OBJECT "${KYBER_REF_DIR_ABS}/fips202.c")
target_include_directories(kyber_fips202_obj PRIVATE "${KYBER_REF_DIR_ABS}")

add_library(dilithium_fips202_obj OBJECT "${DILITHIUM_REF_DIR_ABS}/fips202.c")
target_include_directories(dilithium_fips202_obj PRIVATE "${DILITHIUM_REF_DIR_ABS}")

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

add_executable(scotty
    ${SOURCES}
    $<TARGET_OBJECTS:kyber_fips202_obj>
    $<TARGET_OBJECTS:dilithium_fips202_obj>
)

target_include_directories(scotty PRIVATE
    src
    "${CMAKE_SOURCE_DIR}/../include"
    "${KYBER_REF_DIR_ABS}"       # for randombytes.h
    "${DILITHIUM_REF_DIR_ABS}"   # for dilithium randombytes.h (if needed)
    "${MSGPACK_SRC}"             # for tray_pack.hpp
    "${MSGPACK_INC}"             # msgpack-c header-only library
)

target_compile_definitions(scotty PRIVATE MSGPACK_NO_BOOST)

# Export all global symbols from the executable so dynamically-loaded kyber
# and dilithium .so files can resolve their fips202 dependencies.
target_link_options(scotty PRIVATE -rdynamic)

# ── Link against .so files by full path ───────────────────────────────────────
# Kyber ref only (no fips202 .so — compiled directly into binary above).
# Dilithium ref only (no fips202 .so — compiled directly into binary above).
target_link_libraries(scotty PRIVATE
    "${KYBER_REF_LIBDIR}/libpqcrystals_kyber512_ref.so"
    "${KYBER_REF_LIBDIR}/libpqcrystals_kyber768_ref.so"
    "${KYBER_REF_LIBDIR}/libpqcrystals_kyber1024_ref.so"
    "${DILITHIUM_REF_DIR_ABS}/libpqcrystals_dilithium2_ref.so"
    "${DILITHIUM_REF_DIR_ABS}/libpqcrystals_dilithium3_ref.so"
    "${DILITHIUM_REF_DIR_ABS}/libpqcrystals_dilithium5_ref.so"
    OpenSSL::Crypto
    yaml-cpp
)

# ── Compiler flags ────────────────────────────────────────────────────────────
target_compile_options(scotty PRIVATE -O2 -Wall -Wextra)

# ── Install ───────────────────────────────────────────────────────────────────
install(TARGETS scotty DESTINATION bin)

# Bundle required shared libraries into lib/scotty/.
# No fips202 .so needed — those symbols are compiled into the binary.
install(FILES
    "${KYBER_REF_LIBDIR}/libpqcrystals_kyber512_ref.so"
    "${KYBER_REF_LIBDIR}/libpqcrystals_kyber768_ref.so"
    "${KYBER_REF_LIBDIR}/libpqcrystals_kyber1024_ref.so"
    "${DILITHIUM_REF_DIR_ABS}/libpqcrystals_dilithium2_ref.so"
    "${DILITHIUM_REF_DIR_ABS}/libpqcrystals_dilithium3_ref.so"
    "${DILITHIUM_REF_DIR_ABS}/libpqcrystals_dilithium5_ref.so"
    DESTINATION lib/scotty
)
