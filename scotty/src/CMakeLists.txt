cmake_minimum_required(VERSION 3.15)
project(scotty LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ── Library directories ───────────────────────────────────────────────────────
set(DILITHIUM_REF_DIR  "${CMAKE_SOURCE_DIR}/../dilithium/ref")
set(DILITHIUM_AVX2_DIR "${CMAKE_SOURCE_DIR}/../dilithium/avx2")

get_filename_component(DILITHIUM_REF_DIR_ABS  "${DILITHIUM_REF_DIR}"  ABSOLUTE)
get_filename_component(DILITHIUM_AVX2_DIR_ABS "${DILITHIUM_AVX2_DIR}" ABSOLUTE)

# ── RPATH settings ────────────────────────────────────────────────────────────
set(CMAKE_SKIP_BUILD_RPATH FALSE)
set(CMAKE_BUILD_WITH_INSTALL_RPATH TRUE)
set(CMAKE_INSTALL_RPATH "${DILITHIUM_REF_DIR_ABS}:${DILITHIUM_AVX2_DIR_ABS}")
set(CMAKE_INSTALL_RPATH_USE_LINK_PATH TRUE)

# ── randombytes (dilithium .so files leave it undefined) ──────────────────────
set(RANDOMBYTES_SRC "${DILITHIUM_REF_DIR_ABS}/randombytes.c")

# ── Sources ───────────────────────────────────────────────────────────────────
set(SOURCES
    main.cpp
    dilithium_ops.cpp
    base64.cpp
    pem_io.cpp
    ${RANDOMBYTES_SRC}
)

add_executable(scotty ${SOURCES})
target_include_directories(scotty PRIVATE
    .
    "${DILITHIUM_REF_DIR_ABS}"      # for randombytes.h
)

# ── Link against .so files by full path ───────────────────────────────────────
# Linking by full path avoids any -l name collisions between ref and avx2.
target_link_libraries(scotty PRIVATE
    # ref implementations
    "${DILITHIUM_REF_DIR_ABS}/libpqcrystals_dilithium2_ref.so"
    "${DILITHIUM_REF_DIR_ABS}/libpqcrystals_dilithium3_ref.so"
    "${DILITHIUM_REF_DIR_ABS}/libpqcrystals_dilithium5_ref.so"
    "${DILITHIUM_REF_DIR_ABS}/libpqcrystals_fips202_ref.so"
    # avx2 implementations
    "${DILITHIUM_AVX2_DIR_ABS}/libpqcrystals_dilithium2_avx2.so"
    "${DILITHIUM_AVX2_DIR_ABS}/libpqcrystals_dilithium3_avx2.so"
    "${DILITHIUM_AVX2_DIR_ABS}/libpqcrystals_dilithium5_avx2.so"
    "${DILITHIUM_AVX2_DIR_ABS}/libpqcrystals_fips202_avx2.so"
    "${DILITHIUM_AVX2_DIR_ABS}/libpqcrystals_fips202x4_avx2.so"
)

# ── Compiler flags ────────────────────────────────────────────────────────────
target_compile_options(scotty PRIVATE -O2 -Wall -Wextra)

# ── Install ───────────────────────────────────────────────────────────────────
install(TARGETS scotty DESTINATION bin)
