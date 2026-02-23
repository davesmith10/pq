cmake_minimum_required(VERSION 3.15)
project(luke LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ── Library directories ───────────────────────────────────────────────────────
set(KYBER_REF_DIR  "${CMAKE_SOURCE_DIR}/../kyber/ref")
set(KYBER_AVX2_DIR "${CMAKE_SOURCE_DIR}/../kyber/avx2")

get_filename_component(KYBER_REF_DIR_ABS  "${KYBER_REF_DIR}"  ABSOLUTE)
get_filename_component(KYBER_AVX2_DIR_ABS "${KYBER_AVX2_DIR}" ABSOLUTE)

set(KYBER_REF_LIBDIR  "${KYBER_REF_DIR_ABS}/lib")
set(KYBER_AVX2_LIBDIR "${KYBER_AVX2_DIR_ABS}")

# ── RPATH settings ────────────────────────────────────────────────────────────
set(CMAKE_SKIP_BUILD_RPATH FALSE)
set(CMAKE_BUILD_WITH_INSTALL_RPATH TRUE)
set(CMAKE_INSTALL_RPATH "${KYBER_REF_LIBDIR}:${KYBER_AVX2_LIBDIR}")
set(CMAKE_INSTALL_RPATH_USE_LINK_PATH TRUE)

# ── randombytes (shared between ref and avx2 kyber .so files) ─────────────────
# Both ref and avx2 kyber .so files leave randombytes as undefined;
# we compile it directly into our binary to satisfy the dependency.
set(RANDOMBYTES_SRC "${KYBER_REF_DIR_ABS}/randombytes.c")

# ── Sources ───────────────────────────────────────────────────────────────────
set(SOURCES
    src/main.cpp
    src/kyber_ops.cpp
    src/base64.cpp
    src/pem_io.cpp
    ${RANDOMBYTES_SRC}
)

add_executable(luke ${SOURCES})
target_include_directories(luke PRIVATE
    src
    "${KYBER_REF_DIR_ABS}"      # for randombytes.h
)

# ── Link against .so files by full path ───────────────────────────────────────
# This avoids the naming conflict: both ref/lib and avx2 directories contain
# libpqcrystals_fips202_ref.so, but with different symbol namespaces.
target_link_libraries(luke PRIVATE
    # ref implementations (ref/lib/)
    "${KYBER_REF_LIBDIR}/libpqcrystals_kyber512_ref.so"
    "${KYBER_REF_LIBDIR}/libpqcrystals_kyber768_ref.so"
    "${KYBER_REF_LIBDIR}/libpqcrystals_kyber1024_ref.so"
    "${KYBER_REF_LIBDIR}/libpqcrystals_fips202_ref.so"
    # avx2 implementations (avx2/)
    "${KYBER_AVX2_LIBDIR}/libpqcrystals_kyber512_avx2.so"
    "${KYBER_AVX2_LIBDIR}/libpqcrystals_kyber768_avx2.so"
    "${KYBER_AVX2_LIBDIR}/libpqcrystals_kyber1024_avx2.so"
    "${KYBER_AVX2_LIBDIR}/libpqcrystals_fips202_avx2.so"    # provides fips202_avx2_* symbols (symlink to fips202_ref.so in avx2/)
    "${KYBER_AVX2_LIBDIR}/libpqcrystals_fips202x4_avx2.so" # provides fips202x4_avx2_* symbols
)

# ── Compiler flags ────────────────────────────────────────────────────────────
target_compile_options(luke PRIVATE -O2 -Wall -Wextra)

# ── Install ───────────────────────────────────────────────────────────────────
install(TARGETS luke DESTINATION bin)
