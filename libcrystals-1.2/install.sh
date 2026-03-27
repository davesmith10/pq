#!/usr/bin/env bash
# install.sh — build and install libcrystals-1.2 to a system prefix.
#
# Creates a fat static archive (libcrystals-1.2.a) that bundles the Kyber, Dilithium,
# and scrypt object files together with the crystals objects, so consumers only
# need to link one archive plus the dynamic deps (XKCP, BLAKE3, TBB, OpenSSL,
# yaml-cpp).  Installs a CMake package config and a pkg-config .pc file.
#
# Usage:
#   ./install.sh [--prefix <dir>] [--crystals-root <dir>] [--skip-build] [-h]
#
# Defaults:
#   --prefix        /usr/local
#   --crystals-root auto-detected as two levels above this script (Crystals/)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CRYSTALS_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

PREFIX="/usr/local"
BUILD_DIR="${SCRIPT_DIR}/build"
SKIP_BUILD=0

# ── Argument parsing ───────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --prefix=*)       PREFIX="${1#--prefix=}"; shift ;;
        --prefix)         PREFIX="$2"; shift 2 ;;
        --crystals-root=*) CRYSTALS_ROOT="${1#--crystals-root=}"; shift ;;
        --crystals-root)  CRYSTALS_ROOT="$2"; shift 2 ;;
        --skip-build)     SKIP_BUILD=1; shift ;;
        -h|--help)
            sed -n '2,12p' "$0" | sed 's/^# \?//'
            exit 0 ;;
        *) echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

LOCAL_PREFIX="${CRYSTALS_ROOT}/local"
XKCP_LIBDIR="${CRYSTALS_ROOT}/XKCP/bin/x86-64"
XKCP_INC="${XKCP_LIBDIR}/libXKCP.so.headers"
SCRYPT_DIR="${CRYSTALS_ROOT}/scrypt"

echo "=== libcrystals-1.2 installer ==="
echo "  Source:        ${SCRIPT_DIR}"
echo "  Crystals root: ${CRYSTALS_ROOT}"
echo "  Install prefix: ${PREFIX}"
echo ""

# ── 1. Build ───────────────────────────────────────────────────────────────────
if [[ ${SKIP_BUILD} -eq 0 ]]; then
    echo "[1/5] Building libcrystals-1.2..."
    cmake -S "${SCRIPT_DIR}" -B "${BUILD_DIR}" \
        -DCMAKE_PREFIX_PATH="${LOCAL_PREFIX}" \
        -DCMAKE_BUILD_TYPE=RelWithDebInfo \
        -DCMAKE_POSITION_INDEPENDENT_CODE=ON
    cmake --build "${BUILD_DIR}" -j"$(nproc)"
else
    echo "[1/5] Skipping build (--skip-build)"
fi

if [[ ! -f "${BUILD_DIR}/libcrystals.a" ]]; then
    echo "ERROR: ${BUILD_DIR}/libcrystals.a not found. Build first or remove --skip-build." >&2
    exit 1
fi

# ── 2. Create fat static archive ───────────────────────────────────────────────
# Merges all static deps (PQ ref libs + scrypt archives) into one archive so
# consumers only need to link -lcrystals (plus the dynamic deps listed below).
echo "[2/5] Creating fat static archive..."

WORK_DIR="$(mktemp -d)"
trap 'rm -rf "${WORK_DIR}"' EXIT

# Extract every .o from an archive into WORK_DIR, prefixed with the archive name
# to prevent object-file name collisions across archives.
extract_archive() {
    local archive="$1"
    if [[ ! -f "${archive}" ]]; then
        echo "  WARNING: ${archive} not found — skipping" >&2
        return
    fi
    local name
    name="$(basename "${archive}" .a)"
    local subdir="${WORK_DIR}/_ext_${name}"
    mkdir -p "${subdir}"

    # Use ar xN to extract each member by occurrence index, handling archives
    # that contain multiple members with the same filename (e.g. liboqs.a which
    # bundles objects from multiple algorithm implementations).
    declare -A _seen=()
    local _idx=0
    while IFS= read -r member; do
        local _base
        _base="$(basename "${member}")"
        local _n=$(( ${_seen["${_base}"]:-0} + 1 ))
        _seen["${_base}"]=${_n}
        (cd "${subdir}" && ar xN "${_n}" "${archive}" "${member}" 2>/dev/null) || true
        if [[ -f "${subdir}/${_base}" ]]; then
            mv "${subdir}/${_base}" \
               "${WORK_DIR}/${name}__$(printf '%06d' ${_idx})__${_base}"
        fi
        _idx=$(( _idx + 1 ))
    done < <(ar t "${archive}")

    rm -rf "${subdir}"
}

extract_archive "${BUILD_DIR}/libcrystals.a"

# PQ ref static archives (built via add_subdirectory into build/)
for _a in \
    "${BUILD_DIR}/kyber_ref_build/libpqcrystals_kyber512_ref.a" \
    "${BUILD_DIR}/kyber_ref_build/libpqcrystals_kyber768_ref.a" \
    "${BUILD_DIR}/kyber_ref_build/libpqcrystals_kyber1024_ref.a" \
    "${BUILD_DIR}/kyber_ref_build/libpqcrystals_kyber_fips202_ref.a" \
    "${BUILD_DIR}/dilithium_ref_build/libpqcrystals_dilithium2_ref.a" \
    "${BUILD_DIR}/dilithium_ref_build/libpqcrystals_dilithium3_ref.a" \
    "${BUILD_DIR}/dilithium_ref_build/libpqcrystals_dilithium5_ref.a" \
    "${BUILD_DIR}/dilithium_ref_build/libpqcrystals_dilithium_fips202_ref.a"
do
    extract_archive "${_a}"
done

# scrypt static archives (pre-built from source)
for _a in \
    "${SCRYPT_DIR}/.libs/libscrypt_sse2.a" \
    "${SCRYPT_DIR}/.libs/libcperciva_cpusupport_detect.a" \
    "${SCRYPT_DIR}/.libs/libcperciva_shani.a"
do
    extract_archive "${_a}"
done

# libmceliece (McEliece KEM — statically linked by crystals)
extract_archive "/usr/local/lib/libmceliece.a"

# liboqs (ML-KEM, ML-DSA, FrodoKEM, Falcon — via liboqs)
extract_archive "/usr/local/lib64/liboqs.a"

# Assemble the fat archive
FAT_ARCHIVE="${WORK_DIR}/libcrystals-1.2.a"
mapfile -t _objs < <(find "${WORK_DIR}" -maxdepth 1 -name "*.o" | sort)
if [[ ${#_objs[@]} -eq 0 ]]; then
    echo "ERROR: No object files found to package." >&2
    exit 1
fi
ar rcs "${FAT_ARCHIVE}" "${_objs[@]}"
ranlib "${FAT_ARCHIVE}"

# ── 3. Install files ───────────────────────────────────────────────────────────
echo "[3/5] Installing files to ${PREFIX}..."

install -d "${PREFIX}/include/crystals"
install -d "${PREFIX}/lib"
install -d "${PREFIX}/lib/cmake/crystals"
install -d "${PREFIX}/lib/pkgconfig"

# Headers
for _f in "${SCRIPT_DIR}/include/crystals/"*.hpp; do
    install -m 644 "${_f}" "${PREFIX}/include/crystals/"
done

# Fat static archive
install -m 644 "${FAT_ARCHIVE}" "${PREFIX}/lib/libcrystals-1.2.a"
ranlib "${PREFIX}/lib/libcrystals-1.2.a"

# XKCP shared library — the one remaining dynamic runtime dep from crystals itself
if [[ -f "${XKCP_LIBDIR}/libXKCP.so" ]]; then
    install -m 755 "${XKCP_LIBDIR}/libXKCP.so" "${PREFIX}/lib/"
else
    echo "  WARNING: ${XKCP_LIBDIR}/libXKCP.so not found — skipping" >&2
fi

# ── 4. CMake package config ────────────────────────────────────────────────────
echo "[4/5] Writing CMake package config..."

# Resolve the BLAKE3 + TBB cmake dirs; probe lib64 first, fall back to lib.
_find_cmake_dir() {
    local base="$1" pkg="$2"
    for subdir in lib64 lib; do
        if [[ -d "${base}/${subdir}/cmake/${pkg}" ]]; then
            echo "${base}/${subdir}/cmake/${pkg}"
            return
        fi
    done
    echo "${base}/lib/cmake/${pkg}"  # fallback (dir may not exist yet)
}
BLAKE3_DIR="$(_find_cmake_dir "${LOCAL_PREFIX}" blake3)"   # config file is lowercase blake3-config.cmake
TBB_DIR="$(_find_cmake_dir "${LOCAL_PREFIX}" TBB)"

cat > "${PREFIX}/lib/cmake/crystals/CrystalsConfig.cmake" << EOF
# CrystalsConfig.cmake — generated by libcrystals-1.2/install.sh
cmake_minimum_required(VERSION 3.16)

# Compute prefix relative to this file (handles relocatable installs)
get_filename_component(_crystals_root "\${CMAKE_CURRENT_LIST_DIR}/../../.." ABSOLUTE)

find_package(OpenSSL REQUIRED)
find_package(yaml-cpp REQUIRED)
find_package(TBB    QUIET HINTS "${TBB_DIR}"    "\${_crystals_root}/lib/cmake/TBB"    "\${_crystals_root}/lib64/cmake/TBB")
find_package(blake3 QUIET HINTS "${BLAKE3_DIR}" "\${_crystals_root}/lib/cmake/blake3" "\${_crystals_root}/lib64/cmake/blake3")

if(NOT TARGET Crystals::crystals)
    add_library(Crystals::crystals STATIC IMPORTED GLOBAL)

    set_target_properties(Crystals::crystals PROPERTIES
        IMPORTED_LOCATION             "\${_crystals_root}/lib/libcrystals-1.2.a"
        INTERFACE_INCLUDE_DIRECTORIES "\${_crystals_root}/include;${XKCP_INC}"
    )

    # Collect transitive dynamic link deps
    set(_cl_libs OpenSSL::Crypto yaml-cpp)

    if(TARGET BLAKE3::blake3)
        list(APPEND _cl_libs BLAKE3::blake3)
    endif()
    if(TARGET TBB::tbb)
        list(APPEND _cl_libs TBB::tbb)
    endif()

    # XKCP shared library
    find_library(_xkcp XKCP HINTS "\${_crystals_root}/lib" REQUIRED)
    list(APPEND _cl_libs "\${_xkcp}")

    set_property(TARGET Crystals::crystals APPEND PROPERTY
        INTERFACE_LINK_LIBRARIES "\${_cl_libs}"
    )
endif()

set(Crystals_FOUND          TRUE)
set(Crystals_INCLUDE_DIRS   "\${_crystals_root}/include")
set(Crystals_LIBRARIES      Crystals::crystals)
EOF

# ── 5. pkg-config file ─────────────────────────────────────────────────────────
echo "[5/5] Writing pkg-config file..."

# Libs.private lists what a static consumer must link beyond -lcrystals itself
cat > "${PREFIX}/lib/pkgconfig/crystals.pc" << EOF
prefix=${PREFIX}
exec_prefix=\${prefix}
libdir=\${exec_prefix}/lib
includedir=\${prefix}/include

Name: crystals
Description: Hybrid post-quantum crypto library (Kyber + Dilithium + EC + AEAD)
Version: 1.2.0
Cflags: -I\${includedir}
Libs: -L\${libdir} -lcrystals-1.2 -lXKCP
Libs.private: -lssl -lcrypto -lyaml-cpp
EOF

# ── Finish ─────────────────────────────────────────────────────────────────────
# Refresh the dynamic linker cache if installing under a standard system prefix
if command -v ldconfig &>/dev/null && [[ "${PREFIX}" == /usr* || "${PREFIX}" == /lib* ]]; then
    ldconfig
fi

echo ""
echo "Installation complete."
echo ""
echo "CMake usage:"
echo "  find_package(Crystals REQUIRED"
echo "      HINTS ${PREFIX}/lib/cmake/crystals)"
echo "  target_link_libraries(my_target PRIVATE Crystals::crystals)"
echo ""
echo "pkg-config usage:"
if [[ "${PREFIX}" != /usr/local && "${PREFIX}" != /usr ]]; then
    echo "  export PKG_CONFIG_PATH=${PREFIX}/lib/pkgconfig:\$PKG_CONFIG_PATH"
fi
echo "  pkg-config --cflags --libs crystals"
