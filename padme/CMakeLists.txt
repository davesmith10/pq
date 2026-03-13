cmake_minimum_required(VERSION 3.16)
project(padme LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(yaml-cpp REQUIRED)
find_package(BLAKE3   REQUIRED)
find_package(TBB      REQUIRED)
find_package(OpenSSL  REQUIRED)

# ── RPATH for TBB shared library ──────────────────────────────────────────────
get_target_property(_tbb_loc TBB::tbb IMPORTED_LOCATION_RELEASE)
if(NOT _tbb_loc)
    get_target_property(_tbb_loc TBB::tbb IMPORTED_LOCATION)
endif()
get_filename_component(_tbb_libdir "${_tbb_loc}" DIRECTORY)
set(CMAKE_BUILD_RPATH "${_tbb_libdir}")

# ── Source paths ──────────────────────────────────────────────────────────────
# CMakeLists.txt lives in pq/padme/; libcrystals is at ../libcrystals/
set(LIB_SRC "${CMAKE_SOURCE_DIR}/../libcrystals/src")
set(LIB_INC "${CMAKE_SOURCE_DIR}/../libcrystals/include")
set(MSGPACK_INC "${CMAKE_SOURCE_DIR}/../../msgpack-c/include")

get_filename_component(LIB_SRC_ABS "${LIB_SRC}" ABSOLUTE)
get_filename_component(LIB_INC_ABS "${LIB_INC}" ABSOLUTE)
get_filename_component(MSGPACK_INC_ABS "${MSGPACK_INC}" ABSOLUTE)

# ── Executable ────────────────────────────────────────────────────────────────
add_executable(padme
    src/main.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/lodepng.cpp
    ${LIB_SRC_ABS}/tray_reader.cpp
    ${LIB_SRC_ABS}/tray_pack.cpp
    ${LIB_SRC_ABS}/base64.cpp
    ${LIB_SRC_ABS}/yaml_io.cpp
)

target_include_directories(padme PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}   # lodepng.h
    ${LIB_INC_ABS}                # crystals/*.hpp
    ${MSGPACK_INC_ABS}            # msgpack-c header-only
)

target_compile_definitions(padme PRIVATE MSGPACK_NO_BOOST)
target_compile_options(padme PRIVATE -O2 -Wall -Wextra)

target_link_libraries(padme PRIVATE
    OpenSSL::Crypto
    BLAKE3::blake3
    TBB::tbb
    yaml-cpp
)

# ── Install ───────────────────────────────────────────────────────────────────
install(TARGETS padme DESTINATION bin)
