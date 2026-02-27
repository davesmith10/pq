cmake_minimum_required(VERSION 3.15)
project(traymsgpack LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(MSGPACK_INC "${CMAKE_SOURCE_DIR}/../../msgpack-c/include")
set(TRAY_INC    "${CMAKE_SOURCE_DIR}/../include")

# ── Static library ─────────────────────────────────────────────────────────────
add_library(traymsgpack STATIC src/tray_pack.cpp)
target_include_directories(traymsgpack PUBLIC src "${TRAY_INC}" "${MSGPACK_INC}")
target_compile_definitions(traymsgpack PUBLIC MSGPACK_NO_BOOST)
target_compile_options(traymsgpack PRIVATE -O2 -Wall -Wextra)

# ── Test 1: in-memory round-trip (no external deps) ────────────────────────────
add_executable(test_roundtrip test/test_roundtrip.cpp)
target_link_libraries(test_roundtrip PRIVATE traymsgpack)

# ── Test 2: YAML → pack → unpack (needs yaml-cpp + base64 from scotty) ────────
find_package(yaml-cpp REQUIRED)
set(SCOTTY_SRC "${CMAKE_SOURCE_DIR}/../scotty/src")
add_executable(test_from_yaml
    test/test_from_yaml.cpp
    "${SCOTTY_SRC}/base64.cpp")
target_include_directories(test_from_yaml PRIVATE "${SCOTTY_SRC}")
target_link_libraries(test_from_yaml PRIVATE traymsgpack yaml-cpp)
