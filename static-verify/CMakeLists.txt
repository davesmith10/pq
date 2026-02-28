cmake_minimum_required(VERSION 3.15)
project(static_verify LANGUAGES C)

# Pull in the static library targets from both upstream source trees
add_subdirectory(../../kyber/ref     kyber_ref_build)
add_subdirectory(../../dilithium/ref dilithium_ref_build)

add_executable(test_static_pq
    main.c
    test_kyber.c
    test_dilithium.c
    # randombytes is not in any archive — compile from kyber/ref (identical API to dilithium/ref)
    ../../kyber/ref/randombytes.c
)

target_link_libraries(test_static_pq PRIVATE
    # Kyber variants + their fips202 namespace
    pqcrystals_kyber512_ref
    pqcrystals_kyber768_ref
    pqcrystals_kyber1024_ref
    pqcrystals_kyber_fips202_ref
    # Dilithium variants + their fips202 namespace
    pqcrystals_dilithium2_ref
    pqcrystals_dilithium3_ref
    pqcrystals_dilithium5_ref
    pqcrystals_dilithium_fips202_ref
)
