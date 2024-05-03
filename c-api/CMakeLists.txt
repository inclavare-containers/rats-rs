cmake_minimum_required(VERSION 3.15)
project(rats-rs VERSION 0.1.0)

# Build rats-rs c api binary with cargo in release mode
set_directory_properties(PROPERTIES EP_PREFIX ${CMAKE_BINARY_DIR}/Rust)
include(ExternalProject)
ExternalProject_Add(
    build_c_api
    DOWNLOAD_COMMAND ""
    CONFIGURE_COMMAND ""
    # BUILD_COMMAND echo "Building with cargo now. target dir: <BINARY_DIR>/target" && cargo build --manifest-path ${PROJECT_SOURCE_DIR}/../Cargo.toml --target-dir ./target --package c-api --release
    # INSTALL_COMMAND cp target/release/librats_rs.so target/release/librats_rs.a ${CMAKE_BINARY_DIR}/Rust/
    BUILD_COMMAND echo "Building with cargo now. target dir: <BINARY_DIR>/target" && cargo build --manifest-path ${PROJECT_SOURCE_DIR}/../Cargo.toml --target-dir ./target --package c-api
    INSTALL_COMMAND cp target/debug/librats_rs.so target/debug/librats_rs.a ${CMAKE_BINARY_DIR}/Rust/
    BUILD_ALWAYS 1
)

# Install files of rats-rs c api to system
install(DIRECTORY ${PROJECT_SOURCE_DIR}/include/ DESTINATION include/rats-rs)
install(FILES ${CMAKE_BINARY_DIR}/Rust/librats_rs.so DESTINATION lib/rats-rs)
install(FILES ${CMAKE_BINARY_DIR}/Rust/librats_rs.a DESTINATION lib/rats-rs)


# Create rats-rs (both shared and static) library target for exporting
add_library(shared INTERFACE)
add_dependencies(shared build_c_api)

target_link_libraries(shared INTERFACE
    $<BUILD_INTERFACE:${CMAKE_BINARY_DIR}/Rust/librats_rs.so>
    $<INSTALL_INTERFACE:$<INSTALL_PREFIX>/lib/rats-rs/librats_rs.so>
)

target_link_libraries(shared INTERFACE tdx_attest sgx_dcap_quoteverify dl m pthread)

target_include_directories(shared INTERFACE 
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)

install(
    TARGETS shared
    EXPORT RatsRsTargets
    RUNTIME DESTINATION bin
    LIBRARY DESTINATION lib/rats-rs
    ARCHIVE DESTINATION lib/rats-rs
    PUBLIC_HEADER DESTINATION include/rats-rs
)

add_library(static INTERFACE)
add_dependencies(static build_c_api)

target_link_libraries(static INTERFACE
    $<BUILD_INTERFACE:${CMAKE_BINARY_DIR}/Rust/librats_rs.a>
    $<INSTALL_INTERFACE:$<INSTALL_PREFIX>/lib/rats-rs/librats_rs.a>
)

target_link_libraries(static INTERFACE tdx_attest sgx_dcap_quoteverify dl m pthread)

target_include_directories(static INTERFACE 
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)

install(
    TARGETS static
    EXPORT RatsRsTargets
    RUNTIME DESTINATION bin
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
    PUBLIC_HEADER DESTINATION include
)

# Generate .cmake files for making it easier to import rats-rs from other cmake projects (config mode)
include(CMakePackageConfigHelpers)

install(
    EXPORT RatsRsTargets
    FILE "RatsRsTargets.cmake"
    DESTINATION "lib/cmake/RatsRs"
    NAMESPACE RatsRs::
)

configure_package_config_file(
    "${PROJECT_SOURCE_DIR}/cmake/RatsRsConfig.cmake.in"
    "${PROJECT_BINARY_DIR}/RatsRsConfig.cmake"
    INSTALL_DESTINATION "lib/cmake/RatsRs"
)

install(
    FILES "${PROJECT_BINARY_DIR}/RatsRsConfig.cmake"
    DESTINATION "lib/cmake/RatsRs"
)

write_basic_package_version_file(
    "${PROJECT_BINARY_DIR}/RatsRsConfigVersion.cmake"
    VERSION ${PACKAGE_VERSION}
    COMPATIBILITY AnyNewerVersion
)

install(
    FILES "${PROJECT_BINARY_DIR}/RatsRsConfigVersion.cmake"
    DESTINATION "lib/cmake/RatsRs"
)
