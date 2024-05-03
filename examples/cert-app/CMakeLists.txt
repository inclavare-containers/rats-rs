cmake_minimum_required(VERSION 3.15)

project(cert-app)

option(RATS_RS_STATIC "Link to the rats-rs static library (set OFF to link to shared library)" OFF)

set(SOURCES main.c
    app.c
    helper.c
)
add_executable(${PROJECT_NAME} ${SOURCES})

target_include_directories(${PROJECT_NAME} PUBLIC include)

# Link with rats-rs
find_package(RatsRs REQUIRED)

if(RATS_RS_STATIC)
    target_link_libraries(${PROJECT_NAME} RatsRs::static)
else()
    target_link_libraries(${PROJECT_NAME} RatsRs::shared)
endif()

# Link with OpenSSL which is required by this example app
find_package(OpenSSL REQUIRED)
target_link_libraries(${PROJECT_NAME} OpenSSL::Crypto)
