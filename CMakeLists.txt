cmake_minimum_required(VERSION 3.16)
project(KMTO C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

set(SRC_DIR ${CMAKE_SOURCE_DIR}/src)
set(INC_DIR ${CMAKE_SOURCE_DIR}/include)

set(KMTO_SOURCES
    ${SRC_DIR}/main.c
    ${SRC_DIR}/mitigation_detector.c
    ${SRC_DIR}/telemetry.c
    ${SRC_DIR}/test_harness.c
    ${SRC_DIR}/config_manager.c
    ${SRC_DIR}/reporting.c
)

add_executable(kmto ${KMTO_SOURCES})
target_include_directories(kmto PRIVATE ${INC_DIR})
set_target_properties(kmto PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
)

if(WIN32)
    add_executable(kmto_cli ${SRC_DIR}/kmto_cli.c)
    target_include_directories(kmto_cli PRIVATE ${INC_DIR})
    target_compile_definitions(kmto_cli PRIVATE _WIN32)
    set_target_properties(kmto_cli PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
    )
    target_link_libraries(kmto_cli PRIVATE kernel32 user32 advapi32)
elseif(UNIX)
    target_compile_definitions(kmto PRIVATE __linux__)
endif()
