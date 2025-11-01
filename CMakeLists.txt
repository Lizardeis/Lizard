cmake_minimum_required(VERSION 3.10)
project(LizardProtocol VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -Wpedantic")
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -g -O0")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -O3 -DNDEBUG")

find_package(OpenSSL REQUIRED)
find_package(ZLIB REQUIRED)
find_package(Threads REQUIRED)

set(LIZARD_SOURCES
    lizard_protocol.cpp
    lizard_tls.cpp
    lizard_connection.cpp
    lizard_server.cpp
    lizard_client.cpp
    lizard_compression.cpp
    lizard_cache.cpp
)

set(LIZARD_HEADERS
    lizard_protocol.h
    lizard_tls.h
    lizard_connection.h
    lizard_server.h
    lizard_client.h
    lizard_compression.h
    lizard_cache.h
)

add_library(lizard STATIC ${LIZARD_SOURCES} ${LIZARD_HEADERS})

target_include_directories(lizard PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${OPENSSL_INCLUDE_DIR}
    ${ZLIB_INCLUDE_DIRS}
)

target_link_libraries(lizard PUBLIC
    OpenSSL::SSL
    OpenSSL::Crypto
    ZLIB::ZLIB
    Threads::Threads
)

add_executable(lizard_server_example examples/server_example.cpp)
target_link_libraries(lizard_server_example PRIVATE lizard)

add_executable(lizard_client_example examples/client_example.cpp)
target_link_libraries(lizard_client_example PRIVATE lizard)

add_executable(lizard_benchmark examples/benchmark.cpp)
target_link_libraries(lizard_benchmark PRIVATE lizard)

install(TARGETS lizard
    ARCHIVE DESTINATION lib
    LIBRARY DESTINATION lib
)

install(FILES ${LIZARD_HEADERS}
    DESTINATION include/lizard
)

install(TARGETS lizard_server_example lizard_client_example lizard_benchmark
    RUNTIME DESTINATION bin
)

enable_testing()

add_executable(lizard_tests tests/test_protocol.cpp)
target_link_libraries(lizard_tests PRIVATE lizard)
add_test(NAME ProtocolTests COMMAND lizard_tests)

set(CPACK_PACKAGE_NAME "LizardProtocol")
set(CPACK_PACKAGE_VERSION ${PROJECT_VERSION})
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Lizard Protocol - A comprehensive web protocol implementation")
set(CPACK_PACKAGE_VENDOR "Lizard Protocol Team")
set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_CURRENT_SOURCE_DIR}/LICENSE")
set(CPACK_PACKAGE_INSTALL_DIRECTORY "LizardProtocol")

include(CPack)
