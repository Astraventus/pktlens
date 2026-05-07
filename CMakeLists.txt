cmake_minimum_required(VERSION 3.10)
project(pktlens CXX)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF) # -std=c++14, not -std=gnu++14

# Warnings
add_compile_options(-Wall -Wextra -Wpedantic)

find_package(PkgConfig REQUIRED)
pkg_check_modules(PCAP REQUIRED libpcap)

# Main library
add_library(pktlens_engine 
    src/capture/PcapFileProvider.cpp
    src/dissectors/DissectorRegistry.cpp
    src/dissectors/EthernetDissector.cpp
    src/dissectors/IPv4Dissector.cpp
    src/dissectors/TcpDissector.cpp
)

target_include_directories(pktlens_engine PUBLIC
    ${CMAKE_SOURCE_DIR}/include
    ${PCAP_INCLUDE_DIRS}
)

target_link_libraries(pktlens_engine PUBLIC
    ${PCAP_LIBRARIES}
)

add_executable(pktlens_test_reader
    src/main_test_reader.cpp
)

target_link_libraries(pktlens_test_reader PRIVATE pktlens_engine)