cmake_minimum_required(VERSION 3.10)
project(pktlens CXX)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Warnings
add_compile_options(-Wall -Wextra -Wpedantic)

# Find required libraries with pkg-config
find_package(PkgConfig REQUIRED)
pkg_check_modules(PCAP REQUIRED libpcap)
pkg_check_modules(NCURSES REQUIRED ncurses)

# Main library - engine (no UI dependencies)
add_library(pktlens_engine 
    src/capture/PcapFileProvider.cpp
    src/dissectors/DissectorRegistry.cpp
    src/dissectors/EthernetDissector.cpp
    src/dissectors/IPv4Dissector.cpp
    src/dissectors/TcpDissector.cpp
    src/model/PacketStore.cpp
    src/filter/FilterParser.cpp
    src/session/SessionModel.cpp
)

target_include_directories(pktlens_engine PUBLIC
    ${CMAKE_SOURCE_DIR}/include
    ${PCAP_INCLUDE_DIRS}
)

# Engine needs pcap
target_link_libraries(pktlens_engine PUBLIC
    ${PCAP_LIBRARIES}
)

# UI library (depends on engine and ncurses)
add_library(pktlens_ui
    src/ui/TerminalGuard.cpp
    src/ui/Window.cpp
    src/ui/PacketListPanel.cpp
    src/ui/DetailPanel.cpp
    src/ui/FilterBar.cpp
    src/ui/App.cpp
)

target_include_directories(pktlens_ui PUBLIC
    ${CMAKE_SOURCE_DIR}/include
    ${NCURSES_INCLUDE_DIRS}
)

# UI needs engine and ncurses
target_link_libraries(pktlens_ui PUBLIC
    pktlens_engine
    ${NCURSES_LIBRARIES}
)

# Main application
add_executable(pktlens src/main.cpp)
target_link_libraries(pktlens PRIVATE pktlens_ui)

# Test reader
add_executable(pktlens_test_reader src/main_test_reader.cpp)
target_link_libraries(pktlens_test_reader PRIVATE pktlens_engine)