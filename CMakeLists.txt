cmake_minimum_required(VERSION 3.5)

# use c++11 features, requires cmake > 3.1
set(CMAKE_CXX_STANDARD 11)

# Project
project(dcp-tester)

set(CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake)


if (WIN32)
  add_definitions(-D_WIN32_WINNT=0x0600 -D_CRT_SECURE_NO_WARNINGS -D_SCL_SECURE_NO_WARNINGS)
endif()

add_definitions("-DDEBUG")

find_package(DCPLib REQUIRED)
find_package(Threads REQUIRED)
find_package(ASIO REQUIRED)

include(FindXercesC)
find_package(XercesC REQUIRED)
include_directories( ${XercesC_INCLUDE_DIR} )
link_libraries (${XercesC_LIBRARY} )


add_definitions(-Wno-deprecated)

include_directories("src")


file(GLOB_RECURSE dcp_tester_src_files src/*.cpp src/*.h src/*.cc src/*.hxx src/*.cxx src/*.hpp)

add_executable(dcp-tester ${dcp_tester_src_files})

target_link_libraries(dcp-tester DCPLib::Ethernet DCPLib::Master DCPLib::Xml)
#target_link_libraries(dcptester -static-libgcc -static-libstdc++)

install(TARGETS dcp-tester DESTINATION bin)


