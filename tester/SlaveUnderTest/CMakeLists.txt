cmake_minimum_required(VERSION 3.5)

set(CMAKE_CXX_STANDARD 11)


project(dcpslave)

set(CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake)

    
add_definitions("-DDEBUG")
#add_definitions("-DRELEASE")

if (WIN32)
    add_definitions(-D_WIN32_WINNT=0x0600 -D_CRT_SECURE_NO_WARNINGS -D_SCL_SECURE_NO_WARNINGS)
endif()

find_package(DCPLib REQUIRED)
find_package(Threads REQUIRED)
find_package(ASIO REQUIRED )
find_package(XercesC REQUIRED)


include_directories("src")
    
file(GLOB_RECURSE dcpslave_src src/*.cpp src/*.hpp)
add_executable(dcpslave ${dcpslave_src})
target_link_libraries(dcpslave DCPLib::Ethernet DCPLib::Slave DCPLib::Xml)


install(TARGETS dcpslave DESTINATION bin)

