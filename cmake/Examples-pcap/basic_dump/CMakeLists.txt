cmake_minimum_required(VERSION 3.15)

set(TARGET_NAME macaddress)
project(${TARGET_NAME} VERSION 1.0.0)

message(STATUS ${PROJECT_VERSION})
message(STATUS ${PROJECT_VERSION_MAJOR})
message(STATUS ${PROJECT_VERSION_MINOR})
message(STATUS ${PROJECT_VERSION_PATCH})
message(STATUS ${PROJECT_VERSION_TWEAK})
message(STATUS ${PROJECT_DESCRIPTION})

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/config.h.in
			   ${CMAKE_CURRENT_SOURCE_DIR}/config.h)

set(CMAKE_INCLUDE_CURRENT_DIR ON)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug)
endif()

if(Debug IN_LIST CMAKE_CONFIGURATION_TYPES OR CMAKE_BUILD_TYPE STREQUAL "Debug")
	message(STATUS "Build Debug project.")
	add_compile_definitions(DEBUG)
	add_compile_definitions(_DEBUG)
	add_compile_definitions(_CONSOLE)
	add_compile_definitions(HAVE_REMOTE)
	add_compile_definitions(WPCAP)
else()
	add_compile_definitions(_CONSOLE)
	add_compile_definitions(HAVE_REMOTE)
	add_compile_definitions(WPCAP)
endif()

# add the executable
add_executable(${TARGET_NAME} basic_dump.c)

set_property(TARGET ${TARGET_NAME} PROPERTY FOLDER "Examples-pcap")

target_include_directories(${TARGET_NAME} PUBLIC "${PROJECT_BINARY_DIR}")

set(SolutionDir ${PROJECT_SOURCE_DIR})
message(STATUS "SolutionDir=" ${SolutionDir})

target_include_directories(${TARGET_NAME} PRIVATE "${PROJECT_BINARY_DIR}")
target_include_directories(${TARGET_NAME} PRIVATE "${SolutionDir}")
target_include_directories(${TARGET_NAME} PRIVATE "${SolutionDir}/../../Include")
link_directories("${SolutionDir}/../../Lib")
target_link_libraries(${TARGET_NAME} PRIVATE "${SolutionDir}/../../Lib/x64/wpcap.lib")