cmake_minimum_required(VERSION 3.15)

set(TARGET_NAME npcap)
project(${TARGET_NAME} 
		VERSION 2.0.0
		LANGUAGES CXX
		HOMEPAGE_URL "https://github.com/nmap/npcap.git"
		DESCRIPTION "cpp npcap."
	)

message(STATUS ${PROJECT_VERSION})
#message(STATUS ${PROJECT_VERSION_MAJOR})
#message(STATUS ${PROJECT_VERSION_MINOR})
#message(STATUS ${PROJECT_VERSION_PATCH})
#message(STATUS ${PROJECT_DESCRIPTION})

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/config.h.in
			   ${CMAKE_CURRENT_SOURCE_DIR}/config.h)

set(CMAKE_INCLUDE_CURRENT_DIR ON)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# https://blog.csdn.net/weixin_39766005/article/details/122439200
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE DEBUG STRING "Build Type" FORCE)
    add_compile_definitions(Debug)
	add_compile_definitions(_Debug)
endif()
message(STATUS ${CMAKE_BUILD_TYPE})
message(STATUS "CMAKE_CXX_FLAGS_DEBUG   = ${CMAKE_CXX_FLAGS_DEBUG}")
message(STATUS "CMAKE_CXX_FLAGS_RELEASE = ${CMAKE_CXX_FLAGS_RELEASE}")
message("Generated with config types: ${CMAKE_CONFIGURATION_TYPES}")
message(STATUS "CMAKE_MODULE_PATH = ${CMAKE_MODULE_PATH}")
message(STATUS "CMAKE_ROOT = ${CMAKE_ROOT}")
message(STATUS "Build type:${CMAKE_BUILD_TYPE}")

# Force out-of-source build
if(${CMAKE_SOURCE_DIR} STREQUAL ${CMAKE_BINARY_DIR})
  message(FATAL_ERROR
    "This project requires an out of source build. Remove the file 'CMakeCache.txt' found in this directory before continuing, create a separate build directory and run 'cmake [options] <srcs>' from there."
  )
endif()

# ---------------------------------------------------------------------------------------
# Operator System Detect
# ---------------------------------------------------------------------------------------
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    message(STATUS "Configuring on/for Linux")
elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    message(STATUS "Configuring on/for macOS")
elseif(CMAKE_SYSTEM_NAME STREQUAL "Windows")
    message(STATUS "Configuring on/for Windows")
endif()

# make sure __cplusplus is defined when using msvc and enable parallel build
if(MSVC)
    string(APPEND CMAKE_CXX_FLAGS " /Zc:__cplusplus /MP")
endif()

# Environment var setting
# QT_DIR
# E:\Qt\Qt5.15\5.15.2\msvc2019_64\bin
if(DEFINED ENV{QT_DIR})
    message(STATUS, "current used qt: ${QT_DIR}")
    message(STATUS, $ENV{QT_DIR})
else()
    message(STATUS, "Not found envirment QT_DIR")
endif()

if (CMAKE_BINARY_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
    message(FATAL_ERROR "Building in-source is not supported! Create a build dir and remove ${CMAKE_SOURCE_DIR}/CMakeCache.txt")
endif()

add_definitions(-DUNICODE -D_UNICODE)
add_definitions(-D_HAS_STD_BYTE=0)
add_definitions(-D_SILENCE_CXX17_RESULT_OF_DEPRECATION_WARNING)

if(MSVC)
    add_definitions(-DWIN32)
    add_definitions(-D_WINDOWS)
    add_definitions(-D_CRT_SECURE_NO_WARNINGS)
    add_definitions(-DWIN32_LEAN_AND_MEAN)
    add_definitions(-D_WIN32_WINNT=0x0601)
else()
    # linux
endif()

if(MSVC)
    # Turn on the ability to create folders to organize projects (.vcproj)
    # It creates "CMakePredefinedTargets" folder by default and adds CMake
    # defined projects like INSTALL.vcproj and ZERO_CHECK.vcproj
    set_property(GLOBAL PROPERTY USE_FOLDERS ON)
    set_property(GLOBAL PROPERTY PREDEFINED_TARGETS_FOLDER "CMakeTargets")
endif()

if(MSVC)
    if (CMAKE_SIZEOF_VOID_P EQUAL 4)
	    set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/x86/lib")
	    set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/x86/bin")
	    set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/x86/bin")
    else()
	    set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/x64/lib")
	    set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/x64/bin")
	    set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/x64/bin")
    endif()
endif()

# default
if( CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT )
    message(STATUS "Setting default CMAKE_INSTALL_PREFIX path to ${CMAKE_BINARY_DIR}/install")
    set(CMAKE_INSTALL_PREFIX "${CMAKE_BINARY_DIR}/install" CACHE STRING "The path to use for make install" FORCE)
endif()

if(MSVC)
    add_compile_options(
    /wd4065 # switch statement contains 'default' but no 'case' labels
    /wd4244 # 'conversion' conversion from 'type1' to 'type2', possible loss of data
    /wd4251 # 'identifier' : class 'type' needs to have dll-interface to be used by clients of class 'type2'
    /wd4267 # 'var' : conversion from 'size_t' to 'type', possible loss of data
    /wd4305 # 'identifier' : truncation from 'type1' to 'type2'
    /wd4307 # 'operator' : integral constant overflow
    /wd4309 # 'conversion' : truncation of constant value
    /wd4334 # 'operator' : result of 32-bit shift implicitly converted to 64 bits (was 64-bit shift intended?)
    /wd4355 # 'this' : used in base member initializer list
    /wd4506 # no definition for inline function 'function'
    /wd4800 # 'type' : forcing value to bool 'true' or 'false' (performance warning)
    /wd4996 # The compiler encountered a deprecated declaration.
    )
    add_compile_options(/MP)						# enable parallel compilation
    add_compile_options(/EHsc)						# specify Exception Handling Model in msvc
    add_compile_options(/WX)						# enable warnings-as-errors
    add_compile_options(/wd4068)					# disable unknown pragma warning (4068)
	add_compile_options(/wd4996)					# disable unsafe function warning (4996)
	add_compile_options(/wd4503)					# disable decorated name length exceeded, name was truncated (4503)
	add_compile_options(/wd4267)					# disable conversion from 'size_t' to 'type', possible loss of data (4267)
	add_compile_options(/wd4180)					# disable qualifier applied to function type has no meaning; ignored (4180)
	add_compile_options(/wd4290)					# disable C++ exception specification ignored except to indicate a function is not __declspec(nothrow) (4290)
	add_compile_options(/wd4297)					# disable <vector>'s function assumed not to throw an exception but does (4297)
	add_compile_options(/wd4244)					# disable conversion from 'type1' to 'type2', possible loss of data (4244)
	add_compile_options(/wd4800)					# disable forcing value to bool 'true' or 'false' (performance warning) (4800)
    add_compile_options(-DNOMINMAX)					# undefine windows.h MAX && MIN macros cause it cause conflicts with std::min && std::max functions
endif()

# Environment variable
if(DEFINED ENV{DEVELOP_DIR})
	message(STATUS "$ENV{DEVELOP_DIR}")
else()
	set(ENV{DEVELOP_DIR} "~/DevelopDir")
endif()

option(BUILD_SINGLE_SERVER "Build singleton service." OFF)

# database type enum
# mysql=0 sqlserver=2 sqlite=3 redis/memcached=4
option(BUILD_SQLSERVER "Build with mysql." OFF)

# warning options
option(SERVER_BUILD_WARNINGS "Enable compiler warnings" OFF)

# build by root cmakelist
option(BUILD_ROOT "Build from root dir cmakelist " ON)

add_subdirectory(Examples-pcap)

if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
    install(FILES "start.bat" "stop.bat" DESTINATION bin)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    install(FILES "linux_start.sh" "linux_stop.sh" DESTINATION bin)
endif()

# ------------------------------------------------------------------------
# cmake build
# -------------------------------------------------------------------------
# cd dir
# mkdir build
# cd build
# cmake .. -DCMAKE_BUILD_TYPE=Debug -DCMAKE_INSTALL_PREFIX=./install
# cmake --build .
# -------------------------------------------------------------------------
