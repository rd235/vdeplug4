cmake_minimum_required(VERSION 3.13)
project(vdeplug4
		VERSION 0.1
		DESCRIPTION "Virtual Distributed Ethernet. \
                                Plug your VM directly to the cloud."
		HOMEPAGE_URL "https://github.com/rd235/vdeplug4"
		LANGUAGES C)

include(GNUInstallDirs)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall")
set(BUILD_SHARED_LIBS ON)

set(ALLOW_DUPLICATE_CUSTOM_TARGETS True)

include_directories(
        ${PROJECT_SOURCE_DIR}/include
        ${PROJECT_SOURCE_DIR}/srcvdeplug4
)

list(INSERT CMAKE_MODULE_PATH 0 ${PROJECT_SOURCE_DIR}/cmake)
find_package(EXECS REQUIRED)

include(CheckIncludeFile)
check_include_file(fcntl.h HAVE_FCNTL_H)
check_include_file(stdint.h HAVE_STDINT_H)
check_include_file(stdlib.h HAVE_STDLIB_H)
check_include_file(string.h HAVE_STRING_H)
check_include_file(unistd.h HAVE_UNISTD_H)
check_include_file(syslog.h HAVE_SYSLOG_H)

include(CheckFunctionExists)
check_function_exists(strcmp HAVE_STRCMP)

add_subdirectory(libvdeplug4)
add_subdirectory(srcvdeplug4)
add_subdirectory(include)
add_subdirectory(man)
add_subdirectory(doc)
add_subdirectory(libvdeplug4_static)

add_custom_target(
        uninstall
        "${CMAKE_COMMAND}" -P "${PROJECT_SOURCE_DIR}/Uninstall.cmake"
)
