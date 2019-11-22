cmake_minimum_required(VERSION 3.13)
project(vdeplug4
    VERSION 4.0.0
    DESCRIPTION "Virtual Distributed Ethernet. Plug your VM directly to the cloud."
    HOMEPAGE_URL "https://github.com/rd235/vdeplug4"
    LANGUAGES C)

include(GNUInstallDirs)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -pedantic")
include_directories(
		${PROJECT_SOURCE_DIR}/include
		${PROJECT_SOURCE_DIR}/srcvdeplug4
)

include(CheckIncludeFile)
set(LIBS_REQUIRED execs)

foreach(THISLIB IN LISTS LIBS_REQUIRED)
  find_library(LIB${THISLIB}_OK ${THISLIB})
  if(NOT LIB${THISLIB}_OK)
    message(FATAL_ERROR "library lib${THISLIB} not found")
  endif()
endforeach(THISLIB)

add_subdirectory(libvdeplug4)
add_subdirectory(srcvdeplug4)
add_subdirectory(libvdeplug4_static)
add_subdirectory(include)
add_subdirectory(doc)
add_subdirectory(man)

add_custom_target(uninstall
	"${CMAKE_COMMAND}" -P "${PROJECT_SOURCE_DIR}/Uninstall.cmake")
