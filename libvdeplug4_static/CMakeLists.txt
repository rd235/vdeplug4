cmake_minimum_required(VERSION 3.13)
  
add_library(libvdeplug_a STATIC libvdeplug.c)
set_target_properties(libvdeplug_a PROPERTIES OUTPUT_NAME vdeplug)

install(
        TARGETS libvdeplug_a
        ARCHIVE
        DESTINATION ${CMAKE_INSTALL_LIBDIR}
)
