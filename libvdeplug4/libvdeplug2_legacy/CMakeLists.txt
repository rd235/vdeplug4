cmake_minimum_required(VERSION 3.13)

add_library(vdeplug_legacy SHARED ../libvdeplug.c ../libvdestream.c)
set_target_properties(vdeplug_legacy PROPERTIES OUTPUT_NAME vdeplug)
set_target_properties(vdeplug_legacy PROPERTIES VERSION 2.4.0)
set_target_properties(vdeplug_legacy PROPERTIES SOVERSION 2)
target_link_libraries(vdeplug_legacy -ldl)
target_link_libraries(vdeplug_legacy -export-dynamic)
target_link_libraries(vdeplug_legacy -DVDEPLUG2_LEGACY)

install(
        TARGETS vdeplug_legacy
        LIBRARY
        DESTINATION ${CMAKE_INSTALL_LIBDIR}
)
