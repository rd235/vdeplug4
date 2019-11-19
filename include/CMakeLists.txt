cmake_minimum_required(VERSION 3.13)
  
set_target_properties(vdeplug PROPERTIES PUBLIC_HEADER libvdeplug.h)
set_target_properties(vdeplug_mod PROPERTIES PUBLIC_HEADER libvdeplug_mod.h)

install(
        TARGETS vdeplug vdeplug_mod
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)
