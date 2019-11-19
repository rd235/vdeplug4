cmake_minimum_required(VERSION 3.13)
  
add_executable(
        vde_plug vde_plug.c vde_plug_log.c vde_plug_iplog.c openclosepidfile.c
        selfsighandler.c
)
target_link_libraries(vde_plug vdeplug)

add_executable(dpipe dpipe.c openclosepidfile.c selfsighandler.c)

install(
        TARGETS vde_plug dpipe
        RUNTIME
        DESTINATION ${CMAKE_INSTALL_BINDIR}
)

