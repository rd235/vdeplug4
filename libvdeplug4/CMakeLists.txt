cmake_minimum_required(VERSION 3.13)

add_subdirectory(libvdeplug2_legacy)

add_library(vdeplug_mod SHARED parseparms.c vde_hashtable.c)
set_target_properties(vdeplug_mod PROPERTIES VERSION 4.0.0)
set_target_properties(vdeplug_mod PROPERTIES SOVERSION 4)
target_link_libraries(vdeplug_mod -ldl)
target_link_libraries(vdeplug_mod -export-dynamic)

add_library(vdeplug SHARED libvdeplug.c libvdestream.c)
set_target_properties(vdeplug PROPERTIES VERSION 4.0.0)
set_target_properties(vdeplug PROPERTIES SOVERSION 4)
target_link_libraries(vdeplug -ldl)
target_link_libraries(vdeplug -export-dynamic)

add_library(vdeplug_vde SHARED libvdeplug_vde.c)
target_link_libraries(vdeplug_vde vdeplug_mod)

add_library(vdeplug_ptp SHARED libvdeplug_ptp.c)
target_link_libraries(vdeplug_ptp vdeplug_mod)

add_library(vdeplug_tap SHARED libvdeplug_tap.c)
target_link_libraries(vdeplug_tap vdeplug_mod)

add_library(vdeplug_udp SHARED libvdeplug_udp.c)
target_link_libraries(vdeplug_udp vdeplug_mod)

add_library(vdeplug_vxlan SHARED libvdeplug_vxlan.c)
target_link_libraries(vdeplug_vxlan vdeplug_mod)

add_library(vdeplug_vxvde SHARED libvdeplug_vxvde.c)
target_link_libraries(vdeplug_vxvde vdeplug_mod)

add_library(vdeplug_cmd SHARED libvdeplug_cmd.c)
target_link_libraries(vdeplug_cmd vdeplug_mod -lexecs)

add_library(vdeplug_null SHARED libvdeplug_null.c)
target_link_libraries(vdeplug_null vdeplug_mod)

add_library(vdeplug_hub SHARED libvdeplug_hub.c libvdeplug_netnode.c)
target_link_libraries(vdeplug_hub vdeplug_mod)

add_library(vdeplug_switch SHARED libvdeplug_switch.c libvdeplug_netnode.c)
target_link_libraries(vdeplug_switch vdeplug_mod)

add_library(vdeplug_multi SHARED libvdeplug_multi.c libvdeplug_netnode.c)
target_link_libraries(vdeplug_multi vdeplug_mod)

add_library(vdeplug_bonding SHARED libvdeplug_bonding.c libvdeplug_netnode.c)
target_link_libraries(vdeplug_bonding vdeplug_mod)

add_library(vdeplug_seqpacket SHARED libvdeplug_seqpacket.c)
target_link_libraries(vdeplug_seqpacket vdeplug_mod)