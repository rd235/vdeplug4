lib_LTLIBRARIES = libvdeplug.la libvdeplug_mod.la libvdeplug_vde.la\
									libvdeplug_ptp.la libvdeplug_tap.la libvdeplug_udp.la\
									libvdeplug_vxlan.la libvdeplug_vxvde.la libvdeplug_cmd.la \
									libvdeplug_null.la \
									libvdeplug_hub.la libvdeplug_switch.la libvdeplug_multi.la libvdeplug_bonding.la \
									libvdeplug_seqpacket.la

libvdeplug_mod_la_SOURCES = parseparms.c vde_hashtable.c
libvdeplug_mod_la_LIBADD = -ldl
libvdeplug_mod_la_LDFLAGS = $(AM_LDFLAGS) -version-number 4:0:0 -export-dynamic

libvdeplug_la_SOURCES = libvdeplug.c libvdestream.c
libvdeplug_la_LIBADD = -ldl
libvdeplug_la_LDFLAGS = $(AM_LDFLAGS) -version-number 2:4:0 -export-dynamic

libvdeplug_vde_la_SOURCES = libvdeplug_vde.c
libvdeplug_vde_la_LIBADD = -lvdeplug_mod
libvdeplug_vde_la_LDFLAGS = -module -avoid-version

libvdeplug_ptp_la_SOURCES = libvdeplug_ptp.c
libvdeplug_ptp_la_LIBADD = -lvdeplug_mod
libvdeplug_ptp_la_LDFLAGS = -module -avoid-version

libvdeplug_tap_la_SOURCES = libvdeplug_tap.c
libvdeplug_tap_la_LIBADD = -lvdeplug_mod
libvdeplug_tap_la_LDFLAGS = -module -avoid-version

libvdeplug_udp_la_SOURCES = libvdeplug_udp.c
libvdeplug_udp_la_LIBADD = -lvdeplug_mod
libvdeplug_udp_la_LDFLAGS = -module -avoid-version

libvdeplug_vxlan_la_SOURCES = libvdeplug_vxlan.c
libvdeplug_vxlan_la_LIBADD = -lvdeplug_mod
libvdeplug_vxlan_la_LDFLAGS = -module -avoid-version

libvdeplug_vxvde_la_SOURCES = libvdeplug_vxvde.c
libvdeplug_vxvde_la_LIBADD = -lvdeplug_mod
libvdeplug_vxvde_la_LDFLAGS = -module -avoid-version

libvdeplug_cmd_la_SOURCES = libvdeplug_cmd.c
libvdeplug_cmd_la_LIBADD = -lvdeplug_mod
libvdeplug_cmd_la_LDFLAGS = -module -avoid-version -lexecs

libvdeplug_null_la_SOURCES = libvdeplug_null.c
libvdeplug_null_la_LIBADD = -lvdeplug_mod
libvdeplug_null_la_LDFLAGS = -module -avoid-version

libvdeplug_hub_la_SOURCES = libvdeplug_hub.c libvdeplug_netnode.c
libvdeplug_hub_la_LIBADD = -lvdeplug_mod
libvdeplug_hub_la_LDFLAGS = -module -avoid-version

libvdeplug_switch_la_SOURCES = libvdeplug_switch.c libvdeplug_netnode.c
libvdeplug_switch_la_LIBADD = -lvdeplug_mod
libvdeplug_switch_la_LDFLAGS = -module -avoid-version

libvdeplug_multi_la_SOURCES = libvdeplug_multi.c libvdeplug_netnode.c
libvdeplug_multi_la_LIBADD = -lvdeplug_mod
libvdeplug_multi_la_LDFLAGS = -module -avoid-version

libvdeplug_bonding_la_SOURCES = libvdeplug_bonding.c libvdeplug_netnode.c
libvdeplug_bonding_la_LIBADD = -lvdeplug_mod
libvdeplug_bonding_la_LDFLAGS = -module -avoid-version

libvdeplug_seqpacket_la_SOURCES = libvdeplug_seqpacket.c
libvdeplug_seqpacket_la_LIBADD = -lvdeplug_mod
libvdeplug_seqpacket_la_LDFLAGS = -module -avoid-version

