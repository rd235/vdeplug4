lib_LTLIBRARIES = libvdeplug.la libvdeplug_mod.la libvdeplug_vde.la\
												libvdeplug_p2p.la libvdeplug_tap.la libvdeplug_udp.la\
												libvdeplug_vxlan.la libvdeplug_vxvde.la libvdeplug_cmd.la

libvdeplug_mod_la_SOURCES = parseparms.c
libvdeplug_mod_la_LIBADD = -ldl
libvdeplug_mod_la_LDFLAGS = $(AM_LDFLAGS) -version-number 4:0:0 -export-dynamic

libvdeplug_la_SOURCES = libvdeplug.c libvdestream.c
libvdeplug_la_LIBADD = -ldl
libvdeplug_la_LDFLAGS = $(AM_LDFLAGS) -version-number 4:0:0 -export-dynamic

libvdeplug_vde_la_SOURCES = libvdeplug_vde.c
libvdeplug_vde_la_LIBADD = -lvdeplug_mod
libvdeplug_vde_la_LDFLAGS = -module -avoid-version

libvdeplug_p2p_la_SOURCES = libvdeplug_p2p.c
libvdeplug_p2p_la_LIBADD = -lvdeplug_mod
libvdeplug_p2p_la_LDFLAGS = -module -avoid-version

libvdeplug_tap_la_SOURCES = libvdeplug_tap.c
libvdeplug_tap_la_LIBADD = -lvdeplug_mod
libvdeplug_tap_la_LDFLAGS = -module -avoid-version

libvdeplug_udp_la_SOURCES = libvdeplug_udp.c
libvdeplug_udp_la_LIBADD = -lvdeplug_mod
libvdeplug_udp_la_LDFLAGS = -module -avoid-version

libvdeplug_vxlan_la_SOURCES = libvdeplug_vxlan.c libvdeplug_vxhash.c
libvdeplug_vxlan_la_LIBADD = -lvdeplug_mod
libvdeplug_vxlan_la_LDFLAGS = -module -avoid-version

libvdeplug_vxvde_la_SOURCES = libvdeplug_vxvde.c libvdeplug_vxhash.c
libvdeplug_vxvde_la_LIBADD = -lvdeplug_mod
libvdeplug_vxvde_la_LDFLAGS = -module -avoid-version

libvdeplug_cmd_la_SOURCES = libvdeplug_cmd.c
libvdeplug_cmd_la_LIBADD = -lvdeplug_mod
libvdeplug_cmd_la_LDFLAGS = -module -avoid-version -lexecs

install-data-hook:
	ln -sf libvdeplug.so.4 $(DESTDIR)$(libdir)/libvdeplug.so.3
	ln -sf libvdeplug.so.4 $(DESTDIR)$(libdir)/libvdeplug.so.2

uninstall-hook:
	rm -f $(DESTDIR)$(libdir)/libvdeplug.so.3
	rm -f $(DESTDIR)$(libdir)/libvdeplug.so.2
