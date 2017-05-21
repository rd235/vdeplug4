man_MANS = dpipe.1 vde_plug.1 \
	libvdeplug_p2p.1 libvdeplug_udp.1 libvdeplug_vxlan.1 \
	libvdeplug_tap.1 libvdeplug_vde.1 libvdeplug_vxvde.1 \
	libvdeplug_cmd.1 libvdeplug_null.1 \
	libvdeplug_hub.1 libvdeplug_bonding.1 libvdeplug_multi.1 libvdeplug_switch.1 \
	libvdeplug.3

install-data-hook:
	ln -sf libvdeplug.3 $(DESTDIR)$(man3dir)/vde_open.3
	ln -sf libvdeplug.3 $(DESTDIR)$(man3dir)/vde_close.3
	ln -sf libvdeplug.3 $(DESTDIR)$(man3dir)/vde_recv.3
	ln -sf libvdeplug.3 $(DESTDIR)$(man3dir)/vde_send.3
	ln -sf libvdeplug.3 $(DESTDIR)$(man3dir)/vde_datafd.3
	ln -sf libvdeplug.3 $(DESTDIR)$(man3dir)/vde_stlfd.3

uninstall-hook:
	rm -f  $(DESTDIR)$(man3dir)/vde_open.3
	rm -f  $(DESTDIR)$(man3dir)/vde_close.3
	rm -f  $(DESTDIR)$(man3dir)/vde_recv.3
	rm -f  $(DESTDIR)$(man3dir)/vde_send.3
	rm -f  $(DESTDIR)$(man3dir)/vde_datafd.3
	rm -f  $(DESTDIR)$(man3dir)/vde_stlfd.3
