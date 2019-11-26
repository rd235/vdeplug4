# vdeplug4
VDE: Virtual Distributed Ethernet. Plug your VM directly to the cloud.

Vdeplug4 is a new perspective on virtual networking.

## hello vxvde world

Install vdeplug4:
```
 $ mkdir build
 $ cd build
 $ cmake ..
 $ make
 $ sudo make install
```

Start several VM *on different hosts on the same LAN* (IP ttl must be 1).
(VM virtual controllers must have different MAC addresses).

e.g. kvm:
```
 kvm .... -net nic,macaddr=52:54:00:11:22:11 -net vde,sock=vxvde://
 kvm .... -net nic,macaddr=52:54:00:11:22:22 -net vde,sock=vxvde://
 kvm .... -net nic,macaddr=52:54:00:11:22:33 -net vde,sock=vxvde://
 kvm .... -net nic,macaddr=52:54:00:11:22:44 -net vde,sock=vxvde://
 kvm .... -net nic,macaddr=52:54:00:11:22:55 -net vde,sock=vxvde://
```

All the VM will be automagically on the same Virtual LAN.
(similarly, it is possible to add virtualbox, qemu-system-\* and user-mode-linux
 VMs).

It is possible to connect the virtual newtork to a tuntap interface
and manage in this way the routing towards real networks (maybe the Internet).
The command (to run on any host on the LAN) is:
```
$ sudo vde_plug vxvde:// tap://mytap
```

The tap can be defined on a remote host:
```
$ vde_plug vxvde:// = ssh fqdn.of.remote.host,org vde_plug tap://
```

## what is vdeplug4

This software package includes a modular library (libvdeplug) and some utility tools (vde\_plug and dpipe)

The new libvdeplug library is backwards compatible with the previous versions (so it is already supported
		by qemu, kvm, virtualbox, user-mode-linux, view-os, lwipv6, picotcp and all the other VM or virtual
		stacks supporting vde2).

The new library supports plug-ins so it is open to new developments in vrtual networking.

Several plug-ins are provided as standard extensions of the library (batteries included):
- vde: connect to legacy vde\_switch (provided by vde2)
- ptp: peer to peer connection between two VM
- tap: connect a VM or a virtual network to 
- vxlan: connect vde switches or other vde networks to vxlan
- vxvde: this plug-in implements distributed virtual switches
- udp: udp tunnelling

The address of a virtual network is defined by a syntax similar to web URLs.

examples:
```
vxvde://239.1.2.3/ttl=2
tap://mytap
vde:///tmp/myswitch
myplugin://my.syntax/myarg=myvalue
```
This latter example will work provided there is a dynamic library named libvdeplug\_myplugin.so
available and accepting the syntax of the parameters after '//'

Other modules can be added. Vdeplug4 includes the header file and a support library to implement further plugins.

## Credits:

Mattia Biondi largely contibuted to the conversion from autotools to cmake. (2019)

