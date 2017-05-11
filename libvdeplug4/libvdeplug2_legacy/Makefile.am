lib_LTLIBRARIES = libvdeplug.la 

AM_CPPFLAGS = -DVDEPLUG2_LEGACY

libvdeplug_la_SOURCES = ../libvdeplug.c ../libvdestream.c
libvdeplug_la_LIBADD = -ldl
libvdeplug_la_LDFLAGS = $(AM_LDFLAGS) -version-number 2:4:0 -export-dynamic
