AUTOMAKE_OPTIONS = subdir-objects

lib_LTLIBRARIES = libvdeplug.la 

libvdeplug_la_SOURCES = ../libvdeplug.c ../libvdestream.c
libvdeplug_la_LIBADD = -ldl
libvdeplug_la_LDFLAGS = $(AM_LDFLAGS) -version-number 2:4:0 -export-dynamic
libvdeplug_la_CPPFLAGS = -DVDEPLUG2_LEGACY
