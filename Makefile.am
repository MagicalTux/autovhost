## This is the shared library to be built
lib_LTLIBRARIES = libmodautovhost.la
ACLOCAL_AMFLAGS = -I m4

## Define the source file for the module
libmodautovhost_la_SOURCES = mod_autovhost.c

## Define that an include directory is required.
AM_CPPFLAGS = -I@apache_dir@/include
AM_CFLAGS = -Wall -std=c99 -O2

