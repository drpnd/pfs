#
# Copyright (c) 2018 Hirochika Asai <asai@jar.jp>
# All rights reserved.
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#

#SUBDIRS = 
#EXTRA_DIST = 
#noinst_HEADERS = 
#INCLUDES = -I$(top_srcdir)/include

EXTRA_DIST = fuse-pfs.pc.in
pkgconfigdir = @pkgconfigdir@
pkgconfig_DATA = fuse-pfs.pc
$(pkgconfig_DATA): config.status

bin_PROGRAMS = pfs
pfs_CPPFLAGS = $(FUSE_CFLAGS) $(SSL_CFLAGS)
pfs_LDADD= $(FUSE_LIBS) $(SSL_LIBS)
#libexec_PROGRAMS = 
#lib_LIBRARIES = lib.a
#noinst_LIBRARIES = 
#lib_LTLIBRARIES = lib.la
#noinst_LTLIBRARIES = 
#EXTRA_LTLIBRARIES = 
pfs_SOURCES = main.c
#lib_la_SOURCES = 
#prog_LDADD = lib.la
#prog_LDFLAGS = -static $(top_builddir)/libextra.la
#noinst_HEADERS = 

CLEANFILES = fuse-pfs.pc *~

#run: all
#	$(top_builddir)/.
#
#test: all
#	@echo "We have no test."

