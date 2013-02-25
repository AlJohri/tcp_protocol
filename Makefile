libminet-dir := src/libminet
app-dir := src/apps
core-dir := src/core
lowlevel-dir := src/lowlevel

include $(libminet-dir)/Makefile.in
include $(app-dir)/Makefile.in
include $(core-dir)/Makefile.in
include $(lowlevel-dir)/Makefile.in

CXX=g++
CC=gcc
AR=ar
RANLAB=ranlib


include-dirs = -I/usr/include/pcap -I$(libminet-dir)
libraries = -lnet -lpcap lib/libminet.a

CXXFLAGS = -g -ggdb -gstabs+ -Wall -std=c++0x -fPIC


build = \
	@if [ -z "$V" ]; then \
		echo '    [$1]	$@'; \
		$2; \
	else \
		echo '$2'; \
		$2; \
	fi



CXX_COMPILE = \
	$(call build,CXX,$(CXX) \
		$(CXXFLAGS) \
		$(include-dirs) \
		-c \
		$< \
		-o $@ \
	)


lib-objs      := $(patsubst %, $(libminet-dir)/%, $(lib-objs) )

vpath %.o $(app-dir)
vpath %.o $(core-dir)
vpath %.o $(lowlevel-dir)

apps          := $(patsubst %.o, %, $(app-objs)) \
		 $(patsubst %.o, %, $(core-objs)) \
		 $(patsubst %.o, %, $(lowlevel-objs))

app-objs      := $(patsubst %, $(app-dir)/%, $(app-objs))
core-objs      := $(patsubst %, $(core-dir)/%, $(core-objs))
lowlevel-objs      := $(patsubst %, $(lowlevel-dir)/%, $(lowlevel-objs))

all-objs := $(lib-objs) $(app-objs) $(core-objs) $(lowlevel-objs)

% :  %.o
	$(call build,INSTALL,$(CXX) $< $(libraries) -o  bin/$@ ) 


%.o: %.cc
	$(CXX_COMPILE)


all: libminet $(app-objs) $(core-objs) $(lowlevel-objs) $(apps)


lib/libminet.a: $(lib-objs)
	$(call build,AR,$(AR) rcs $@ $^)

libminet: lib/libminet.a



clean: 
	rm -f $(lib-objs) $(app-objs) $(core-objs) $(lowlevel-objs)
	rm -f lib/* bin/*

depend:
	$(CXX) $(CXXFLAGS) $(include-dirs)  -MM $(all-objs:.o=.cc) > .dependencies



include .dependencies
