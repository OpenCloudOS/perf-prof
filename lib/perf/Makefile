# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
# Most of this file is copied from lib/bpf/Makefile

LIBPERF_VERSION = 0
LIBPERF_PATCHLEVEL = 0
LIBPERF_EXTRAVERSION = 1

MAKEFLAGS += --no-print-directory

ifeq ($(srctree),)
srctree := $(patsubst %/,%,$(dir $(CURDIR)))
srctree := $(patsubst %/,%,$(dir $(srctree)))
#$(info Determined 'srctree' to be $(srctree))
endif

INSTALL = install

# Use DESTDIR for installing into a different root directory.
# This is useful for building a package. The program will be
# installed in this directory as if it was the root directory.
# Then the build tool can move it later.
DESTDIR ?=
DESTDIR_SQ = '$(subst ','\'',$(DESTDIR))'

include $(srctree)/scripts/Makefile.include
include $(srctree)/scripts/Makefile.arch

ifeq ($(LP64), 1)
  libdir_relative = lib64
else
  libdir_relative = lib
endif

prefix ?=
libdir = $(prefix)/$(libdir_relative)

# Shell quotes
libdir_SQ = $(subst ','\'',$(libdir))
libdir_relative_SQ = $(subst ','\'',$(libdir_relative))

ifeq ("$(origin V)", "command line")
  VERBOSE = $(V)
endif
ifndef VERBOSE
  VERBOSE = 0
endif

ifeq ($(VERBOSE),1)
  Q =
else
  Q = @
endif

TEST_ARGS := $(if $(V),-v)

# Set compile option CFLAGS
ifdef EXTRA_CFLAGS
  CFLAGS := $(EXTRA_CFLAGS)
else
  CFLAGS := -g -Wall
endif

INCLUDES = \
-I$(srctree)/lib/perf/include \
-I$(srctree)/lib/ \
-I$(srctree)/include \
-I$(srctree)/arch/$(SRCARCH)/include/ \
-I$(srctree)/arch/$(SRCARCH)/include/uapi \
-I$(srctree)/include/uapi

# Append required CFLAGS
override CFLAGS += $(EXTRA_WARNINGS)
override CFLAGS += -Werror -Wall
override CFLAGS += -fPIC
override CFLAGS += $(INCLUDES)
override CFLAGS += -fvisibility=hidden

all:

export srctree OUTPUT CC LD CFLAGS V
export DESTDIR DESTDIR_SQ

include $(srctree)/build/Makefile.include

VERSION_SCRIPT := libperf.map

PATCHLEVEL    = $(LIBPERF_PATCHLEVEL)
EXTRAVERSION  = $(LIBPERF_EXTRAVERSION)
VERSION       = $(LIBPERF_VERSION).$(LIBPERF_PATCHLEVEL).$(LIBPERF_EXTRAVERSION)

LIBPERF_SO := $(OUTPUT)libperf.so.$(VERSION)
LIBPERF_A  := $(OUTPUT)libperf.a
LIBPERF_IN := $(OUTPUT)libperf-in.o
LIBPERF_PC := $(OUTPUT)libperf.pc

LIBPERF_ALL := $(LIBPERF_A) $(OUTPUT)libperf.so*

LIB_DIR := $(srctree)/lib/api/

ifneq ($(OUTPUT),)
ifneq ($(subdir),)
  API_PATH=$(OUTPUT)/../lib/api/
else
  API_PATH=$(OUTPUT)
endif
else
  API_PATH=$(LIB_DIR)
endif


$(LIBPERF_IN): FORCE
	$(Q)$(MAKE) $(build)=libperf

$(LIBPERF_A): $(LIBPERF_IN)
	$(QUIET_AR)$(RM) $@ && $(AR) rcs $@ $(LIBPERF_IN)

$(LIBPERF_SO): $(LIBPERF_IN)
	$(QUIET_LINK)$(CC) --shared -Wl,-soname,libperf.so \
                                    -Wl,--version-script=$(VERSION_SCRIPT) $^ -o $@
	@ln -sf $(@F) $(OUTPUT)libperf.so
	@ln -sf $(@F) $(OUTPUT)libperf.so.$(LIBPERF_VERSION)


libs: $(LIBPERF_A) $(LIBPERF_SO) $(LIBPERF_PC)

all: fixdep
	$(Q)$(MAKE) libs

clean:
	$(call QUIET_CLEAN, libperf) $(RM) $(LIBPERF_A) \
                *.o *~ *.a *.so *.so.$(VERSION) *.so.$(LIBPERF_VERSION) .*.d .*.cmd tests/*.o LIBPERF-CFLAGS $(LIBPERF_PC) \
                $(TESTS_STATIC) $(TESTS_SHARED)

TESTS_IN = tests-in.o

TESTS_STATIC = $(OUTPUT)tests-static
TESTS_SHARED = $(OUTPUT)tests-shared

$(TESTS_IN): FORCE
	$(Q)$(MAKE) $(build)=tests

$(TESTS_STATIC): $(TESTS_IN) $(LIBPERF_A)
	$(QUIET_LINK)$(CC) -o $@ $^

$(TESTS_SHARED): $(TESTS_IN)
	$(QUIET_LINK)$(CC) -o $@ -L$(if $(OUTPUT),$(OUTPUT),.) $^ -lperf

make-tests: libs $(TESTS_SHARED) $(TESTS_STATIC)

tests: make-tests
	@echo "running static:"
	@./$(TESTS_STATIC) $(TEST_ARGS)
	@echo "running dynamic:"
	@LD_LIBRARY_PATH=. ./$(TESTS_SHARED) $(TEST_ARGS)

$(LIBPERF_PC):
	$(QUIET_GEN)sed -e "s|@PREFIX@|$(prefix)|" \
		-e "s|@LIBDIR@|$(libdir_SQ)|" \
		-e "s|@VERSION@|$(VERSION)|" \
		< libperf.pc.template > $@

define do_install_mkdir
	if [ ! -d '$(DESTDIR_SQ)$1' ]; then             \
		$(INSTALL) -d -m 755 '$(DESTDIR_SQ)$1'; \
	fi
endef

define do_install
	if [ ! -d '$(DESTDIR_SQ)$2' ]; then             \
		$(INSTALL) -d -m 755 '$(DESTDIR_SQ)$2'; \
	fi;                                             \
	$(INSTALL) $1 $(if $3,-m $3,) '$(DESTDIR_SQ)$2'
endef

install_lib: libs
	$(call QUIET_INSTALL, $(LIBPERF_ALL)) \
		$(call do_install_mkdir,$(libdir_SQ)); \
		cp -fpR $(LIBPERF_ALL) $(DESTDIR)$(libdir_SQ)

install_headers:
	$(call QUIET_INSTALL, headers) \
		$(call do_install,include/perf/core.h,$(prefix)/include/perf,644); \
		$(call do_install,include/perf/cpumap.h,$(prefix)/include/perf,644); \
		$(call do_install,include/perf/threadmap.h,$(prefix)/include/perf,644); \
		$(call do_install,include/perf/evlist.h,$(prefix)/include/perf,644); \
		$(call do_install,include/perf/evsel.h,$(prefix)/include/perf,644); \
		$(call do_install,include/perf/event.h,$(prefix)/include/perf,644); \
		$(call do_install,include/perf/mmap.h,$(prefix)/include/perf,644);

install_pkgconfig: $(LIBPERF_PC)
	$(call QUIET_INSTALL, $(LIBPERF_PC)) \
		$(call do_install,$(LIBPERF_PC),$(libdir_SQ)/pkgconfig,644)

install_doc:
	$(Q)$(MAKE) -C Documentation install-man install-html install-examples

install: install_lib install_headers install_pkgconfig install_doc

FORCE:

.PHONY: all install clean tests FORCE
