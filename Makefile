# SPDX-License-Identifier: GPL-2.0
# # Some of the tools (perf) use same make variables
# # as in kernel build.
export srctree=$(CURDIR)
export objtree=$(CURDIR)

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

MAKEFLAGS += --no-print-directory

all: __build
include $(srctree)/scripts/Makefile.include
include $(srctree)/build/Makefile.include
include $(srctree)/scripts/Makefile.arch

INCLUDES = \
-I$(srctree)/lib/perf/include \
-I$(srctree)/lib/traceevent \
-I$(srctree)/lib/ \
-I$(srctree)/include \
-I$(srctree)/include/uapi \
-I$(srctree)/arch/$(SRCARCH)/include \
-I$(srctree)/arch/$(SRCARCH)/include/uapi \
-I$(srctree)/

EXTRA_CFLAGS := -O3 -g

# Append required CFLAGS
override CFLAGS += $(EXTRA_WARNINGS) $(EXTRA_CFLAGS)
override CFLAGS += -Werror -Wall
override CFLAGS += $(INCLUDES)
override CFLAGS += -fvisibility=hidden
ifdef CONFIG_LIBBPF
    override CFLAGS += -D CONFIG_LIBBPF=1
endif

export srctree OUTPUT CFLAGS V EXTRA_CFLAGS

__build clean:
	$(Q)$(MAKE) -f $(srctree)/build/Makefile.bin dir=. $@

