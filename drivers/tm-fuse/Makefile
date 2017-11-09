#
# Makefile for the TMFS filesystem, adapted for use on The Machine.
# For only --shadow_xxx and FAME "direct" mode, use as-is "make [targets]".
# For FAME with descriptors and TM(AS), "make zbridge=1 flushtm=1 [targets]".
# CONFIG_TMFS is used to determine if the build is happening as part of a
# full kernel build from source, do not set this variable on the command line.

DRIVERNAME = tmfs
KERNELDIR ?= /lib/modules/$(shell uname -r)/build
V=0

# Create a variable in "make" that's not wiped via sudo for target install
PWD = $(shell /bin/pwd)

ifdef CONFIG_TMFS
  # Compile as part of linux kernel
  ifdef CONFIG_TM_MFT
    $(info Compiling tmfs with zbridge and flushtm support)
    EXTRA_CFLAGS=-DUSE_ZBRIDGE_APIS
    EXTRA_CFLAGS+=-DUSE_FLUSHTM_APIS
    DESC_SYMBOLS=
  else
    $(info Compiling tmfs without zbridge and flushtm support)
    EXTRA_CFLAGS=
    DESC_SYMBOLS=
  endif
else
  # Compile outside of the linux kernel source (default)
  ifneq ($(zbridge), 1)
    # Compile without zbridge support (default)
    $(info Compiling without zbridge interaction)
    EXTRA_CFLAGS=
    DESC_SYMBOLS=
  else
    # Non-default mode, make sure affected files always rebuilt
    $(info Compiling with zbridge APIs which may modprobe zbridge)
    EXTRA_CFLAGS=-DUSE_ZBRIDGE_APIS
    DESC_SYMBOLS+=$(PWD)/../zbridge_driver/Module.symvers
  endif

  ifneq ($(flushtm), 1)
    # Compile without flushtm support (default)
    $(info Compiling without flushtm interaction)
  else
    # Non-default mode, make sure affected files always rebuilt
    $(info Compiling with flushtm APIs which may modprobe flushtm)
    EXTRA_CFLAGS+=-DUSE_FLUSHTM_APIS
    DESC_SYMBOLS+=$(PWD)/../tm-flush/Module.symvers
  endif
endif

CONFIG_TMFS ?= m

obj-$(CONFIG_TMFS) += tmcd.o $(DRIVERNAME).o

$(DRIVERNAME)-objs := dev.o dir.o file.o inode.o control.o xattr.o acl.o lfs.o lfs_book2lza.o file_lfs.o

all:
	@# inode.c and lfs.c examine USE_ZBRIDGE_APIS and USE_FLUSHTM_APIS.
	@# ALWAYS rebuild inode.c as it has the dmesg announcment; lfs.c is
	@# pedantic. zbridge=1 and flushtm=1 creates EXTRA_CFLAGS which also
	@# seems todo a full rebuild but I don't fully grok that mechanism.
	/bin/touch inode.c

	make -C $(KERNELDIR) M=$(PWD) \
		KBUILD_EXTRA_SYMBOLS="${DESC_SYMBOLS}" \
		V=$V modules

clean:
	make -C $(KERNELDIR) M=$(PWD) clean
	rm -f *.png *.expand

install:
	INSTALL_MOD_DIR=l4tm make -C $(KERNELDIR) M=$(PWD) \
		KBUILD_EXTRA_SYMBOLS="${DESC_SYMBOLS}" \
		V=$V modules_install
	@depmod -A	# modinfo needs this to work correctly

###########################################################################
# Needs dot(1) and "egypt" from Rocky Craig

# INCEXT:=--include-external
OMITS:=--omit printk
CLUDES:=$(INCEXT) $(OMITS)

callgraph:      clean
	@[ "`which egypt`" ] && true || (echo "No pyramids" >&2 && false)
	make -C $(KERNELDIR) \
	CFLAGS_MODULE="-DCALLGRAPH -dx -fdump-rtl-expand" M=$(PWD) modules
	egypt --color --title $(DRIVERNAME) \
		$(CLUDES) *.expand 2>$(DRIVERNAME).egypt | \
		dot -Tpng -o $(DRIVERNAME).png
