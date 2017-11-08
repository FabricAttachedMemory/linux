# Makefile for zbridge

CONFIG_ZBRIDGE ?= m

KERNELBASE = /lib/modules/$(shell uname -r)
KERNELDIR ?= $(KERNELBASE)/build
PWD:=$(shell /bin/pwd)

obj-$(CONFIG_ZBRIDGE) += zbridge.o

zbridge-objs := zbridge_base.o zbridge_ioctl.o zbridge_sysfs.o zbridge_notify.o zbridge_desbk.o

architecture := $(shell dpkg-architecture -qDEB_BUILD_ARCH_CPU 2>/dev/null)

all:
ifeq "$(architecture)" "amd64"
	make $(CFLAGS) -C $(KERNELDIR) M=$(PWD) ARCH=x86 modules
else
	make $(CFLAGS) -C $(KERNELDIR) M=$(PWD) modules
endif

clean:
ifeq "$(architecture)" "amd64"
	make -C $(KERNELDIR) M=$(PWD) ARCH=x86 clean
else
	make -C $(KERNELDIR) M=$(PWD) clean
endif

install:
	INSTALL_MOD_DIR=l4tm make -C $(KERNELDIR) M=$(PWD) modules_install
	depmod -a
