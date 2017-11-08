# Makefile for tm-flush

CONFIG_FLUSHTM ?= m

KERNELBASE = /lib/modules/$(shell uname -r)
KERNELDIR ?= $(KERNELBASE)/build
PWD:=$(shell /bin/pwd)

obj-$(CONFIG_FLUSHTM) += flushtm.o

flushtm-objs := flushtm_base.o setway.o

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

install:	all
	INSTALL_MOD_DIR=l4tm make -C $(KERNELDIR) M=$(PWD) modules_install
	depmod -a


