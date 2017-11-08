# Makefile for fam-atomic-driver

CONFIG_FAM_ATOMIC ?= m

KERNELBASE = /lib/modules/$(shell uname -r)
KERNELDIR ?= $(KERNELBASE)/build
PWD:=$(shell /bin/pwd)

DESC_SYMBOLS+=$(PWD)/../tm-fuse-4.7.2/Module.symvers
DESC_SYMBOLS+=/root/l4tm/tm-fuse-4.7.2/Module.symvers
DESC_SYMBOLS+=$(PWD)/../tm-fuse-4.5.2/Module.symvers
DESC_SYMBOLS+=/root/l4tm/tm-fuse-4.5.2/Module.symvers
DESC_SYMBOLS+=$(PWD)/../tm-fuse-4.3.3/Module.symvers
DESC_SYMBOLS+=/root/l4tm/tm-fuse-4.3.3/Module.symvers

obj-$(CONFIG_FAM_ATOMIC) += fam-atomic-driver.o


all:
	make $(CFLAGS) -C $(KERNELDIR) M=$(PWD) KBUILD_EXTRA_SYMBOLS="${DESC_SYMBOLS}" modules

clean:
	make -C $(KERNELDIR) M=$(PWD) clean

install:	all
	INSTALL_MOD_DIR=l4tm make -C $(KERNELDIR) M=$(PWD) modules_install
	depmod -a
