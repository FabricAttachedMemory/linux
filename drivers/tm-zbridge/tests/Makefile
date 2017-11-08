
all: ioctl desbk tabledump zap hsr

ioctl:
	gcc -o ioctl_test ioctl_test.c

desbk:
	gcc -o desbk desbk.c

tabledump:
	gcc -o tabledump tabledump.c

zap:
	gcc -o zap zap.c

hsr:
	 cc -D_GNU_SOURCE -Wall -lpmem -o hsr hsr.c
clean:
	rm -f ioctl_test desbk tabledump zap hsr
