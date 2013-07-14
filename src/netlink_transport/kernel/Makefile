KDIR := /lib/modules/$(shell uname -r)/build

obj-m += vhsm_transport.o

default:
	make -C $(KDIR) SUBDIRS=$(PWD) modules

clean:
	rm -f *.o *~ *.out *.ko *.order *.symvers *.mod.c
	rm -rf .tmp_versions
