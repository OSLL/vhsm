KDIR := /lib/modules/$(shell uname -r)/build

obj-m += vhsm_transport.o

default:
	make -C $(KDIR) SUBDIRS=$(PWD) modules
