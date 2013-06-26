KDIR := /lib/modules/$(shell uname -r)/build

obj-m += main.o

default:
	make -C $(KDIR) SUBDIRS=$(PWD) modules
