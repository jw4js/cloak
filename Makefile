obj-m := cloak.o
cloak-objs += module.o patch.o mm.o

all:
	make -C ../virtio_kernel/lib/modules/4.12.2/build M=$(PWD) modules

clean:
	make -C ../virtio_kernel/lib/modules/4.12.2/build M=$(PWD) clean

running:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules