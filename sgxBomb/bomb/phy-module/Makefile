obj-m = phyaddr.o bootmem.h dma-debug.h

M=$(shell pwd)

all:
	make -C /lib/modules/$(shell uname -r)/build/ M=$(M) modules

clean:
	rm -rf *.ko *.mod.* *.o *.cmd *.order .*.cmd *.symvers .tmp_versions *.o.ur-safe

