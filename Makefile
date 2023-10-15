
KERNELDIR ?= /lib/modules/$(shell uname -r)/build
MODULE_NAME :=aes_cbc_module

obj-m  := aes_cbc_module.o
aes_cbc_module-objs := aes_cbc_chrdev.o

build: kernel_modules

kernel_modules:
	make -C $(KERNELDIR) M=$(PWD) modules

clean:
	make -C $(KERNELDIR) M=$(PWD) clean
