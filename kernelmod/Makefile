MODULE_NAME	= myfw

SRC := tools.c module/netlink_module.c module/log_module.c module/rule_module.c module/conn_module.c module/nat_module.c module/app_module.c hooks/hook_main.c hooks/hook_nat.c mod_main.c

KDIR := /lib/modules/$(shell uname -r)/build

EXTRA_CFLAGS := -I$(src)/include -I$(src)/hooks -I$(src)/module

$(MODULE_NAME)-objs = $(SRC:.c=.o)
obj-m := $(MODULE_NAME).o
PWD := $(shell pwd)

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

install:
	insmod $(PWD)/$(MODULE_NAME).ko
	$(MAKE) clean

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) modules clean
	rm -rf modules.order
	rm -f *.symvers
