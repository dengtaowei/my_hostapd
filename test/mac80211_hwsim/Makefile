
include /boot/config-$(shell uname -r)

obj-$(CONFIG_MAC80211_HWSIM)	+= mac80211_hwsim.o

obj-$(CONFIG_VIRT_WIFI)	+= virt_wifi.o

KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

# add cur dir for include dir
# ccflags-y += -DDEBUG -I$(src)

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

install:
	sudo insmod mac80211_hwsim.ko

uninstall:
	sudo rmmod mac80211_hwsim
