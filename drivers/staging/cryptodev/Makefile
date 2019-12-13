# Kernel Version support included in source code.

KERNEL_DIR ?= /lib/modules/$(shell uname -r)/build
KBUILD_CFLAGS += -I$(src)
VERSION = 1.5
PREFIX ?=

cryptodev-objs = ioctl.o main.o cryptlib.o authenc.o zc.o util.o

obj-$(CONFIG_CRYPTODEV) += cryptodev.o

# Enables async mode.
ifeq ($(CONFIG_CRYPTODEV_ENABLE_ASYNC),y)
	ccflags-y += -DENABLE_ASYNC
endif

#Enables debug mode.
ifeq ($(CONFIG_CRYPTODEV_DEBUG),y)
	ccflags-y += -DDEBUG
endif

#Crypto algorithm kernel driver only.
ifeq ($(CONFIG_CRYPTODEV_CRYPTO_ALG_KERN_DRIVER_ONLY),y)
	ccflags-y += -DCRYPTO_ALG_KERN_DRIVER_ONLY
endif

#Enable 32 bit user space compatibility.
ifeq ($(CONFIG_CRYPTODEV_CONFIG_COMPAT),y)
	ccflags-y += -DCONFIG_COMPAT
endif

KERNEL_MAKE_OPTS := -C $(KERNEL_DIR) SUBDIRS=`pwd`
ifneq ($(ARCH),)
KERNEL_MAKE_OPTS += ARCH=$(ARCH)
endif
ifneq ($(CROSS_COMPILE),)
KERNEL_MAKE_OPTS += CROSS_COMPILE=$(CROSS_COMPILE)
endif

build: version.h
	$(MAKE) $(KERNEL_MAKE_OPTS) modules

version.h: Makefile
	@echo "#define VERSION \"$(VERSION)\"" > version.h

install: modules_install

modules_install:
	$(MAKE) -C $(KERNEL_DIR) SUBDIRS=`pwd` modules_install
	@echo "Installing cryptodev.h in $(PREFIX)/usr/include/crypto ..."
	@install -D crypto/cryptodev.h $(PREFIX)/usr/include/crypto/cryptodev.h

clean:
	$(MAKE) -C $(KERNEL_DIR) SUBDIRS=`pwd` clean
	rm -f $(hostprogs) *~ version.h
	CFLAGS=KERNEL_DIR=$(KERNEL_DIR) $(MAKE) -C tests clean

check:
	CFLAGS=KERNEL_DIR=$(KERNEL_DIR) $(MAKE) -C tests check

CPOPTS =
ifneq ($(SHOW_TYPES),)
CPOPTS += --show-types
endif
ifneq ($(IGNORE_TYPES),)
CPOPTS += --ignore $(IGNORE_TYPES)
endif

checkpatch:
	$(KERNEL_DIR)/scripts/checkpatch.pl $(CPOPTS) --file *.c *.h

FILEBASE = cryptodev-$(VERSION)
TMPDIR ?= /tmp
OUTPUT = $(FILEBASE).tar.gz

.PHONY: dist

dist: clean
	@echo Packing
	@rm -f *.tar.gz
	@mkdir $(TMPDIR)/$(FILEBASE)
	@cp -ar crypto extras tests examples Makefile *.c *.h README NEWS \
		INSTALL AUTHORS COPYING $(TMPDIR)/$(FILEBASE)
	@rm -rf $(TMPDIR)/$(FILEBASE)/.git* $(TMPDIR)/$(FILEBASE)/releases $(TMPDIR)/$(FILEBASE)/scripts
	@tar -C /tmp -czf ./$(OUTPUT) $(FILEBASE)
	@rm -rf $(TMPDIR)/$(FILEBASE)
	@echo Signing $(OUTPUT)
	@gpg --output $(OUTPUT).sig -sb $(OUTPUT)
	@gpg --verify $(OUTPUT).sig $(OUTPUT)
	@mv $(OUTPUT) $(OUTPUT).sig releases/
