
# srctree is set to an absolute path in kernel build.
ifeq ($(srctree),)
TOPDIR ?= $(shell pwd)
export TOPDIR
include $(TOPDIR)/config.mk
#else
#include $(srctree)/drivers/staging/skmm-host/config.mk
endif

# srctree = . second call in linux-headers from standalone build.
ifneq ($(TOPDIR),)
include $(TOPDIR)/config.mk
endif

ifeq ("$(ARCH)","powerpc")
P4080_BUILD=y
endif

ifeq ($(CONFIG_FSL_C2X0_HIGH_PERF_MODE),y)
EXTRA_CFLAGS += -DHIGH_PERF
endif

# Kernel Version support included in source code.

KERNEL_DIR ?= /lib/modules/$(shell uname -r)/build
KBUILD_CFLAGS += -I$(src)
VERSION = 1.5

PREFIX ?=

#Specifies the endianness
BE=1
LE=2

ifeq ($(P4080_BUILD),y)
DEVICE_ENDIAN=$(LE)
HOST_ENDIAN=$(BE)
else
DEVICE_ENDIAN=$(BE)
HOST_ENDIAN=$(LE)
endif

# Below code sets the compile time flags
EXTRA_CFLAGS += -DBIG_ENDIAN=$(BE) -DLITTLE_ENDIAN=$(LE) -g3

ifeq ($(DEVICE_ENDIAN),$(BE))
EXTRA_CFLAGS += -DDEVICE_ENDIAN=$(BE)
else
EXTRA_CFLAGS += -DDEVICE_ENDIAN=$(LE)
endif

ifeq ($(P4080_BUILD),y)
EXTRA_CFLAGS += -DHOST_ENDIAN=$(BE)
else
EXTRA_CFLAGS += -DHOST_ENDIAN=$(LE)
endif

ifeq ($(P4080_BUILD),y)
EXTRA_CFLAGS += -DP4080_BUILD
endif

ifeq ($(CONFIG_FSL_C2X0_P4080_EP),y)
EXTRA_CFLAGS += -DP4080_EP
endif

ifeq ($(CONFIG_FSL_C2X0_C293_EP),y)
EXTRA_CFLAGS += -DC293_EP
endif

ifeq ($(CONFIG_FSL_C2X0_DEBUG_PRINT),y)
EXTRA_CFLAGS += -DDEV_PRINT_DBG -DPRINT_DEBUG
endif

ifeq ($(CONFIG_FSL_C2X0_ERROR_PRINT),y)
EXTRA_CFLAGS += -DDEV_PRINT_ERR -DPRINT_ERROR
endif

ifeq ($(CONFIG_FSL_C2X0_INFO_PRINT),y)
EXTRA_CFLAGS += -DPRINT_INFO
endif

EXTRA_CFLAGS += -DDEV_PHYS_ADDR_64BIT -DDEV_VIRT_ADDR_32BIT

ifeq ($(CONFIG_FSL_C2X0_VIRTIO),y)
EXTRA_CFLAGS += -DVIRTIO_C2X0
endif

ifeq ($(CONFIG_FSL_C2X0_HASH_OFFLOAD),y)
EXTRA_CFLAGS += -DHASH_OFFLOAD
endif

ifeq ($(CONFIG_FSL_C2X0_SYMMETRIC_OFFLOAD),y)
EXTRA_CFLAGS += -DSYMMETRIC_OFFLOAD
endif

ifeq ($(CONFIG_FSL_C2X0_RNG_OFFLOAD),y)
EXTRA_CFLAGS += -DRNG_OFFLOAD
endif

ifeq ($(CONFIG_FSL_C2X0_NO_PKC),y)
EXTRA_CFLAGS += -DNO_PKC
endif

ifeq ($(CONFIG_FSL_C2X0_USE_HOST_DMA),y)
EXTRA_CFLAGS += -DUSE_HOST_DMA
endif

EXTRA_CFLAGS += -I$(src)/host_driver -I$(src)/algs -I$(src)/crypto_dev -I$(src)/dcl -I$(src)/test

# Enable/Disable driver.
CONFIG_FSL_C2X0_CRYPTO_DRV ?= m

obj-$(CONFIG_FSL_C2X0_CRYPTO_DRV) = fsl_skmm_crypto_offload_drv.o
obj-$(CONFIG_FSL_C2X0_CRYPTO_DRV) += pci_dma_test.o

fsl_skmm_crypto_offload_drv-objs := host_driver/fsl_c2x0_driver.o
fsl_skmm_crypto_offload_drv-objs += host_driver/fsl_c2x0_crypto_layer.o
fsl_skmm_crypto_offload_drv-objs += host_driver/memmgr.o
fsl_skmm_crypto_offload_drv-objs += host_driver/command.o
fsl_skmm_crypto_offload_drv-objs += host_driver/sysfs.o
ifeq ($(CONFIG_FSL_C2X0_EXTRA_PKC),y)
fsl_skmm_crypto_offload_drv-objs += crypto/pkc.o
endif
ifeq ($(CONFIG_FSL_C2X0_USE_HOST_DMA),y)
fsl_skmm_crypto_offload_drv-objs += host_driver/dma.o
endif
fsl_skmm_crypto_offload_drv-objs += algs/algs.o
fsl_skmm_crypto_offload_drv-objs += algs/abs_req.o
fsl_skmm_crypto_offload_drv-objs += algs/rsa.o
fsl_skmm_crypto_offload_drv-objs += algs/dsa.o
fsl_skmm_crypto_offload_drv-objs += algs/dh.o
fsl_skmm_crypto_offload_drv-objs += algs/desc_cnstr.o
fsl_skmm_crypto_offload_drv-objs += algs/rng_init.o
fsl_skmm_crypto_offload_drv-objs += crypto_dev/algs_reg.o
ifeq ($(CONFIG_FSL_C2X0_HASH_OFFLOAD),y)
fsl_skmm_crypto_offload_drv-objs += algs/hash.o
endif
ifeq ($(CONFIG_FSL_C2X0_SYMMETRIC_OFFLOAD),y)
fsl_skmm_crypto_offload_drv-objs += algs/symmetric.o
endif
ifeq ($(CONFIG_FSL_C2X0_RNG_OFFLOAD),y)
fsl_skmm_crypto_offload_drv-objs += algs/rng.o
endif

# Reverse logic, "n" not supported in kernel config.
ifneq ($(CONFIG_FSL_C2X0_VIRTIO),y)
fsl_skmm_crypto_offload_drv-objs += test/rsa_test.o
fsl_skmm_crypto_offload_drv-objs += test/dsa_test.o
fsl_skmm_crypto_offload_drv-objs += test/ecdsa_test.o
fsl_skmm_crypto_offload_drv-objs += test/ecp_test.o
fsl_skmm_crypto_offload_drv-objs += test/ecpbn_test.o
fsl_skmm_crypto_offload_drv-objs += test/dh_test.o
fsl_skmm_crypto_offload_drv-objs += test/ecdh_test.o
fsl_skmm_crypto_offload_drv-objs += test/ecdh_keygen_test.o
fsl_skmm_crypto_offload_drv-objs += test/test.o
endif

pci_dma_test-objs := pci_dma_test/pci_dma_dev.o
pci_dma_test-objs += pci_dma_test/pci_dma_sys.o
pci_dma_test-objs += pci_dma_test/pci_dma_test.o

.PHONY: build

#================= WARNING ================
# 'SUBDIRS' will be removed after Linux 5.3
# Please use 'M=' or 'KBUILD_EXTMOD' instead
#==========================================

build:
	$(MAKE) -C $(KERNEL_DIR) M=`pwd` modules
	$(CROSS_COMPILE)gcc  -Wall perf/mini_calc/mini_calc.c -o perf/mini_calc/mini_calc -static


modules_install:
	$(MAKE) -C $(KERNEL_DIR) M=`pwd` modules_install
	@install -D skmm_crypto.cfg $(PREFIX)/etc/skmm/skmm_crypto.cfg
	@install -D perf/c29x_skmm_perf_profile.sh $(PREFIX)/usr/bin/c29x_skmm_perf_profile.sh
	@install -D perf/mini_calc/mini_calc $(PREFIX)/usr/bin/mini_calc

clean:
	$(MAKE) -C $(KERNEL_DIR) SUBDIRS=`pwd` clean

VERSIONTAG = refs/tags/skmm-host-$(VERSION)
FILEBASE = skmm-host-$(VERSION)
TMPDIR ?= /tmp
OUTPUT = $(FILEBASE).tar.gz

dist: clean
	@echo Packing
	@rm -f *.tar.gz
	@git archive --format=tar.gz --prefix=$(FILEBASE)/ --output=$(OUTPUT) $(VERSIONTAG)
	@echo Signing $(OUTPUT)
	@gpg --output $(OUTPUT).sig -sb $(OUTPUT)
	@gpg --verify $(OUTPUT).sig $(OUTPUT)
