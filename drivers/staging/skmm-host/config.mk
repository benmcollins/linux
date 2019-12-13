CONFIG_FSL_C2X0_CRYPTO_DRV=m

#Device configurations

#Specifies type of EP
CONFIG_FSL_C2X0_P4080_EP=n
CONFIG_FSL_C2X0_C293_EP=y

#Controls the debug print level
CONFIG_FSL_C2X0_DEBUG_PRINT=y
#Controls error printing.
CONFIG_FSL_C2X0_ERROR_PRINT=y
#Controls info printing.
CONFIG_FSL_C2X0_INFO_PRINT=y

# n values cannot be used in kernel config.
# ifneq y will be used instead in the Makefile.

#Enable HASH/SYMMETRIC offloading
CONFIG_FSL_C2X0_HASH_OFFLOAD=y
CONFIG_FSL_C2X0_SYMMETRIC_OFFLOAD=y

#Enable RNG offloading
CONFIG_FSL_C2X0_RNG_OFFLOAD=y

#Specifies whether host DMA support to be enabled /disabled in the driver
CONFIG_FSL_C2X0_USE_HOST_DMA=n

#Specifies whether driver/firmware is running high performance mode
CONFIG_FSL_C2X0_HIGH_PERF_MODE=y

#Specify building host-driver to support Virtualization
CONFIG_FSL_C2X0_VIRTIO=y

#Specify whether build cryptoapi pkc-related into host driver on x86
CONFIG_FSL_C2X0_EXTRA_PKC=y

# Specify no pkc in kernel or module.
CONFIG_FSL_C2X0_NO_PKC=n
