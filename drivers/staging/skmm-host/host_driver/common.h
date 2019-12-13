/* Copyright 2013 Freescale Semiconductor, Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *
 *
 * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 * Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 *
 * Neither the name of Freescale Semiconductor nor the
 * names of its contributors may be used to endorse or promote products
 * derived from this software without specific prior written permission.
 *
 *
 * ALTERNATIVELY, this software may be distributed under the terms of the
 * GNU General Public License ("GPL") as published by the Free Software
 * Foundation, either version 2 of that License or (at your option) any
 * later version.
 *
 * THIS SOFTWARE IS PROVIDED BY Freescale Semiconductor ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL Freescale Semiconductor BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE)ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef __COMMON_H__
#define __COMMON_H__

#include <linux/version.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/workqueue.h>
#include <linux/kdev_t.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/slab.h>
#include <linux/ioctl.h>
#include <linux/device.h>	/* class_creatre */
#include <asm/page.h>
#include <asm/pgtable.h>
#include <linux/highmem.h>
#include <asm/pgalloc.h>
#include <linux/sched.h>
#include <linux/list.h>		/* Kernel Linked List */
#include <linux/percpu.h>
#include <linux/semaphore.h>
#include <linux/spinlock.h>
#include <linux/interrupt.h>
#include <linux/miscdevice.h>
#include <linux/file.h>
/*#include <asm/io.h>*/
#include <linux/io.h>
#include <linux/pci.h>
#include <linux/smp.h>
#include <linux/dmaengine.h>

#include <linux/completion.h>
#include <linux/sched.h>
#include<linux/kthread.h>
#include <linux/cpumask.h>

#ifndef __WORDSIZE
#if defined(__x86_64__)
#define __WORDSIZE 64
#else
#define __WORDSIZE 32
#endif
#endif

#define LINKED_LIST_HEAD(x)     struct list_head x

/* Endian conversion macro's */

#define IO_BE_WRITE64(val, addr)        { \
	iowrite32(__cpu_to_be32((uint32_t)(val>>32)), (void *)addr); \
	iowrite32(__cpu_to_be32((uint32_t)val), \
		((uint8_t *)addr + sizeof(uint32_t)));\
	};

#define IO_BE_WRITE64_PTR(val, addr)        { \
	iowrite32(__cpu_to_be32((uint32_t)(*val>>32)), (void *)addr); \
	iowrite32(__cpu_to_be32((uint32_t)val), \
		((uint8_t *)addr + sizeof(uint32_t)));\
	};

#define IO_BE_READ64(val, addr)         { \
	val = (__cpu_to_be32(ioread32((void *)addr))); \
	val = (val << 32); \
	val = val | \
		(__cpu_to_be32(ioread32((uint8_t *)addr + sizeof(uint32_t)))); \
	};

#define IO_LE_READ64(val, addr)         { \
	val = (__cpu_to_le32(ioread32((void *)addr))); \
	val = (val << 32); \
	val = val | \
		(__cpu_to_le32(ioread32((uint8_t *)addr + sizeof(uint32_t)))); \
	};

#define IO_BE_WRITE32(val, addr)    iowrite32(__cpu_to_be32(val), (void *)addr)
#define IO_BE_READ32(addr)          __cpu_to_be32(ioread32(addr))

#define IO_BE_WRITE16(val, addr)    iowrite16(__cpu_to_be16(val), (void *)addr)
#define IO_BE_READ16(addr)          __cpu_to_be16(ioread16(addr))

#define IO_BE_WRITE8(val, addr)     iowrite8(val, (void *)addr)
#define IO_BE_READ8(addr)			ioread8((void *)addr)

#define IO_LE_WRITE64(val, addr) { \
	iowrite32(__cpu_to_le32((uint32_t)(val>>32)), (void *)addr); \
	iowrite32(__cpu_to_le32((uint32_t)val), \
		((uint8_t *)addr + sizeof(uint32_t)));\
	};

#define IO_LE_WRITE32(val, addr)	\
	iowrite32(__cpu_to_le32(val), (void *)addr)
#define IO_LE_READ32(addr)	\
	__cpu_to_le32(ioread32(addr))

#define IO_LE_WRITE16(val, addr)	\
	iowrite16(__cpu_to_le16(val), (void *)addr)
#define IO_LE_READ16(addr)	\
	__cpu_to_le16(ioread16(addr))

#define IO_LE_WRITE8(val, addr)	\
	iowrite8(val, (void *)addr)
#define IO_LE_READ8(addr)	\
	ioread8((void *)addr)

#if (DEVICE_ENDIAN != HOST_ENDIAN)
#if (DEVICE_ENDIAN == BIG_ENDIAN)

/* Macros to read-write from BARs */
#define FSL_DEVICE_WRITE32_BAR0_REG(base, offset, value)      \
	IO_BE_WRITE32(value, (base+offset))
#define FSL_DEVICE_READ32_BAR0_REG(base, offset, value)       \
	IO_BE_READ32(base+offset)

#define FSL_DEVICE_WRITE32_BAR1_REG(base, offset, value)      \
	IO_BE_WRITE32(value, (base+offset))
#define FSL_DEVICE_READ32_BAR1_REG(base, offset, value)       \
	IO_BE_READ32(base+offset)

#define FSL_DEVICE_WRITE16_BAR1_REG(base, offset, value)      \
	IO_BE_WRITE16(value, (base+offset))
#define FSL_DEVICE_READ16_BAR1_REG(base, offset, value)       \
	IO_BE_READ16(base+offset)

#define FSL_DEVICE_WRITE8_BAR1_REG(base, offset, value)       \
	IO_BE_WRITE8(value, (base+offset))
#define FSL_DEVICE_READ8_BAR1_REG(base, offset, value)        \
	IO_BE_READ8(base+offset)

#define FSL_DEVICE_WRITE8_BAR1_REG_DIRECT(addr, value)		\
	IO_BE_WRITE8(value, addr)
#define FSL_DEVICE_WRITE16_BAR1_REG_DIRECT(addr, value)		\
	IO_BE_WRITE16(value, addr)
#define FSL_DEVICE_WRITE32_BAR1_REG_DIRECT(addr, value)		\
	IO_BE_WRITE32(value, addr)
#define FSL_DEVICE_WRITE64_BAR1_REG_DIRECT(addr, value)		\
	IO_BE_WRITE64(value, addr)

/* Macros used during value assignment to the device memory */
#define ASSIGN8(l, r)        IO_BE_WRITE8(r, &l)
#define ASSIGN16(l, r)       IO_BE_WRITE16(r, &l)
#define ASSIGN32(l, r)       IO_BE_WRITE32(r, &l)
#define ASSIGN64(l, r)       IO_BE_WRITE64(r, &l)

#define ASSIGN64_PTR(l, r)   IO_BE_WRITE64(r, l)
#define ASSIGN32_PTR(l, r)   IO_BE_WRITE32(r, l)
/*#define ASSIGN64_PTR(l, r)   IO_BE_WRITE32(r, l)*/
#define ASSIGN8_PTR(l, r)    IO_BE_WRITE8(r,  l)

#elif (DEVICE_ENDIAN == LITTLE_ENDIAN)
/* Macros to read-write from BARs */
#define FSL_DEVICE_WRITE32_BAR0_REG(base, offset, value)      \
	IO_LE_WRITE32(value, (base+offset))
#define FSL_DEVICE_READ32_BAR0_REG(base, offset, value)       \
	IO_LE_READ32(base+offset)

#define FSL_DEVICE_WRITE32_BAR1_REG(base, offset, value)      \
	IO_LE_WRITE32(value, (base+offset))
#define FSL_DEVICE_READ32_BAR1_REG(base, offset, value)       \
	IO_LE_READ32(base+offset)

#define FSL_DEVICE_WRITE16_BAR1_REG(base, offset, value)      \
	IO_LE_WRITE16(value, (base+offset))
#define FSL_DEVICE_READ16_BAR1_REG(base, offset, value)       \
	IO_LE_READ16(base+offset)

#define FSL_DEVICE_WRITE8_BAR1_REG(base, offset, value)       \
	IO_LE_WRITE8(value, (base+offset))
#define FSL_DEVICE_READ8_BAR1_REG(base, offset, value)        \
	IO_LE_READ8(base+offset)

#define FSL_DEVICE_WRITE8_BAR1_REG_DIRECT(addr, value)      \
	IO_LE_WRITE8(value, addr)
#define FSL_DEVICE_WRITE16_BAR1_REG_DIRECT(addr, value)     \
	IO_LE_WRITE16(value, addr)
#define FSL_DEVICE_WRITE32_BAR1_REG_DIRECT(addr, value)     \
	IO_LE_WRITE32(value, addr)
#define FSL_DEVICE_WRITE64_BAR1_REG_DIRECT(addr, value)     \
	IO_LE_WRITE64(value, addr)

/* Macros used during value assignment to the device memory */
#define ASSIGN8(l, r)        IO_LE_WRITE8(r, &l)
#define ASSIGN16(l, r)       IO_LE_WRITE16(r, &l)
#define ASSIGN32(l, r)       IO_LE_WRITE32(r, &l)
#define ASSIGN64(l, r)       IO_LE_WRITE64(r, &l)

/*#define ASSIGN64_PTR(l,r)       IO_LE_WRITE64_PTR(r, l)*/
#define ASSIGN32_PTR(l, r)   IO_LE_WRITE32(r, l)
#define ASSIGN8_PTR(l, r)    IO_LE_WRITE8(r,  l)

#endif

#endif

/* Application ring properties bit masks and shift */
#define APP_RING_PROP_ORDER_MASK    0x01
#define APP_RING_PROP_ORDER_SHIFT   0

#define APP_RING_PROP_AFFINE_MASK   0X0E
#define APP_RING_PROP_AFFINE_SHIFT  1

#define APP_RING_PROP_PRIO_MASK     0XF0
#define APP_RING_PROP_PRIO_SHIFT    4

#define PHYS_ADDR_L_32_BIT_MASK       0xFFFFFFFF
/* Since the device has 36bit bus --
 * Only two bits from higher address is sufficient */
#define PHYS_ADDR_H_32_BIT_MASK       0x300000000ull

#define HOST_64_BIT_ADDR_SIZE         sizeof(u64)

/* Typedefs */
#ifdef DEV_VIRT_ADDR_32BIT
typedef uint32_t dev_v_addr_t;
#else
typedef uint64_t dev_v_addr_t;
#endif

#ifdef DEV_PHYS_ADDR_32BIT
typedef uint32_t dev_p_addr_t;
typedef uint32_t dev_dma_addr_t;
#else
typedef uint64_t dev_p_addr_t;
typedef uint64_t dev_dma_addr_t;
#endif

/* Identifier for the ring pairs */
typedef enum ring_id {
	CRYPTO_COMMAND_RING_ID,
	CRYPTO_APP_RING_ID,
	/*This ID is not used in driver but the same
	 * enum will be used by firmware*/
	CRYPTO_SEC_RING_ID
} ring_id_t;

/*******************************************************************************
Description :	Contains the configuration read from the file.
Fields      :	dev_no    : Number of the device to which this config applies.
		ring_id   : Identifies the ring Command/App
		flags     : Useful only for App to identify its properties
			0-4 : Priority level 32- priority levels
			5-7 : SEC engine affinity
			8   : Ordered/Un-ordered
		list      : To maintain list of config structures per device
*******************************************************************************/
typedef struct crypto_dev_config {
	uint32_t dev_no;
/*  int8_t      *name;  We may not need this field  */
#define FIRMWARE_FILE_DEFAULT_PATH  "/etc/skmm/u-boot-sd.bin"
#define FIRMWARE_FILE_PATH_LEN  100
	uint8_t fw_file_path[FIRMWARE_FILE_PATH_LEN];

	uint8_t *firmware;

	uint8_t num_of_rings;

/* Safe MAX number of ring pairs -
 * Only required for some static data structures. */
#define FSL_CRYPTO_MAX_RING_PAIRS   6

	struct ring_info {
		ring_id_t ring_id;
		uint32_t depth;
		uint8_t flags;
		uint32_t msi_addr_l;
		uint32_t msi_addr_h;
		uint16_t msi_data;
	} ring[FSL_CRYPTO_MAX_RING_PAIRS];

	struct list_head list;
} crypto_dev_config_t;

/* Different types of memory between driver and ep */
typedef enum crypto_dev_mem_type {
	MEM_TYPE_CONFIG,
	MEM_TYPE_SRAM,
	MEM_TYPE_DRIVER,
	MEM_TYPE_MSI,
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4, 19, 0))
	MEM_TYPE_MAX
#else
	MEM_TYPE_MAX_SKMM
#endif
} crypto_dev_mem_type_t;

/*******************************************************************************
Description :	Contains the information of all the mem associated with this dev
Fields      :	type          : Type of the memory ~= BAR's
		host_v_addr   : Virtual address of mem in host
		host_p_addr   : Physical address of mem in host
		dev_v_addr    : Virtual/TLB address in the dev.
				Required in case of desc where in certain
				pointers need to be built with exact
				device addresses.
		dev_p_addr    : May not need. Holding it for now.
*******************************************************************************/
typedef struct crypto_dev_mem_info {
	crypto_dev_mem_type_t type;

	uint32_t len;

	void *host_v_addr;
	phys_addr_t host_p_addr;

	dev_v_addr_t dev_v_addr;
	dev_p_addr_t dev_p_addr;

	dma_addr_t host_dma_addr;
} crypto_dev_mem_info_t;

#ifndef VAR
extern uint32_t wt_cpu_mask;
#else
int32_t wt_cpu_mask = -1;
#endif

#endif
