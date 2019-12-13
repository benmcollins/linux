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

#ifndef __DEVICE_H__
#define __DEVICE_H__

#define NUM_OF_RESP_RINGS	1

#if defined P4080_EP
#define FSL_CRYPTO_PCI_DEVICE_ID        0X0400
#define FSL_CRYPTO_PCI_VENDOR_ID        0X1957

/* 32byte aligned address gives best performance */
#define DEV_DMA_ALIGNMENT_BYTES				32

#elif defined C293_EP
#define FSL_CRYPTO_PCI_VENDOR_ID        	0X1957
#define FSL_CRYPTO_C290_PCI_DEVICE_ID       0X0800
#define FSL_CRYPTO_C280_PCI_DEVICE_ID       0X0801
#define FSL_CRYPTO_C270_PCI_DEVICE_ID       0X0803
#define FSL_CRYPTO_C291_PCI_DEVICE_ID       0X0808
#define FSL_CRYPTO_C281_PCI_DEVICE_ID       0X0809
#define FSL_CRYPTO_C271_PCI_DEVICE_ID       0X080B
#define FSL_CRYPTO_TBD1_PCI_DEVICE_ID       0X0804
#define FSL_CRYPTO_TBD2_PCI_DEVICE_ID       0X0805
#define FSL_CRYPTO_TBD3_PCI_DEVICE_ID       0X0807
#define FSL_CRYPTO_TBD4_PCI_DEVICE_ID       0X080C
#define FSL_CRYPTO_TBD5_PCI_DEVICE_ID       0X080D
#define FSL_CRYPTO_TBD6_PCI_DEVICE_ID       0X080F

/* 32byte aligned address gives best performance */
#define DEV_DMA_ALIGNMENT_BYTES				32
#endif

#define ALIGN_LEN_TO_DMA(x)		\
	((x+(DEV_DMA_ALIGNMENT_BYTES-1))&~(DEV_DMA_ALIGNMENT_BYTES-1))
#define DEV_MEM_SIZE            (512*1024)
#define FSL_FIRMWARE_SIZE       (0)

#define FIRMWARE_IMAGE_START_OFFSET (DEV_MEM_SIZE - FSL_FIRMWARE_SIZE)

#if defined P4O80_EP || C293_EP
/* Enabling 36bit DMA support - This helps in setting the DMA mask */
#define SEC_ENGINE_DMA_36BIT
#endif

#ifdef P4080_BUILD
/* Assuming that P4080 linux has multiple MSI support */
/*#define MULTIPLE_MSI_SUPPORT*/
#endif

/*** Register Offsets ***/

#if defined P4080_EP || C293_EP

/* PCIE1 controller defines */
#define PCIE1_OB_REGS_BASE_ADDRESS  0X200000

#define PCIE1_OB_WINDOW1_TAR    (PCIE1_OB_REGS_BASE_ADDRESS + 0x0C20)
#define PCIE1_OB_WINDOW1_ATTR   (PCIE1_OB_REGS_BASE_ADDRESS + 0x0C30)
#define PCIE1_OB_WINDOW1_BADDR  (PCIE1_OB_REGS_BASE_ADDRESS + 0x0C28)

#define PCIE1_OB_WINDOW2_TAR    (PCIE1_OB_REGS_BASE_ADDRESS + 0x0C40)
#define PCIE1_OB_WINDOW2_ATTR   (PCIE1_OB_REGS_BASE_ADDRESS + 0x0C50)
#define PCIE1_OB_WINDOW2_BADDR  (PCIE1_OB_REGS_BASE_ADDRESS + 0x0C48)

#define PCIE1_OB_WINDOW1_ATTR_REG_EN        0x80000000
#define PCIE1_OB_WINDOW1_ATTR_REG_RTT       0X00040000	/* Memory read */
#define PCIE1_OB_WINDOW1_ATTR_REG_WTT       0X00044000	/* Memory write */
/* 1G size :- 1d=29 :- Size = 2^(29+1) */
#define PCIE1_OB_WINDOW1_ATTR_REG_SIZE      0x0000001d

#define PCIE1_OB_WINDOW1_ATTR_REG_VALUE     \
	(PCIE1_OB_WINDOW1_ATTR_REG_EN | PCIE1_OB_WINDOW1_ATTR_REG_RTT | \
	PCIE1_OB_WINDOW1_ATTR_REG_WTT | PCIE1_OB_WINDOW1_ATTR_REG_SIZE)

#define PCIE1_OB_WINDOW2_ATTR_REG_RTT       0X00040000	/* Memory read */
#define PCIE1_OB_WINDOW2_ATTR_REG_WTT       0X00044000	/* Memory write */
/* 1M size :- 1d=19 :- Size = 2^(19+1) */
#define PCIE1_OB_WINDOW2_ATTR_REG_SIZE      0x00000013
#define PCIE1_OB_WINDOW2_ATTR_REG_VALUE     \
	(PCIE1_OB_WINDOW2_ATTR_REG_EN | PCIE1_OB_WINDOW2_ATTR_REG_RTT | \
	PCIE1_OB_WINDOW2_ATTR_REG_WTT | PCIE1_OB_WINDOW2_ATTR_REG_SIZE)

#define PCIE1_CONTROLLER_ADDR_IN_DEV        0X00c00000

/* Boot Release Register defines */
#ifdef P4080_EP
#define BRR_OFFSET                          0x000e00e4
#define BRR_RELEASE_CORE0                   0x01
#elif C293_EP
#define BRR_OFFSET                          0x1010
#define BRR_RELEASE_CORE0                   0x01000000
#endif
#define BRR_VALUE                           (0x0 | BRR_RELEASE_CORE0)

#define DEVICE_CONFIG_AND_PIN_CNTRL_BLK_OFFSET      0X0E0000
#define DEVICE_RESET_CONTROL_REGISTER_OFFSET        \
	(DEVICE_CONFIG_AND_PIN_CNTRL_BLK_OFFSET | 0x00B0)
#define DEVICE_RESET_REG_VALUE                      0X02

#endif

#ifdef EP_VIRT_ADDR_32BIT
#define DEV_VIRT_ADDR_32BIT
#endif

#ifdef EP_PHYS_ADDR_64BIT
#define DEV_PHYS_ADDR_64BIT
#endif

#ifdef DEV_PHYS_ADDR_64BIT
#define DEV_WORD_SIE    32
#else
#define DEV_WORD_SIZE   64
#endif

#define DEVICE_CACHE_LINE_SIZE                  64
#define DEVICE_MAX_OUTBOUND_RANGE_ACCESS        0X400000000ull	/* 16G */

#endif
