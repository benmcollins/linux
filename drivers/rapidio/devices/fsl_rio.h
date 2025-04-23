/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Freescale MPC85xx/MPC86xx RapidIO support
 *
 * Copyright (C) 2025 Ben Collins <bcollins@maclara-llc.com>
 *
 * Copyright 2009 Sysgo AG
 * Thomas Moll <thomas.moll@sysgo.com>
 * - fixed maintenance access routines, check for aligned access
 *
 * Copyright 2009 Integrated Device Technology, Inc.
 * Alex Bounine <alexandre.bounine@idt.com>
 * - Added Port-Write message handling
 * - Added Machine Check exception handling
 *
 * Copyright (C) 2007, 2008, 2010, 2011 Freescale Semiconductor, Inc.
 * Zhang Wei <wei.zhang@freescale.com>
 * Lian Minghuan-B31939 <Minghuan.Lian@freescale.com>
 * Liu Gang <Gang.Liu@freescale.com>
 *
 * Copyright 2005 MontaVista Software, Inc.
 * Matt Porter <mporter@kernel.crashing.org>
 */

#ifndef __FSL_RIO_H
#define __FSL_RIO_H

#include <linux/rio.h>
#include <linux/rio_drv.h>
#include <linux/rio_regs.h>
#include <linux/platform_device.h>

#define RIO_MAINT_WIN_SIZE	0x400000
#define RIO_LTLEDCSR		0x0608

#define RIO_ATMU_REGS_PORT1_OFFSET	0x10c00
#define RIO_ATMU_REGS_PORT2_OFFSET	0x10e00
#define RIO_S_DBELL_REGS_OFFSET	0x13400
#define RIO_S_PW_REGS_OFFSET	0x134e0
#define RIO_ATMU_REGS_DBELL_OFFSET	0x10C40
#define RIO_INB_ATMU_REGS_PORT1_OFFSET 0x10d60
#define RIO_INB_ATMU_REGS_PORT2_OFFSET 0x10f60

#define MAX_PORT_NUM		4
#define RIO_INB_ATMU_COUNT	4

#define RIO_PORT1_EDCSR         0x0640
#define RIO_PORT2_EDCSR         0x0680
#define RIO_PORT1_IECSR         0x10130
#define RIO_PORT2_IECSR         0x101B0

#define RIO_GCCSR               0x13c
#define RIO_ESCSR               0x158
#define ESCSR_CLEAR             0x07120204
#define RIO_PORT2_ESCSR         0x178
#define RIO_CCSR                0x15c
#define RIO_LTLEDCSR_IER        0x80000000
#define RIO_LTLEDCSR_PRT        0x01000000
#define IECSR_CLEAR             0x80000000
#define RIO_ISR_AACR            0x10120
#define RIO_ISR_AACR_AA         0x1     /* Accept All ID */

#define RIWTAR_TRAD_VAL_SHIFT   12
#define RIWTAR_TRAD_MASK        0x00FFFFFF
#define RIWBAR_BADD_VAL_SHIFT   12
#define RIWBAR_BADD_MASK        0x003FFFFF
#define RIWAR_ENABLE            0x80000000
#define RIWAR_TGINT_LOCAL       0x00F00000
#define RIWAR_RDTYP_NO_SNOOP    0x00040000
#define RIWAR_RDTYP_SNOOP       0x00050000
#define RIWAR_WRTYP_NO_SNOOP    0x00004000
#define RIWAR_WRTYP_SNOOP       0x00005000
#define RIWAR_WRTYP_ALLOC       0x00006000
#define RIWAR_SIZE_MASK         0x0000003F

struct rio_atmu_regs {
	 u32 rowtar;
	 u32 rowtear;
	 u32 rowbar;
	 u32 pad1;
	 u32 rowar;
	 u32 pad2[3];
};

struct rio_inb_atmu_regs {
	u32 riwtar;
	u32 pad1;
	u32 riwbar;
	u32 pad2;
	u32 riwar;
	u32 pad3[3];
};

struct srio_dev;

struct rio_mport_priv {
	struct srio_dev *sriodev;
	void __iomem *regs_win;
	void __iomem *window;
	struct rio_atmu_regs __iomem *atmu_regs;
	struct rio_atmu_regs __iomem *maint_atmu_regs;
	struct rio_inb_atmu_regs __iomem *inb_atmu_regs;
	void __iomem *maint_win;
	void *mmu_handle;
	struct rio_ops saved_ops;
};

struct srio_dev {
	struct resource *res;
	int active_ports;
	void __iomem *regs;
	struct device *dev;
	struct rio_mport ports[MAX_PORT_NUM];
	struct rio_mport_priv ports_priv[MAX_PORT_NUM];
	void *mmu_handle;
	const char *mmu_name;
	void (*mmu_exit)(struct srio_dev *);
	int (*mmu_port_init)(struct rio_mport *);
};

/* Exported by the MMU provider for fsl_rio */
extern int fsl_rio_mmu_init(struct srio_dev *sriodev);
extern struct platform_driver fsl_rio_driver;

/* Exported by fsl_rio for the MMUs */
extern int __init fsl_rio_init(void);
extern void __exit fsl_rio_exit(void);
extern int fsl_rio_probe(struct platform_device *dev);
extern void fsl_rio_remove(struct platform_device *dev);

#endif
