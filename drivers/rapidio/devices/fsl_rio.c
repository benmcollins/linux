// SPDX-License-Identifier: GPL-2.0-or-later
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
 *
 * Copyright 2005 MontaVista Software, Inc.
 * Matt Porter <mporter@kernel.crashing.org>
 */

#include <linux/init.h>
#include <linux/extable.h>
#include <linux/types.h>
#include <linux/dma-mapping.h>
#include <linux/interrupt.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/of_irq.h>
#include <linux/slab.h>
#include <linux/delay.h>

#include <linux/io.h>
#include <linux/uaccess.h>
#include <asm/machdep.h>

#include "fsl_rio.h"

static DEFINE_SPINLOCK(fsl_rio_config_lock);

#define ___fsl_read_rio_config(x, addr, err, op, barrier)	\
	__asm__ __volatile__(				\
		"1:	"op" %1,0(%2)\n"		\
		"	"barrier"\n"			\
		"2:\n"					\
		".section .fixup,\"ax\"\n"		\
		"3:	li %1,-1\n"			\
		"	li %0,%3\n"			\
		"	b 2b\n"				\
		".previous\n"				\
		EX_TABLE(1b, 3b)			\
		: "=r" (err), "=r" (x)			\
		: "b" (addr), "i" (-EFAULT), "0" (err))

#ifdef CONFIG_BOOKE
#define __fsl_read_rio_config(x, addr, err, op)	\
	___fsl_read_rio_config(x, addr, err, op, "mbar")
#else
#define __fsl_read_rio_config(x, addr, err, op)	\
	___fsl_read_rio_config(x, addr, err, op, "eieio")
#endif

/* Exported from traps.c for exception handling */
extern void __iomem *rio_regs_win;

/* Stubs to be replaced by the Message Manager */
static int stub_pwenable(struct rio_mport *mport, int enable)
{
	return -EINVAL;
}

static int stub_dsend(struct rio_mport *mport, int index, u16 destid, u16 data)
{
	return -EINVAL;
}

static int stub_add_outb_message(struct rio_mport *mport, struct rio_dev *rdev,
				 int mbox, void *buffer, size_t len)
{
	return -EINVAL;
}

static int stub_open_outb_mbox(struct rio_mport *mport, void *dev_id, int mbox,
			       int entries)
{
	return -EINVAL;
}

static void stub_close_outb_mbox(struct rio_mport *mport, int mbox)
{
	return;
}

static int stub_open_inb_mbox(struct rio_mport *mport, void *dev_id, int mbox,
			      int entries)
{
	return -EINVAL;
}

static void stub_close_inb_mbox(struct rio_mport *mport, int mbox)
{
	return;
}

static int stub_add_inb_buffer(struct rio_mport *mport, int mbox, void *buf)
{
	return -EINVAL;
}

static void *stub_get_inb_message(struct rio_mport *mport, int mbox)
{
	return NULL;
}

/**
 * fsl_lcread - Generate a MPC85xx local config space read
 * @mport: RapidIO master port info
 * @index: ID of RapdiIO interface
 * @offset: Offset into configuration space
 * @len: Length (in bytes) of the maintenance transaction
 * @data: Value to be read into
 *
 * Generates a MPC85xx local configuration space read. Returns %0 on
 * success or %-EINVAL on failure.
 */
static int fsl_lcread(struct rio_mport *mport, int index, u32 offset, int len,
		      u32 *data)
{
	struct rio_mport_priv *priv = mport->priv;
	pr_debug("fsl_lcread: index %d offset %8.8x\n", index,
		 offset);
	*data = in_be32(priv->regs_win + offset);

	return 0;
}

/**
 * fsl_lcwrite - Generate a MPC85xx local config space write
 * @mport: RapidIO master port info
 * @index: ID of RapdiIO interface
 * @offset: Offset into configuration space
 * @len: Length (in bytes) of the maintenance transaction
 * @data: Value to be written
 *
 * Generates a MPC85xx local configuration space write. Returns %0 on
 * success or %-EINVAL on failure.
 */
static int fsl_lcwrite(struct rio_mport *mport,
				int index, u32 offset, int len, u32 data)
{
	struct rio_mport_priv *priv = mport->priv;
	pr_debug("fsl_lcwrite: index %d offset %8.8x data %8.8x\n",
		 index, offset, data);
	out_be32(priv->regs_win + offset, data);

	return 0;
}

/**
 * fsl_cread - Generate a MPC85xx read maintenance transaction
 * @mport: RapidIO master port info
 * @index: ID of RapdiIO interface
 * @destid: Destination ID of transaction
 * @hopcount: Number of hops to target device
 * @offset: Offset into configuration space
 * @len: Length (in bytes) of the maintenance transaction
 * @val: Location to be read into
 *
 * Generates a MPC85xx read maintenance transaction. Returns %0 on
 * success or %-EINVAL on failure.
 */
static int fsl_cread(struct rio_mport *mport, int index, u16 destid,
		     u8 hopcount, u32 offset, int len, u32 *val)
{
	struct rio_mport_priv *priv = mport->priv;
	unsigned long flags;
	u8 *data;
	u32 rval, err = 0;

	pr_debug("fsl_cread: index %d destid %d hopcount %d offset %8.8x "
		 "len %d\n", index, destid, hopcount, offset, len);

	/* 16MB maintenance window possible */
	/* allow only aligned access to maintenance registers */
	if (offset > (0x1000000 - len) || !IS_ALIGNED(offset, len))
		return -EINVAL;

	spin_lock_irqsave(&fsl_rio_config_lock, flags);

	out_be32(&priv->maint_atmu_regs->rowtar,
		 (destid << 22) | (hopcount << 12) | (offset >> 12));
	out_be32(&priv->maint_atmu_regs->rowtear, (destid >> 10));

	data = (u8 *) priv->maint_win + (offset & (RIO_MAINT_WIN_SIZE - 1));
	switch (len) {
	case 1:
		__fsl_read_rio_config(rval, data, err, "lbz");
		break;
	case 2:
		__fsl_read_rio_config(rval, data, err, "lhz");
		break;
	case 4:
		__fsl_read_rio_config(rval, data, err, "lwz");
		break;
	default:
		spin_unlock_irqrestore(&fsl_rio_config_lock, flags);
		return -EINVAL;
	}

	if (err) {
		pr_debug("RIO: cfg_read error %d for %x:%x:%x\n",
			 err, destid, hopcount, offset);
	}

	spin_unlock_irqrestore(&fsl_rio_config_lock, flags);
	*val = rval;

	return err;
}

/**
 * fsl_cwrite - Generate a MPC85xx write maintenance transaction
 * @mport: RapidIO master port info
 * @index: ID of RapdiIO interface
 * @destid: Destination ID of transaction
 * @hopcount: Number of hops to target device
 * @offset: Offset into configuration space
 * @len: Length (in bytes) of the maintenance transaction
 * @val: Value to be written
 *
 * Generates an MPC85xx write maintenance transaction. Returns %0 on
 * success or %-EINVAL on failure.
 */
static int fsl_cwrite(struct rio_mport *mport, int index, u16 destid,
		      u8 hopcount, u32 offset, int len, u32 val)
{
	struct rio_mport_priv *priv = mport->priv;
	unsigned long flags;
	u8 *data;
	int ret = 0;

	pr_debug("fsl_cwrite: index %d destid %d hopcount %d offset %8.8x len"
		 " %d val %8.8x\n", index, destid, hopcount, offset, len, val);

	/* 16MB maintenance windows possible */
	/* allow only aligned access to maintenance registers */
	if (offset > (0x1000000 - len) || !IS_ALIGNED(offset, len))
		return -EINVAL;

	spin_lock_irqsave(&fsl_rio_config_lock, flags);

	out_be32(&priv->maint_atmu_regs->rowtar,
		 (destid << 22) | (hopcount << 12) | (offset >> 12));
	out_be32(&priv->maint_atmu_regs->rowtear, (destid >> 10));

	data = (u8 *) priv->maint_win + (offset & (RIO_MAINT_WIN_SIZE - 1));
	switch (len) {
	case 1:
		out_8((u8 *) data, val);
		break;
	case 2:
		out_be16((u16 *) data, val);
		break;
	case 4:
		out_be32((u32 *) data, val);
		break;
	default:
		ret = -EINVAL;
	}
	spin_unlock_irqrestore(&fsl_rio_config_lock, flags);

	return ret;
}

static void fsl_rio_inbound_mem_init(struct rio_mport_priv *priv)
{
	int i;

	/* close inbound windows */
	for (i = 0; i < RIO_INB_ATMU_COUNT; i++)
		out_be32(&priv->inb_atmu_regs[i].riwar, 0);
}

static int fsl_map_inb(struct rio_mport *mport, dma_addr_t lstart,
		       u64 rstart, u64 size, u32 flags)
{
	struct rio_mport_priv *priv = mport->priv;
	u32 base_size;
	unsigned int base_size_log;
	u64 win_start, win_end;
	u32 riwar;
	int i;

	if ((size & (size - 1)) != 0 || size > 0x400000000ULL)
		return -EINVAL;

	base_size_log = ilog2(size);
	base_size = 1 << base_size_log;

	/* check if addresses are aligned with the window size */
	if (lstart & (base_size - 1))
		return -EINVAL;
	if (rstart & (base_size - 1))
		return -EINVAL;

	/* check for conflicting ranges */
	for (i = 0; i < RIO_INB_ATMU_COUNT; i++) {
		riwar = in_be32(&priv->inb_atmu_regs[i].riwar);
		if ((riwar & RIWAR_ENABLE) == 0)
			continue;
		win_start = ((u64)(in_be32(&priv->inb_atmu_regs[i].riwbar) & RIWBAR_BADD_MASK))
			<< RIWBAR_BADD_VAL_SHIFT;
		win_end = win_start + ((1 << ((riwar & RIWAR_SIZE_MASK) + 1)) - 1);
		if (rstart < win_end && (rstart + size) > win_start)
			return -EINVAL;
	}

	/* find unused atmu */
	for (i = 0; i < RIO_INB_ATMU_COUNT; i++) {
		riwar = in_be32(&priv->inb_atmu_regs[i].riwar);
		if ((riwar & RIWAR_ENABLE) == 0)
			break;
	}
	if (i >= RIO_INB_ATMU_COUNT)
		return -ENOMEM;

	out_be32(&priv->inb_atmu_regs[i].riwtar, lstart >> RIWTAR_TRAD_VAL_SHIFT);
	out_be32(&priv->inb_atmu_regs[i].riwbar, rstart >> RIWBAR_BADD_VAL_SHIFT);
	out_be32(&priv->inb_atmu_regs[i].riwar, RIWAR_ENABLE | RIWAR_TGINT_LOCAL |
		RIWAR_RDTYP_SNOOP | RIWAR_WRTYP_SNOOP | (base_size_log - 1));

	return 0;
}

static void fsl_unmap_inb(struct rio_mport *mport, dma_addr_t lstart)
{
	u32 win_start_shift, base_start_shift;
	struct rio_mport_priv *priv = mport->priv;
	u32 riwar, riwtar;
	int i;

	/* skip default window */
	base_start_shift = lstart >> RIWTAR_TRAD_VAL_SHIFT;
	for (i = 0; i < RIO_INB_ATMU_COUNT; i++) {
		riwar = in_be32(&priv->inb_atmu_regs[i].riwar);
		if ((riwar & RIWAR_ENABLE) == 0)
			continue;

		riwtar = in_be32(&priv->inb_atmu_regs[i].riwtar);
		win_start_shift = riwtar & RIWTAR_TRAD_MASK;
		if (win_start_shift == base_start_shift) {
			out_be32(&priv->inb_atmu_regs[i].riwar, riwar & ~RIWAR_ENABLE);
			return;
		}
	}
}

static int fsl_query_mport(struct rio_mport *mport,
			   struct rio_mport_attr *attr)
{
	struct rio_mport_priv *priv = mport->priv;
	int id = mport->index;
	u32 rval;

	rval = in_be32(priv->regs_win + 0x100 + RIO_PORT_N_ERR_STS_CSR(id, 1));
	if (rval & 1) {
		attr->link_speed = RIO_LINK_DOWN;
	} else {
		/*
		 * Not sure how to get link speed from QorIQ. It doesn't
		 * support RIO_PORT_N_CTL2_CSR. Min speed is 2.5, so set
		 * that.
		 */
		attr->link_speed = RIO_LINK_250;

		/* Link width is standard. */
		rval = in_be32(priv->regs_win + 0x100 +
				RIO_PORT_N_CTL_CSR(id, 1));
		attr->link_width = (rval >> 27) & 7;
	}

#ifdef CONFIG_RAPIDIO_DMA_ENGINE
	attr->flags = RIO_MPORT_DMA | RIO_MPORT_DMA_SG;
	attr->dma_max_sge = 0;
	attr->dma_max_size = 0x10000000;
	attr->dma_align = 0;
#else
	attr->flags = 0;
#endif
	return 0;
}

static void fsl_mport_release(struct device *dev)
{
	/* Nothing to do here */
}

static struct rio_ops fsl_rio_ops = {
	.lcread			= fsl_lcread,
	.lcwrite		= fsl_lcwrite,
	.cread			= fsl_cread,
	.cwrite			= fsl_cwrite,
	.query_mport		= fsl_query_mport,
	.map_inb		= fsl_map_inb,
	.unmap_inb		= fsl_unmap_inb,

	.dsend			= stub_dsend,
	.pwenable		= stub_pwenable,
	.open_outb_mbox		= stub_open_outb_mbox,
	.open_inb_mbox		= stub_open_inb_mbox,
	.close_outb_mbox	= stub_close_outb_mbox,
	.close_inb_mbox		= stub_close_inb_mbox,
	.add_outb_message	= stub_add_outb_message,
	.add_inb_buffer		= stub_add_inb_buffer,
	.get_inb_message	= stub_get_inb_message,
};

static int fsl_rio_setup_port(struct device *dev, void *data)
{
	struct srio_dev *sriodev = data;
	struct rio_mport *port;
	struct rio_mport_priv *mprv;
	const u32 *idx;
	u32 len, ecsr;
	int id, rc;

	if (!of_device_is_compatible(dev_of_node(dev), "fsl,srio-mport"))
		return 0;

	idx = of_get_property(dev_of_node(dev), "cell-index", &len);
	if (!idx) {
		dev_err(dev, "missing cell-index property\n");
		return -EINVAL;
	}
	id = *idx - 1;

	port = &sriodev->ports[id];
	mprv = &sriodev->ports_priv[id];

	rc = rio_mport_initialize(port);
	if (rc)
		return -EINVAL;

	port->index = id;

	rc = of_range_to_resource(dev_of_node(dev), 0, &port->iores);
	if (rc < 0)
		return rc;

	mprv->window = devm_ioremap_resource(sriodev->dev, &port->iores);
	if (IS_ERR(mprv->window))
		return PTR_ERR(mprv->window);

	dev_set_drvdata(dev, port);

	sprintf(port->name, "fsl mport %d", id);
	mprv->sriodev = sriodev;
	port->dev.parent = dev;
	port->dev.release = fsl_mport_release;

	/* Copy ops since MMU might override some */
	memcpy(&mprv->saved_ops, &fsl_rio_ops, sizeof(fsl_rio_ops));
	port->ops = &mprv->saved_ops;

	port->phys_efptr = 0x100;
	port->phys_rmap = 1;
	mprv->regs_win = sriodev->regs;

	ecsr = in_be32(mprv->regs_win + 0x100 + RIO_PORT_N_ERR_STS_CSR(id, 1));

	/* Checking the port training status */
	if (ecsr & 1) {
		dev_err(dev, "port not ready, restarting...\n");

		/* Disable ports */
		out_be32(mprv->regs_win + 0x100 + RIO_PORT_N_CTL_CSR(id, 1), 0);
		/* Set 1x lane */
		setbits32(mprv->regs_win + 0x100 +
			  RIO_PORT_N_CTL_CSR(id, 1), 0x02000000);
		/* Enable ports */
		setbits32(mprv->regs_win + 0x100 +
			  RIO_PORT_N_CTL_CSR(id, 1), 0x00600000);

		msleep(100);

		ecsr = in_be32(mprv->regs_win + 0x100 +
			       RIO_PORT_N_CTL_CSR(id, 1));
		if (ecsr & 1) {
			dev_err(dev, "port restart failed\n");
			return -EINVAL;
		}

		dev_info(dev, "port restart succeded\n");
	}

	port->sys_size = (in_be32((mprv->regs_win + RIO_PEF_CAR)) &
			  RIO_PEF_CTLS) >> 4;

	if (port->host_deviceid >= 0)
		out_be32(mprv->regs_win + RIO_GCCSR, RIO_PORT_GEN_HOST |
			 RIO_PORT_GEN_MASTER | RIO_PORT_GEN_DISCOVERED);
	else
		out_be32(mprv->regs_win + RIO_GCCSR, RIO_PORT_GEN_MASTER);

	mprv->atmu_regs = (struct rio_atmu_regs *)(mprv->regs_win
		+ ((id == 0) ? RIO_ATMU_REGS_PORT1_OFFSET :
		RIO_ATMU_REGS_PORT2_OFFSET));

	mprv->maint_atmu_regs = mprv->atmu_regs + 1;
	mprv->inb_atmu_regs = (struct rio_inb_atmu_regs __iomem *)
		(mprv->regs_win + ((id == 0) ? RIO_INB_ATMU_REGS_PORT1_OFFSET :
		RIO_INB_ATMU_REGS_PORT2_OFFSET));

	/* Set to receive packets with any dest ID */
	out_be32((mprv->regs_win + RIO_ISR_AACR + id*0x80),
		 RIO_ISR_AACR_AA);

	/* Configure maintenance transaction window */
	out_be32(&mprv->maint_atmu_regs->rowbar, port->iores.start >> 12);
	out_be32(&mprv->maint_atmu_regs->rowar,
		 0x80077000 | (ilog2(RIO_MAINT_WIN_SIZE) - 1));

	mprv->maint_win = devm_ioremap(sriodev->dev, port->iores.start,
				       RIO_MAINT_WIN_SIZE);

	port->priv = mprv;

	if (sriodev->mmu_port_init)
		sriodev->mmu_port_init(port);

	fsl_rio_inbound_mem_init(mprv);

	if (rio_register_mport(port)) {
		port->priv = NULL;
		return -EINVAL;
	}

	sriodev->active_ports++;

	return 0;
}

/**
 * fsl_rio_setup - Setup Freescale PowerPC RapidIO interface
 * @dev: platform_device pointer
 *
 * Initializes MPC85xx RapidIO hardware interface, configures
 * master port with system-specific info, and registers the
 * master port with the RapidIO subsystem.
 */
static int fsl_rio_setup(struct platform_device *dev)
{
	struct srio_dev *sriodev;
	int rc;

	sriodev = devm_kzalloc(&dev->dev, sizeof(*sriodev), GFP_KERNEL);
	if (!sriodev)
		return -ENOMEM;

	sriodev->dev = &dev->dev;
	platform_set_drvdata(dev, sriodev);

	sriodev->regs = devm_platform_get_and_ioremap_resource(dev, 0,
							       &sriodev->res);
	if (IS_ERR(sriodev->regs))
		return PTR_ERR(sriodev->regs);

	/* Register with the Message Manager */
	rc = fsl_rio_mmu_init(sriodev);
	if (rc && rc != -ENODEV) {
		dev_err(&dev->dev, "Error configuring messaging unit\n");
		return rc;
	}

	dev_info(&dev->dev, "Freescale SRIO: %s\n", sriodev->mmu_name ?:
		 "No messaging unit\n");

	/* Configure the mports */
	device_for_each_child(&dev->dev, sriodev, fsl_rio_setup_port);

	if (!sriodev->active_ports)
		return -ENOLINK;

	/* Let the exception handler know we're here */
	rio_regs_win = sriodev->regs;

	return 0;
}

/* The probe function for RapidIO peer-to-peer network.
 */
int fsl_rio_probe(struct platform_device *dev)
{
	return fsl_rio_setup(dev);
};

void fsl_rio_remove(struct platform_device *dev)
{
	struct srio_dev *sriodev = platform_get_drvdata(dev);
	int i;

	for (i = MAX_PORT_NUM - 1; i >= 0; i--) {
		if (!sriodev->ports[i].priv)
			continue;
		rio_unregister_mport(&sriodev->ports[i]);
	}

	if (sriodev->mmu_exit)
		sriodev->mmu_exit(sriodev);

	rio_regs_win = NULL;
}

int __init fsl_rio_init(void)
{
	return platform_driver_register(&fsl_rio_driver);
}

void __exit fsl_rio_exit(void)
{
	platform_driver_unregister(&fsl_rio_driver);
}

module_init(fsl_rio_init);
module_exit(fsl_rio_exit);

MODULE_AUTHOR("Freescale Semiconductor, Inc.");
MODULE_LICENSE("GPL");
