// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Freescale MPC85xx/MPC86xx RapidIO support
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
#include <linux/platform_device.h>
#include <linux/delay.h>
#include <linux/slab.h>

#include <linux/io.h>
#include <linux/uaccess.h>
#include <asm/machdep.h>

#include "fsl_rio.h"

#undef DEBUG_PW	/* Port-Write debugging */

#define RIO_PORT1_EDCSR		0x0640
#define RIO_PORT2_EDCSR		0x0680
#define RIO_PORT1_IECSR		0x10130
#define RIO_PORT2_IECSR		0x101B0

#define RIO_GCCSR		0x13c
#define RIO_ESCSR		0x158
#define ESCSR_CLEAR		0x07120204
#define RIO_PORT2_ESCSR		0x178
#define RIO_CCSR		0x15c
#define RIO_LTLEDCSR_IER	0x80000000
#define RIO_LTLEDCSR_PRT	0x01000000
#define IECSR_CLEAR		0x80000000
#define RIO_ISR_AACR		0x10120
#define RIO_ISR_AACR_AA		0x1	/* Accept All ID */

#define RIWTAR_TRAD_VAL_SHIFT	12
#define RIWTAR_TRAD_MASK	0x00FFFFFF
#define RIWBAR_BADD_VAL_SHIFT	12
#define RIWBAR_BADD_MASK	0x003FFFFF
#define RIWAR_ENABLE		0x80000000
#define RIWAR_TGINT_LOCAL	0x00F00000
#define RIWAR_RDTYP_NO_SNOOP	0x00040000
#define RIWAR_RDTYP_SNOOP	0x00050000
#define RIWAR_WRTYP_NO_SNOOP	0x00004000
#define RIWAR_WRTYP_SNOOP	0x00005000
#define RIWAR_WRTYP_ALLOC	0x00006000
#define RIWAR_SIZE_MASK		0x0000003F

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

struct srio_dev {
	struct resource *res;
	int active_ports;
	void __iomem *regs;
	void __iomem *rmu_regs_win;
	struct device *dev;
	struct fsl_rio_dbell dbell;
	struct fsl_rio_pw pw;
	resource_size_t rio_law_start;
	struct rio_mport ports[MAX_PORT_NUM];
	struct rio_priv ports_priv[MAX_PORT_NUM];
	struct device_node *rmu_np[MAX_PORT_NUM];
};

/**
 * fsl_local_config_read - Generate a MPC85xx local config space read
 * @mport: RapidIO master port info
 * @index: ID of RapdiIO interface
 * @offset: Offset into configuration space
 * @len: Length (in bytes) of the maintenance transaction
 * @data: Value to be read into
 *
 * Generates a MPC85xx local configuration space read. Returns %0 on
 * success or %-EINVAL on failure.
 */
static int fsl_local_config_read(struct rio_mport *mport,
				int index, u32 offset, int len, u32 *data)
{
	struct rio_priv *priv = mport->priv;
	pr_debug("fsl_local_config_read: index %d offset %8.8x\n", index,
		 offset);
	*data = in_be32(priv->regs_win + offset);

	return 0;
}

/**
 * fsl_local_config_write - Generate a MPC85xx local config space write
 * @mport: RapidIO master port info
 * @index: ID of RapdiIO interface
 * @offset: Offset into configuration space
 * @len: Length (in bytes) of the maintenance transaction
 * @data: Value to be written
 *
 * Generates a MPC85xx local configuration space write. Returns %0 on
 * success or %-EINVAL on failure.
 */
static int fsl_local_config_write(struct rio_mport *mport,
				int index, u32 offset, int len, u32 data)
{
	struct rio_priv *priv = mport->priv;
	pr_debug
		("fsl_local_config_write: index %d offset %8.8x data %8.8x\n",
		index, offset, data);
	out_be32(priv->regs_win + offset, data);

	return 0;
}

/**
 * fsl_rio_config_read - Generate a MPC85xx read maintenance transaction
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
static int
fsl_rio_config_read(struct rio_mport *mport, int index, u16 destid,
			u8 hopcount, u32 offset, int len, u32 *val)
{
	struct rio_priv *priv = mport->priv;
	unsigned long flags;
	u8 *data;
	u32 rval, err = 0;

	pr_debug
		("fsl_rio_config_read:"
		" index %d destid %d hopcount %d offset %8.8x len %d\n",
		index, destid, hopcount, offset, len);

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
 * fsl_rio_config_write - Generate a MPC85xx write maintenance transaction
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
static int
fsl_rio_config_write(struct rio_mport *mport, int index, u16 destid,
			u8 hopcount, u32 offset, int len, u32 val)
{
	struct rio_priv *priv = mport->priv;
	unsigned long flags;
	u8 *data;
	int ret = 0;

	pr_debug
		("fsl_rio_config_write:"
		" index %d destid %d hopcount %d offset %8.8x len %d val %8.8x\n",
		index, destid, hopcount, offset, len, val);

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

static void fsl_rio_inbound_mem_init(struct rio_priv *priv)
{
	int i;

	/* close inbound windows */
	for (i = 0; i < RIO_INB_ATMU_COUNT; i++)
		out_be32(&priv->inb_atmu_regs[i].riwar, 0);
}

static int fsl_map_inb_mem(struct rio_mport *mport, dma_addr_t lstart,
			   u64 rstart, u64 size, u32 flags)
{
	struct rio_priv *priv = mport->priv;
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

static void fsl_unmap_inb_mem(struct rio_mport *mport, dma_addr_t lstart)
{
	u32 win_start_shift, base_start_shift;
	struct rio_priv *priv = mport->priv;
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

void fsl_rio_port_error_handler(struct fsl_rio_pw *pw, int offset)
{
	/*XXX: Error recovery is not implemented, we just clear errors */
	out_be32((u32 *)(pw->rio_regs_win + RIO_LTLEDCSR), 0);

	if (offset == 0) {
		out_be32((u32 *)(pw->rio_regs_win + RIO_PORT1_EDCSR), 0);
		out_be32((u32 *)(pw->rio_regs_win + RIO_PORT1_IECSR), IECSR_CLEAR);
		out_be32((u32 *)(pw->rio_regs_win + RIO_ESCSR), ESCSR_CLEAR);
	} else {
		out_be32((u32 *)(pw->rio_regs_win + RIO_PORT2_EDCSR), 0);
		out_be32((u32 *)(pw->rio_regs_win + RIO_PORT2_IECSR), IECSR_CLEAR);
		out_be32((u32 *)(pw->rio_regs_win + RIO_PORT2_ESCSR), ESCSR_CLEAR);
	}
}

static int fsl_query_mport(struct rio_mport *mport,
			   struct rio_mport_attr *attr)
{
	struct rio_priv *priv = mport->priv;
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
	.lcread			= fsl_local_config_read,
	.lcwrite		= fsl_local_config_write,
	.cread			= fsl_rio_config_read,
	.cwrite			= fsl_rio_config_write,
	.dsend			= fsl_rio_doorbell_send,
	.pwenable		= fsl_rio_pw_enable,
	.open_outb_mbox		= fsl_open_outb_mbox,
	.open_inb_mbox		= fsl_open_inb_mbox,
	.close_outb_mbox	= fsl_close_outb_mbox,
	.close_inb_mbox		= fsl_close_inb_mbox,
	.add_outb_message	= fsl_add_outb_message,
	.add_inb_buffer		= fsl_add_inb_buffer,
	.get_inb_message	= fsl_get_inb_message,
	.query_mport		= fsl_query_mport,
	.map_inb		= fsl_map_inb_mem,
	.unmap_inb		= fsl_unmap_inb_mem,
};

static int fsl_rio_setup_port(struct device *dev, void *data)
{
	struct srio_dev *sriodev = data;
	struct rio_mport *port;
	struct rio_priv *priv;
	const u32 *idx;
	u32 ccsr, len, ecsr;
	int id, rc;

	idx = of_get_property(dev_of_node(dev), "cell-index", &len);
	if (!idx) {
		dev_err(dev, "missing cell-index property\n");
		return -EINVAL;
	}
	id = *idx - 1;

	port = &sriodev->ports[id];
	priv = &sriodev->ports_priv[id];

	rc = rio_mport_initialize(port);
	if (rc)
		return -EINVAL;

	port->index = id;

	rc = of_range_to_resource(dev_of_node(dev), 0, &port->iores);
	if (rc < 0)
		return rc;

	priv->window = devm_ioremap_resource(sriodev->dev, &port->iores);
	if (IS_ERR(priv->window))
		return PTR_ERR(priv->window);

	dev_set_drvdata(dev, port);

	sprintf(port->name, "fsl mport %d", id);
	priv->dev = sriodev->dev;
	port->dev.parent = dev;
	port->dev.release = fsl_mport_release;

	port->ops = &fsl_rio_ops;
	port->phys_efptr = 0x100;
	port->phys_rmap = 1;
	priv->regs_win = sriodev->regs;
	priv->pw_regs = sriodev->pw.pw_regs;
	priv->dbell = &sriodev->dbell;

	ccsr = in_be32(priv->regs_win + 0x100 + RIO_PORT_N_CTL_CSR(id, 1));
	ecsr = in_be32(priv->regs_win + 0x100 + RIO_PORT_N_ERR_STS_CSR(id, 1));

	/* Checking the port training status */
	if (ecsr & 1) {
		dev_err(dev, "port not ready, restarting...\n");

		/* Disable ports */
		out_be32(priv->regs_win + RIO_PORT_N_CTL_CSR(0x100, id), 0);
		/* Set 1x lane */
		setbits32(priv->regs_win +
			  RIO_PORT_N_CTL_CSR(0x100, id), 0x02000000);
		/* Enable ports */
		setbits32(priv->regs_win +
			  RIO_PORT_N_CTL_CSR(0x100, id), 0x00600000);

		msleep(100);

		ecsr = in_be32(priv->regs_win + 0x100 +
			       RIO_PORT_N_CTL_CSR(id, 1));
		if (ecsr & 1) {
			dev_err(dev, "port restart failed\n");
			return -EINVAL;
		}

		dev_info(dev, "port restart succeded\n");
	}

	port->sys_size = (in_be32((priv->regs_win + RIO_PEF_CAR)) &
			  RIO_PEF_CTLS) >> 4;

	if (port->host_deviceid >= 0)
		out_be32(priv->regs_win + RIO_GCCSR, RIO_PORT_GEN_HOST |
			 RIO_PORT_GEN_MASTER | RIO_PORT_GEN_DISCOVERED);
	else
		out_be32(priv->regs_win + RIO_GCCSR, RIO_PORT_GEN_MASTER);

	priv->atmu_regs = (struct rio_atmu_regs *)(priv->regs_win
		+ ((id == 0) ? RIO_ATMU_REGS_PORT1_OFFSET :
		RIO_ATMU_REGS_PORT2_OFFSET));

	priv->maint_atmu_regs = priv->atmu_regs + 1;
	priv->inb_atmu_regs = (struct rio_inb_atmu_regs __iomem *)
		(priv->regs_win + ((id == 0) ? RIO_INB_ATMU_REGS_PORT1_OFFSET :
		RIO_INB_ATMU_REGS_PORT2_OFFSET));

	/* Set to receive packets with any dest ID */
	out_be32((priv->regs_win + RIO_ISR_AACR + id*0x80),
		 RIO_ISR_AACR_AA);

	/* Configure maintenance transaction window */
	out_be32(&priv->maint_atmu_regs->rowbar, port->iores.start >> 12);
	out_be32(&priv->maint_atmu_regs->rowar,
		 0x80077000 | (ilog2(RIO_MAINT_WIN_SIZE) - 1));

	priv->maint_win = devm_ioremap(sriodev->dev, port->iores.start,
				       RIO_MAINT_WIN_SIZE);

	fsl_rio_setup_rmu(port, sriodev->rmu_np[id]);
	fsl_rio_inbound_mem_init(priv);

	sriodev->dbell.mport[id] = port;
	sriodev->pw.mport[id] = port;

	port->priv = priv;

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
	struct device_node *np;
	u64 range_start;
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

	/* Setup RMU */
	np = of_parse_phandle(dev->dev.of_node, "fsl,srio-rmu-handle", 0);
	if (!np) {
		dev_err(&dev->dev, "No valid fsl,srio-rmu-handle property\n");
		return -ENOENT;
	}
	sriodev->rmu_regs_win = devm_of_iomap(&dev->dev, np, 0, NULL);
	of_node_put(np);
	if (IS_ERR(sriodev->rmu_regs_win))
		return PTR_ERR(sriodev->rmu_regs_win);

	rc = 0;
	for_each_compatible_node(np, NULL, "fsl,srio-msg-unit")
		sriodev->rmu_np[rc++] = np;

	/* Setup doorbell */
	np = of_find_compatible_node(NULL, NULL, "fsl,srio-dbell-unit");
	if (!np) {
		dev_err(&dev->dev, "No fsl,srio-dbell-unit node\n");
                return -ENODEV;
	}
        sriodev->dbell.dev = &dev->dev;
        sriodev->dbell.bellirq = irq_of_parse_and_map(np, 1);

	if (of_property_read_reg(np, 0, &range_start, NULL)) {
		dev_err(&dev->dev, "%pOF: unable to find 'reg' property\n",
			np);
		return -ENOMEM;
	}
        sriodev->dbell.dbell_regs =
		(struct rio_dbell_regs *)(sriodev->rmu_regs_win + range_start);

	of_node_put(np);

	/* Setup port write */
	np = of_find_compatible_node(NULL, NULL, "fsl,srio-port-write-unit");
	if (!np) {
		dev_err(&dev->dev, "No fsl,srio-port-write-unit node\n");
		return -ENODEV;
	}

	sriodev->pw.dev = &dev->dev;
	sriodev->pw.pwirq = irq_of_parse_and_map(np, 0);
	sriodev->pw.dbell_regs = sriodev->dbell.dbell_regs;

	if (of_property_read_reg(np, 0, &range_start, NULL)) {
		dev_err(&dev->dev, "%pOF: unable to find 'reg' property\n",
			np);
		return -ENOMEM;
	}
	sriodev->pw.pw_regs =
		(struct rio_pw_regs *)(sriodev->rmu_regs_win + range_start);
	sriodev->pw.rio_regs_win = sriodev->regs;
	sriodev->pw.rmu_regs_win = sriodev->rmu_regs_win;

	dev_info(&dev->dev, "Freescale Serial RapidIO initialized\n");

	/* Configure the mports */
	device_for_each_child(&dev->dev, sriodev, fsl_rio_setup_port);

	if (!sriodev->active_ports)
		return -ENOLINK;

	fsl_rio_doorbell_init(&sriodev->dbell);
	fsl_rio_port_write_init(&sriodev->pw);

	/* Let the exception handler know we're here */
	rio_regs_win = sriodev->regs;

	return 0;
}

/* The probe function for RapidIO peer-to-peer network.
 */
static int fsl_of_rio_rpn_probe(struct platform_device *dev)
{
	return fsl_rio_setup(dev);
};

static void fsl_of_rio_rpn_remove(struct platform_device *dev)
{
	struct srio_dev *sriodev = platform_get_drvdata(dev);
	int i;

	for (i = MAX_PORT_NUM - 1; i >= 0; i--) {
		if (!sriodev->ports[i].priv)
			continue;
		rio_unregister_mport(&sriodev->ports[i]);
	}

	kfifo_free(&sriodev->pw.pw_fifo);

	rio_regs_win = NULL;
}

static const struct of_device_id fsl_of_rio_rpn_ids[] = {
	{
		.compatible = "fsl,srio",
	},
	{},
};

static struct platform_driver fsl_of_rio_rpn_driver = {
	.driver = {
		.owner = THIS_MODULE,
		.name = "fsl-of-rio",
		.of_match_table = fsl_of_rio_rpn_ids,
	},
	.probe = fsl_of_rio_rpn_probe,
	.remove = fsl_of_rio_rpn_remove,
};

static __init int fsl_of_rio_rpn_init(void)
{
	return platform_driver_register(&fsl_of_rio_rpn_driver);
}

static void __exit fsl_of_rio_rpn_exit(void)
{
	platform_driver_unregister(&fsl_of_rio_rpn_driver);
}

module_init(fsl_of_rio_rpn_init);
module_exit(fsl_of_rio_rpn_exit);

MODULE_DESCRIPTION("Freescale Embedded SRIO Controller");
MODULE_AUTHOR("Freescale Semiconductor, Inc.");
MODULE_LICENSE("GPL");
