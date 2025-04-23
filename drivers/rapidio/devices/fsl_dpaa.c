// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Freescale MPC85xx/MPC86xx RapidIO DPAA support
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

#include <linux/types.h>
#include <linux/dma-mapping.h>
#include <linux/interrupt.h>
#include <linux/of_address.h>
#include <linux/of_irq.h>
#include <linux/slab.h>
#include <linux/kfifo.h>

#include "fsl_rio.h"

struct dpaa_private;

struct dpaa_msg_port {
	struct device *dev;
	struct dpaa_private *dpaa;
};

struct dpaa_private {
	struct device *dev;
	struct srio_dev *sriodev;
	void __iomem *rio_regs;
};

/**
 * dpaa_pwenable - enable/disable port-write interface init
 * @mport: Master port implementing the port write unit
 * @enable:    1=enable; 0=disable port-write message handling
 */
static int dpaa_pwenable(struct rio_mport *mport, int enable)
{
	return -EINVAL;
}

/**
 * dpaa_dsend - Send a MPC85xx doorbell message
 * @mport: RapidIO master port info
 * @index: ID of RapidIO interface
 * @destid: Destination ID of target device
 * @data: 16-bit info field of RapidIO doorbell message
 *
 * Sends a MPC85xx doorbell message. Returns %0 on success or
 * %-EINVAL on failure.
 */
static int dpaa_dsend(struct rio_mport *mport, int index, u16 destid, u16 data)
{
	return -EINVAL;
}

/**
 * dpaa_add_outb_message - Add message to the MPC85xx outbound message queue
 * @mport: Master port with outbound message queue
 * @rdev: Target of outbound message
 * @mbox: Outbound mailbox
 * @buffer: Message to add to outbound queue
 * @len: Length of message
 *
 * Adds the @buffer message to the MPC85xx outbound message queue. Returns
 * %0 on success or %-EINVAL on failure.
 */
static int dpaa_add_outb_message(struct rio_mport *mport, struct rio_dev *rdev,
				int mbox, void *buffer, size_t len)
{
	return -EINVAL;
}

/**
 * dpaa_open_outb_mbox - Initialize MPC85xx outbound mailbox
 * @mport: Master port implementing the outbound message unit
 * @dev_id: Device specific pointer to pass on event
 * @mbox: Mailbox to open
 * @entries: Number of entries in the outbound mailbox ring
 *
 * Initializes buffer ring, request the outbound message interrupt,
 * and enables the outbound message unit. Returns %0 on success and
 * %-EINVAL or %-ENOMEM on failure.
 */
static int dpaa_open_outb_mbox(struct rio_mport *mport, void *dev_id, int mbox,
			      int entries)
{
	return -EINVAL;
}

/**
 * dpaa_close_outb_mbox - Shut down MPC85xx outbound mailbox
 * @mport: Master port implementing the outbound message unit
 * @mbox: Mailbox to close
 *
 * Disables the outbound message unit, free all buffers, and
 * frees the outbound message interrupt.
 */
static void dpaa_close_outb_mbox(struct rio_mport *mport, int mbox)
{
	return;
}

/**
 * dpaa_open_inb_mbox - Initialize MPC85xx inbound mailbox
 * @mport: Master port implementing the inbound message unit
 * @dev_id: Device specific pointer to pass on event
 * @mbox: Mailbox to open
 * @entries: Number of entries in the inbound mailbox ring
 *
 * Initializes buffer ring, request the inbound message interrupt,
 * and enables the inbound message unit. Returns %0 on success
 * and %-EINVAL or %-ENOMEM on failure.
 */
static int dpaa_open_inb_mbox(struct rio_mport *mport, void *dev_id, int mbox,
			     int entries)
{
	return -EINVAL;
}

/**
 * dpaa_close_inb_mbox - Shut down MPC85xx inbound mailbox
 * @mport: Master port implementing the inbound message unit
 * @mbox: Mailbox to close
 *
 * Disables the inbound message unit, free all buffers, and
 * frees the inbound message interrupt.
 */
static void dpaa_close_inb_mbox(struct rio_mport *mport, int mbox)
{
	return;
}

/**
 * dpaa_add_inb_buffer - Add buffer to the MPC85xx inbound message queue
 * @mport: Master port implementing the inbound message unit
 * @mbox: Inbound mailbox number
 * @buf: Buffer to add to inbound queue
 *
 * Adds the @buf buffer to the MPC85xx inbound message queue. Returns
 * %0 on success or %-EINVAL on failure.
 */
static int dpaa_add_inb_buffer(struct rio_mport *mport, int mbox, void *buf)
{
	return -EINVAL;
}

/**
 * dpaa_get_inb_message - Fetch inbound message from the MPC85xx message unit
 * @mport: Master port implementing the inbound message unit
 * @mbox: Inbound mailbox number
 *
 * Gets the next available inbound message from the inbound message queue.
 * A pointer to the message is returned on success or NULL on failure.
 */
static void *dpaa_get_inb_message(struct rio_mport *mport, int mbox)
{
	return NULL;
}

static int dpaa_mmu_port_init(struct rio_mport *mport)
{
	struct rio_mport_priv *mprv = mport->priv;
	struct dpaa_private *dpaa;
	struct dpaa_msg_port *dpaa_port;
	struct device *dev;
	int id;

	dpaa = mprv->sriodev->mmu_handle;
	id = mport->index;
	dev = dpaa->dev;

	dpaa_port = devm_kzalloc(dpaa->dev, sizeof(*dpaa_port), GFP_KERNEL);
	if (!dpaa_port)
		return -ENOMEM;

	dpaa_port->dpaa = dpaa;
	dpaa_port->dev = dev;

	mport->ops->dsend		= dpaa_dsend,
	mport->ops->pwenable		= dpaa_pwenable,
	mport->ops->open_outb_mbox	= dpaa_open_outb_mbox,
	mport->ops->open_inb_mbox	= dpaa_open_inb_mbox,
	mport->ops->close_outb_mbox	= dpaa_close_outb_mbox,
	mport->ops->close_inb_mbox	= dpaa_close_inb_mbox,
	mport->ops->add_outb_message	= dpaa_add_outb_message,
	mport->ops->add_inb_buffer	= dpaa_add_inb_buffer,
	mport->ops->get_inb_message	= dpaa_get_inb_message,

	mprv->mmu_handle = dpaa_port;

	rio_init_dbell_res(&mport->riores[RIO_DOORBELL_RESOURCE], 0, 0xffff);
	rio_init_mbox_res(&mport->riores[RIO_INB_MBOX_RESOURCE], 0, 3);
	rio_init_mbox_res(&mport->riores[RIO_OUTB_MBOX_RESOURCE], 0, 3);

	return 0;
}

static void dpaa_mmu_exit(struct srio_dev *sriodev)
{
	return;
}

int fsl_rio_mmu_init(struct srio_dev *sriodev)
{
	struct dpaa_private *dpaa;
	struct device *dev = sriodev->dev;

	dpaa = devm_kzalloc(dev, sizeof(*dpaa), GFP_KERNEL);
	if (!dpaa)
		return -ENOMEM;

	dpaa->sriodev = sriodev;
	dpaa->dev = dev;
	dpaa->rio_regs = sriodev->regs;

	sriodev->mmu_exit = dpaa_mmu_exit;
	sriodev->mmu_port_init = dpaa_mmu_port_init;
	sriodev->mmu_name = "QorIQ DPAA";

	/* Set this last */
	sriodev->mmu_handle = dpaa;

	return 0;
}

static const struct of_device_id fsl_rio_ids[] = {
	{
		.compatible = "fsl,srio-dpaa",
	},
	{},
};

struct platform_driver fsl_rio_driver = {
	.driver = {
		.owner = THIS_MODULE,
		.name = "fsl-rio-dpaa",
		.of_match_table = fsl_rio_ids,
	},
	.probe = fsl_rio_probe,
	.remove = fsl_rio_remove,
};

MODULE_DESCRIPTION("QorIQ SRIO-DPAA Controller");
