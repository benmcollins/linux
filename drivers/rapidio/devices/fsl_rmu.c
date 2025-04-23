// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Freescale MPC85xx/MPC86xx RapidIO RMU support
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

#define GET_RMM_HANDLE(mport) \
		(((struct rio_mport_priv *)(mport->priv))->mmu_handle)

#define RIO_MIN_RING_SIZE	2
#define RIO_MAX_RING_SIZE	2048

#define RIO_IPWMR_SEN		0x00100000
#define RIO_IPWMR_QFIE		0x00000100
#define RIO_IPWMR_EIE		0x00000020
#define RIO_IPWMR_CQ		0x00000002
#define RIO_IPWMR_PWE		0x00000001

#define RIO_IPWSR_QF		0x00100000
#define RIO_IPWSR_TE		0x00000080
#define RIO_IPWSR_QFI		0x00000010
#define RIO_IPWSR_PWD		0x00000008
#define RIO_IPWSR_PWB		0x00000004

#define RIO_EPWISR		0x10010
/* EPWISR Error match value */
#define RIO_EPWISR_PINT1	0x80000000
#define RIO_EPWISR_PINT2	0x40000000
#define RIO_EPWISR_MU		0x00000002
#define RIO_EPWISR_PW		0x00000001

#define IPWSR_CLEAR		0x98
#define OMSR_CLEAR		0x1cb3
#define IMSR_CLEAR		0x491
#define IDSR_CLEAR		0x91
#define ODSR_CLEAR		0x1c00
#define LTLEECSR_ENABLE_ALL	0xFFC000FC
#define RIO_LTLEECSR		0x060c

#define RIO_IM0SR		0x64
#define RIO_IM1SR		0x164
#define RIO_OM0SR		0x4
#define RIO_OM1SR		0x104

#define RIO_DBELL_WIN_SIZE	0x1000

#define RIO_MSG_OMR_MUI		0x00000002
#define RIO_MSG_OSR_TE		0x00000080
#define RIO_MSG_OSR_QOI		0x00000020
#define RIO_MSG_OSR_QFI		0x00000010
#define RIO_MSG_OSR_MUB		0x00000004
#define RIO_MSG_OSR_EOMI	0x00000002
#define RIO_MSG_OSR_QEI		0x00000001

#define RIO_MSG_IMR_MI		0x00000002
#define RIO_MSG_ISR_TE		0x00000080
#define RIO_MSG_ISR_QFI		0x00000010
#define RIO_MSG_ISR_DIQI	0x00000001

#define RIO_MSG_DESC_SIZE	32
#define RIO_MSG_BUFFER_SIZE	4096

#define DOORBELL_DMR_DI		0x00000002
#define DOORBELL_DSR_TE		0x00000080
#define DOORBELL_DSR_QFI	0x00000010
#define DOORBELL_DSR_DIQI	0x00000001

#define DOORBELL_MESSAGE_SIZE	0x08

static DEFINE_SPINLOCK(rmu_dbell_lock);

struct rmu_msg_regs {
	u32 omr;
	u32 osr;
	u32 pad1;
	u32 odqdpar;
	u32 pad2;
	u32 osar;
	u32 odpr;
	u32 odatr;
	u32 odcr;
	u32 pad3;
	u32 odqepar;
	u32 pad4[13];
	u32 imr;
	u32 isr;
	u32 pad5;
	u32 ifqdpar;
	u32 pad6;
	u32 ifqepar;
};

struct rmu_dbell_regs {
	u32 odmr;
	u32 odsr;
	u32 pad1[4];
	u32 oddpr;
	u32 oddatr;
	u32 pad2[3];
	u32 odretcr;
	u32 pad3[12];
	u32 dmr;
	u32 dsr;
	u32 pad4;
	u32 dqdpar;
	u32 pad5;
	u32 dqepar;
};

struct rmu_pw_regs {
	u32 pwmr;
	u32 pwsr;
	u32 epwqbar;
	u32 pwqbar;
};


struct rmu_tx_desc {
	u32 pad1;
	u32 saddr;
	u32 dport;
	u32 dattr;
	u32 pad2;
	u32 pad3;
	u32 dwcnt;
	u32 pad4;
};

struct rmu_dbell_desc {
	u16 pad1;
	u16 tid;
	u16 sid;
	u16 info;
};

struct rmu_msg_ring {
	void *virt;
	dma_addr_t phys;
	void *virt_buffer[RIO_MAX_RING_SIZE];
	dma_addr_t phys_buffer[RIO_MAX_RING_SIZE];
	int slot;
	int size;
	void *dev_id;
};

struct rmu_private;

struct rmu_msg_port {
	struct device *dev;
	struct rmu_private *rmu;
	struct rmu_msg_regs __iomem *regs;
	struct rmu_msg_ring tx_ring;
	struct rmu_msg_ring rx_ring;
	int txirq;
	int rxirq;
	void __iomem *rmu_regs;
};

struct rmu_dbell_ring {
	void *virt;
	dma_addr_t phys;
};

struct rmu_port_mwrite {
	void *virt;
	dma_addr_t phys;
	u32 msg_count;
	u32 err_count;
	u32 discard_count;
};

struct rmu_dbell_unit {
	struct rmu_dbell_regs __iomem *regs;
	struct rmu_dbell_ring ring;
	int irq;
};

struct rmu_pw_unit {
	struct rmu_pw_regs __iomem *regs;
	struct rmu_port_mwrite msg;
	int irq;
	struct work_struct work;
	struct kfifo fifo;
	spinlock_t fifo_lock;
};

struct rmu_private {
	struct device *dev;
	struct srio_dev *sriodev;
	struct rmu_dbell_unit dbell;
	struct rmu_pw_unit pw;
	struct device_node *mu_np[MAX_PORT_NUM];
	void __iomem *regs;
	void __iomem *rio_regs;
};

/**
 * rmu_isr_tx_handler - MPC85xx outbound message interrupt handler
 * @irq: Linux interrupt number
 * @data: Pointer to interrupt-specific data
 *
 * Handles outbound message interrupts. Executes a register outbound
 * mailbox event handler and acks the interrupt occurrence.
 */
static irqreturn_t rmu_isr_tx_handler(int irq, void *data)
{
	int osr;
	struct rio_mport *port = data;
	struct rmu_msg_port *rmu = GET_RMM_HANDLE(port);

	osr = in_be32(&rmu->regs->osr);

	if (osr & RIO_MSG_OSR_TE) {
		pr_info("RIO: outbound message transmission error\n");
		out_be32(&rmu->regs->osr, RIO_MSG_OSR_TE);
		goto out;
	}

	if (osr & RIO_MSG_OSR_QOI) {
		pr_info("RIO: outbound message queue overflow\n");
		out_be32(&rmu->regs->osr, RIO_MSG_OSR_QOI);
		goto out;
	}

	if (osr & RIO_MSG_OSR_EOMI) {
		u32 dqp = in_be32(&rmu->regs->odqdpar);
		int slot = (dqp - rmu->tx_ring.phys) >> 5;
		if (port->outb_msg[0].mcback != NULL) {
			port->outb_msg[0].mcback(port, rmu->tx_ring.dev_id,
					-1,
					slot);
		}
		/* Ack the end-of-message interrupt */
		out_be32(&rmu->regs->osr, RIO_MSG_OSR_EOMI);
	}

out:
	return IRQ_HANDLED;
}

/**
 * rmu_isr_rx_handler - MPC85xx inbound message interrupt handler
 * @irq: Linux interrupt number
 * @data: Pointer to interrupt-specific data
 *
 * Handles inbound message interrupts. Executes a registered inbound
 * mailbox event handler and acks the interrupt occurrence.
 */
static irqreturn_t rmu_isr_rx_handler(int irq, void *data)
{
	int isr;
	struct rio_mport *port = data;
	struct rmu_msg_port *rmu = GET_RMM_HANDLE(port);

	isr = in_be32(&rmu->regs->isr);

	if (isr & RIO_MSG_ISR_TE) {
		pr_info("RIO: inbound message reception error\n");
		out_be32((void *)&rmu->regs->isr, RIO_MSG_ISR_TE);
		goto out;
	}

	/* XXX Need to check/dispatch until queue empty */
	if (isr & RIO_MSG_ISR_DIQI) {
		/*
		* Can receive messages for any mailbox/letter to that
		* mailbox destination. So, make the callback with an
		* unknown/invalid mailbox number argument.
		*/
		if (port->inb_msg[0].mcback != NULL)
			port->inb_msg[0].mcback(port, rmu->rx_ring.dev_id,
				-1,
				-1);

		/* Ack the queueing interrupt */
		out_be32(&rmu->regs->isr, RIO_MSG_ISR_DIQI);
	}

out:
	return IRQ_HANDLED;
}

/**
 * rmu_isr_dbell_handler - MPC85xx doorbell interrupt handler
 * @irq: Linux interrupt number
 * @data: Pointer to interrupt-specific data
 *
 * Handles doorbell interrupts. Parses a list of registered
 * doorbell event handlers and executes a matching event handler.
 */
static irqreturn_t rmu_isr_dbell_handler(int irq, void *data)
{
	struct rmu_private *rmu = data;
	struct rmu_dbell_unit *dbell = &rmu->dbell;
	struct rmu_dbell_desc *dmsg;
	struct rio_dbell *db;
	int dsr;
	int i, found = 0;

	dsr = in_be32(&dbell->regs->dsr);

	if (dsr & DOORBELL_DSR_TE) {
		pr_info("RIO: doorbell reception error\n");
		out_be32(&dbell->regs->dsr, DOORBELL_DSR_TE);
		return IRQ_HANDLED;
	}

	if (dsr & DOORBELL_DSR_QFI) {
		pr_info("RIO: doorbell queue full\n");
		out_be32(&dbell->regs->dsr, DOORBELL_DSR_QFI);
	}

	/* XXX Need to check/dispatch until queue empty */
	if (!(dsr & DOORBELL_DSR_DIQI))
		return IRQ_HANDLED;

	dmsg = dbell->ring.virt + (in_be32(&dbell->regs->dqdpar) & 0xfff);

	pr_debug("RIO: processing doorbell, sid %2.2x tid %2.2x info %4.4x\n",
		 dmsg->sid, dmsg->tid, dmsg->info);

	for (i = 0; i < MAX_PORT_NUM; i++) {
		if (!rmu->sriodev->ports[i].priv)
			continue;

		list_for_each_entry(db, &rmu->sriodev->ports[i].dbells, node) {
			if ((db->res->start <= dmsg->info) &&
			    (db->res->end >= dmsg->info)) {
				found = 1;
				break;
			}
		}

		if (found && db->dinb) {
			db->dinb(&rmu->sriodev->ports[i], db->dev_id, dmsg->sid,
				 dmsg->tid, dmsg->info);
			break;
		}
	}

	if (!found) {
		pr_debug("RIO: spurious doorbell,"
			 " sid %2.2x tid %2.2x info %4.4x\n",
			 dmsg->sid, dmsg->tid, dmsg->info);
	}

	setbits32(&dbell->regs->dmr, DOORBELL_DMR_DI);
	out_be32(&dbell->regs->dsr, DOORBELL_DSR_DIQI);

	return IRQ_HANDLED;
}

static void rmu_error_handler(struct rmu_private *rmu)
{
	struct rmu_dbell_unit *dbell = &rmu->dbell;
	struct rmu_pw_unit *pw = &rmu->pw;

	/*XXX: Error recovery is not implemented, we just clear errors */
	out_be32((u32 *)(rmu->rio_regs + RIO_LTLEDCSR), 0);

	out_be32((u32 *)(rmu->regs + RIO_IM0SR), IMSR_CLEAR);
	out_be32((u32 *)(rmu->regs + RIO_IM1SR), IMSR_CLEAR);
	out_be32((u32 *)(rmu->regs + RIO_OM0SR), OMSR_CLEAR);
	out_be32((u32 *)(rmu->regs + RIO_OM1SR), OMSR_CLEAR);

	out_be32(&dbell->regs->odsr, ODSR_CLEAR);
	out_be32(&dbell->regs->dsr, IDSR_CLEAR);
	out_be32(&pw->regs->pwsr, IPWSR_CLEAR);
}


static void rmu_port_error_handler(struct rmu_private *rmu, int offset)
{
	/*XXX: Error recovery is not implemented, we just clear errors */
	out_be32((u32 *)(rmu->rio_regs + RIO_LTLEDCSR), 0);

	if (offset == 0) {
		out_be32((u32 *)(rmu->rio_regs + RIO_PORT1_EDCSR), 0);
		out_be32((u32 *)(rmu->rio_regs + RIO_PORT1_IECSR), IECSR_CLEAR);
		out_be32((u32 *)(rmu->rio_regs + RIO_ESCSR), ESCSR_CLEAR);
	} else {
		out_be32((u32 *)(rmu->rio_regs + RIO_PORT2_EDCSR), 0);
		out_be32((u32 *)(rmu->rio_regs + RIO_PORT2_IECSR), IECSR_CLEAR);
		out_be32((u32 *)(rmu->rio_regs + RIO_PORT2_ESCSR), ESCSR_CLEAR);
	}
}

/**
 * rmu_isr_write_handler - MPC85xx port write interrupt handler
 * @irq: Linux interrupt number
 * @data: Pointer to interrupt-specific data
 *
 * Handles port write interrupts. Parses a list of registered
 * port write event handlers and executes a matching event handler.
 */
static irqreturn_t rmu_isr_write_handler(int irq, void *data)
{
	struct rmu_private *rmu = data;
	struct rmu_pw_unit *pw = &rmu->pw;
	u32 ipwmr, ipwsr;
	u32 epwisr, tmp;

	epwisr = in_be32(rmu->rio_regs + RIO_EPWISR);
	if (!(epwisr & RIO_EPWISR_PW))
		goto pw_done;

	ipwmr = in_be32(&pw->regs->pwmr);
	ipwsr = in_be32(&pw->regs->pwsr);

#ifdef DEBUG_PW
	pr_debug("PW Int->IPWMR: 0x%08x IPWSR: 0x%08x (", ipwmr, ipwsr);
	if (ipwsr & RIO_IPWSR_QF)
		pr_debug(" QF");
	if (ipwsr & RIO_IPWSR_TE)
		pr_debug(" TE");
	if (ipwsr & RIO_IPWSR_QFI)
		pr_debug(" QFI");
	if (ipwsr & RIO_IPWSR_PWD)
		pr_debug(" PWD");
	if (ipwsr & RIO_IPWSR_PWB)
		pr_debug(" PWB");
	pr_debug(" )\n");
#endif
	/* Schedule deferred processing if PW was received */
	if (ipwsr & RIO_IPWSR_QFI) {
		/* Save PW message (if there is room in FIFO),
		 * otherwise discard it.
		 */
		if (kfifo_avail(&pw->fifo) >= RIO_PW_MSG_SIZE) {
			pw->msg.msg_count++;
			kfifo_in(&pw->fifo, pw->msg.virt,
				 RIO_PW_MSG_SIZE);
		} else {
			pw->msg.discard_count++;
			pr_debug("RIO: ISR Discarded Port-Write Msg(s) (%d)\n",
				 pw->msg.discard_count);
		}
		/* Clear interrupt and issue Clear Queue command. This allows
		 * another port-write to be received.
		 */
		out_be32(&pw->regs->pwsr,	RIO_IPWSR_QFI);
		out_be32(&pw->regs->pwmr, ipwmr | RIO_IPWMR_CQ);

		schedule_work(&pw->work);
	}

	if ((ipwmr & RIO_IPWMR_EIE) && (ipwsr & RIO_IPWSR_TE)) {
		pw->msg.err_count++;
		pr_debug("RIO: Port-Write Transaction Err (%d)\n",
			 pw->msg.err_count);
		/* Clear Transaction Error: port-write controller should be
		 * disabled when clearing this error
		 */
		out_be32(&pw->regs->pwmr, ipwmr & ~RIO_IPWMR_PWE);
		out_be32(&pw->regs->pwsr,	RIO_IPWSR_TE);
		out_be32(&pw->regs->pwmr, ipwmr);
	}

	if (ipwsr & RIO_IPWSR_PWD) {
		pw->msg.discard_count++;
		pr_debug("RIO: Port Discarded Port-Write Msg(s) (%d)\n",
			 pw->msg.discard_count);
		out_be32(&pw->regs->pwsr, RIO_IPWSR_PWD);
	}

pw_done:
	if (epwisr & RIO_EPWISR_PINT1) {
		tmp = in_be32(rmu->rio_regs + RIO_LTLEDCSR);
		pr_debug("RIO_LTLEDCSR = 0x%x\n", tmp);
		rmu_port_error_handler(rmu, 0);
	}

	if (epwisr & RIO_EPWISR_PINT2) {
		tmp = in_be32(rmu->rio_regs + RIO_LTLEDCSR);
		pr_debug("RIO_LTLEDCSR = 0x%x\n", tmp);
		rmu_port_error_handler(rmu, 1);
	}

	if (epwisr & RIO_EPWISR_MU) {
		tmp = in_be32(rmu->rio_regs + RIO_LTLEDCSR);
		pr_debug("RIO_LTLEDCSR = 0x%x\n", tmp);
		rmu_error_handler(rmu);
	}

	return IRQ_HANDLED;
}

static void rmu_pw_dpc(struct work_struct *work)
{
	struct rmu_pw_unit *pw = container_of(work, struct rmu_pw_unit, work);
	struct rmu_private *rmu = container_of(pw, struct rmu_private, pw);
	union rio_pw_msg msg_buffer;
	int i;

	/*
	 * Process port-write messages
	 */
	while (kfifo_out_spinlocked(&pw->fifo, (unsigned char *)&msg_buffer,
			 RIO_PW_MSG_SIZE, &pw->fifo_lock)) {
#ifdef DEBUG_PW
		{
		u32 i;
		pr_debug("%s : Port-Write Message:", __func__);
		for (i = 0; i < RIO_PW_MSG_SIZE/sizeof(u32); i++) {
			if ((i%4) == 0)
				pr_debug("\n0x%02x: 0x%08x", i*4,
					 msg_buffer.raw[i]);
			else
				pr_debug(" 0x%08x", msg_buffer.raw[i]);
		}
		pr_debug("\n");
		}
#endif
		/* Pass the port-write message to RIO core for processing */
		for (i = 0; i < MAX_PORT_NUM; i++) {
			if (rmu->sriodev->ports[i].priv)
				rio_inb_pwrite_handler(&rmu->sriodev->ports[i],
						       &msg_buffer);
		}
	}
}

/**
 * rmu_pwenable - enable/disable port-write interface init
 * @mport: Master port implementing the port write unit
 * @enable:    1=enable; 0=disable port-write message handling
 */
static int rmu_pwenable(struct rio_mport *mport, int enable)
{
	struct rmu_msg_port *rmu_port = GET_RMM_HANDLE(mport);
	struct rmu_private *rmu = rmu_port->rmu;
	u32 rval;

	rval = in_be32(&rmu->pw.regs->pwmr);

	if (enable)
		rval |= RIO_IPWMR_PWE;
	else
		rval &= ~RIO_IPWMR_PWE;

	out_be32(&rmu->pw.regs->pwmr, rval);

	return 0;
}

/**
 * rmu_pwrite_init - MPC85xx port write interface init
 * @mport: Master port implementing the port write unit
 *
 * Initializes port write unit hardware and DMA buffer
 * ring. Called from fsl_rio_mmu_init(). Returns %0 on success
 * or %-ENOMEM on failure.
 */
static int rmu_pwrite_init(struct rmu_private *rmu)
{
	struct rmu_pw_unit *pw = &rmu->pw;
	int rc = 0;

	/* Following configurations require a disabled port write controller */
	out_be32(&pw->regs->pwmr,
		 in_be32(&pw->regs->pwmr) & ~RIO_IPWMR_PWE);

	/* Initialize port write */
	pw->msg.virt = dma_alloc_coherent(rmu->dev, RIO_PW_MSG_SIZE,
					  &pw->msg.phys, GFP_KERNEL);
	if (!pw->msg.virt) {
		pr_err("RIO: unable allocate port write queue\n");
		return -ENOMEM;
	}

	pw->msg.err_count = 0;
	pw->msg.discard_count = 0;

	/* Point dequeue/enqueue pointers at first entry */
	out_be32(&pw->regs->epwqbar, 0);
	out_be32(&pw->regs->pwqbar, (u32) pw->msg.phys);

	pr_debug("EIPWQBAR: 0x%08x IPWQBAR: 0x%08x\n",
		 in_be32(&pw->regs->epwqbar),
		 in_be32(&pw->regs->pwqbar));

	/* Clear interrupt status IPWSR */
	out_be32(&pw->regs->pwsr,
		 (RIO_IPWSR_TE | RIO_IPWSR_QFI | RIO_IPWSR_PWD));

	/* Configure port write controller for snooping enable all reporting,
	   clear queue full */
	out_be32(&pw->regs->pwmr,
		 RIO_IPWMR_SEN | RIO_IPWMR_QFIE | RIO_IPWMR_EIE | RIO_IPWMR_CQ);


	/* Hook up port-write handler */
	rc = devm_request_irq(rmu->dev, pw->irq,
			      rmu_isr_write_handler,
			      IRQF_SHARED, "port-write", rmu);
	if (rc < 0) {
		pr_err("MPC85xx RIO: unable to request inbound doorbell irq");
		return rc;
	}
	/* Enable Error Interrupt */
	out_be32((u32 *)(rmu->rio_regs + RIO_LTLEECSR), LTLEECSR_ENABLE_ALL);

	INIT_WORK(&pw->work, rmu_pw_dpc);
	spin_lock_init(&pw->fifo_lock);
	if (kfifo_alloc(&pw->fifo, RIO_PW_MSG_SIZE * 32, GFP_KERNEL)) {
		pr_err("FIFO allocation failed\n");
		return -ENOMEM;
	}

	pr_debug("IPWMR: 0x%08x IPWSR: 0x%08x\n",
		 in_be32(&pw->regs->pwmr),
		 in_be32(&pw->regs->pwsr));

	return 0;
}

/**
 * rmu_dsend - Send a MPC85xx doorbell message
 * @mport: RapidIO master port info
 * @index: ID of RapidIO interface
 * @destid: Destination ID of target device
 * @data: 16-bit info field of RapidIO doorbell message
 *
 * Sends a MPC85xx doorbell message. Returns %0 on success or
 * %-EINVAL on failure.
 */
static int rmu_dsend(struct rio_mport *mport, int index, u16 destid, u16 data)
{
	struct rio_mport_priv *prt_priv = mport->priv;
	struct rmu_private *priv = prt_priv->mmu_handle;
	unsigned long flags;

	pr_debug("rmu_dsend: index %d destid %4.4x data %4.4x\n",
		 index, destid, data);

	spin_lock_irqsave(&rmu_dbell_lock, flags);

	/* In the serial version silicons, such as MPC8548, MPC8641,
	 * below operations is must be.
	 */
	out_be32(&priv->dbell.regs->odmr, 0x00000000);
	out_be32(&priv->dbell.regs->odretcr, 0x00000004);
	out_be32(&priv->dbell.regs->oddpr, destid << 16);
	out_be32(&priv->dbell.regs->oddatr, (index << 20) | data);
	out_be32(&priv->dbell.regs->odmr, 0x00000001);

	spin_unlock_irqrestore(&rmu_dbell_lock, flags);

	return 0;
}

/**
 * rmu_add_outb_message - Add message to the MPC85xx outbound message queue
 * @mport: Master port with outbound message queue
 * @rdev: Target of outbound message
 * @mbox: Outbound mailbox
 * @buffer: Message to add to outbound queue
 * @len: Length of message
 *
 * Adds the @buffer message to the MPC85xx outbound message queue. Returns
 * %0 on success or %-EINVAL on failure.
 */
static int rmu_add_outb_message(struct rio_mport *mport, struct rio_dev *rdev,
				int mbox, void *buffer, size_t len)
{
	struct rmu_msg_port *rmu = GET_RMM_HANDLE(mport);
	u32 omr;
	struct rmu_tx_desc *desc = (struct rmu_tx_desc *)rmu->tx_ring.virt
					+ rmu->tx_ring.slot;
	int ret = 0;

	pr_debug("RIO: rmu_add_outb_message(): destid %4.4x mbox %d buffer " \
		 "%p len %8.8zx\n", rdev->destid, mbox, buffer, len);
	if ((len < 8) || (len > RIO_MAX_MSG_SIZE)) {
		ret = -EINVAL;
		goto out;
	}

	/* Copy and clear rest of buffer */
	memcpy(rmu->tx_ring.virt_buffer[rmu->tx_ring.slot], buffer,
			len);
	if (len < (RIO_MAX_MSG_SIZE - 4))
		memset(rmu->tx_ring.virt_buffer[rmu->tx_ring.slot]
				+ len, 0, RIO_MAX_MSG_SIZE - len);

	/* Set mbox field for message, and set destid */
	desc->dport = (rdev->destid << 16) | (mbox & 0x3);

	/* Enable EOMI interrupt and priority */
	desc->dattr = 0x28000000 | ((mport->index) << 20);

	/* Set transfer size aligned to next power of 2 (in double words) */
	desc->dwcnt = is_power_of_2(len) ? len : 1 << get_bitmask_order(len);

	/* Set snooping and source buffer address */
	desc->saddr = 0x00000004
		| rmu->tx_ring.phys_buffer[rmu->tx_ring.slot];

	/* Increment enqueue pointer */
	omr = in_be32(&rmu->regs->omr);
	out_be32(&rmu->regs->omr, omr | RIO_MSG_OMR_MUI);

	/* Go to next descriptor */
	if (++rmu->tx_ring.slot == rmu->tx_ring.size)
		rmu->tx_ring.slot = 0;

out:
	return ret;
}

/**
 * rmu_open_outb_mbox - Initialize MPC85xx outbound mailbox
 * @mport: Master port implementing the outbound message unit
 * @dev_id: Device specific pointer to pass on event
 * @mbox: Mailbox to open
 * @entries: Number of entries in the outbound mailbox ring
 *
 * Initializes buffer ring, request the outbound message interrupt,
 * and enables the outbound message unit. Returns %0 on success and
 * %-EINVAL or %-ENOMEM on failure.
 */
static int rmu_open_outb_mbox(struct rio_mport *mport, void *dev_id, int mbox,
			      int entries)
{
	int i, j, rc = 0;
	struct rmu_msg_port *rmu = GET_RMM_HANDLE(mport);

	if ((entries < RIO_MIN_RING_SIZE) ||
		(entries > RIO_MAX_RING_SIZE) || (!is_power_of_2(entries))) {
		rc = -EINVAL;
		goto out;
	}

	/* Initialize shadow copy ring */
	rmu->tx_ring.dev_id = dev_id;
	rmu->tx_ring.size = entries;

	for (i = 0; i < rmu->tx_ring.size; i++) {
		rmu->tx_ring.virt_buffer[i] =
			dma_alloc_coherent(rmu->dev, RIO_MSG_BUFFER_SIZE,
				&rmu->tx_ring.phys_buffer[i], GFP_KERNEL);
		if (!rmu->tx_ring.virt_buffer[i]) {
			rc = -ENOMEM;
			for (j = 0; j < rmu->tx_ring.size; j++)
				if (rmu->tx_ring.virt_buffer[j])
					dma_free_coherent(rmu->dev,
							RIO_MSG_BUFFER_SIZE,
							rmu->tx_ring.
							virt_buffer[j],
							rmu->tx_ring.
							phys_buffer[j]);
			goto out;
		}
	}

	/* Initialize outbound message descriptor ring */
	rmu->tx_ring.virt = dma_alloc_coherent(rmu->dev,
						   rmu->tx_ring.size * RIO_MSG_DESC_SIZE,
						   &rmu->tx_ring.phys,
						   GFP_KERNEL);
	if (!rmu->tx_ring.virt) {
		rc = -ENOMEM;
		goto out_dma;
	}
	rmu->tx_ring.slot = 0;

	/* Point dequeue/enqueue pointers at first entry in ring */
	out_be32(&rmu->regs->odqdpar, rmu->tx_ring.phys);
	out_be32(&rmu->regs->odqepar, rmu->tx_ring.phys);

	/* Configure for snooping */
	out_be32(&rmu->regs->osar, 0x00000004);

	/* Clear interrupt status */
	out_be32(&rmu->regs->osr, 0x000000b3);

	/* Hook up outbound message handler */
	rc = devm_request_irq(rmu->dev, rmu->txirq, rmu_isr_tx_handler,
			      0, "msg_tx", (void *)mport);
	if (rc < 0)
		goto out_irq;

	/*
	 * Configure outbound message unit
	 *      Snooping
	 *      Interrupts (all enabled, except QEIE)
	 *      Chaining mode
	 *      Disable
	 */
	out_be32(&rmu->regs->omr, 0x00100220);

	/* Set number of entries */
	out_be32(&rmu->regs->omr,
		 in_be32(&rmu->regs->omr) |
		 ((get_bitmask_order(entries) - 2) << 12));

	/* Now enable the unit */
	out_be32(&rmu->regs->omr, in_be32(&rmu->regs->omr) | 0x1);

out:
	return rc;

out_irq:
	dma_free_coherent(rmu->dev,
		rmu->tx_ring.size * RIO_MSG_DESC_SIZE,
		rmu->tx_ring.virt, rmu->tx_ring.phys);

out_dma:
	for (i = 0; i < rmu->tx_ring.size; i++)
		dma_free_coherent(rmu->dev, RIO_MSG_BUFFER_SIZE,
		rmu->tx_ring.virt_buffer[i],
		rmu->tx_ring.phys_buffer[i]);

	return rc;
}

/**
 * rmu_close_outb_mbox - Shut down MPC85xx outbound mailbox
 * @mport: Master port implementing the outbound message unit
 * @mbox: Mailbox to close
 *
 * Disables the outbound message unit, free all buffers, and
 * frees the outbound message interrupt.
 */
static void rmu_close_outb_mbox(struct rio_mport *mport, int mbox)
{
	struct rmu_msg_port *rmu = GET_RMM_HANDLE(mport);

	/* Disable inbound message unit */
	out_be32(&rmu->regs->omr, 0);

	/* Free ring */
	dma_free_coherent(rmu->dev,
	rmu->tx_ring.size * RIO_MSG_DESC_SIZE,
	rmu->tx_ring.virt, rmu->tx_ring.phys);

	/* Free interrupt */
	free_irq(rmu->txirq, (void *)mport);
}

/**
 * rmu_open_inb_mbox - Initialize MPC85xx inbound mailbox
 * @mport: Master port implementing the inbound message unit
 * @dev_id: Device specific pointer to pass on event
 * @mbox: Mailbox to open
 * @entries: Number of entries in the inbound mailbox ring
 *
 * Initializes buffer ring, request the inbound message interrupt,
 * and enables the inbound message unit. Returns %0 on success
 * and %-EINVAL or %-ENOMEM on failure.
 */
static int rmu_open_inb_mbox(struct rio_mport *mport, void *dev_id, int mbox,
			     int entries)
{
	int i, rc = 0;
	struct rmu_msg_port *rmu = GET_RMM_HANDLE(mport);

	if ((entries < RIO_MIN_RING_SIZE) ||
		(entries > RIO_MAX_RING_SIZE) || (!is_power_of_2(entries))) {
		rc = -EINVAL;
		goto out;
	}

	/* Initialize client buffer ring */
	rmu->rx_ring.dev_id = dev_id;
	rmu->rx_ring.size = entries;
	rmu->rx_ring.slot = 0;
	for (i = 0; i < rmu->rx_ring.size; i++)
		rmu->rx_ring.virt_buffer[i] = NULL;

	/* Initialize inbound message ring */
	rmu->rx_ring.virt = dma_alloc_coherent(rmu->dev,
				rmu->rx_ring.size * RIO_MAX_MSG_SIZE,
				&rmu->rx_ring.phys, GFP_KERNEL);
	if (!rmu->rx_ring.virt) {
		rc = -ENOMEM;
		goto out;
	}

	/* Point dequeue/enqueue pointers at first entry in ring */
	out_be32(&rmu->regs->ifqdpar, (u32) rmu->rx_ring.phys);
	out_be32(&rmu->regs->ifqepar, (u32) rmu->rx_ring.phys);

	/* Clear interrupt status */
	out_be32(&rmu->regs->isr, 0x00000091);

	/* Hook up inbound message handler */
	rc = devm_request_irq(rmu->dev, rmu->rxirq, rmu_isr_rx_handler,
			      0, "msg_rx", mport);
	if (rc < 0) {
		dma_free_coherent(rmu->dev,
			rmu->rx_ring.size * RIO_MAX_MSG_SIZE,
			rmu->rx_ring.virt, rmu->rx_ring.phys);
		goto out;
	}

	/*
	 * Configure inbound message unit:
	 *      Snooping
	 *      4KB max message size
	 *      Unmask all interrupt sources
	 *      Disable
	 */
	out_be32(&rmu->regs->imr, 0x001b0060);

	/* Set number of queue entries */
	setbits32(&rmu->regs->imr, (get_bitmask_order(entries) - 2) << 12);

	/* Now enable the unit */
	setbits32(&rmu->regs->imr, 0x1);

out:
	return rc;
}

/**
 * rmu_close_inb_mbox - Shut down MPC85xx inbound mailbox
 * @mport: Master port implementing the inbound message unit
 * @mbox: Mailbox to close
 *
 * Disables the inbound message unit, free all buffers, and
 * frees the inbound message interrupt.
 */
static void rmu_close_inb_mbox(struct rio_mport *mport, int mbox)
{
	struct rmu_msg_port *rmu = GET_RMM_HANDLE(mport);

	/* Disable inbound message unit */
	out_be32(&rmu->regs->imr, 0);

	/* Free ring */
	dma_free_coherent(rmu->dev, rmu->rx_ring.size * RIO_MAX_MSG_SIZE,
	rmu->rx_ring.virt, rmu->rx_ring.phys);

	/* Free interrupt */
	free_irq(rmu->rxirq, (void *)mport);
}

/**
 * rmu_add_inb_buffer - Add buffer to the MPC85xx inbound message queue
 * @mport: Master port implementing the inbound message unit
 * @mbox: Inbound mailbox number
 * @buf: Buffer to add to inbound queue
 *
 * Adds the @buf buffer to the MPC85xx inbound message queue. Returns
 * %0 on success or %-EINVAL on failure.
 */
static int rmu_add_inb_buffer(struct rio_mport *mport, int mbox, void *buf)
{
	int rc = 0;
	struct rmu_msg_port *rmu = GET_RMM_HANDLE(mport);

	pr_debug("RIO: rmu_add_inb_buffer(), rx_ring.slot %d\n",
		 rmu->rx_ring.slot);

	if (rmu->rx_ring.virt_buffer[rmu->rx_ring.slot]) {
		printk(KERN_ERR
			"RIO: error adding inbound buffer %d, buffer exists\n",
			rmu->rx_ring.slot);
		rc = -EINVAL;
		goto out;
	}

	rmu->rx_ring.virt_buffer[rmu->rx_ring.slot] = buf;
	if (++rmu->rx_ring.slot == rmu->rx_ring.size)
		rmu->rx_ring.slot = 0;

out:
	return rc;
}

/**
 * rmu_get_inb_message - Fetch inbound message from the MPC85xx message unit
 * @mport: Master port implementing the inbound message unit
 * @mbox: Inbound mailbox number
 *
 * Gets the next available inbound message from the inbound message queue.
 * A pointer to the message is returned on success or NULL on failure.
 */
static void *rmu_get_inb_message(struct rio_mport *mport, int mbox)
{
	struct rmu_msg_port *rmu = GET_RMM_HANDLE(mport);
	u32 phys_buf;
	void *virt_buf;
	void *buf = NULL;
	int buf_idx;

	phys_buf = in_be32(&rmu->regs->ifqdpar);

	/* If no more messages, then bail out */
	if (phys_buf == in_be32(&rmu->regs->ifqepar))
		goto out2;

	virt_buf = rmu->rx_ring.virt + (phys_buf
						- rmu->rx_ring.phys);
	buf_idx = (phys_buf - rmu->rx_ring.phys) / RIO_MAX_MSG_SIZE;
	buf = rmu->rx_ring.virt_buffer[buf_idx];

	if (!buf) {
		printk(KERN_ERR
			"RIO: inbound message copy failed, no buffers\n");
		goto out1;
	}

	/* Copy max message size, caller is expected to allocate that big */
	memcpy(buf, virt_buf, RIO_MAX_MSG_SIZE);

	/* Clear the available buffer */
	rmu->rx_ring.virt_buffer[buf_idx] = NULL;

out1:
	setbits32(&rmu->regs->imr, RIO_MSG_IMR_MI);

out2:
	return buf;
}

/**
 * rmu_dbell_init - MPC85xx doorbell interface init
 * @mport: Master port implementing the inbound doorbell unit
 *
 * Initializes doorbell unit hardware and inbound DMA buffer
 * ring. Called from fsl_rio_mmu_init(). Returns %0 on success
 * or %-ENOMEM on failure.
 */
static int rmu_dbell_init(struct rmu_private *rmu)
{
	struct rmu_dbell_unit *dbell = &rmu->dbell;
	int rc = 0;

	/* Initialize inbound doorbells */
	dbell->ring.virt = dma_alloc_coherent(rmu->dev, 512 *
		DOORBELL_MESSAGE_SIZE, &dbell->ring.phys, GFP_KERNEL);
	if (!dbell->ring.virt) {
		printk(KERN_ERR "RIO: unable allocate inbound doorbell ring\n");
		return -ENOMEM;
	}

	/* Point dequeue/enqueue pointers at first entry in ring */
	out_be32(&dbell->regs->dqdpar, (u32) dbell->ring.phys);
	out_be32(&dbell->regs->dqepar, (u32) dbell->ring.phys);

	/* Clear interrupt status */
	out_be32(&dbell->regs->dsr, 0x00000091);

	/* Hook up doorbell handler */
	rc = devm_request_irq(rmu->dev, dbell->irq, rmu_isr_dbell_handler, 0,
			      "dbell_rx", rmu);
	if (rc < 0) {
		dma_free_coherent(rmu->dev, 512 * DOORBELL_MESSAGE_SIZE,
			 dbell->ring.virt, dbell->ring.phys);
		dev_err(rmu->dev, "unable to request inbound doorbell irq");
		return rc;
	}

	/* Configure doorbells for snooping, 512 entries, and enable */
	out_be32(&dbell->regs->dmr, 0x00108161);

	return 0;
}

static int rmu_mmu_port_init(struct rio_mport *mport)
{
	struct rio_mport_priv *mprv = mport->priv;
	struct rmu_private *rmu;
	struct rmu_msg_port *rmu_port;
	struct device_node *node;
	struct device *dev;
	u64 msg_start;
	int id;

	rmu = mprv->sriodev->mmu_handle;
	id = mport->index;
	dev = rmu->dev;

	node = rmu->mu_np[id];
	if (!node) {
		dev_warn(dev, "Can't get property 'fsl,rmu'\n");
		return -EINVAL;
	}

	rmu_port = devm_kzalloc(rmu->dev, sizeof(*rmu_port), GFP_KERNEL);
	if (!rmu_port)
		return -ENOMEM;
	rmu_port->rmu_regs = rmu->regs;
	rmu_port->rmu = rmu;
	rmu_port->dev = dev;

	if (of_property_read_reg(node, 0, &msg_start, NULL)) {
		dev_err(rmu->dev, "%pOF: no 'reg' property of message-unit\n",
			node);
		return -ENOMEM;
	}
	rmu_port->regs = (struct rmu_msg_regs *)
		(rmu->rio_regs + msg_start);

	rmu_port->txirq = irq_of_parse_and_map(node, 0);
	rmu_port->rxirq = irq_of_parse_and_map(node, 1);

	mport->ops->dsend		= rmu_dsend,
	mport->ops->pwenable		= rmu_pwenable,
	mport->ops->open_outb_mbox	= rmu_open_outb_mbox,
	mport->ops->open_inb_mbox	= rmu_open_inb_mbox,
	mport->ops->close_outb_mbox	= rmu_close_outb_mbox,
	mport->ops->close_inb_mbox	= rmu_close_inb_mbox,
	mport->ops->add_outb_message	= rmu_add_outb_message,
	mport->ops->add_inb_buffer	= rmu_add_inb_buffer,
	mport->ops->get_inb_message	= rmu_get_inb_message,

	mprv->mmu_handle = rmu_port;

	rio_init_dbell_res(&mport->riores[RIO_DOORBELL_RESOURCE], 0, 0xffff);
	rio_init_mbox_res(&mport->riores[RIO_INB_MBOX_RESOURCE], 0, 0);
	rio_init_mbox_res(&mport->riores[RIO_OUTB_MBOX_RESOURCE], 0, 0);

	return 0;
}

static void rmu_mmu_exit(struct srio_dev *sriodev)
{
	struct rmu_private *rmu_priv = sriodev->mmu_handle;

	kfifo_free(&rmu_priv->pw.fifo);
}

int fsl_rio_mmu_init(struct srio_dev *sriodev)
{
	struct rmu_private *rmu;
	struct device_node *np;
	struct device *dev = sriodev->dev;
	int rc;
	u64 range_start;

	rmu = devm_kzalloc(dev, sizeof(*rmu), GFP_KERNEL);
	if (!rmu)
		return -ENOMEM;

	rmu->sriodev = sriodev;
	rmu->dev = dev;
	rmu->rio_regs = sriodev->regs;

	/* Setup RMU */
	np = of_parse_phandle(dev_of_node(dev),
			      "fsl,srio-rmu-handle", 0);
	if (!np) {
		dev_err(dev, "No valid fsl,srio-rmu-handle property\n");
		return -ENODEV;
	}
	rmu->regs = devm_of_iomap(dev, np, 0, NULL);
	of_node_put(np);
	if (IS_ERR(rmu->regs))
		return PTR_ERR(rmu->regs);

	rc = 0;
	for_each_compatible_node(np, NULL, "fsl,srio-msg-unit")
		rmu->mu_np[rc++] = np;

	/* Setup doorbell */
	np = of_find_compatible_node(NULL, NULL, "fsl,srio-dbell-unit");
	if (!np) {
		dev_err(dev, "No fsl,srio-dbell-unit node\n");
		return -ENODEV;
	}
	rmu->dbell.irq = irq_of_parse_and_map(np, 1);

	if (of_property_read_reg(np, 0, &range_start, NULL)) {
		dev_err(dev, "%pOF: unable to find 'reg' property\n", np);
		return -ENOMEM;
	}
	rmu->dbell.regs =
		(struct rmu_dbell_regs *)(rmu->regs + range_start);

	of_node_put(np);

	/* Setup port write */
	np = of_find_compatible_node(NULL, NULL, "fsl,srio-port-write-unit");
	if (!np) {
		dev_err(dev, "No fsl,srio-port-write-unit node\n");
		return -ENODEV;
	}

	rmu->pw.irq = irq_of_parse_and_map(np, 0);

	if (of_property_read_reg(np, 0, &range_start, NULL)) {
		dev_err(dev, "%pOF: unable to find 'reg' property\n", np);
		return -ENOMEM;
	}
	rmu->pw.regs = (struct rmu_pw_regs *)(rmu->regs + range_start);

	rmu_dbell_init(rmu);
	rmu_pwrite_init(rmu);

	sriodev->mmu_exit = rmu_mmu_exit;
	sriodev->mmu_port_init = rmu_mmu_port_init;
	sriodev->mmu_name = "QorIQ RMU";

	/* Set this last */
	sriodev->mmu_handle = rmu;

	return 0;
}

static const struct of_device_id fsl_rio_ids[] = {
	{
		.compatible = "fsl,srio",
	},
	{},
};

struct platform_driver fsl_rio_driver = {
	.driver = {
		.owner = THIS_MODULE,
		.name = "fsl-rio-rmu",
		.of_match_table = fsl_rio_ids,
	},
	.probe = fsl_rio_probe,
	.remove = fsl_rio_remove,
};

MODULE_DESCRIPTION("QorIQ SRIO-RMU Controller");
