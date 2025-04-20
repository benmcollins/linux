/*
 * Copyright 2011-2013 Freescale Semiconductor, Inc.
 *
 * Author: Kai Jiang <Kai.Jiang@freescale.com>
 *
 * This program is free software; you can redistribute  it and/or modify it
 * under  the terms of  the GNU General  Public License as published by the
 * Free Software Foundation;  either version 2 of the  License, or (at your
 * option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the  GNU General Public License along
 * with this program; if not, write  to the Free Software Foundation, Inc.,
 * 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include <linux/kernel.h>
#include <linux/of_address.h>
#include <linux/of_irq.h>
#include <linux/platform_device.h>
#include <linux/of_platform.h>
#include <linux/io.h>
#include <linux/module.h>
#include <linux/uio_driver.h>
#include <linux/list.h>
#include <linux/dma-mapping.h>

#define SRIO_POOL_SIZE  0x1000000

#define EPWISR	 0x10010 /* Error/Port-Write Interrupt Status */
#define IECSR	 0x10130 /* Port Implementation Err Cmd & Status */
#define ESCSR	 0x00158 /* Port Error and Status Cmd & Status */
#define EDCSR	 0x00640 /* Port Error Detect Cmd & Status */
#define LTLEDCSR 0x00608 /* Logical/Transport Layer Err Detect Cmd & Status */
#define LTLEECSR 0x0060c /* Logical/Transport Layer Err Enable Cmd & Status */
#define SRIO_ESCSR_CLEAR 0x07120204
#define SRIO_IECSR_CLEAR 0x80000000

struct srio_uio_info {
	atomic_t ref;
	struct uio_info uio;
	char name[32];
};

struct srio_port_info {
	struct device *dev;
	struct srio_uio_info *info;
	struct resource res;
	void __iomem *window;
	struct list_head list;
	u32 port_id;
};

struct srio_regs_info {
	struct device *dev;
	struct srio_uio_info *info;
	struct resource *res;
	void __iomem *regs_win;
};

struct srio_dev {
	struct device *dev;
	struct srio_regs_info regs;
	struct list_head port_list;
	int irq;
	u32 port_num;
};

static const char srio_uio_version[] = "SRIO UIO driver v1.0";

static int srio_uio_open(struct uio_info *info, struct inode *inode)
{
	struct srio_uio_info *i = container_of(info, struct srio_uio_info, uio);

	if (atomic_dec_return(&i->ref) < 0) {
		pr_err("%s: failing open()\n", i->name);
		atomic_inc(&i->ref);
		return -EBUSY;
	}

	return 0;
}

static int srio_uio_release(struct uio_info *info, struct inode *inode)
{
	struct srio_uio_info *i = container_of(info, struct srio_uio_info, uio);

	atomic_inc(&i->ref);

	return 0;
}

static irqreturn_t srio_uio_irq_handler(int irq, struct uio_info *dev_info)
{
	struct srio_dev *sriodev = dev_info->priv;
	int i;
	unsigned int port_bits, ltledcsr;

	ltledcsr = in_be32(sriodev->regs.regs_win + LTLEDCSR);
	port_bits = in_be32(sriodev->regs.regs_win + EPWISR);

	if (!port_bits && !ltledcsr)
		return IRQ_NONE;

	if (ltledcsr)
		/* Disable logical/transport layer error interrupt */
		out_be32(sriodev->regs.regs_win + LTLEECSR, 0);

	for (i = 0; i < sriodev->port_num; i++) {
			/* Clear retry error threshold exceeded */
			out_be32(sriodev->regs.regs_win + IECSR + 0x80 * i,
				 SRIO_IECSR_CLEAR);
			/* Clear ESCSR */
			out_be32(sriodev->regs.regs_win + ESCSR + 0x20 * i,
				 SRIO_ESCSR_CLEAR);
			/* Clear EDCSR */
			out_be32(sriodev->regs.regs_win + EDCSR + 0x40 * i,
				 0);
	}

	return IRQ_HANDLED;
}

static int srio_uio_setup(struct srio_dev *sriodev,
			  struct srio_port_info *srio_port)
{
	struct srio_uio_info *info;
	struct resource *res;
	int err;

	info = devm_kzalloc(sriodev->dev, sizeof(struct srio_uio_info),
			    GFP_KERNEL);
	if (!info)
		return -ENOMEM;

	atomic_set(&info->ref, 1);

	if (srio_port) {
		res = &srio_port->res;
		srio_port->info = info;
		snprintf(info->name, sizeof(info->name) - 1,
			 "srio-uio-port%d", srio_port->port_id);
	} else {
		struct uio_mem *mem = &info->uio.mem[1];
		void *addr;

		res = sriodev->regs.res;
		sriodev->regs.info = info;
		snprintf(info->name, sizeof(info->name) - 1, "srio-uio-regs");
		info->uio.irq = sriodev->irq;

		mem->memtype = UIO_MEM_PHYS;
		mem->name = "dma-space";
		mem->size = SRIO_POOL_SIZE;

		addr = dma_alloc_coherent(sriodev->dev, mem->size,
					  &mem->dma_addr, GFP_KERNEL);
		mem->addr = addr ? (uintptr_t) addr : DMA_MAPPING_ERROR;
	}

	info->uio.mem[0].memtype = UIO_MEM_PHYS;
	info->uio.mem[0].name = info->name;
	info->uio.mem[0].addr = res->start;
	info->uio.mem[0].size =	res->end - res->start + 1;

	info->uio.name = info->name;
	info->uio.version = srio_uio_version;

	info->uio.irq_flags = IRQF_SHARED;
	info->uio.handler = srio_uio_irq_handler;
	info->uio.open = srio_uio_open;
	info->uio.release = srio_uio_release;
	info->uio.priv = sriodev;

	err = uio_register_device(sriodev->dev, &info->uio);
	if (err) {
		dev_err(sriodev->dev, "srio: uio registration failed\n");
		return err;
	}

        return 0;
}



static int srio_uio_init(struct srio_dev *sriodev)
{
	struct srio_port_info *srio_port;
	int err;

	srio_uio_setup(sriodev, NULL);

	list_for_each_entry(srio_port, &sriodev->port_list, list) {
		err = srio_uio_setup(sriodev, srio_port);
		if (err < 0)
			return err;
	}

	return 0;
}

static int srio_uio_cleanup(struct srio_dev *sriodev)
{
	struct srio_port_info *srio_port, *port_tmp;

	list_for_each_entry_safe(srio_port, port_tmp,
				 &sriodev->port_list, list) {
		uio_unregister_device(&srio_port->info->uio);
		list_del(&srio_port->list);
	}

	uio_unregister_device(&sriodev->regs.info->uio);

	return 0;
}

static int fsl_srio_uio_probe_port(struct device *dev, void *data)
{
	struct srio_dev *srio_dev = data;
	struct srio_port_info *srio_port;
	int err, len;
	const u32 *idx;

	idx = of_get_property(dev_of_node(dev), "cell-index", &len);
	if (!idx) {
		dev_err(dev, "missing cell-index property\n");
		return -EINVAL;
	}

	srio_port = devm_kzalloc(srio_dev->dev, sizeof(struct srio_port_info),
				 GFP_KERNEL);
	if (!srio_port)
		return -ENOMEM;

	err = of_range_to_resource(dev_of_node(dev), 0, &srio_port->res);
	if (err < 0)
		return err;

	srio_port->window = devm_ioremap_resource(srio_dev->dev,
						  &srio_port->res);
	if (IS_ERR(srio_port->window))
		return PTR_ERR(srio_port->window);

	dev_set_drvdata(dev, srio_port);

	srio_port->port_id = *idx;
	srio_port->dev = dev;

	srio_dev->port_num++;
	list_add_tail(&srio_port->list, &srio_dev->port_list);

	dev_info(srio_dev->dev, "port %d: %pR\n",
		 srio_port->port_id, &srio_port->res);

	return 0;
}

static void fsl_srio_port_remove(struct srio_dev *srio_dev)
{
	struct srio_port_info *srio_port, *port_tmp;

	list_for_each_entry_safe(srio_port, port_tmp,
				 &srio_dev->port_list, list)
		list_del(&srio_port->list);
}

static int fsl_srio_uio_probe(struct platform_device *dev)
{
	struct srio_dev *srio_dev;
	int err;

	srio_dev = devm_kzalloc(&dev->dev, sizeof(struct srio_dev), GFP_KERNEL);
	if (!srio_dev)
		return -ENOMEM;

	srio_dev->dev = &dev->dev;
	platform_set_drvdata(dev, srio_dev);
	INIT_LIST_HEAD(&srio_dev->port_list);

	srio_dev->regs.regs_win =
		devm_platform_get_and_ioremap_resource(dev, 0,
					&srio_dev->regs.res);

	if (IS_ERR(srio_dev->regs.regs_win))
		return PTR_ERR(srio_dev->regs.regs_win);

	srio_dev->irq = platform_get_irq(dev, 0);

	dev_info(&dev->dev, "srio device: %pR\n", srio_dev->regs.res);

	err = device_for_each_child(&dev->dev, srio_dev,
				    fsl_srio_uio_probe_port);
	if (err < 0) {
		fsl_srio_port_remove(srio_dev);
		return err;
	}

	err = srio_uio_init(srio_dev);
	if (err < 0) {
		srio_uio_cleanup(srio_dev);
		return err;
	}

	return 0;
}

static void fsl_srio_uio_remove(struct platform_device *dev)
{
	struct srio_dev *srio_dev = platform_get_drvdata(dev);

	srio_uio_cleanup(srio_dev);
}

static const struct of_device_id fsl_srio_uio_match[] = {
	{
		.compatible = "fsl,srio",
	},
	{}
};

static struct platform_driver fsl_of_srio_driver = {
	.driver = {
		.owner = THIS_MODULE,
		.name = "fsl,srio-uio",
		.of_match_table = fsl_srio_uio_match,
	},
	.probe = fsl_srio_uio_probe,
	.remove = fsl_srio_uio_remove,
};

static __init int fsl_srio_uio_init(void)
{
	return platform_driver_register(&fsl_of_srio_driver);
}

static void __exit fsl_srio_uio_exit(void)
{
	platform_driver_unregister(&fsl_of_srio_driver);
}

module_init(fsl_srio_uio_init);
module_exit(fsl_srio_uio_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("UIO Driver for Freescale Serial RapidIO devices");
