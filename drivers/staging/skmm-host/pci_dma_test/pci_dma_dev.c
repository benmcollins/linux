/*
 * Copyright 2013 Freescale Semiconductor, Inc.
 *
 * Author: Minghuan Lian <Minghuan.Lian@freescale.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License, version 2, as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 */

#include <linux/kernel.h>
#include <linux/pci.h>
#include <linux/pci_ids.h>
#include <linux/of_device.h>
#include <linux/device.h>
#include <linux/interrupt.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/version.h>

#include "pci_dma_test.h"

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 15, 0))
/**
 * DEFINE_PCI_DEVICE_TABLE - macro used to describe a pci device table
 * @_table: device table name
 *
 * This macro is used to create a struct pci_device_id array (a device table)
 * in a generic manner.
 */
#define DEFINE_PCI_DEVICE_TABLE(_table) \
        const struct pci_device_id _table[]
#endif

static const char *driver_name = "FSL-PCIDMA-driver";

#define PCI_DEVICE_ID_T4240 0x0440

LIST_HEAD(pcidma_list);

static unsigned int num_vfs;
module_param(num_vfs, uint, S_IRUGO);
MODULE_PARM_DESC(num_vfs, "Number of PCI VFs to initialize");

static void pcidma_dev_release(struct device *dev)
{
	/* nothing to do */
}

static void pcidma_class_release(struct class *cls)
{
	/* nothing to do */
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,11,0)
struct attribute *pcidma_attrs [] = {
	&pcidma_attributes[0].attr,
	&pcidma_attributes[1].attr,
	&pcidma_attributes[2].attr,
	&pcidma_attributes[3].attr,
	&pcidma_attributes[4].attr,
	&pcidma_attributes[5].attr,
	&pcidma_attributes[6].attr,
	&pcidma_attributes[7].attr,
	&pcidma_attributes[8].attr,
	&pcidma_attributes[9].attr,
	&pcidma_attributes[10].attr,
	&pcidma_attributes[11].attr,
	NULL,
};

ATTRIBUTE_GROUPS(pcidma);
#endif

static struct class pcidma_class = {
	.name = "pcidma",
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,11,0)
	.dev_groups = pcidma_groups,
#else
	.dev_attrs = pcidma_attributes,
#endif
	.dev_release = pcidma_dev_release,
	.class_release = pcidma_class_release,
};

static int pcidma_class_init(void)
{
	int ret;

	ret = class_register(&pcidma_class);
	if (ret) {
		pr_err("class_register failed for pcidma\n");
		return -EINVAL;
	}

	return 0;
}

static void pcidma_class_free(void)
{
	class_unregister(&pcidma_class);
}

static irqreturn_t pcidma_intr(int irq, void *data)
{
	struct fsl_pcidma_dev *pcidma = data;

	pr_debug("%s gets pcidma_intr interrupt %d\n", pcidma->name, irq);
	return IRQ_HANDLED;
}

static irqreturn_t pcidma_intr_msi(int irq, void *data)
{
	struct fsl_pcidma_dev *pcidma = data;

	pr_debug("%s gets pcidma_intr_msi interrupt %d\n", pcidma->name, irq);
	return IRQ_HANDLED;
}

static irqreturn_t pcidma_intr_msix_other(int irq, void *data)
{
	struct fsl_pcidma_dev *pcidma = data;

	pr_debug("%s gets msix_other interrupt %d\n", pcidma->name, irq);
	return IRQ_HANDLED;
}

static irqreturn_t pcidma_intr_msix_tx(int irq, void *data)
{
	struct fsl_pcidma_dev *pcidma = data;

	pr_debug("%s gets msix_tx interrupt %d\n", pcidma->name, irq);
	return IRQ_HANDLED;
}

static irqreturn_t pcidma_intr_msix_rx(int irq, void *data)
{
	struct fsl_pcidma_dev *pcidma = data;

	pr_debug("%s gets msix_rx interrupt %d\n", pcidma->name, irq);
	return IRQ_HANDLED;
}

void pcidma_reset_interrupt_capability(struct fsl_pcidma_dev *pcidma)
{
	if (pcidma->msix_entries) {
		pci_disable_msix(pcidma->pdev);
		kfree(pcidma->msix_entries);
		pcidma->msix_entries = NULL;
	} else if (pcidma->flags & FLAG_MSI_ENABLED) {
		pci_disable_msi(pcidma->pdev);
		pcidma->flags &= ~FLAG_MSI_ENABLED;
	}
}

/*
 * pcidma_set_interrupt_capability - set MSI or MSI-X if supported
 *
 * Attempt to configure interrupts using the best available
 * capabilities of the hardware and kernel.
 */
void pcidma_set_interrupt_capability(struct fsl_pcidma_dev *pcidma, int mode)
{
	int err, i;

	/* Check whether the device has MSIx cap */
	switch (mode) {
	case PCIDMA_INT_MODE_MSIX:
		if (pci_find_capability(pcidma->pdev, PCI_CAP_ID_MSIX)) {
			pcidma->num_vectors = 3; /* RxQ0, TxQ0 and other */
			pcidma->msix_entries =
					kcalloc(pcidma->num_vectors,
						sizeof(struct msix_entry),
						GFP_KERNEL);
			if (pcidma->msix_entries) {
				for (i = 0; i < pcidma->num_vectors; i++)
					pcidma->msix_entries[i].entry = i;

#if (LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0))
				err = 
                                    pci_enable_msix(pcidma->pdev,
						      pcidma->msix_entries,
						      pcidma->num_vectors);
#else
				err = 
                                    pci_enable_msix_exact(pcidma->pdev,
						      pcidma->msix_entries,
						      pcidma->num_vectors);
#endif
				if (err == 0) {
					pcidma->int_mode = PCIDMA_INT_MODE_MSIX;
					return;
				}
			}

			/* MSI-X failed, so fall through and try MSI */
			dev_warn(&pcidma->dev,
				 "Failed to initialize MSI-X interrupts.  Falling back to MSI interrupts.\n");
			pcidma_reset_interrupt_capability(pcidma);
		}

		/* Fall through */
	case PCIDMA_INT_MODE_MSI:
		if (!pci_enable_msi(pcidma->pdev)) {
			pcidma->flags &= FLAG_MSI_ENABLED;
			pcidma->int_mode = PCIDMA_INT_MODE_MSI;
		} else
			dev_warn(&pcidma->dev,
				 "Failed to initialize MSI interrupts.  Falling back to legacy interrupts.\n");
		/* Fall through */
	case PCIDMA_INT_MODE_LEGACY:
		pcidma->int_mode = PCIDMA_INT_MODE_LEGACY;
		break;
	case PCIDMA_INT_MODE_NONE:
		pcidma->int_mode = PCIDMA_INT_MODE_NONE;
		break;
	}
}

/*
 * pcidma_request_msix - Initialize MSI-X interrupts
 *
 * pcidma_request_msix allocates MSI-X vectors and requests interrupts from the
 * kernel.
 */

static int pcidma_request_msix(struct fsl_pcidma_dev *pcidma)
{
	int err = 0, vector = 0;

	snprintf(pcidma->rx_name, sizeof(pcidma->rx_name) - 1,
			 "%s-rx", pcidma->name);

	err = request_irq(pcidma->msix_entries[vector].vector,
			  pcidma_intr_msix_rx, 0, pcidma->rx_name, pcidma);
	if (err)
		return err;

	vector++;

	snprintf(pcidma->tx_name, sizeof(pcidma->tx_name) - 1,
		 "%s-tx", pcidma->name);

	err = request_irq(pcidma->msix_entries[vector].vector,
			  pcidma_intr_msix_tx, 0, pcidma->tx_name, pcidma);
	if (err)
		return err;

	vector++;

	err = request_irq(pcidma->msix_entries[vector].vector,
			  pcidma_intr_msix_other, 0, pcidma->name, pcidma);
	if (err)
		return err;

	return 0;
}

/**
 * pcidma_request_irq - initialize interrupts
 *
 * Attempts to configure interrupts using the best available
 * capabilities of the hardware and kernel.
 **/
static int pcidma_request_irq(struct fsl_pcidma_dev *pcidma)
{
	int err;

	if (PCIDMA_INT_MODE_NONE == pcidma->int_mode)
		return 0;

	if (PCIDMA_INT_MODE_MSIX == pcidma->int_mode) {
		err = pcidma_request_msix(pcidma);
		if (!err)
			return err;
		/* fall back to MSI */
		pcidma_reset_interrupt_capability(pcidma);
		pcidma_set_interrupt_capability(pcidma, PCIDMA_INT_MODE_MSI);
	}
	if (pcidma->flags & FLAG_MSI_ENABLED) {
		err = request_irq(pcidma->pdev->irq, pcidma_intr_msi, 0,
				  pcidma->name, pcidma);
		if (!err)
			return err;

		/* fall back to legacy interrupt */
		pcidma_reset_interrupt_capability(pcidma);
		pcidma_set_interrupt_capability(pcidma, PCIDMA_INT_MODE_LEGACY);
	}

	err = request_irq(pcidma->pdev->irq, pcidma_intr, IRQF_SHARED,
			  pcidma->name, pcidma);
	if (err)
		dev_err(&pcidma->dev,
			"Unable to allocate interrupt, Error: %d\n", err);

	return err;
}

static void pcidma_free_irq(struct fsl_pcidma_dev *pcidma)
{
	if (pcidma->int_mode == PCIDMA_INT_MODE_NONE)
		return;

	if (pcidma->msix_entries) {
		int vector = 0;

		free_irq(pcidma->msix_entries[vector].vector, pcidma);
		vector++;

		free_irq(pcidma->msix_entries[vector].vector, pcidma);
		vector++;

		/* Other Causes interrupt vector */
		free_irq(pcidma->msix_entries[vector].vector, pcidma);
		return;
	}

	free_irq(pcidma->pdev->irq, pcidma);
}

/*
 * pcidma_irq_disable - Mask off interrupt generation
 */

static void pcidma_irq_disable(struct fsl_pcidma_dev *pcidma)
{

	if (pcidma->msix_entries) {
		int i;
		for (i = 0; i < pcidma->num_vectors; i++)
			synchronize_irq(pcidma->msix_entries[i].vector);
	} else {
		synchronize_irq(pcidma->pdev->irq);
	}
}

/*
 * pcidma_irq_enable - Enable default interrupt generation settings
 */
static void pcidma_irq_enable(struct fsl_pcidma_dev *pcidma)
{
	;
}

static int pcidma_vf_init(struct fsl_pcidma_dev *pcidma)
{
	struct pci_dev *pdev = pcidma->pdev;
	struct vf_info *vf;
	int pos;

	if (!pci_is_pcie(pdev))
		return -ENODEV;

	pos = pci_find_ext_capability(pdev, PCI_EXT_CAP_ID_SRIOV);
	if (!pos)
		return 0;

	vf = kzalloc(sizeof(*vf), GFP_KERNEL);
	if (!vf)
		return 0;
	pcidma->vf = vf;

	pci_read_config_word(pdev, pos + PCI_SRIOV_TOTAL_VF, &vf->total);
	if (!vf->total)
		return 0;

	if (num_vfs > vf->total)
		num_vfs = vf->total;

	vf->availbe_num = num_vfs;

	pci_read_config_word(pdev, pos + PCI_SRIOV_VF_OFFSET, &vf->offset);
	pci_read_config_word(pdev, pos + PCI_SRIOV_VF_STRIDE, &vf->stride);

	pci_enable_sriov(pdev, vf->availbe_num);

	dev_dbg(&pdev->dev, "offset is %d  stride is %d %d VFs allocated\n",
		vf->offset, vf->stride, vf->availbe_num);

	return 0;
}

static void pcidma_dev_free(struct fsl_pcidma_dev *pcidma)
{
	if (!pcidma)
		return;

	if (pcidma->config)
		pci_iounmap(pcidma->pdev, pcidma->config);

	pcidma_irq_disable(pcidma);
	pcidma_free_irq(pcidma);
	pcidma_reset_interrupt_capability(pcidma);

	pcidma_test_info_free(pcidma->test_info);

	device_unregister(&pcidma->dev);

	/* Delete the device from list */
	if (pcidma->node.next)
		list_del(&pcidma->node);

	pci_set_drvdata(pcidma->pdev, NULL);
	kfree(pcidma);
}

static int pcidma_tune_caps(struct pci_dev *pdev)
{
	struct pci_dev *parent;
	u16 pcaps, ecaps, ctl;
	int rc_sup, ep_sup;

	/* Find out supported and configured values for parent (root) */
	parent = pdev->bus->self;
	if (parent->bus->parent) {
		dev_info(&pdev->dev, "Parent not root\n");
		return -EINVAL;
	}

	if (!pci_is_pcie(parent) || !pci_is_pcie(pdev))
		return -EINVAL;

	pcie_capability_read_word(parent, PCI_EXP_DEVCAP, &pcaps);
	pcie_capability_read_word(pdev, PCI_EXP_DEVCAP, &ecaps);

	/* Find max payload supported by root, endpoint */
	rc_sup = pcaps & PCI_EXP_DEVCAP_PAYLOAD;
	ep_sup = ecaps & PCI_EXP_DEVCAP_PAYLOAD;

	if (rc_sup > ep_sup)
		rc_sup = ep_sup;

	pcie_capability_clear_and_set_word(parent, PCI_EXP_DEVCTL,
					   PCI_EXP_DEVCTL_PAYLOAD, rc_sup << 5);

	pcie_capability_clear_and_set_word(pdev, PCI_EXP_DEVCTL,
					   PCI_EXP_DEVCTL_PAYLOAD, rc_sup << 5);

	pcie_capability_read_word(pdev, PCI_EXP_DEVCTL, &ctl);
	dev_dbg(&pdev->dev, "MAX payload size is %dB, MAX read size is %dB.\n",
		128 << ((ctl & PCI_EXP_DEVCTL_PAYLOAD) >> 5),
		128 << ((ctl & PCI_EXP_DEVCTL_READRQ) >> 12));

	return 0;
}

static struct fsl_pcidma_dev *pcidma_dev_init(struct pci_dev *pdev)
{
	struct fsl_pcidma_dev *pcidma;
	static int pcidma_num;
	int i;

	pcidma = kzalloc(sizeof(*pcidma), GFP_KERNEL);
	if (!pcidma) {
		dev_err(&pdev->dev, "failed to kzalloc for pcidma\n");
		return NULL;
	}

	pcidma->dev.parent = &pdev->dev;
	pcidma->pdev = pdev;
	pci_set_drvdata(pdev, pcidma);

	pcidma->dev.bus = NULL;
	pcidma->dev.class = &pcidma_class;

	dev_set_name(&pcidma->dev, "pcidma%d", pcidma_num++);
	pcidma->name = dev_name(&pcidma->dev);

	if (device_register(&pcidma->dev)) {
		dev_err(&pdev->dev, "failed to register pcidma\n");
		kfree(pcidma);
		return NULL;
	}

	/* Get the BAR resources and remap them into the driver memory */
	for (i = 0; i < PCI_MAX_BAR; i++) {
		/* Read the hardware address */
		pcidma->bars[i].phy_addr = pci_resource_start(pdev, i);
		pcidma->bars[i].size = pci_resource_len(pdev, i);
		dev_dbg(&pdev->dev, "BAR:%d  addr:0x%llx len:0x%llx\n",
			 i, pcidma->bars[i].phy_addr,
			 (u64)pcidma->bars[i].size);
	}

	/* Map the MEM to the kernel address space */
	pcidma->config = pci_iomap(pdev, PCI_CONFIG_BAR, 0);
	if (!pcidma->config) {
		dev_err(&pdev->dev,
			"%s failed to Map config space\n", pci_name(pdev));
		goto _err;
	}

	pcidma_set_interrupt_capability(pcidma, PCIDMA_INT_MODE_MSIX);
	pcidma_request_irq(pcidma);
	pcidma_irq_enable(pcidma);

	/* Init VF */
	pcidma_vf_init(pcidma);

	pcidma->test_info = pcidma_test_info_init(pcidma);
	if (!pcidma->test_info)
		goto _err;

	dev_info(&pdev->dev, "initialized and associated with %s\n",
		 dev_name(&pcidma->dev));

	list_add_tail(&pcidma->node, &pcidma_list);
	return pcidma;

_err:
	pcidma_dev_free(pcidma);
	return NULL;
}


static int fsl_pcidma_dev_probe(struct pci_dev *pdev,
				const struct pci_device_id *id)
{
	int err;
	struct fsl_pcidma_dev *pcidma;

	err = pci_enable_device(pdev);
	if (err) {
		dev_err(&pdev->dev, "failed to enable\n");
		return err;
	}

	err = pci_request_regions(pdev, driver_name);
	if (err) {
		dev_err(&pdev->dev, "failed to request pci regions\n");
		goto _err;
	}

	pci_set_master(pdev);

	err = dma_set_mask(&pdev->dev, DMA_BIT_MASK(64));
	if (err) {
		err = dma_set_mask(&pdev->dev, DMA_BIT_MASK(32));
		if (err) {
			dev_err(&pdev->dev, "Could not set PCI DMA Mask\n");
			goto _err;
		}
	}

	pcidma_tune_caps(pdev);

	/* Allocate memory for the new PCI device data structure */
	pcidma = pcidma_dev_init(pdev);
	if (!pcidma) {
		err = -EINVAL;
		goto _err;
	}

	return 0;

_err:
	pci_disable_device(pdev);
	return err;
}

static void fsl_pcidma_dev_remove(struct pci_dev *pdev)
{
	struct fsl_pcidma_dev *pcidma = pci_get_drvdata(pdev);

	if (!pcidma)
		return;

	pcidma_dev_free(pcidma);

	pci_release_regions(pdev);

	pci_disable_device(pdev);
}

#define PCI_DEVICE_ID_T2080 0x0830
#define PCI_DEVICE_ID_T2080_VF_PF0 0
#define PCI_DEVICE_ID_T2080_VF_PF1 0x1957

static DEFINE_PCI_DEVICE_TABLE(fsl_pci_dev_ids) = {
	{ PCI_DEVICE(PCI_VENDOR_ID_FREESCALE, PCI_DEVICE_ID_T4240) },
	{ PCI_DEVICE(PCI_VENDOR_ID_FREESCALE, PCI_DEVICE_ID_P4080) },
	{ PCI_DEVICE(PCI_VENDOR_ID_FREESCALE, PCI_DEVICE_ID_P5020) },
	{ PCI_DEVICE(PCI_VENDOR_ID_FREESCALE, PCI_DEVICE_ID_P5020E) },
	{ PCI_DEVICE(PCI_VENDOR_ID_FREESCALE, PCI_DEVICE_ID_P3041) },
	{ PCI_DEVICE(PCI_VENDOR_ID_FREESCALE, 0) },
	{ PCI_DEVICE(PCI_VENDOR_ID_FREESCALE, 0x13) },
	/* For T2080 */
	{ PCI_DEVICE(PCI_VENDOR_ID_FREESCALE, PCI_DEVICE_ID_T2080) },
	{ PCI_DEVICE(PCI_VENDOR_ID_FREESCALE, PCI_DEVICE_ID_T2080_VF_PF0) },
	{ PCI_DEVICE(PCI_VENDOR_ID_FREESCALE, PCI_DEVICE_ID_T2080_VF_PF1) },
	{ 0 },
};

static struct pci_driver fsl_pcidma_dev_driver = {
	.name		= "FSL-PCIDMA-Driver",
	.id_table	= fsl_pci_dev_ids,
	.probe		= fsl_pcidma_dev_probe,
	.remove		= fsl_pcidma_dev_remove
};

static int __init fsl_pcidma_dev_init(void)
{
	int err = 0;

	pr_info("FSL PCI DMA Test Driver.\n");

	err = pcidma_class_init();
	if (err)
		return err;

	err = pci_register_driver(&fsl_pcidma_dev_driver);
	if (err) {
		pr_err("%s:%d pci_register_driver() failed\n",
			__func__, __LINE__);
		pcidma_class_free();
		return err;
	}

	return 0;
}

static void __exit fsl_pcidma_dev_exit(void)
{
	pr_err("Exit from FSL PCI DMA driver\n");
	pci_unregister_driver(&fsl_pcidma_dev_driver);
	pcidma_class_free();
	return;
}

module_init(fsl_pcidma_dev_init);
module_exit(fsl_pcidma_dev_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Minghuan Lian <Minghuan.Lian@freescale.com>");
MODULE_DESCRIPTION("Freescale PCI DMA Test Driver");
MODULE_VERSION("Version 1.0.0");
