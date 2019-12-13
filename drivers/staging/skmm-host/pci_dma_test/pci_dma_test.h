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

#ifndef _PCI_DMA_TEST_H
#define _PCI_DMA_TEST_H

#include <linux/device.h>
#include <linux/pci.h>
#include "pciep_dma_cfg.h"

#define MAX_LENS_NUM 16

#define FLAG_MSI_ENABLED 1

/* Interrupt modes, as used by the IntMode parameter */
#define PCIDMA_INT_MODE_NONE		0
#define PCIDMA_INT_MODE_LEGACY		1
#define PCIDMA_INT_MODE_MSI		2
#define PCIDMA_INT_MODE_MSIX		3

/* PCI bar types */
enum pci_bars {
	PCI_CCSR_BAR = 0,
	PCI_MSIX_BAR,
	PCI_CONFIG_BAR,
	PCI_IDLE_BAR,
	PCI_BUFF_BAR,
	PCI_MAX_BAR
};

enum PCIDMA_TEST_STATUS {
	TEST_READY,
	TEST_START,
	TEST_DONE,
	TEST_ERROR
};

struct pci_bar_info {
	phys_addr_t phy_addr;
	size_t size;
};

struct pcidma_test_info {
	struct fsl_pcidma_dev *pcidma;
	spinlock_t lock;
	int status;
	int verify;
	int rc2ep;
	int ep2rc;
	struct task_struct *rc2ep_thread;
	struct task_struct *ep2rc_thread;
	struct completion rc2ep_thread_done;
	struct completion ep2rc_thread_done;
	int rc2ep_core;
	int ep2rc_core;
	int multi_dev;
	int dma_enable;
	int write;
	int read;
	u32 loop;
	u32 lens_num;
	u32 lens[MAX_LENS_NUM];
	u64 rc2ep_results[2][MAX_LENS_NUM]; /* RC to EP write/read results */
	u64 ep2rc_results[2][MAX_LENS_NUM]; /* EP to RC write/read results */
};

struct pcidma_test {
	int status;
	struct pcidma_test_info *info;
	struct pcidma_config *config;
	u32 loop;
	enum rw_type type;
	size_t len;
	void *local;
	void *remote;
	dma_addr_t local_addr;
	dma_addr_t remote_addr;
	struct dma_chan *chan;
	struct completion done;
	u64 result;
};

struct vf_info {
	u16 total;
	u16 offset;
	u16 stride;
	u16 availbe_num;
};

struct fsl_pcidma_dev {
	struct list_head node;
	const char *name;
	int flags;
	int int_mode;
	struct pci_dev *pdev;
	struct device dev;
	struct pcidma_config *config;
	struct pci_bar_info bars[PCI_MAX_BAR];
	int vf_enabled;
	struct vf_info *vf;
	int num_vectors;
	struct msix_entry *msix_entries;
	char rx_name[32];
	char tx_name[32];

	struct pcidma_test_info *test_info;
};

extern struct device_attribute pcidma_attributes[];

int pcidma_test_start(struct fsl_pcidma_dev *pcidma);

struct pcidma_test_info *pcidma_test_info_init(struct fsl_pcidma_dev *pcidma);
void pcidma_test_info_free(struct pcidma_test_info *info);

bool pcidma_test_running(struct pcidma_test_info *info);
bool pcidma_test_done(struct pcidma_test_info *info);
#endif /* _PCI_DMA_TEST_H */
