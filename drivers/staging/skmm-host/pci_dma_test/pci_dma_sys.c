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
#include <linux/log2.h>
#include <linux/of.h>
#include <linux/of_device.h>
#include <linux/device.h>
#include <linux/eventfd.h>
#include <linux/interrupt.h>
#include <linux/iommu.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/dmaengine.h>

#include "pci_dma_test.h"

static struct fsl_pcidma_dev *get_pcidma(struct device *dev)
{
	return container_of(dev, struct fsl_pcidma_dev, dev);
}

static ssize_t
bars_info_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct fsl_pcidma_dev *pcidma = get_pcidma(dev);
	char *str = buf;
	int i;

	for (i = 0; i < PCI_MAX_BAR; i++) {
		str += sprintf(str, "PCI DMA BAR%d:\n"
				"\tcpu_addr:0x%016llx size:0x%016llx\n",
				i,
				pcidma->bars[i].phy_addr,
				(u64)pcidma->bars[i].size);
	}

	return str - buf;
}

static ssize_t
link_info_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct fsl_pcidma_dev *pcidma = get_pcidma(dev);
	char *str = buf, *speed;
	u16 link_status, width;

	pcie_capability_read_word(pcidma->pdev, PCI_EXP_LNKSTA, &link_status);

	switch (link_status & PCI_EXP_LNKSTA_CLS) {
	case PCI_EXP_LNKSTA_CLS_2_5GB:
		speed = "2.5GT/s";
		break;
	case PCI_EXP_LNKSTA_CLS_5_0GB:
		speed = "5GT/s";
		break;
	default:
		speed = "unknown";
		break;
	}

	width = (link_status & PCI_EXP_LNKSTA_NLW) >> PCI_EXP_LNKSTA_NLW_SHIFT;

	str += sprintf(str, "link info:\n");
	str += sprintf(str, "\tlink width:%dx  speed:%s\n", width, speed);

	return str - buf;
}

static ssize_t
config_info_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct fsl_pcidma_dev *pcidma = get_pcidma(dev);
	char *str = buf;

	if (!pcidma->config)
		return sprintf(buf, "NULL\n");

	str += sprintf(str, "\tstatus:0x%08x command:0x%08x\n",
			ioread32be(&pcidma->config->status),
			ioread32be(&pcidma->config->command));
	str += sprintf(str, "\trx config: addr:0x%llx, size:0x%x, loop:0x%x\n",
			(u64)ioread32be(&pcidma->config->rwcfg.hbar) << 32 |
			ioread32be(&pcidma->config->rwcfg.lbar),
			ioread32be(&pcidma->config->rwcfg.size),
			ioread32be(&pcidma->config->rwcfg.loop));

	return str - buf;
}

static ssize_t
test_write_store(struct device *dev, struct device_attribute *attr,
		const char *buf, size_t count)
{
	struct fsl_pcidma_dev *pcidma = get_pcidma(dev);
	struct pcidma_test_info *info = pcidma->test_info;

	if (!info || pcidma_test_running(info))
		return -EIO;

	if (kstrtoint(buf, 0, &info->write))
		return -EINVAL;

	return count;
}

static ssize_t
test_write_show(struct device *dev, struct device_attribute *attr,
		     char *buf)
{
	struct fsl_pcidma_dev *pcidma = get_pcidma(dev);
	struct pcidma_test_info *info = pcidma->test_info;

	if (!info)
		return -EIO;

	return sprintf(buf, "test write status: %s\n",
			info->write ? "enabled" : "disabled");
}

static ssize_t
test_read_store(struct device *dev, struct device_attribute *attr,
		const char *buf, size_t count)
{
	struct fsl_pcidma_dev *pcidma = get_pcidma(dev);
	struct pcidma_test_info *info = pcidma->test_info;

	if (!info || pcidma_test_running(info))
		return -EIO;

	if (kstrtoint(buf, 0, &info->read))
		return -EINVAL;

	return count;
}

static ssize_t
test_read_show(struct device *dev, struct device_attribute *attr,
		     char *buf)
{
	struct fsl_pcidma_dev *pcidma = get_pcidma(dev);
	struct pcidma_test_info *info = pcidma->test_info;

	if (!info)
		return -EIO;

	return sprintf(buf, "test read status: %s\n",
			info->read ? "enabled" : "disabled");
}

static ssize_t
test_info_rw_show(struct pcidma_test_info *info, char *buf, enum rw_type type)
{
	char *str = buf;
	int i;

	str += sprintf(str, "%s test info:\n",
		       type == RW_TYPE_WRITE ? "write" : "read");

	for (i = 0; i < info->lens_num; i++) {
		str += sprintf(str,
			       "\ttest%d packet length:%uB loop:%utimes\n",
			       i, info->lens[i], info->loop);

		if (info->rc2ep)
			str += sprintf(str,
				       "\t\tRC->EP throughput:%lldMbps\n",
				       info->rc2ep_results[type][i] / 1000000);
		if (info->ep2rc)
			str += sprintf(str, "\t\tEP->RC throughput:%lldMbps\n",
				info->ep2rc_results[type][i] / 1000000);
	}

	return str - buf;
}

static ssize_t
test_info_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct fsl_pcidma_dev *pcidma = get_pcidma(dev);
	struct pcidma_test_info *info = pcidma->test_info;
	char *str = buf;

	if (!info)
		return 0;

	if (!pcidma_test_done(info)) {
		str += sprintf(str, "There is no test info\n");
		return str - buf;
	}

	if (info->write)
		str += test_info_rw_show(info, str, RW_TYPE_WRITE);
	if (info->read)
		str += test_info_rw_show(info, str, RW_TYPE_READ);

	return str - buf;
}

static ssize_t
test_start_store(struct device *dev, struct device_attribute *attr,
		const char *buf, size_t count)
{
	struct fsl_pcidma_dev *pcidma = get_pcidma(dev);

	pr_info("test starting\n");
	pcidma_test_start(pcidma);

	return count;
}

static ssize_t
test_start_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct fsl_pcidma_dev *pcidma = get_pcidma(dev);
	struct pcidma_test_info *info = pcidma->test_info;

	if (!info)
		return 0;

	return sprintf(buf, "test status: %d\n", info->status);
}

static ssize_t
test_loop_store(struct device *dev, struct device_attribute *attr,
		const char *buf, size_t count)
{
	struct fsl_pcidma_dev *pcidma = get_pcidma(dev);
	struct pcidma_test_info *info = pcidma->test_info;

	if (!info || pcidma_test_running(info))
		return -EIO;

	if (kstrtouint(buf, 0, &info->loop))
		return -EINVAL;

	return count;
}

static ssize_t
test_loop_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct fsl_pcidma_dev *pcidma = get_pcidma(dev);
	struct pcidma_test_info *info = pcidma->test_info;

	if (!info)
		return -EIO;

	return sprintf(buf, "test loop: %u\n", info->loop);
}

static ssize_t
test_ep2rc_store(struct device *dev, struct device_attribute *attr,
		const char *buf, size_t count)
{
	struct fsl_pcidma_dev *pcidma = get_pcidma(dev);
	struct pcidma_test_info *info = pcidma->test_info;

	if (!info || pcidma_test_running(info))
		return -EIO;

	if (kstrtoint(buf, 0, &info->ep2rc))
		return -EINVAL;

	return count;
}

static ssize_t
test_ep2rc_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct fsl_pcidma_dev *pcidma = get_pcidma(dev);
	struct pcidma_test_info *info = pcidma->test_info;

	if (!info)
		return -EIO;

	return sprintf(buf, "test ep2rc: %s\n",
			info->ep2rc ? "true" : "false");
}

static ssize_t
test_rc2ep_store(struct device *dev, struct device_attribute *attr,
		const char *buf, size_t count)
{
	struct fsl_pcidma_dev *pcidma = get_pcidma(dev);
	struct pcidma_test_info *info = pcidma->test_info;

	if (!info || pcidma_test_running(info))
		return -EIO;

	if (kstrtoint(buf, 0, &info->rc2ep))
		return -EINVAL;

	return count;
}

static ssize_t
test_rc2ep_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct fsl_pcidma_dev *pcidma = get_pcidma(dev);
	struct pcidma_test_info *info = pcidma->test_info;

	if (!info)
		return -EIO;

	return sprintf(buf, "test rc2ep: %s\n",
			info->rc2ep ? "true" : "false");
}

static ssize_t
test_dma_enable_store(struct device *dev, struct device_attribute *attr,
		const char *buf, size_t count)
{
	struct fsl_pcidma_dev *pcidma = get_pcidma(dev);
	struct pcidma_test_info *info = pcidma->test_info;

	if (!info || pcidma_test_running(info))
		return -EIO;

	if (kstrtoint(buf, 0, &info->dma_enable))
		return -EINVAL;

	return count;
}

static ssize_t
test_dma_enable_show(struct device *dev, struct device_attribute *attr,
		     char *buf)
{
	struct fsl_pcidma_dev *pcidma = get_pcidma(dev);
	struct pcidma_test_info *info = pcidma->test_info;

	if (!info)
		return -EIO;

	return sprintf(buf, "test dma status: %s\n",
			info->dma_enable ? "enabled" : "disabled");
}

static ssize_t
test_length_store(struct device *dev, struct device_attribute *attr,
		  const char *buf, size_t count)
{
	struct fsl_pcidma_dev *pcidma = get_pcidma(dev);
	struct pcidma_test_info *info = pcidma->test_info;
	char *p, *str = (char *)buf;
	int i = 0, len;

	if (!info || pcidma_test_running(info))
		return -EIO;

	while ((p = strsep(&str, " "))) {
		if (kstrtouint(p, 0, &len))
			return -EINVAL;

		if (len > pcidma->bars[PCI_BUFF_BAR].size)
			return -EINVAL;

		info->lens[i++] = len;

		if (i >= MAX_LENS_NUM)
			break;
	}

	info->lens_num = i;

	return count;
}

static ssize_t
test_length_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct fsl_pcidma_dev *pcidma = get_pcidma(dev);
	struct pcidma_test_info *info = pcidma->test_info;
	char *str = buf;
	int i;

	if (!info)
		return -EIO;

	str += sprintf(str, "test length:");
	for (i = 0; i < info->lens_num; i++)
		str += sprintf(str, " %dB", info->lens[i]);
	str += sprintf(str, "\n");

	return str - buf;
}

struct device_attribute pcidma_attributes[] = {
	__ATTR_RO(link_info),
	__ATTR_RO(bars_info),
	__ATTR_RO(config_info),
	__ATTR_RO(test_info),
	__ATTR(test_start, S_IRUGO|S_IWUSR, test_start_show, test_start_store),
	__ATTR(test_write, S_IRUGO|S_IWUSR, test_write_show, test_write_store),
	__ATTR(test_read, S_IRUGO|S_IWUSR, test_read_show, test_read_store),
	__ATTR(test_ep2rc, S_IRUGO|S_IWUSR, test_ep2rc_show, test_ep2rc_store),
	__ATTR(test_rc2ep, S_IRUGO|S_IWUSR, test_rc2ep_show, test_rc2ep_store),
	__ATTR(test_dma_enable, S_IRUGO|S_IWUSR, test_dma_enable_show,
	       test_dma_enable_store),
	__ATTR(test_lens, S_IRUGO|S_IWUSR, test_length_show, test_length_store),
	__ATTR(test_loop, S_IRUGO|S_IWUSR, test_loop_show, test_loop_store),
	__ATTR_NULL,
};
