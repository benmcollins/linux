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
#include <linux/completion.h>
#include <linux/sched.h>
#include <linux/kthread.h>
#include <linux/cpumask.h>
#include <linux/delay.h>
#include <linux/dmaengine.h>
#include <linux/ktime.h>
#include <linux/version.h>

#include "pci_dma_test.h"

static void pcidma_test_status_set(struct pcidma_test_info *info,
		int status)
{
	spin_lock(&info->lock);
	info->status = status;
	spin_unlock(&info->lock);
}

bool pcidma_test_running(struct pcidma_test_info *info)
{
	bool running;

	spin_lock(&info->lock);
	running = info->status == TEST_START;
	spin_unlock(&info->lock);

	return running;
}

static int pcidma_test_try_run(struct pcidma_test_info *info)
{
	int ret;

	spin_lock(&info->lock);
	if (info->status == TEST_START)
		ret = -EBUSY;
	else {
		info->status = TEST_START;
		ret = 0;
	}
	spin_unlock(&info->lock);

	return ret;
}

bool pcidma_test_done(struct pcidma_test_info *info)
{
	bool done;

	spin_lock(&info->lock);
	done = info->status == TEST_DONE;
	spin_unlock(&info->lock);

	return done;
}

struct pcidma_test_info *pcidma_test_info_init(struct fsl_pcidma_dev *pcidma)
{
	struct pcidma_test_info *info;

	info = kzalloc(sizeof(*info), GFP_KERNEL);
	if (!info) {
		pr_err("failed to allocate mem for test info\n");
		return NULL;
	}

	info->pcidma = pcidma;
	spin_lock_init(&info->lock);
	info->rc2ep = 1;
	info->ep2rc = 1;
	info->write = 1;
	info->read = 1;
	info->dma_enable = 1;
	info->lens_num = 15;
	info->lens[0] = 64;
	info->lens[1] = 128;
	info->lens[2] = 256;
	info->lens[3] = 512;
	info->lens[4] = 1024;
	info->lens[5] = 2 * 1024;
	info->lens[6] = 4 * 1024;
	info->lens[7] = 8 * 1024;
	info->lens[8] = 16 * 1024;
	info->lens[9] = 32 * 1024;
	info->lens[10] = 64 * 1024;
	info->lens[11] = 128 * 1024;
	info->lens[12] = 256 * 1024;
	info->lens[13] = 512 * 1024;
	info->lens[14] = 1024 * 1024;
	info->loop = 50;
	pcidma_test_status_set(info, TEST_READY);

	return info;
}

void pcidma_test_info_free(struct pcidma_test_info *info)
{
	if (!info)
		return;

	while (pcidma_test_running(info))
		msleep(100);

	kfree(info);
}

void pcidma_test_info_dump(struct pcidma_test_info *info)
{
	int i;

	if (info->write) {
		pr_info("\n%s test info:\n", "write");

		for (i = 0; i < info->lens_num; i++) {
			pr_info("\ttest%d packet length:%uB loop:%utimes\n",
				i, info->lens[i], info->loop);
			if (info->rc2ep)
				pr_info("\t\tRC->EP throughput:%lldMbps\n",
					info->rc2ep_results[RW_TYPE_WRITE][i] /
					1000000);
			if (info->ep2rc)
				pr_info("\t\tEP->RC throughput:%lldMbps\n",
					info->ep2rc_results[RW_TYPE_WRITE][i] /
					1000000);
		}
	}

	if (info->read) {
		pr_info("\n%s test info:\n", "read");

		for (i = 0; i < info->lens_num; i++) {
			pr_info("\ttest%d packet length:%uB loop:%utimes\n",
				i, info->lens[i], info->loop);
			if (info->rc2ep)
				pr_info("\t\tRC->EP throughput:%lldMbps\n",
					info->rc2ep_results[RW_TYPE_READ][i] /
					1000000);
			if (info->ep2rc)
				pr_info("\t\tEP->RC throughput:%lldMbps\n",
					info->ep2rc_results[RW_TYPE_READ][i] /
					1000000);
		}
	}
};

static int pcidma_memcmp_test(struct pcidma_test *rc2ep)
{
	return memcmp((void *)rc2ep->remote, rc2ep->local, rc2ep->len);
}

static void pcidma_rc2ep_test_free(struct pcidma_test *rc2ep)
{
	struct fsl_pcidma_dev *pcidma = rc2ep->info->pcidma;

	if (rc2ep->chan)
		dmaengine_put();

	if (rc2ep->remote)
		iounmap(rc2ep->remote);

	if (rc2ep->local)
		free_pages((unsigned long)rc2ep->local,
			   get_order(pcidma->bars[PCI_BUFF_BAR].size));

	kfree(rc2ep);

	return;
}

static struct pcidma_test *pcidma_rc2ep_test_init(struct pcidma_test_info *info)
{
	struct pcidma_test *rc2ep;
	struct fsl_pcidma_dev *pcidma = info->pcidma;
	int order;

	rc2ep = kzalloc(sizeof(*rc2ep), GFP_KERNEL);
	if (!rc2ep) {
		pr_err("failed to init pcidma rc2ep\n");
		return NULL;
	}

	if (info->dma_enable) {
		dmaengine_get();
		rc2ep->chan = dma_find_channel(DMA_MEMCPY);
		if (!rc2ep->chan) {
			pr_err("failed to request dma channel\n");
			goto _err;
		}

		pr_debug("get chan %d\n", rc2ep->chan->chan_id);
	}

	rc2ep->remote_addr = pcidma->bars[PCI_BUFF_BAR].phy_addr;
	rc2ep->remote = ioremap(pcidma->bars[PCI_BUFF_BAR].phy_addr,
				pcidma->bars[PCI_BUFF_BAR].size);
	if (!rc2ep->remote) {
		pr_err("failed to call ioremap destination space\n");
		goto _err;
	}

	order = get_order(pcidma->bars[PCI_BUFF_BAR].size);
	rc2ep->local = (void *)__get_dma_pages(GFP_KERNEL, order);

	if (!rc2ep->local) {
		pr_err("failed to call pci_alloc_consistent\n");
		goto _err;
	}

	rc2ep->info = info;

	return rc2ep;

_err:
	pcidma_rc2ep_test_free(rc2ep);
	return NULL;
}

static void pcidma_rc2ep_dma_cb(void *arg)
{
	struct pcidma_test *rc2ep = arg;

	complete(&rc2ep->done);
	return;
}

static int pcidma_rc2ep_dma_test_one(struct pcidma_test *rc2ep,
				     size_t len, u32 loop,
				     enum rw_type type)
{
	struct fsl_pcidma_dev *pcidma = rc2ep->info->pcidma;
	dma_addr_t src, dest;
	int dma_direction, status;
	enum dma_ctrl_flags dma_flags = 0;
	ktime_t start, end;
	u64 total_time = 0;

	rc2ep->len = len;
	rc2ep->loop = 0;
	rc2ep->type = type;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,12,0)
	dma_flags = DMA_CTRL_ACK | DMA_PREP_INTERRUPT;
#else
	dma_flags = DMA_CTRL_ACK | DMA_PREP_INTERRUPT |
			DMA_COMPL_SKIP_DEST_UNMAP |
			DMA_COMPL_SRC_UNMAP_SINGLE;
#endif

	if (type == RW_TYPE_WRITE) {
		memset(rc2ep->local, 0x12, len);
		src = rc2ep->local_addr;
		dest = rc2ep->remote_addr;
		dma_direction = PCI_DMA_TODEVICE;
	} else if (type == RW_TYPE_READ) {
		memset(rc2ep->local, 0x34, len);
		src = rc2ep->remote_addr;
		dest = rc2ep->local_addr;
		dma_direction = PCI_DMA_FROMDEVICE;
	} else
		goto _err;

	rc2ep->local_addr = dma_map_single(&pcidma->pdev->dev,
					   rc2ep->local,
					   len,
					   dma_direction);
	if (dma_mapping_error(&pcidma->pdev->dev, rc2ep->local_addr)) {
		pr_err("mapping error with src addr=%p len=0x%llx\n",
			rc2ep->local, (u64)len);
		goto _err;
	}

	while (!kthread_should_stop() && (rc2ep->loop < loop)) {
		struct dma_device *dma_dev = rc2ep->chan->device;
		struct dma_async_tx_descriptor *dma_desc;
		dma_cookie_t	dma_cookie = {0};
		unsigned long tmo;

		init_completion(&rc2ep->done);

		dma_desc = dma_dev->device_prep_dma_memcpy(rc2ep->chan,
							   dest, src,
							   rc2ep->len,
							   dma_flags);
		if (!dma_desc) {
			pr_err("DMA desc constr failed...\n");
			goto _dma_err;
		}

		dma_desc->callback = pcidma_rc2ep_dma_cb;
		dma_desc->callback_param = rc2ep;
		dma_cookie = dma_desc->tx_submit(dma_desc);

		if (dma_submit_error(dma_cookie)) {
			pr_err("DMA submit error....\n");
			goto _dma_err;
		}

		start = ktime_get();

		/* Trigger the transaction */
		dma_async_issue_pending(dma_desc->chan);

		tmo = wait_for_completion_timeout(&rc2ep->done,
						  msecs_to_jiffies(5 * len));
		if (tmo == 0) {
			pr_err("Self-test copy timed out, disabling\n");
			goto _dma_err;
		}

		status = dma_async_is_tx_complete(rc2ep->chan, dma_cookie,
						  NULL, NULL);
#if LINUX_VERSION_CODE > KERNEL_VERSION(3,12,0)
		if (status != DMA_COMPLETE) {
#else
		if (status != DMA_SUCCESS) {
#endif
			pr_err(
			       "got completion callback, "
			       "but status is \'%s\'\n",
			       status == DMA_ERROR ? "error" : "in progress");
			goto _dma_err;
		}

		end = ktime_get();

		if (rc2ep->info->verify) {
			dma_sync_single_for_cpu(&pcidma->pdev->dev,
						rc2ep->local_addr, len,
						dma_direction);

			if (pcidma_memcmp_test(rc2ep))
				goto _test_err;

			dma_sync_single_for_device(&pcidma->pdev->dev,
						   rc2ep->local_addr, len,
						   dma_direction);
		}

		rc2ep->loop++;
		total_time += ktime_to_ns(ktime_sub(end, start));

		pr_debug("test loop%d take time:%lldns total time:%lldns\n",
			  rc2ep->loop, ktime_to_ns(ktime_sub(end, start)),
			  total_time);
	}

	if (rc2ep->loop == loop)
		rc2ep->status = TEST_DONE;
	else
		goto _test_err;

	rc2ep->result = (u64)(rc2ep->len * 8 * loop) * 1000000000 / total_time;

	dma_unmap_single(&pcidma->pdev->dev, rc2ep->local_addr,
			 len, dma_direction);
	return 0;

_test_err:
_dma_err:
	dma_unmap_single(&pcidma->pdev->dev, rc2ep->local_addr,
			 len, dma_direction);
_err:
	rc2ep->status = TEST_ERROR;
	return -EINVAL;
}

static int pcidma_rc2ep_memcpy_test_one(struct pcidma_test *rc2ep,
					u32 len, u32 loop,
					enum rw_type type)
{
	int i;
	ktime_t start, end;
	void *dest, *src;

	if (type == RW_TYPE_WRITE) {
		memset(rc2ep->local, 0x56, len);
		dest = rc2ep->remote;
		src = rc2ep->local;
	} else if (type == RW_TYPE_READ) {
		memset(rc2ep->local, 0x78, len);
		dest = rc2ep->local;
		src = rc2ep->remote;
	} else
		goto _err;

	start = ktime_get();

	for (i = 0; i < loop; i++)
		memcpy(dest, src, len);

	end = ktime_get();

	rc2ep->result = (u64)(len * 8 * loop) * 1000000000 /
			ktime_to_ns(ktime_sub(end, start));

	rc2ep->status = TEST_DONE;

	pr_debug("start:%lldns end:%lldns total time:%lldns\n",
		  ktime_to_ns(start), ktime_to_ns(end),
		  ktime_to_ns(ktime_sub(end, start)));

	return 0;
_err:
	rc2ep->status = TEST_ERROR;
	return -EINVAL;
}

static int pcidma_rc2ep_test_rw(struct pcidma_test_info *info,
				 struct pcidma_test *rc2ep,
				 enum rw_type type)
{
	int i;

	for (i = 0; i < info->lens_num; i++) {
		if (info->dma_enable)
			pcidma_rc2ep_dma_test_one(rc2ep, info->lens[i],
						  info->loop,
						  type);
		else
			pcidma_rc2ep_memcpy_test_one(rc2ep, info->lens[i],
						     info->loop,
						     type);

		if (rc2ep->status != TEST_DONE) {
			info->rc2ep_results[type][i] = 0;
			break;
		}

		info->rc2ep_results[type][i] = rc2ep->result;

		pr_debug("%s-test%d length:%uB loop:%utimes throughput:%lluMbps\n",
			 type == RW_TYPE_WRITE ? "write" : "read",
			 i, info->lens[i], info->loop,
			 info->rc2ep_results[type][i] / 1000000);
	}

	return 0;
}

static int pcidma_rc2ep_test(void *arg)
{
	struct pcidma_test_info *info = arg;
	struct pcidma_test *rc2ep;

	rc2ep = pcidma_rc2ep_test_init(info);
	if (!rc2ep)
		goto _done;

	if (info->write)
		pcidma_rc2ep_test_rw(info, rc2ep, RW_TYPE_WRITE);

	if (info->read)
		pcidma_rc2ep_test_rw(info, rc2ep, RW_TYPE_READ);


	pcidma_rc2ep_test_free(rc2ep);

_done:
	complete(&info->rc2ep_thread_done);
	return 0;
}

static void pcidma_ep2rc_test_free(struct pcidma_test *ep2rc)
{
	struct pcidma_test_info *info = ep2rc->info;

	if (ep2rc->local)
		pci_free_consistent(info->pcidma->pdev,
				    info->pcidma->bars[PCI_BUFF_BAR].size,
				    ep2rc->local,
				    ep2rc->local_addr);
	kfree(ep2rc);

	return;
}

static struct pcidma_test *pcidma_ep2rc_test_init(struct pcidma_test_info *info)
{
	struct pcidma_test *ep2rc;

	ep2rc = kzalloc(sizeof(*ep2rc), GFP_KERNEL);
	if (!ep2rc)
		return NULL;

	ep2rc->local = pci_alloc_consistent(info->pcidma->pdev,
					info->pcidma->bars[PCI_BUFF_BAR].size,
					&ep2rc->local_addr);
	if (!ep2rc->local) {
		pr_err("failed to call pci_alloc_consistent ");
		goto _err;
	}

	ep2rc->info = info;
	ep2rc->config = info->pcidma->config;

	return ep2rc;

_err:
	pcidma_ep2rc_test_free(ep2rc);
	return NULL;
}

static u32 pcidma_command(struct pcidma_config *config)
{
	return ioread32be(&config->command);
}

static u32 pcidma_status(struct pcidma_config *config)
{
	return ioread32be(&config->status);
}

static u64 pcidma_result(struct pcidma_config *config)
{
	return (u64)ioread32be(&config->rwcfg.hresult) << 32 |
		ioread32be(&config->rwcfg.lresult);
}

static void pcidma_ep2rc_test_start(struct pcidma_test *ep2rc)
{
	struct pcidma_config *config = ep2rc->config;

	iowrite32be(ep2rc->local_addr >> 32, &config->rwcfg.hbar);
	iowrite32be(ep2rc->local_addr, &config->rwcfg.lbar);
	iowrite32be(ep2rc->len, &config->rwcfg.size);
	iowrite32be(ep2rc->loop, &config->rwcfg.loop);
	iowrite32be(ep2rc->type, &config->rwcfg.type);

	iowrite32be(PCIDMA_CMD_START, &config->command);
}

static int
pcidma_ep2rc_test_one(struct pcidma_test *ep2rc, size_t len, int loop,
		      enum rw_type type)
{
	struct pcidma_config *config = ep2rc->config;
	ktime_t start;

	ep2rc->len = len;
	ep2rc->loop = loop;
	ep2rc->type = type;

	if (pcidma_command(config) == PCIDMA_CMD_START) {
		ep2rc->status = TEST_ERROR;
		pr_err("the device is busy\n");
		return -EBUSY;
	}

	start = ktime_get();
	pcidma_ep2rc_test_start(ep2rc);

	while (pcidma_command(config) == PCIDMA_CMD_START) {
		schedule();
		if (ktime_to_ms(ktime_sub(ktime_get(), start)) >
			len * loop * 10 /* 10ms */)
			break;
	}

	if (pcidma_command(config) == PCIDMA_CMD_START) {
		pr_err("ep2rc test timeout\n");
		goto _err;
	}

	if (pcidma_status(config) != PCIDMA_STATUS_DONE) {
		pr_err("ep2rc test error\n");
		goto _err;
	}

	ep2rc->result = pcidma_result(config);
	ep2rc->status = TEST_DONE;

	pr_debug("ep2rc %s-test  size:%uB loop:%d  throughput:0x%lldMbps\n",
		 type == RW_TYPE_WRITE ? "write" : "read",
		 (u32)len, loop, ep2rc->result / 1000000);

	return 0;

_err:
	ep2rc->status = TEST_ERROR;
	return -EINVAL;
}

static int pcidma_ep2rc_test_rw(struct pcidma_test_info *info,
				struct pcidma_test *ep2rc,
				enum rw_type type)
{
	int i;

	for (i = 0; i < info->lens_num; i++) {
		pcidma_ep2rc_test_one(ep2rc, info->lens[i], info->loop, type);

		if (ep2rc->status != TEST_DONE) {
			info->ep2rc_results[type][i] = 0;
			break;
		}

		info->ep2rc_results[type][i] = ep2rc->result;
	}

	return 0;
}

int pcidma_ep2rc_test(void *arg)
{
	struct pcidma_test_info *info = arg;
	struct pcidma_test *ep2rc;

	ep2rc = pcidma_ep2rc_test_init(info);
	if (!ep2rc)
		goto _done;

	if (info->write)
		pcidma_ep2rc_test_rw(info, ep2rc, RW_TYPE_WRITE);

	if (info->read)
		pcidma_ep2rc_test_rw(info, ep2rc, RW_TYPE_READ);

	pcidma_ep2rc_test_free(ep2rc);

_done:
	complete(&info->ep2rc_thread_done);
	return 0;
}

int pcidma_test_thread(void *arg)
{
	struct pcidma_test_info *info = arg;
	struct fsl_pcidma_dev *pcidma = info->pcidma;

	if (!info || !pcidma_test_running(info))
		return -EINVAL;

	if (info->rc2ep) {
		init_completion(&info->rc2ep_thread_done);
		info->rc2ep_thread =
			kthread_create(pcidma_rc2ep_test, info, "%s_%s",
				       pcidma->name, "rc2ep");
		wake_up_process(info->rc2ep_thread);

		wait_for_completion(&info->rc2ep_thread_done);
		kthread_stop(info->rc2ep_thread);
	}

	if (info->ep2rc) {
		init_completion(&info->ep2rc_thread_done);
		info->ep2rc_thread =
			kthread_create(pcidma_ep2rc_test, info, "%s_%s",
				       pcidma->name, "ep2rc");
		wake_up_process(info->ep2rc_thread);

		wait_for_completion(&info->ep2rc_thread_done);
		kthread_stop(info->ep2rc_thread);
	}

	pcidma_test_status_set(info, TEST_DONE);
	pcidma_test_info_dump(info);

	do_exit(0);
}

int pcidma_test_start(struct fsl_pcidma_dev *pcidma)
{
	struct pcidma_test_info *info = pcidma->test_info;
	struct task_struct *tsk;
	int ret = 0;

	if (pcidma_test_try_run(info))
		return -EINVAL;

	tsk = kthread_run(pcidma_test_thread, info, pcidma->name);
	if (IS_ERR(tsk)) {
		pr_err("fork failed for %s test\n", pcidma->name);
		ret = PTR_ERR(tsk);
	}

	return ret;
}
