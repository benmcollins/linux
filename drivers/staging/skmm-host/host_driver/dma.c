/* Copyright 2013 Freescale Semiconductor, Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *
 *
 * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 * Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 *
 * Neither the name of Freescale Semiconductor nor the
 * names of its contributors may be used to endorse or promote products
 * derived from this software without specific prior written permission.
 *
 *
 * ALTERNATIVELY, this software may be distributed under the terms of the
 * GNU General Public License ("GPL") as published by the Free Software
 * Foundation, either version 2 of that License or (at your option) any
 * later version.
 *
 * THIS SOFTWARE IS PROVIDED BY Freescale Semiconductor ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL Freescale Semiconductor BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE)ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <linux/version.h>
#include "common.h"
#include "fsl_c2x0_crypto_layer.h"
#include "fsl_c2x0_driver.h"
#include "desc_cnstr.h"
#include "algs.h"
#include "dma.h"

host_dma_t hostdma;

per_cpu_dma_chnls_t per_cpu_dma[NR_CPUS];

#if (LINUX_VERSION_CODE < KERNEL_VERSION(3, 8, 13))
#define USE_IOAT_DMA_FIND_CHANNEL
#endif

extern int dma_channel_count;

/* Following bitfields specifies the channel distribution to CPUs. */
/* Channels = CPUs will be ideal. */
extern int dma_channel_cpu_mask[NR_CPUS];
extern int cpu_mask_count;

/*
module_param(dma_channel_count, int, S_IRUGO);
MODULE_PARM_DESC(dev_config_file, "No of dma chnls to use");

module_param_array(dma_channel_cpu_mask, int, &cpu_mask_count, 0000);
MODULE_PARM_DESC(dma_channel_cpu_mask, "CPU mask for dma chnl alloc");
*/

static int alloc_channel_to_cpu(int cpu, int mask)
{
	int i = 0;
	if (!mask) {
		print_info("No DMA channel is \
				allocated for CPU: %d Please check the \
				dma_channel_cpu_mask \n", cpu);
		return -1;
	}

	for (i = 0; i < dma_channel_count; i++) {
		if (mask & (1 << i)) {
			print_debug("DMA channel.. : %d for CPU : %d \n", i,
				    cpu);
			if (!per_cpu_dma[cpu].head)
				per_cpu_dma[cpu].head =
				    &(hostdma.dma_channels[i]);
			if (per_cpu_dma[cpu].tail)
				per_cpu_dma[cpu].tail->next =
				    &(hostdma.dma_channels[i]);
			per_cpu_dma[cpu].tail = &(hostdma.dma_channels[i]);
			/* Make it circular */
			hostdma.dma_channels[i].next = per_cpu_dma[cpu].head;
			if (!per_cpu_dma[cpu].cursor)
				per_cpu_dma[cpu].cursor = per_cpu_dma[cpu].head;
		}
	}

	return 0;
}

static int distribute_dma_channels(void)
{
	int i = 0;
	for_each_online_cpu(i) {
		if (alloc_channel_to_cpu(i, dma_channel_cpu_mask[i]))
			return -1;
	}

	return 0;
}

#ifdef USE_IOAT_DMA_FIND_CHANNEL
static struct completion chnl_acquire_done;
static int chnl_acquire_status;
static struct task_struct *dma_chnl_task;

static int dma_chnl_acquire_thread(void *p)
{
	chnl_info_t *dmachnl = p;

	dmachnl->chnl = dma_find_channel(DMA_MEMCPY);
	if (NULL == dmachnl->chnl) {
		print_error("Failed acquiring channel :.... \n");
		chnl_acquire_status =  0;
        complete(&chnl_acquire_done);
		return -1;
	}

	print_debug(KERN_ERR "%s( ): DMA channel             :%0x \n",
		    __FUNCTION__, dmachnl->chnl);

	chnl_acquire_status = 1;
	complete(&chnl_acquire_done);

	return 0;
}

static int acquire_ioat_dma_chnls(void)
{
	int i = 0;
	for (i = 0; i < dma_channel_count; i++) {
		init_completion(&chnl_acquire_done);
		chnl_acquire_status = 0;
		dma_chnl_task = kthread_create(dma_chnl_acquire_thread,
					       &(hostdma.dma_channels[i]),
					       "DMA-CHNL-ACQUIRE-THRD");
		kthread_bind(dma_chnl_task, i);
		wake_up_process(dma_chnl_task);

		wait_for_completion_interruptible(&chnl_acquire_done);
		if (!chnl_acquire_status) {
			print_error("Channel acquire failed.. \n");
			goto free_channels;
		}
	}

	return 0;
free_channels:
	for (; i; --i)
	;
	/* Free the channel */
	return -1;
}
#else

static int acquire_dma_chnls(void)
{
	int i = 0;
	for (i = 0; i < dma_channel_count; i++) {
		hostdma.dma_channels[i].chnl =
		    dma_request_channel(hostdma.dma_mask, NULL, NULL);
		if (NULL == hostdma.dma_channels[i].chnl) {
			print_error("Channel :%d acquire failed \n", i);
			goto free_channels;
		}
	}

	return 0;
free_channels:
	for (; i; --i)
	;
	/* Free the channel */
	return -1;
}
#endif

static int32_t prep_dma_tx(dma_addr_t s_dma_addr, dma_addr_t d_dma_addr,
			   uint32_t len, chnl_info_t *dma_chnl,
			   void (*cb) (void *), void *param)
{
	struct dma_device *dma_dev = dma_chnl->chnl->device;
	struct dma_async_tx_descriptor *dma_desc = NULL;
	dma_cookie_t dma_cookie = { 0 };
	enum dma_ctrl_flags dma_flags = 0;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,12,0)
	dma_flags =
	    DMA_CTRL_ACK | DMA_PREP_INTERRUPT;
#else
	dma_flags =
		DMA_CTRL_ACK | DMA_PREP_INTERRUPT | DMA_COMPL_SKIP_DEST_UNMAP;
#endif

	dma_desc =
	    dma_dev->device_prep_dma_memcpy(dma_chnl->chnl, d_dma_addr,
					    s_dma_addr, len, dma_flags);
	if (unlikely(!dma_desc)) {
		print_error("DMA desc constr failed...\n");
		goto error;
	}

	dma_desc->callback = cb;
	dma_desc->callback_param = param;

	dma_cookie = dma_desc->tx_submit(dma_desc);
	if (dma_submit_error(dma_cookie)) {
		print_error("DMA submit error....\n");
		goto error;
	}

	/* Trigger the transaction */
	dma_async_issue_pending(dma_chnl->chnl);

	return 0;
error:

	return -1;

}

static uint32_t prep_dma_tx_sg(crypto_mem_info_t *mem_info)
{
	struct scatterlist *ip, *op;
	int32_t i = 0;

	mem_info->ip_sg = kzalloc(mem_info->sg_cnt * sizeof(struct scatterlist),
				  GFP_KERNEL | GFP_DMA);

    if( NULL == mem_info->ip_sg )
    {
        print_error("Mem alloc failed for input sg \n");
        return -1;
    }

	mem_info->op_sg = kzalloc(mem_info->sg_cnt * sizeof(struct scatterlist),
				  GFP_KERNEL | GFP_DMA);

    if( NULL == mem_info->op_sg )
    {
        print_error("Mem alloc failed for output sg \n");
        return -1;
    }
	
    ip = mem_info->ip_sg;
	op = mem_info->op_sg;

	sg_init_table(ip, mem_info->sg_cnt);
	sg_init_table(op, mem_info->sg_cnt);

	sg_set_buf(ip++, mem_info->src_buff, mem_info->alloc_len);
	sg_set_buf(op, mem_info->src_buff, mem_info->alloc_len);
	sg_dma_address(op) = mem_info->buffers[0].dev_buffer.h_map_p_addr;
	sg_dma_len(op) = mem_info->alloc_len;
	op++;

	for (i = 0; i < mem_info->count; i++) {
		if (BT_IP == mem_info->buffers[i].bt) {
			sg_set_buf(ip++, mem_info->buffers[i].v_mem,
				   mem_info->buffers[i].len);
			sg_set_buf(op, mem_info->buffers[i].v_mem,
				   mem_info->buffers[i].len);
			sg_dma_address(op) =
			    mem_info->buffers[i].dev_buffer.h_map_p_addr;
			sg_dma_len(op) = mem_info->buffers[i].len;
			op++;
		}
	}

    return 0;
}

/******************************************************************************
Description :	Initializing the host DMA channels.  		   
Fields      :	None   
Returns     :	SUCCESS/ FAILURE
******************************************************************************/

int init_rc_dma(void)
{
	int ret;
#ifndef USE_HOST_DMA
	return 0;
#endif
	print_debug("Init RC DMA \n");

	if (cpu_mask_count != NR_CPUS) {
		print_info("Config for all CPUs are not provided.."
			   "Provided : %d, available: %d,"
			   "Hence using default - one channel for all"
			   "CPUs... \n", cpu_mask_count, NR_CPUS);
		dma_channel_count = 1;
		{
			int i = 0;
			for (i = 0; i < NR_CPUS; i++)
				dma_channel_cpu_mask[i] = 0x1;
		}
	}

	hostdma.dma_channels =
	    kzalloc(sizeof(chnl_info_t) * dma_channel_count, GFP_KERNEL);
	if (!hostdma.dma_channels) {
		print_error("Mem allocation failed \n");
		return -1;
	}

	dma_cap_zero(hostdma.dma_mask);
	dma_cap_set(DMA_MEMCPY, hostdma.dma_mask);

#ifdef USE_IOAT_DMA_FIND_CHANNEL
	/* As of the current situation, dma_request_channel( )
	 * is not working with intel IOAT
	 * dma_find_channel( ) should be used to get the channel.
	 * This API in DMA engine allocates channel percpu.
	 * Hence to get the different channels, different threads
	 * has to be created and bound to each CPU and from
	 * each different context, dma_find_channel( )
	 * API needs to be called.
	 * This difference btw p4080 and x86 should be removed
	 * later once we find the request channel working on x86.
	 */
	ret = acquire_ioat_dma_chnls();
#else
	ret = acquire_dma_chnls();
#endif

	if (-1 == ret) {
		print_error("Acquiring DMA channels failed \n");
		return -1;
	}

	if (distribute_dma_channels()) {
		print_error("Distribute channel failed... \n");
		goto free_channels;
	}

	return 0;
free_channels:
	/* Free the channels */
	return -1;
}

/******************************************************************************
Description : Cleanup the HOST DMA channels acquired earlier.   
Fields      :   None
Returns     :	None
******************************************************************************/

void cleanup_rc_dma(void)
{
	/* With IOAT - actual channel is never grabbed, hence
	 * cannot release it. Following piece of code should
	 * go away after dma_request_channel( ) gets working
	 * in X86.
	 */
#ifndef USE_IOAT_DMA_FIND_CHANNEL
	int i = 0;
	for (i = 0; i < dma_channel_count; i++)
		dma_release_channel(hostdma.dma_channels[i].chnl);
#endif
	kfree(hostdma.dma_channels);
}

/******************************************************************************
Description :	Retrieve a dma channel from the pool of dma channels in round
				robin fashion. 
Fields      :   None.
Returns     :	The dma channel.
******************************************************************************/

chnl_info_t *get_dma_chnl(void)
{
	int cpu = get_cpu();
	chnl_info_t *cursor = per_cpu_dma[cpu].cursor;
	per_cpu_dma[cpu].cursor = per_cpu_dma[cpu].cursor->next;
	if (!cursor)
		print_error("NULL DMA channel for cpu... :%d \n", cpu);
	return cursor;
}

/******************************************************************************
Description :	To transfer the data from an SG one by one, in case the DMA
				engine would not support SG. 
Fields      :  	
			dma_chnl	:	The dma channel to be used for transfer.
			ip			:	source SG.
			op			:	destination SG
			sg_cnt		:	no of entries in the SG.
			cb			:	callback function of the dma transfer.
			param		:	callback function parameter. 
Returns     :	SUCCESS/ FAILURE
******************************************************************************/

int32_t transfer_dma_sg(chnl_info_t *dma_chnl, struct scatterlist *ip,
			struct scatterlist *op, int32_t sg_cnt,
			void (*cb) (void *), void *param)
{
	while (ip && op) {
		if (prep_dma_tx(sg_dma_address(ip), sg_dma_address(op),
				sg_dma_len(op), dma_chnl, cb, param))
			return -1;
		ip = sg_next(ip);
		op = sg_next(op);
	}

	return 0;
}

int dma_abs_req(chnl_info_t *dma_chnl, crypto_mem_info_t *mem,
		void (*cb) (void *), crypto_op_ctx_t *ctx)
{
	struct dma_device *dma_dev = dma_chnl->chnl->device;
	struct dma_async_tx_descriptor *dma_desc;
	dma_cookie_t dma_cookie;
	dma_addr_t s_dma_addr;
	enum dma_ctrl_flags dma_flags = 0;
	int ret;

	if ((NULL == dma_chnl) || (NULL == mem)) {
		print_error("NULL input parameters.....\n");
		return -1;
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,12,0)
	dma_flags = DMA_CTRL_ACK | DMA_PREP_INTERRUPT;
#else
	dma_flags =
		DMA_CTRL_ACK | DMA_PREP_INTERRUPT | DMA_COMPL_SKIP_DEST_UNMAP;
#endif

	s_dma_addr =
	    dma_map_single(dma_dev->dev, mem->abs_req, mem->alloc_len,
			   DMA_BIDIRECTIONAL);
	if (unlikely(!s_dma_addr)) {
		print_error("DMA map for source buffer failed...\n");
		goto error;
	}

	atomic_set(&ctx->maxreqs, 1);
	atomic_set(&ctx->reqcnt, 0);
	dma_desc =
	    dma_dev->device_prep_dma_memcpy(dma_chnl->chnl,
					    mem->abs_p_h_map_addr,
					    s_dma_addr, mem->alloc_len,
					    dma_flags);

	if (unlikely(!dma_desc)) {
		print_error("DMA desc constr failed...\n");
		goto error;
	}

	dma_desc->callback = cb;
	dma_desc->callback_param = ctx;

	dma_cookie = dma_desc->tx_submit(dma_desc);
	if (dma_submit_error(dma_cookie)) {
		print_error("DMA submit error....\n");
		goto error;
	}

	/* Trigger the transaction */
	dma_async_issue_pending(dma_chnl->chnl);

	return 0;
error:
	if (s_dma_addr)
		dma_unmap_single(dma_dev->dev, s_dma_addr, mem->alloc_len,
				 DMA_BIDIRECTIONAL);
	return -1;

}

/******************************************************************************
Description :	Transfer data from host memory to device memory using DMA.   
Fields      :   
			dma_chnl	:	dma channel to be used for transfer.
			mem			:	the structure which contains all the information
							related to the source and the destination.
			cb			:	callback function of the DMA transfer.
			ctx			:	This contains information needed to enqueue the 
							job latter(after DMA tx) to the SEC engine.						
Returns     :	SUCCESS/ FAILURE
******************************************************************************/

int32_t dma_to_dev(chnl_info_t *dma_chnl, crypto_mem_info_t *mem,
		   void (*cb) (void *), crypto_op_ctx_t *ctx)
{
	struct dma_device *dma_dev = dma_chnl->chnl->device;
	struct dma_async_tx_descriptor *dma_desc = NULL;
	dma_cookie_t dma_cookie = { 0 };
	enum dma_ctrl_flags dma_flags = 0;

	dma_addr_t s_dma_addr = 0;
	int32_t ret = 0;

	if ((NULL == dma_chnl) || (NULL == mem)) {
		print_error("NULL input parameters.....\n");
		return -1;
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,12,0)
	dma_flags =
	    DMA_CTRL_ACK | DMA_PREP_INTERRUPT;
#else
	dma_flags =
		DMA_CTRL_ACK | DMA_PREP_INTERRUPT | DMA_COMPL_SKIP_DEST_UNMAP;
#endif

    if (mem->split_ip && (mem->sg_cnt > 1)) {
        if( -1 == prep_dma_tx_sg(mem))
        {
            print_error("DMA tx sg failed...\n");
            goto error;
        }
		ret = dma_map_sg(dma_dev->dev, mem->ip_sg, mem->sg_cnt,
				 DMA_BIDIRECTIONAL);
		if (unlikely(!ret)) {
			print_error("DMA map for source sg failed...\n");
			goto error;
		}

		atomic_set(&ctx->reqcnt, 0);
		/* For compatability with old DMA engines which does
		 * not have SG transfer capability.
		 */
		if (dma_dev->device_prep_dma_sg) {
			atomic_set(&ctx->maxreqs, 1);
			dma_desc =
			    dma_dev->device_prep_dma_sg(dma_chnl->chnl,
							mem->op_sg, mem->sg_cnt,
							mem->ip_sg, mem->sg_cnt,
							dma_flags);
		} else {
			atomic_set(&ctx->maxreqs, mem->sg_cnt);
			ret = transfer_dma_sg(dma_chnl, mem->ip_sg, mem->op_sg,
					      mem->sg_cnt, cb, ctx);
			if (ret)
				goto error;
			return 0;
		}
	} else {

		s_dma_addr =
		    dma_map_single(dma_dev->dev, mem->src_buff, mem->alloc_len,
				   DMA_BIDIRECTIONAL);
		if (unlikely(!s_dma_addr)) {
			print_error("DMA map for source buffer failed...\n");
			goto error;
		}

		atomic_set(&ctx->maxreqs, 1);
		atomic_set(&ctx->reqcnt, 0);
		dma_desc =
		    dma_dev->device_prep_dma_memcpy(dma_chnl->chnl,
						    mem->dest_buff_dma,
						    s_dma_addr, mem->alloc_len,
						    dma_flags);
	}
	if (unlikely(!dma_desc)) {
		print_error("DMA desc constr failed...\n");
		goto error;
	}

	dma_desc->callback = cb;
	dma_desc->callback_param = ctx;

	dma_cookie = dma_desc->tx_submit(dma_desc);
	if (dma_submit_error(dma_cookie)) {
		print_error("DMA submit error....\n");
		goto error;
	}

	/* Trigger the transaction */
	dma_async_issue_pending(dma_chnl->chnl);
#if 0
	kfree(mem->ip_sg);
	kfree(mem->op_sg);
#endif

	return 0;
error:
	if (s_dma_addr)
		dma_unmap_single(dma_dev->dev, s_dma_addr, mem->alloc_len,
				 DMA_BIDIRECTIONAL);
	if (mem->ip_sg) {
		dma_unmap_sg(dma_dev->dev, mem->ip_sg, mem->sg_cnt,
			     DMA_BIDIRECTIONAL);
		kfree(mem->ip_sg);
		kfree(mem->op_sg);
	}

	/* Need to cleanup the desc */
	return -1;
}
