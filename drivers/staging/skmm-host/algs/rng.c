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

#include <linux/hw_random.h>
#include <linux/completion.h>
#include <linux/atomic.h>
#include "common.h"
#include "fsl_c2x0_crypto_layer.h"
#include "fsl_c2x0_driver.h"
#include "memmgr.h"
#include "algs.h"
#include "crypto_ctx.h"
#ifdef VIRTIO_C2X0
#include "fsl_c2x0_virtio.h"
#endif

static struct rng_ctx *r_ctx;
static struct hwrng *rng;

static int32_t get_device_n_ring(struct rng_ctx *ctx, uint32_t *r_id)
{
	int32_t ret = -1;

	if (NULL == (ctx->c_dev = get_device_rr())) {
		print_error("Could not get an active device.\n");
	} else if (0 == (*r_id = get_ring_rr(ctx->c_dev))) {
		print_error("Could not get an app ring\n");
	} else 
		ret = 0;

	atomic_inc(&ctx->c_dev->active_jobs);
	return ret;	
	
}

static void rng_init_len(crypto_mem_info_t *mem_info)
{
	rng_buffers_t *mem = (rng_buffers_t *) (mem_info->buffers);

	mem->output_buff.len = RN_BUF_SIZE;
	mem->sh_desc_buff.len = DESC_RNG_LEN;
	mem->desc_buff.len = DESC_JOB_O_LEN;
}

static int rng_cp_output(uint8_t *output, crypto_mem_info_t *mem_info)
{
	rng_buffers_t *mem = (rng_buffers_t *) (mem_info->buffers);

	rng_init_len(mem_info);

	/* Alloc mem requrd for crypto operation */
	print_debug("\t \t Calling alloc_crypto_mem\n");
	if (-ENOMEM == alloc_crypto_mem(mem_info))
		return -ENOMEM;

	mem->output_buff.v_mem = output;
	return 0;
}

static void rng_init_crypto_mem(crypto_mem_info_t *crypto_mem)
{
	rng_buffers_t *rng_buffs = NULL;

	crypto_mem->count = sizeof(rng_buffers_t) / sizeof(buffer_info_t);

	crypto_mem->buffers = (buffer_info_t *) (&(crypto_mem->c_buffers.rng));
	memset(crypto_mem->buffers, 0, sizeof(rng_buffers_t));

	/* Mark the op buffer */
	rng_buffs = (rng_buffers_t *) crypto_mem->buffers;
	rng_buffs->output_buff.bt = BT_OP;
}

static void rng_done(void *ctx, int32_t res)
{
	crypto_op_ctx_t *crypto_ctx = ctx;

	print_debug("[RNG DONE ]\n");

	dealloc_crypto_mem(&(crypto_ctx->crypto_mem));

	atomic_set(&crypto_ctx->req.rng->empty, BUF_NOT_EMPTY);
	complete(&crypto_ctx->req.rng->filled);

	free_crypto_ctx(crypto_ctx->ctx_pool, crypto_ctx);
}

static int rng_create_sh_desc(struct rng_ctx *ctx)
{
	ctx->sh_desc = kzalloc(DESC_RNG_LEN, GFP_KERNEL);
	if (!ctx->sh_desc)
		return -1;
	init_rng_sh_desc(ctx->sh_desc);
	ctx->sh_desc_len = desc_len(ctx->sh_desc);
	return 0;
}

static void constr_rng_desc(crypto_mem_info_t *mem_info, struct rng_ctx *ctx)
{
	rng_buffers_t *mem = (rng_buffers_t *) (mem_info->buffers);
	uint32_t *sh_desc_buff = (uint32_t *) mem->sh_desc_buff.v_mem;
	uint32_t *desc_buff = (uint32_t *) mem->desc_buff.v_mem;
	u32 desc[DESC_JOB_O_LEN];

	change_desc_endianness(sh_desc_buff, ctx->sh_desc, ctx->sh_desc_len);

	init_rng_job_desc(desc, mem->sh_desc_buff.dev_buffer.d_p_addr,
			  ctx->sh_desc_len,
			  mem->output_buff.dev_buffer.d_p_addr);
	change_desc_endianness(desc_buff, desc, desc_len(desc));
}

static int submit_job(struct rng_ctx *ctx, int to_current)
{
	int32_t ret = 0;
	struct buf_data *bd = &ctx->bufs[!(to_current ^ ctx->current_buf)];
	crypto_op_ctx_t *crypto_ctx = NULL;
	uint32_t r_id = 0;
	dev_dma_addr_t sec_dma = 0;
	rng_buffers_t *rng_buffs = NULL;

	if (get_device_n_ring(ctx, &r_id))
		return -1;

	crypto_ctx = get_crypto_ctx(ctx->c_dev->ctx_pool);
	print_debug("\t crypto_ctx addr :           :%0llx\n", crypto_ctx);

	if (unlikely(!crypto_ctx)) {
		print_error("Mem alloc failed....\n");
		ret = -ENOMEM;
		goto error;
	}

	crypto_ctx->ctx_pool = ctx->c_dev->ctx_pool;
	crypto_ctx->crypto_mem.dev = ctx->c_dev;
	crypto_ctx->crypto_mem.pool = ctx->c_dev->ring_pairs[r_id].ip_pool;
	print_debug("\t IP Buffer pool address      :%0x\n",
		    crypto_ctx->crypto_mem.pool);

	rng_init_crypto_mem(&crypto_ctx->crypto_mem);
	rng_buffs = (rng_buffers_t *) crypto_ctx->crypto_mem.buffers;

	if (-ENOMEM == rng_cp_output(bd->buf, &crypto_ctx->crypto_mem)) {
		ret = -ENOMEM;
		goto error;
	}

	print_debug("\t \t \t RNG mem complete.....\n");

	/* Convert the buffers to dev */
	host_to_dev(&crypto_ctx->crypto_mem);

	print_debug("\t \t \t Host to dev convert complete....\n");

	/* Constr the hw desc */
	constr_rng_desc(&crypto_ctx->crypto_mem, ctx);
	print_debug("\t \t \t Desc constr complete...\n");

	sec_dma = rng_buffs->desc_buff.dev_buffer.d_p_addr;

	/* Store the context */
	print_debug
	    ("[Enq]Desc addr :%0llx Hbuff addr :%0x Crypto ctx :%0x\n",
	     rng_buffs->desc_buff.dev_buffer.d_p_addr,
	     rng_buffs->desc_buff.v_mem, crypto_ctx);

	store_priv_data(crypto_ctx->crypto_mem.pool,
			rng_buffs->desc_buff.v_mem, (unsigned long)crypto_ctx);
	crypto_ctx->oprn = RNG;

	memcpy_to_dev(&crypto_ctx->crypto_mem);

	crypto_ctx->req.rng = bd;
	crypto_ctx->rid = r_id;
	crypto_ctx->desc = sec_dma;
	crypto_ctx->c_dev = ctx->c_dev;

	crypto_ctx->op_done = rng_done;

	print_debug("submitting job %d\n", !(to_current ^ ctx->current_buf));
	init_completion(&bd->filled);

	sec_dma = set_sec_affinity(ctx->c_dev, r_id, sec_dma);
	atomic_dec(&ctx->c_dev->active_jobs);
	if (-1 == app_ring_enqueue(ctx->c_dev, r_id, sec_dma)) {
		print_error("Application Ring Enqueue Failed\n");
		complete(&bd->filled);	/* don't wait on failed job */
		ret = -1;
		goto error1;
	} else {
		atomic_inc(&bd->empty);	/* note if pending */
	}

	return 0;

error:
	atomic_dec(&ctx->c_dev->active_jobs);
error1:
	if (crypto_ctx) {
		if (crypto_ctx->crypto_mem.buffers)
			dealloc_crypto_mem(&crypto_ctx->crypto_mem);

		free_crypto_ctx(ctx->c_dev->ctx_pool, crypto_ctx);
	}

	return ret;
}

static int rng_read(struct hwrng *rng, void *data, size_t max, bool wait)
{
	struct rng_ctx *ctx = r_ctx;
	struct buf_data *bd = &ctx->bufs[ctx->current_buf];
	int next_buf_idx, copied_idx;
	int err;
	spin_lock(&ctx->ctx_lock);

	if (atomic_read(&bd->empty)) {
		/* try to submit job if there wasn't one */
		if (atomic_read(&bd->empty) == BUF_EMPTY) {
			err = submit_job(ctx, 1);
			/* if can't submit job, can't even wait */
			if (err)
				return 0;
		}
		/* no immediate data, so exit if not waiting */
		if (!wait)
			return 0;

		/* waiting for pending job */
		if (atomic_read(&bd->empty))
			wait_for_completion(&bd->filled);
	}

	next_buf_idx = ctx->cur_buf_idx + max;
	print_debug("start reading at buffer %d, idx %d\n", ctx->current_buf,
		    ctx->cur_buf_idx);

	/* if enough data in current buffer */
	if (next_buf_idx < RN_BUF_SIZE) {
		memcpy(data, bd->buf + ctx->cur_buf_idx, max);
		ctx->cur_buf_idx = next_buf_idx;
		spin_unlock(&ctx->ctx_lock);
		return max;
	}

	/* else, copy what's left... */
	copied_idx = RN_BUF_SIZE - ctx->cur_buf_idx;
	memcpy(data, bd->buf + ctx->cur_buf_idx, copied_idx);
	ctx->cur_buf_idx = 0;
	atomic_set(&bd->empty, BUF_EMPTY);

	/* ...refill... */
	submit_job(ctx, 1);

	/* and use next buffer */
	ctx->current_buf = !ctx->current_buf;
	print_debug("switched to buffer %d\n", ctx->current_buf);
	spin_unlock(&ctx->ctx_lock);
	/* since there already is some data read, don't wait */
	return copied_idx + rng_read(rng, data + copied_idx, max - copied_idx,
				     true);
}

static void rng_cleanup(struct hwrng *rng)
{
	int i;
	struct buf_data *bd;
	spin_lock(&r_ctx->ctx_lock);
	for (i = 0; i < 2; i++) {
		bd = &r_ctx->bufs[i];
		if (atomic_read(&bd->empty) == BUF_PENDING)
			wait_for_completion(&bd->filled);
	}

	kfree(r_ctx->sh_desc);
	spin_unlock(&r_ctx->ctx_lock);
}

static int init_buf(struct rng_ctx *ctx, int buf_id)
{
#ifndef VIRTIO_C2X0
	struct buf_data *bd = &ctx->bufs[buf_id];

	atomic_set(&bd->empty, BUF_EMPTY);
	if (submit_job(ctx, buf_id == ctx->current_buf))
		return -1;
	wait_for_completion(&bd->filled);
#endif
	return 0;
}

static int init_rng(struct hwrng *rng)
{
	struct rng_ctx *ctx = r_ctx;
	spin_lock_init(&(ctx->ctx_lock));

	if (-1 == rng_create_sh_desc(ctx))
		return -1;

	ctx->current_buf = 0;
	ctx->cur_buf_idx = 0;

	if (-1 == init_buf(ctx, 0))
		return -1;
	if (-1 == init_buf(ctx, 1))
		return -1;

	return 0;
}

void rng_exit(void)
{
	if (rng) {
		hwrng_unregister(rng);
		kfree(rng);
	}
	kfree(r_ctx);
}

int rng_init(void)
{
	r_ctx = kzalloc(sizeof(struct rng_ctx), GFP_KERNEL | GFP_DMA);
	if (NULL == r_ctx) {
		print_error("Not Enough Kernel Memory\n");
		goto error2;
	}

	rng = kzalloc(sizeof(struct hwrng), GFP_KERNEL);
	if (NULL == rng) {
		print_error("Not Enough Kernel Memory\n");
		goto error1;
	}

	rng->name = "rng-fsl";
	rng->cleanup = rng_cleanup;
	rng->read = rng_read;
	rng->init = init_rng;

	if (hwrng_register(rng))
		goto error;
	return 0;

error:
	rng_cleanup(rng);
	kfree(rng);
error1:
	kfree(r_ctx);
error2:
	print_error("RNG registration failed.\n");
	return -1;
}

#ifdef VIRTIO_C2X0
int32_t process_virtio_rng_job(struct virtio_c2x0_job_ctx *virtio_job)
{
	int32_t ret = 0;
	struct virtio_c2x0_qemu_cmd *qemu_cmd = &virtio_job->qemu_cmd;
	struct rng_ctx *ctx = r_ctx;
	struct buf_data *bd = NULL;
	int buf_id;

	ctx->cur_buf_idx = qemu_cmd->u.rng.rng_req.cur_buf_idx;
	ctx->current_buf = qemu_cmd->u.rng.rng_req.current_buf;

	buf_id = ctx->current_buf;
	bd = &ctx->bufs[buf_id];

	atomic_set(&bd->empty, BUF_EMPTY);
	ret = submit_job(ctx, buf_id == ctx->current_buf);
	if (0 == ret) {
		wait_for_completion(&bd->filled);
#if 0
		{
			int i = 0;

			for (i = 0; i < RN_BUF_SIZE; i++)
				printk("%c", bd->buf[i]);
			printk("\n");
		}
#endif
		ret =
		    copy_to_user(qemu_cmd->u.rng.rng_req.buf, bd->buf,
				 RN_BUF_SIZE);
		if (0 != ret) {
			print_error("COPY TO USER failed with %d ret\n", ret);
			return -1;
		}
	}
	return ret;
}
#endif
