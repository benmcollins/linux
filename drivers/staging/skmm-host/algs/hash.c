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

#include "common.h"
#include "fsl_c2x0_crypto_layer.h"
#include "fsl_c2x0_driver.h"
#include "algs.h"
#include "memmgr.h"
#include "crypto_ctx.h"
#include "sg_sw_sec4.h"
#ifdef VIRTIO_C2X0
#include "fsl_c2x0_virtio.h"
#endif

#include "dma.h"

#ifndef USE_HOST_DMA
#define HOST_TO_DEV_MEMCPY
#endif

static void hash_op_done(void *ctx, int32_t res)
{
	crypto_op_ctx_t *crypto_ctx = ctx;

	print_debug("[HASH OP DONE ]\n");

	dealloc_crypto_mem(&(crypto_ctx->crypto_mem));
	kfree(crypto_ctx->crypto_mem.c_buffers.hash);

#ifndef VIRTIO_C2X0
	crypto_ctx->req.ahash->base.complete(&crypto_ctx->req.ahash->base, res);

	free_crypto_ctx(crypto_ctx->ctx_pool, crypto_ctx);
#endif
#ifdef VIRTIO_C2X0
	/* Update the sec result to crypto job context */
	crypto_ctx->card_status = res;
	print_debug("Updated card status to %d\n", crypto_ctx->card_status);
#endif
}

static void hash_key_op_done(void *ctx, int32_t res)
{
	crypto_op_ctx_t *crypto_ctx = ctx;

	print_debug("[HASH KEY DONE ]\n");

	dealloc_crypto_mem(&(crypto_ctx->crypto_mem));

	crypto_ctx->result->err = res;
	complete(&crypto_ctx->result->completion);

	free_crypto_ctx(crypto_ctx->ctx_pool, crypto_ctx);
}

static void hash_key_init_len(uint32_t ip_len, uint32_t op_len,
			      crypto_mem_info_t *mem_info)
{
	hash_key_buffers_t *mem = (hash_key_buffers_t *) (mem_info->buffers);

	mem->output_buff.len = op_len;
	mem->input_buff.len = ip_len;

	mem->desc_buff.len = (CAAM_CMD_SZ * 6 + CAAM_PTR_SZ * 2);
}

static void hash_key_init_crypto_mem(crypto_mem_info_t *crypto_mem)
{
	hash_key_buffers_t *key_buffs = NULL;

	crypto_mem->count = sizeof(hash_key_buffers_t) / sizeof(buffer_info_t);
	crypto_mem->buffers =
	    (buffer_info_t *) (&(crypto_mem->c_buffers.hash_key));
	memset(crypto_mem->buffers, 0, sizeof(hash_key_buffers_t));

	key_buffs = (hash_key_buffers_t *) crypto_mem->buffers;
	key_buffs->input_buff.bt = BT_IP;
	key_buffs->output_buff.bt = BT_OP;
}

static int hash_cp_key(const uint8_t *input, uint32_t ip_len,
		       uint8_t *output, uint32_t op_len,
		       crypto_mem_info_t *mem_info)
{
	hash_key_buffers_t *mem = (hash_key_buffers_t *) (mem_info->buffers);

	hash_key_init_len(ip_len, op_len, mem_info);

	print_debug("\t \t Calling alloc_crypto_mem\n");
	if (-ENOMEM == alloc_crypto_mem(mem_info))
		return -ENOMEM;

#ifndef HOST_TO_DEV_MEMCPY
	memcpy(mem->input_buff.v_mem, input, ip_len);
#else
	mem->input_buff.req_ptr = (uint8_t *) input;
#endif

	mem->output_buff.v_mem = output;
	return 0;
}

static void hash_init_crypto_mem(crypto_mem_info_t *crypto_mem,
				 uint32_t sg_cnt)
{
	hash_buffers_t *hash_buffs = NULL;

	crypto_mem->split_ip = 1;
	crypto_mem->count = 4 + sg_cnt;
	crypto_mem->c_buffers.hash =
	    kzalloc(crypto_mem->count * sizeof(buffer_info_t), GFP_KERNEL);
	crypto_mem->buffers = (buffer_info_t *) ((crypto_mem->c_buffers.hash));

	hash_buffs = (hash_buffers_t *) crypto_mem->buffers;

	while (sg_cnt--)
		hash_buffs->input_buffs[sg_cnt].bt = BT_IP;
	hash_buffs->output_buff.bt = BT_OP;
}

static void hash_init_len(struct ahash_request *req, struct hash_lengths *len,
			  crypto_mem_info_t *mem_info)
{
	int32_t i = 0;
	struct scatterlist *sg = req->src;
	hash_buffers_t *mem = (hash_buffers_t *) (mem_info->buffers);

	mem->output_buff.len = len->output_len;

	if (len->src_nents || len->addon_nents) {
		mem->sec_sg_buff.len =
		    (len->src_nents +
		     len->addon_nents) * sizeof(struct sec4_sg_entry);

		if (len->ctx_len)
			mem->input_buffs[i++].len = len->ctx_len;

		if (len->buff_len)
			mem->input_buffs[i++].len = len->buff_len;

		for (; i < (len->src_nents + len->addon_nents); i++) {
			mem->input_buffs[i].len = sg->length;
			sg = sg_next(sg);
		}
	} else
		mem->sec_sg_buff.len = len->src_len;

	mem->desc_buff.len = DESC_JOB_IO_LEN;
	mem->sh_desc_buff.len = len->sh_desc_len;
}

static void create_sg_table(crypto_mem_info_t *mem_info, uint32_t count)
{
	int32_t i = 0;
	hash_buffers_t *mem = NULL;
	struct sec4_sg_entry *sec4_sg_ptr = NULL;

	if (!count)
		return;

	mem = (hash_buffers_t *) (mem_info->buffers);
	sec4_sg_ptr = (struct sec4_sg_entry *)mem->sec_sg_buff.v_mem;

	for (i = 0; i < count; i++) {
		ASSIGN64(sec4_sg_ptr->ptr,
			 mem->input_buffs[i].dev_buffer.d_p_addr);
		ASSIGN32(sec4_sg_ptr->len, mem->input_buffs[i].len);
		ASSIGN8(sec4_sg_ptr->reserved, 0);
		ASSIGN8(sec4_sg_ptr->buf_pool_id, 0);
		ASSIGN16(sec4_sg_ptr->offset, 0);
		sec4_sg_ptr++;
	}
	sec4_sg_ptr--;
	ASSIGN32(sec4_sg_ptr->len,
		 (mem->input_buffs[i - 1].len | SEC4_SG_LEN_FIN));
}

static int hash_cp_req(struct ahash_request *req, struct hash_lengths *len,
		       uint8_t *output, uint8_t *buff, uint8_t *ctx,
		       uint32_t *sh_desc, crypto_mem_info_t *mem_info)
{
	int32_t i = 0;
	struct scatterlist *sg = req->src;
	hash_buffers_t *mem = (hash_buffers_t *) (mem_info->buffers);

	hash_init_len(req, len, mem_info);

	print_debug("\t \t Calling alloc_crypto_mem\n");
	if (-ENOMEM == alloc_crypto_mem(mem_info))
		return -ENOMEM;
	if (len->src_nents || len->addon_nents) {
		if (ctx && len->ctx_len)
			memcpy(mem->input_buffs[i++].v_mem, ctx, len->ctx_len);

		if (buff && len->buff_len)
			memcpy(mem->input_buffs[i++].v_mem, buff,
			       len->buff_len);

		for (; i < (len->src_nents + len->addon_nents); i++) {
			sg_map_copy(mem->input_buffs[i].v_mem, sg, sg->length,
				    sg->offset);
			sg = sg_next(sg);
		}

	} else if (buff && len->buff_len)
		memcpy(mem->sec_sg_buff.v_mem, buff, len->buff_len);

	else if (ctx && len->ctx_len)
		memcpy(mem->sec_sg_buff.v_mem, ctx, len->ctx_len);

	else if (len->src_len)
		scatterwalk_map_and_copy(mem->sec_sg_buff.v_mem, req->src, 0,
					 len->src_len, 0);

	memcpy(mem->sh_desc_buff.v_mem, sh_desc, len->sh_desc_len);

	mem->output_buff.v_mem = output;

#ifdef HOST_TO_DEV_MEMCPY
	for (i = 0; i < (mem_info->count); i++)
		mem_info->buffers[i].req_ptr = mem_info->buffers[i].v_mem;
#endif
	return 0;
}

#ifdef VIRTIO_C2X0
int ahash_set_sh_desc(crypto_dev_sess_t *c_sess, int digestsize)
#else
int ahash_set_sh_desc(struct crypto_ahash *ahash)
#endif
{
	uint32_t *desc = NULL;
	uint32_t have_key = 0;
#ifndef VIRTIO_C2X0
	crypto_dev_sess_t *c_sess = crypto_ahash_ctx(ahash);
	int digestsize = crypto_ahash_digestsize(ahash);
#endif
	struct hash_ctx *ctx = &c_sess->u.hash;

	if (ctx->split_key_len)
		have_key = OP_ALG_AAI_HMAC_PRECOMP;

	desc = kzalloc(DESC_HASH_MAX_USED_BYTES, GFP_KERNEL);
	if (!desc)
		return -ENOMEM;

	ahash_update_desc(desc, ctx);
	ctx->len_desc_update = desc_len(desc);
	change_desc_endianness(ctx->sh_desc_update, desc, ctx->len_desc_update);
	memset(desc, 0, DESC_HASH_MAX_USED_BYTES);

	ahash_data_to_out(desc, have_key | ctx->alg_type, OP_ALG_AS_INIT,
			  ctx->ctx_len, ctx);
	ctx->len_desc_update_first = desc_len(desc);
	change_desc_endianness(ctx->sh_desc_update_first, desc,
			       ctx->len_desc_update_first);
	memset(desc, 0, DESC_HASH_MAX_USED_BYTES);

	ahash_ctx_data_to_out(desc, have_key | ctx->alg_type,
			      OP_ALG_AS_FINALIZE, digestsize, ctx);
	ctx->len_desc_fin = desc_len(desc);
	change_desc_endianness(ctx->sh_desc_fin, desc, ctx->len_desc_fin);
	memset(desc, 0, DESC_HASH_MAX_USED_BYTES);

	ahash_ctx_data_to_out(desc, have_key | ctx->alg_type,
			      OP_ALG_AS_FINALIZE, digestsize, ctx);
	ctx->len_desc_finup = desc_len(desc);
	change_desc_endianness(ctx->sh_desc_finup, desc, ctx->len_desc_finup);
	memset(desc, 0, DESC_HASH_MAX_USED_BYTES);

	ahash_data_to_out(desc, have_key | ctx->alg_type, OP_ALG_AS_INITFINAL,
			  digestsize, ctx);
	ctx->len_desc_digest = desc_len(desc);
	change_desc_endianness(ctx->sh_desc_digest, desc, ctx->len_desc_digest);
	kfree(desc);

	return 0;
}

static int32_t gen_split_hash_key(crypto_dev_sess_t *c_sess,
				   const uint8_t *key_in, uint32_t keylen)
{
	int32_t ret = 0;
	uint32_t r_id = 0;
	uint32_t *desc = NULL;
	hash_key_buffers_t *mem = NULL;
	crypto_op_ctx_t *crypto_ctx = NULL;
	fsl_crypto_dev_t *c_dev = NULL;
	dev_dma_addr_t sec_dma = 0;

	struct hash_ctx *ctx = &c_sess->u.hash;
	struct split_key_result result;

	c_dev = c_sess->c_dev;
	r_id = c_sess->r_id;

	if (-1 == check_device(c_dev))
		return -1;

	crypto_ctx = get_crypto_ctx(c_dev->ctx_pool);
	print_debug("\t crypto_ctx addr :            :%0llx\n", crypto_ctx);

	if (unlikely(!crypto_ctx)) {
		print_error("Mem alloc failed....\n");
		ret = -ENOMEM;
		goto error;
	}

	crypto_ctx->ctx_pool = c_dev->ctx_pool;
	crypto_ctx->crypto_mem.dev = c_dev;
	crypto_ctx->crypto_mem.pool = c_dev->ring_pairs[r_id].ip_pool;
	print_debug("\t IP Buffer pool address          :%0x\n",
		    crypto_ctx->crypto_mem.pool);

	hash_key_init_crypto_mem(&crypto_ctx->crypto_mem);
	hash_cp_key(key_in, keylen, ctx->key, ctx->split_key_pad_len,
		    &crypto_ctx->crypto_mem);
	host_to_dev(&crypto_ctx->crypto_mem);

	mem = (hash_key_buffers_t *) (crypto_ctx->crypto_mem.buffers);

	desc = kzalloc((CAAM_CMD_SZ * 6 + CAAM_PTR_SZ * 2), GFP_KERNEL);

	hash_splitkey_jobdesc(desc, ctx->alg_op,
			      mem->input_buff.dev_buffer.d_p_addr, keylen,
			      mem->output_buff.dev_buffer.d_p_addr,
			      ctx->split_key_len);
	change_desc_endianness((uint32_t *) mem->desc_buff.v_mem, desc,
			       desc_len(desc));

	kfree(desc);
	store_priv_data(crypto_ctx->crypto_mem.pool,
			mem->desc_buff.v_mem, (unsigned long)crypto_ctx);
	sec_dma = mem->desc_buff.dev_buffer.d_p_addr;

#ifndef HOST_TO_DEV_MEMCPY
	crypto_ctx->crypto_mem.dest_buff_dma =
	    crypto_ctx->crypto_mem.buffers[BT_DESC].dev_buffer.h_map_p_addr;
#endif
#ifdef HOST_TO_DEV_MEMCPY
	memcpy_to_dev(&crypto_ctx->crypto_mem);
#endif

	crypto_ctx->req.ahash = NULL;
	crypto_ctx->oprn = HASH_SPLIT_KEY;
	crypto_ctx->rid = r_id;
	crypto_ctx->op_done = hash_key_op_done;
	crypto_ctx->desc = sec_dma;
	crypto_ctx->c_dev = c_dev;
	crypto_ctx->result = &result;

	result.err = 0;
	init_completion(&result.completion);

#ifndef HOST_TO_DEV_MEMCPY
	if (-1 ==
	    dma_to_dev(get_dma_chnl(), &crypto_ctx->crypto_mem,
		       dma_tx_complete_cb, crypto_ctx)) {
		print_error("DMA to dev failed....\n");
		ret = -1;
		goto error;
	}
#else
	sec_dma = set_sec_affinity(c_dev, r_id, sec_dma);
	atomic_dec(&c_dev->active_jobs);
	/* Now enqueue the job into the app ring */
	if (-1 == app_ring_enqueue(c_dev, r_id, sec_dma)) {
		print_error("Application Ring Enqueue Failed\n");
		ret = -1;
		goto error1;
	}
#endif
	wait_for_completion_interruptible(&result.completion);

	return result.err;

error:
	atomic_dec(&c_dev->active_jobs);
#ifdef HOST_TO_DEV_MEMCPY
error1:
#endif
	if (crypto_ctx) {
		if (crypto_ctx->crypto_mem.buffers) {
			dealloc_crypto_mem(&crypto_ctx->crypto_mem);
		}
		free_crypto_ctx(c_dev->ctx_pool, crypto_ctx);
	}
	return ret;
}

static uint32_t hash_digest_key(crypto_dev_sess_t *c_sess,
				const uint8_t *key_in, uint32_t *keylen,
				uint8_t *key_out, uint32_t digestsize)
{
	int32_t ret = 0;
	uint32_t r_id = 0;
	uint32_t *desc = NULL;
	hash_key_buffers_t *mem = NULL;
	crypto_op_ctx_t *crypto_ctx = NULL;
	fsl_crypto_dev_t *c_dev = NULL;
	dev_dma_addr_t sec_dma = 0;
	struct hash_ctx *ctx = &c_sess->u.hash;

	struct split_key_result result;

	c_dev = c_sess->c_dev;
	r_id = c_sess->r_id;

	if (-1 == check_device(c_dev))
		return -1;

	crypto_ctx = get_crypto_ctx(c_dev->ctx_pool);
	print_debug("\t crypto_ctx addr :            :%0llx\n", crypto_ctx);

	if (unlikely(!crypto_ctx)) {
		print_error("Mem alloc failed....\n");
		ret = -ENOMEM;
		goto error;
	}

	crypto_ctx->ctx_pool = c_dev->ctx_pool;
	crypto_ctx->crypto_mem.dev = c_dev;
	crypto_ctx->crypto_mem.pool = c_dev->ring_pairs[r_id].ip_pool;
	print_debug("\t IP Buffer pool address          :%0x\n",
		    crypto_ctx->crypto_mem.pool);

	hash_key_init_crypto_mem(&crypto_ctx->crypto_mem);
	hash_cp_key(key_in, *keylen, key_out, digestsize,
		    &crypto_ctx->crypto_mem);
	host_to_dev(&crypto_ctx->crypto_mem);

	mem = (hash_key_buffers_t *) (crypto_ctx->crypto_mem.buffers);

	/* Job descriptor to perform unkeyed hash on key_in */
	desc = kzalloc((CAAM_CMD_SZ * 6 + CAAM_PTR_SZ * 2), GFP_KERNEL);
	hash_digestkey_desc(desc, ctx->alg_type,
			    mem->input_buff.dev_buffer.d_p_addr, *keylen,
			    mem->output_buff.dev_buffer.d_p_addr, digestsize);
	change_desc_endianness((uint32_t *) mem->desc_buff.v_mem, desc,
			       desc_len(desc));
	kfree(desc);

	store_priv_data(crypto_ctx->crypto_mem.pool,
			mem->desc_buff.v_mem, (unsigned long)crypto_ctx);
	sec_dma = mem->desc_buff.dev_buffer.d_p_addr;

#ifndef HOST_TO_DEV_MEMCPY
	crypto_ctx->crypto_mem.dest_buff_dma =
	    crypto_ctx->crypto_mem.buffers[BT_DESC].dev_buffer.h_map_p_addr;
#endif
#ifdef HOST_TO_DEV_MEMCPY
	memcpy_to_dev(&crypto_ctx->crypto_mem);
#endif

	crypto_ctx->req.ahash = NULL;
	crypto_ctx->oprn = HASH_DIGEST_KEY;
	crypto_ctx->rid = r_id;
	crypto_ctx->op_done = hash_key_op_done;
	crypto_ctx->desc = sec_dma;
	crypto_ctx->c_dev = c_dev;
	crypto_ctx->result = &result;

	result.err = 0;
	init_completion(&result.completion);

#ifndef HOST_TO_DEV_MEMCPY
	if (-1 ==
	    dma_to_dev(get_dma_chnl(), &crypto_ctx->crypto_mem,
		       dma_tx_complete_cb, crypto_ctx)) {
		print_error("DMA to dev failed....\n");
		ret = -1;
		goto error;
	}
#else
	sec_dma = set_sec_affinity(c_dev, r_id, sec_dma);
	atomic_dec(&c_dev->active_jobs);
	/* Now enqueue the job into the app ring */
	if (-1 == app_ring_enqueue(c_dev, r_id, sec_dma)) {
		print_error("Application Ring Enqueue Failed\n");
		ret = -1;
		goto error1;
	}
#endif
	wait_for_completion_interruptible(&result.completion);
	*keylen = digestsize;

	return result.err;
error:
	atomic_dec(&c_dev->active_jobs);
#ifdef HOST_TO_DEV_MEMCPY
error1:
#endif
	if (crypto_ctx) {
		if (crypto_ctx->crypto_mem.buffers) {
			dealloc_crypto_mem(&crypto_ctx->crypto_mem);
		}
		free_crypto_ctx(c_dev->ctx_pool, crypto_ctx);
	}
	return ret;
}

#ifdef VIRTIO_C2X0
int ahash_setkey(const uint8_t *key, struct virtio_c2x0_qemu_cmd *qemu_cmd)
#else
int ahash_setkey(struct crypto_ahash *ahash, const uint8_t *key,
		 unsigned int keylen)
#endif
{
	/* Sizes for MDHA pads (*not* keys): MD5, SHA1, 224, 256, 384, 512 */
	static const u8 mdpadlen[] = { 16, 20, 32, 32, 64, 64 };
	int ret = 0;
	uint8_t *hashed_key = NULL;
#ifndef VIRTIO_C2X0
	crypto_dev_sess_t *c_sess = crypto_ahash_ctx(ahash);
	struct hash_ctx *ctx = &c_sess->u.hash;

	int blocksize = crypto_tfm_alg_blocksize(&ahash->base);
	int digestsize = crypto_ahash_digestsize(ahash);
#else
	crypto_dev_sess_t *c_sess = NULL;
	unsigned int keylen = (qemu_cmd->u.hash).setkey_req.keylen;
	struct hash_ctx *ctx = NULL;
	int blocksize, digestsize;
	struct virtio_c2x0_crypto_sess_ctx *hash_sess = NULL, *next_sess = NULL;
	int flag = 0;

	spin_lock(&hash_sess_list_lock);
	list_for_each_entry_safe(hash_sess, next_sess,
				 &virtio_c2x0_hash_sess_list, list_entry) {
		if (hash_sess->sess_id == qemu_cmd->u.hash.setkey_req.sess_id
		    && hash_sess->guest_id == qemu_cmd->guest_id) {
			c_sess = &hash_sess->c_sess;
			ctx = &c_sess->u.hash;
			flag = 1;
			print_debug("Hash session FOUND; sess_id = %x\n",
				    hash_sess->sess_id);
			break;
		}
	}
	if (0 == flag) {
		print_error("Hash session[%lx],guest[%d] NOT found\n",
			    qemu_cmd->u.hash.setkey_req.sess_id,
			    qemu_cmd->guest_id);
		/* print_sess_list(); */
		spin_unlock(&hash_sess_list_lock);
		return -1;
	}
	spin_unlock(&hash_sess_list_lock);

	blocksize = qemu_cmd->u.hash.setkey_req.blocksize;
	digestsize = qemu_cmd->u.hash.setkey_req.digestsize;
#endif

	if (keylen > blocksize) {
		hashed_key = kzalloc(digestsize, GFP_KERNEL | GFP_DMA);
		if (!hashed_key)
			return -ENOMEM;
		ret =
		    hash_digest_key(c_sess, key, &keylen, hashed_key,
				    digestsize);
		if (ret)
			goto badkey;
		key = hashed_key;
	}

	/* Pick class 2 key length from algorithm submask */
	ctx->split_key_len =
	    mdpadlen[(ctx->alg_op & OP_ALG_ALGSEL_SUBMASK) >>
		     OP_ALG_ALGSEL_SHIFT] * 2;
	ctx->split_key_pad_len = ALIGN(ctx->split_key_len, 16);

	ret = gen_split_hash_key(c_sess, key, keylen);
	if (ret)
		goto badkey;

#ifdef VIRTIO_C2X0
	ret = ahash_set_sh_desc(c_sess, digestsize);
#else
	ret = ahash_set_sh_desc(ahash);
#endif
	kfree(hashed_key);
	return ret;
badkey:
	kfree(hashed_key);
#ifndef VIRTIO_C2X0
	crypto_ahash_set_flags(ahash, CRYPTO_TFM_RES_BAD_KEY_LEN);
#endif
	return -EINVAL;
}

#ifdef VIRTIO_C2X0
int ahash_digest(struct ahash_request *req,
		 struct virtio_c2x0_job_ctx *virtio_job)
#else
int ahash_digest(struct ahash_request *req)
#endif
{
	int32_t ret = 0;
	uint32_t r_id = 0;
	uint32_t *desc = NULL;
	bool chained = false;
	hash_buffers_t *mem = NULL;
	crypto_op_ctx_t *crypto_ctx = NULL;
	fsl_crypto_dev_t *c_dev = NULL;
	dev_dma_addr_t sec_dma = 0;
	uint32_t options = 0;
	struct hash_lengths len;

#ifndef VIRTIO_C2X0
	struct crypto_ahash *ahash = crypto_ahash_reqtfm(req);
	crypto_dev_sess_t *c_sess = crypto_ahash_ctx(ahash);
	struct hash_ctx *ctx = &c_sess->u.hash;

	int digestsize = crypto_ahash_digestsize(ahash);
#endif
#ifdef VIRTIO_C2X0
	crypto_dev_sess_t *c_sess = NULL;
	struct hash_ctx *ctx = NULL;
	int digestsize;
	struct virtio_c2x0_crypto_sess_ctx *hash_sess = NULL, *next_sess = NULL;
	struct virtio_c2x0_qemu_cmd *qemu_cmd = &virtio_job->qemu_cmd;
	int flag = 0;

	spin_lock(&hash_sess_list_lock);
	list_for_each_entry_safe(hash_sess, next_sess,
				 &virtio_c2x0_hash_sess_list, list_entry) {
		if (hash_sess->sess_id == qemu_cmd->u.hash.digest_req.sess_id
		    && hash_sess->guest_id == qemu_cmd->guest_id) {
			c_sess = &(hash_sess->c_sess);
			ctx = &c_sess->u.hash;
			flag = 1;
			print_debug("Hash session FOUND; sess_id = %x\n",
				    hash_sess->sess_id);
			break;
		}
	}
	if (0 == flag) {
		print_error("Hash session[%lx], guest[%d] NOT found\n",
			    qemu_cmd->u.hash.digest_req.sess_id,
			    qemu_cmd->guest_id);
		/* print_sess_list(); */
		spin_unlock(&hash_sess_list_lock);
		return -1;
	}
	spin_unlock(&hash_sess_list_lock);

	digestsize = qemu_cmd->u.hash.digest_req.digestsize;
#endif
	c_dev = c_sess->c_dev;
	r_id = c_sess->r_id;

	if (-1 == check_device(c_dev))
		return -1;

	crypto_ctx = get_crypto_ctx(c_dev->ctx_pool);
	print_debug("\t crypto_ctx addr :            :%0llx\n", crypto_ctx);

	if (unlikely(!crypto_ctx)) {
		print_error("Mem alloc failed....\n");
		ret = -ENOMEM;
		goto error;
	}

	crypto_ctx->ctx_pool = c_dev->ctx_pool;
	crypto_ctx->crypto_mem.dev = c_dev;
	crypto_ctx->crypto_mem.pool = c_dev->ring_pairs[r_id].ip_pool;
	print_debug("\t IP Buffer pool address          :%0x\n",
		    crypto_ctx->crypto_mem.pool);

	len.src_nents = sg_count(req->src, req->nbytes, &chained);
	len.addon_nents = 0;
	len.output_len = digestsize;
	len.src_len = 0;
	len.buff_len = 0;
	len.ctx_len = 0;
	len.sh_desc_len = ctx->len_desc_digest * CAAM_CMD_SZ;

	hash_init_crypto_mem(&crypto_ctx->crypto_mem, len.src_nents);
	mem = (hash_buffers_t *) (crypto_ctx->crypto_mem.buffers);

	if (len.src_nents)
		options = LDST_SGF;
	else {
		len.src_len = req->nbytes;
		options = 0;
	}

	if (-ENOMEM == hash_cp_req(req, &len, req->result, NULL, NULL,
			      ctx->sh_desc_digest, &crypto_ctx->crypto_mem)) {
		ret = -ENOMEM;
		goto error;
	}
	host_to_dev(&crypto_ctx->crypto_mem);
	create_sg_table(&crypto_ctx->crypto_mem,
			len.src_nents + len.addon_nents);

	desc = kzalloc(DESC_JOB_IO_LEN, GFP_KERNEL);
	hash_jobdesc(desc, mem->sh_desc_buff.dev_buffer.d_p_addr,
		     ctx->len_desc_digest, mem->sec_sg_buff.dev_buffer.d_p_addr,
		     req->nbytes, options, mem->output_buff.dev_buffer.d_p_addr,
		     mem->output_buff.len);
	change_desc_endianness((uint32_t *) mem->desc_buff.v_mem, desc,
			       desc_len(desc));
	kfree(desc);

	store_priv_data(crypto_ctx->crypto_mem.pool,
			mem->desc_buff.v_mem, (unsigned long)crypto_ctx);
	sec_dma = mem->desc_buff.dev_buffer.d_p_addr;

#ifndef HOST_TO_DEV_MEMCPY
	crypto_ctx->crypto_mem.dest_buff_dma =
	    crypto_ctx->crypto_mem.buffers[BT_DESC].dev_buffer.h_map_p_addr;
#endif
#ifdef HOST_TO_DEV_MEMCPY
	memcpy_to_dev(&crypto_ctx->crypto_mem);
#endif

	crypto_ctx->req.ahash = req;
	crypto_ctx->oprn = AHASH_DIGEST;
	crypto_ctx->rid = r_id;
	crypto_ctx->op_done = hash_op_done;
	crypto_ctx->desc = sec_dma;
	crypto_ctx->c_dev = c_dev;
#ifdef VIRTIO_C2X0
	/* Initialise card status as Unfinished */
	crypto_ctx->card_status = -1;

	/* Updating crypto context to virtio job
	   structure for further refernce */
	virtio_job->ctx = crypto_ctx;
#endif

#ifndef HOST_TO_DEV_MEMCPY
	if (-1 ==
	    dma_to_dev(get_dma_chnl(), &crypto_ctx->crypto_mem,
		       dma_tx_complete_cb, crypto_ctx)) {
		print_error("DMA to dev failed....\n");
		ret = -1;
		goto error;
	}
#else
	sec_dma = set_sec_affinity(c_dev, r_id, sec_dma);
	atomic_dec(&c_dev->active_jobs);
	/* Now enqueue the job into the app ring */
	if (-1 == app_ring_enqueue(c_dev, r_id, sec_dma)) {
		print_error("Application Ring Enqueue Failed\n");
		ret = -1;
		goto error1;
	}
#endif
	return -EINPROGRESS;
error:
	atomic_dec(&c_dev->active_jobs);
#ifdef HOST_TO_DEV_MEMCPY
error1:
#endif
	if (crypto_ctx) {
		if (crypto_ctx->crypto_mem.buffers)
			dealloc_crypto_mem(&crypto_ctx->crypto_mem);
		kfree(crypto_ctx->crypto_mem.c_buffers.hash);
		free_crypto_ctx(c_dev->ctx_pool, crypto_ctx);
	}
	return ret;
}

int ahash_finup_first(struct ahash_request *req)
{
#ifdef VIRTIO_C2X0
	return 0;
#else
	return ahash_digest(req);
#endif
}

#ifdef VIRTIO_C2X0
int ahash_update_ctx(struct ahash_request *req,
		     struct virtio_c2x0_job_ctx *virtio_job)
#else
int ahash_update_ctx(struct ahash_request *req)
#endif
{
	int32_t ret = 0;
	int32_t to_hash = 0;
	uint32_t r_id = 0;
	uint32_t *desc = NULL;
	bool chained = false;
	hash_buffers_t *mem = NULL;
	crypto_op_ctx_t *crypto_ctx = NULL;
	fsl_crypto_dev_t *c_dev = NULL;
	dev_dma_addr_t sec_dma = 0;
	struct hash_lengths len;

#ifndef VIRTIO_C2X0
	struct crypto_ahash *ahash = crypto_ahash_reqtfm(req);

	crypto_dev_sess_t *c_sess = crypto_ahash_ctx(ahash);
	struct hash_ctx *ctx = &c_sess->u.hash;
#endif
	struct hash_state *state = ahash_request_ctx(req);

	uint8_t *buf = state->current_buf ? state->buf_1 : state->buf_0;
	int *buflen = state->current_buf ? &state->buflen_1 : &state->buflen_0;
	uint8_t *next_buf = state->current_buf ? state->buf_0 : state->buf_1;
	int *next_buflen =
	    state->current_buf ? &state->buflen_0 : &state->buflen_1,
	    last_buflen;
	int in_len = *buflen + req->nbytes;

#ifdef VIRTIO_C2X0
	crypto_dev_sess_t *c_sess = NULL;
	struct hash_ctx *ctx = NULL;
	struct virtio_c2x0_crypto_sess_ctx *hash_sess = NULL, *next_sess = NULL;
	struct virtio_c2x0_qemu_cmd *qemu_cmd = &virtio_job->qemu_cmd;
	int flag = 0;

	spin_lock(&hash_sess_list_lock);
	list_for_each_entry_safe(hash_sess, next_sess,
				 &virtio_c2x0_hash_sess_list, list_entry) {
		if (hash_sess->sess_id == qemu_cmd->u.hash.update_req.sess_id
		    && hash_sess->guest_id == qemu_cmd->guest_id) {
			c_sess = &(hash_sess->c_sess);
			ctx = &c_sess->u.hash;
			flag = 1;
			print_debug("Hash session FOUND; sess_id = %x\n",
				    hash_sess->sess_id);
			break;
		}
	}
	if (0 == flag) {
		print_error("Hash session[%lx], guest[%d] NOT found\n",
			    qemu_cmd->u.hash.update_req.sess_id,
			    qemu_cmd->guest_id);
		/* print_sess_list(); */
		spin_unlock(&hash_sess_list_lock);
		return -1;
	}
	spin_unlock(&hash_sess_list_lock);

	/* Denotes the size of output */
	qemu_cmd->u.hash.update_req.ctxlen = ctx->ctx_len;

#endif

	last_buflen = *next_buflen;
#ifdef VIRTIO_C2X0
	*next_buflen = qemu_cmd->u.hash.update_req.next_buflen;
#else
	*next_buflen = in_len & (crypto_tfm_alg_blocksize(&ahash->base) - 1);
#endif
	to_hash = in_len - *next_buflen;

	if (to_hash) {
		c_dev = c_sess->c_dev;
		r_id = c_sess->r_id;
		
		if (-1 == check_device(c_dev))
			return -1;

		crypto_ctx = get_crypto_ctx(c_dev->ctx_pool);
		print_debug("\t crypto_ctx addr :            :%0llx\n",
			    crypto_ctx);

		if (unlikely(!crypto_ctx)) {
			print_error("Mem alloc failed....\n");
			ret = -ENOMEM;
			goto error;
		}

		crypto_ctx->ctx_pool = c_dev->ctx_pool;
		crypto_ctx->crypto_mem.dev = c_dev;
		crypto_ctx->crypto_mem.pool = c_dev->ring_pairs[r_id].ip_pool;
		print_debug("\t IP Buffer pool address          :%0x\n",
			    crypto_ctx->crypto_mem.pool);

		len.src_nents =
		    __sg_count(req->src, req->nbytes - (*next_buflen),
			       &chained);
		len.addon_nents = 1 + (*buflen ? 1 : 0);
		len.output_len = ctx->ctx_len;
		len.src_len = 0;
		len.buff_len = *buflen;
		len.ctx_len = ctx->ctx_len;
		len.sh_desc_len = ctx->len_desc_update * CAAM_CMD_SZ;

		hash_init_crypto_mem(&crypto_ctx->crypto_mem,
				     len.src_nents + len.addon_nents);
		if (-ENOMEM ==
		    hash_cp_req(req, &len, state->ctx, buf, state->ctx,
				ctx->sh_desc_update, &crypto_ctx->crypto_mem)) {
			ret = -ENOMEM;
			goto error;
		}
		host_to_dev(&crypto_ctx->crypto_mem);
		create_sg_table(&crypto_ctx->crypto_mem,
				len.src_nents + len.addon_nents);
		mem = (hash_buffers_t *) (crypto_ctx->crypto_mem.buffers);

		desc = kzalloc(DESC_JOB_IO_LEN, GFP_KERNEL);
		hash_jobdesc(desc, mem->sh_desc_buff.dev_buffer.d_p_addr,
			     ctx->len_desc_update,
			     mem->sec_sg_buff.dev_buffer.d_p_addr,
			     ctx->ctx_len + to_hash, LDST_SGF,
			     mem->output_buff.dev_buffer.d_p_addr,
			     mem->output_buff.len);
		change_desc_endianness((uint32_t *) mem->desc_buff.v_mem, desc,
				       desc_len(desc));
		kfree(desc);

		store_priv_data(crypto_ctx->crypto_mem.pool,
				mem->desc_buff.v_mem,
				(unsigned long)crypto_ctx);
		sec_dma = mem->desc_buff.dev_buffer.d_p_addr;
#ifndef HOST_TO_DEV_MEMCPY
		crypto_ctx->crypto_mem.dest_buff_dma =
		    crypto_ctx->crypto_mem.buffers[BT_DESC].dev_buffer.
		    h_map_p_addr;
#endif
#ifdef HOST_TO_DEV_MEMCPY
		memcpy_to_dev(&crypto_ctx->crypto_mem);
#endif

		crypto_ctx->req.ahash = req;
		crypto_ctx->oprn = AHASH_UPDATE_CTX;
		crypto_ctx->rid = r_id;
		crypto_ctx->op_done = hash_op_done;
		crypto_ctx->desc = sec_dma;
		crypto_ctx->c_dev = c_dev;

#ifdef VIRTIO_C2X0
		/* Initialise card status as Unfinished */
		crypto_ctx->card_status = -1;

		/* Updating crypto context to virtio
		   job structure for further refernce */
		virtio_job->ctx = crypto_ctx;
#endif

#ifndef HOST_TO_DEV_MEMCPY
		if (-1 ==
		    dma_to_dev(get_dma_chnl(), &crypto_ctx->crypto_mem,
			       dma_tx_complete_cb, crypto_ctx)) {
			print_error("DMA to dev failed....\n");
			ret = -1;
			goto error;
		}
#else
		sec_dma = set_sec_affinity(c_dev, r_id, sec_dma);
		atomic_dec(&c_dev->active_jobs);
		/* Now enqueue the job into the app ring */
		if (-1 == app_ring_enqueue(c_dev, r_id, sec_dma)) {
			print_error("Application Ring Enqueue Failed\n");
			ret = -1;
			goto error1;
		}
#endif
		if (len.src_nents) {
			if (*next_buflen) {
				scatterwalk_map_and_copy(next_buf, req->src,
							 to_hash - *buflen,
							 *next_buflen, 0);
				state->current_buf = !state->current_buf;
			}
		}
		return -EINPROGRESS;

	} else if (*next_buflen) {
		scatterwalk_map_and_copy(buf + *buflen, req->src, 0,
					 req->nbytes, 0);
		*buflen = *next_buflen;
		*next_buflen = last_buflen;
	}

	return ret;
error:
	atomic_dec(&c_dev->active_jobs);
#ifdef HOST_TO_DEV_MEMCPY
error1:
#endif
	if (crypto_ctx) {
		if (crypto_ctx->crypto_mem.buffers) {
			dealloc_crypto_mem(&crypto_ctx->crypto_mem);
		}
		kfree(crypto_ctx->crypto_mem.c_buffers.hash);
		free_crypto_ctx(c_dev->ctx_pool, crypto_ctx);
	}
	return ret;
}

#ifdef VIRTIO_C2X0
int ahash_finup_ctx(struct ahash_request *req,
		    struct virtio_c2x0_job_ctx *virtio_job)
#else
int ahash_finup_ctx(struct ahash_request *req)
#endif
{
	int32_t ret = 0;
	uint32_t r_id = 0;
	uint32_t *desc = NULL;
	bool chained = false;
	hash_buffers_t *mem = NULL;
	crypto_op_ctx_t *crypto_ctx = NULL;
	fsl_crypto_dev_t *c_dev = NULL;
	dev_dma_addr_t sec_dma = 0;
	struct hash_lengths len;

#ifndef VIRTIO_C2X0
	struct crypto_ahash *ahash = crypto_ahash_reqtfm(req);
	crypto_dev_sess_t *c_sess = crypto_ahash_ctx(ahash);
	struct hash_ctx *ctx = &c_sess->u.hash;

	int digestsize = crypto_ahash_digestsize(ahash);
#endif
	struct hash_state *state = ahash_request_ctx(req);
	uint8_t *buf = state->current_buf ? state->buf_1 : state->buf_0;
	int buflen = state->current_buf ? state->buflen_1 : state->buflen_0;
#ifdef VIRTIO_C2X0
	crypto_dev_sess_t *c_sess = NULL;
	struct hash_ctx *ctx = NULL;
	struct virtio_c2x0_crypto_sess_ctx *hash_sess = NULL, *next_sess = NULL;
	struct virtio_c2x0_qemu_cmd *qemu_cmd = &virtio_job->qemu_cmd;
	int digestsize = 0;
	int flag = 0;

	spin_lock(&hash_sess_list_lock);
	list_for_each_entry_safe(hash_sess, next_sess,
				 &virtio_c2x0_hash_sess_list, list_entry) {
		if (hash_sess->sess_id == qemu_cmd->u.hash.finup_req.sess_id
		    && hash_sess->guest_id == qemu_cmd->guest_id) {
			c_sess = &(hash_sess->c_sess);
			ctx = &c_sess->u.hash;
			flag = 1;
			print_debug("Hash session FOUND; sess_id = %x\n",
				    hash_sess->sess_id);
			break;
		}
	}
	if (0 == flag) {
		print_error("Hash session[%lx], guest[%d] NOT found\n",
			    qemu_cmd->u.hash.finup_req.sess_id,
			    qemu_cmd->guest_id);
		/* print_sess_list(); */
		spin_unlock(&hash_sess_list_lock);
		return -1;
	}
	spin_unlock(&hash_sess_list_lock);

	/* Denotes the size of output */
	digestsize = qemu_cmd->u.hash.finup_req.digestsize;
#endif

	c_dev = c_sess->c_dev;
	r_id = c_sess->r_id;

	if (-1 == check_device(c_dev))
		return -1;

	crypto_ctx = get_crypto_ctx(c_dev->ctx_pool);
	print_debug("\t crypto_ctx addr :            :%0llx\n", crypto_ctx);

	if (unlikely(!crypto_ctx)) {
		print_error("Mem alloc failed....\n");
		ret = -ENOMEM;
		goto error;
	}

	crypto_ctx->ctx_pool = c_dev->ctx_pool;
	crypto_ctx->crypto_mem.dev = c_dev;
	crypto_ctx->crypto_mem.pool = c_dev->ring_pairs[r_id].ip_pool;
	print_debug("\t IP Buffer pool address          :%0x\n",
		    crypto_ctx->crypto_mem.pool);

	len.src_nents = __sg_count(req->src, req->nbytes, &chained);
	len.addon_nents = 1 + (buflen ? 1 : 0);
	len.output_len = digestsize;
	len.src_len = 0;
	len.buff_len = buflen;
	len.ctx_len = ctx->ctx_len;
	len.sh_desc_len = ctx->len_desc_finup * CAAM_CMD_SZ;

	hash_init_crypto_mem(&crypto_ctx->crypto_mem,
			     len.src_nents + len.addon_nents);
	if (-ENOMEM ==
	    hash_cp_req(req, &len, req->result, buf, state->ctx,
			ctx->sh_desc_finup, &crypto_ctx->crypto_mem)) {
		ret = -ENOMEM;
		goto error;
	}
	host_to_dev(&crypto_ctx->crypto_mem);
	create_sg_table(&crypto_ctx->crypto_mem,
			len.src_nents + len.addon_nents);
	mem = (hash_buffers_t *) (crypto_ctx->crypto_mem.buffers);

	desc = kzalloc(DESC_JOB_IO_LEN, GFP_KERNEL);
	hash_jobdesc(desc, mem->sh_desc_buff.dev_buffer.d_p_addr,
		     ctx->len_desc_finup, mem->sec_sg_buff.dev_buffer.d_p_addr,
		     ctx->ctx_len + buflen + req->nbytes, LDST_SGF,
		     mem->output_buff.dev_buffer.d_p_addr,
		     mem->output_buff.len);
	change_desc_endianness((uint32_t *) mem->desc_buff.v_mem, desc,
			       desc_len(desc));
	kfree(desc);

	store_priv_data(crypto_ctx->crypto_mem.pool,
			mem->desc_buff.v_mem, (unsigned long)crypto_ctx);
	sec_dma = mem->desc_buff.dev_buffer.d_p_addr;

#ifndef HOST_TO_DEV_MEMCPY
	crypto_ctx->crypto_mem.dest_buff_dma =
	    crypto_ctx->crypto_mem.buffers[BT_DESC].dev_buffer.h_map_p_addr;
#endif
#ifdef HOST_TO_DEV_MEMCPY
	memcpy_to_dev(&crypto_ctx->crypto_mem);
#endif

	crypto_ctx->req.ahash = req;
	crypto_ctx->oprn = AHASH_FINUP_CTX;
	crypto_ctx->rid = r_id;
	crypto_ctx->op_done = hash_op_done;
	crypto_ctx->desc = sec_dma;
	crypto_ctx->c_dev = c_dev;
#ifdef VIRTIO_C2X0
	/* Initialise card status as Unfinished */
	crypto_ctx->card_status = -1;

	/* Updating crypto context to virtio
	   job structure for further refernce */
	virtio_job->ctx = crypto_ctx;
#endif

#ifndef HOST_TO_DEV_MEMCPY
	if (-1 ==
	    dma_to_dev(get_dma_chnl(), &crypto_ctx->crypto_mem,
		       dma_tx_complete_cb, crypto_ctx)) {
		print_error("DMA to dev failed....\n");
		ret = -1;
		goto error;
	}
#else
	sec_dma = set_sec_affinity(c_dev, r_id, sec_dma);
	atomic_dec(&c_dev->active_jobs);
	/* Now enqueue the job into the app ring */
	if (-1 == app_ring_enqueue(c_dev, r_id, sec_dma)) {
		print_error("Application Ring Enqueue Failed\n");
		ret = -1;
		goto error1;
	}
#endif
	return -EINPROGRESS;
error:
	atomic_dec(&c_dev->active_jobs);
#ifdef HOST_TO_DEV_MEMCPY
error1:
#endif
	if (crypto_ctx) {
		if (crypto_ctx->crypto_mem.buffers)
			dealloc_crypto_mem(&crypto_ctx->crypto_mem);
		kfree(crypto_ctx->crypto_mem.c_buffers.hash);
		free_crypto_ctx(c_dev->ctx_pool, crypto_ctx);
	}
	return ret;
}

#ifdef VIRTIO_C2X0
int ahash_final_ctx(struct ahash_request *req,
		    struct virtio_c2x0_job_ctx *virtio_job)
#else
int ahash_final_ctx(struct ahash_request *req)
#endif
{
	int32_t ret = 0;
	uint32_t r_id = 0;
	uint32_t *desc = NULL;
	hash_buffers_t *mem = NULL;
	crypto_op_ctx_t *crypto_ctx = NULL;
	fsl_crypto_dev_t *c_dev = NULL;
	dev_dma_addr_t sec_dma = 0;
	uint32_t options = 0;
	struct hash_lengths len;
#ifndef VIRTIO_C2X0
	struct crypto_ahash *ahash = crypto_ahash_reqtfm(req);
	crypto_dev_sess_t *c_sess = crypto_ahash_ctx(ahash);
	struct hash_ctx *ctx = &c_sess->u.hash;
	int digestsize = crypto_ahash_digestsize(ahash);
#endif

	struct hash_state *state = ahash_request_ctx(req);
	uint8_t *buf = state->current_buf ? state->buf_1 : state->buf_0;
	int buflen = state->current_buf ? state->buflen_1 : state->buflen_0;
#ifdef VIRTIO_C2X0
	crypto_dev_sess_t *c_sess = NULL;
	struct hash_ctx *ctx = NULL;
	struct virtio_c2x0_crypto_sess_ctx *hash_sess = NULL, *next_sess = NULL;
	struct virtio_c2x0_qemu_cmd *qemu_cmd = &virtio_job->qemu_cmd;
	int flag = 0;
	int digestsize = 0;

	spin_lock(&hash_sess_list_lock);
	list_for_each_entry_safe(hash_sess, next_sess,
				 &virtio_c2x0_hash_sess_list, list_entry) {
		if (hash_sess->sess_id == qemu_cmd->u.hash.final_req.sess_id
		    && hash_sess->guest_id == qemu_cmd->guest_id) {
			c_sess = &(hash_sess->c_sess);
			ctx = &c_sess->u.hash;
			flag = 1;
			print_debug("Hash session FOUND; sess_id = %x\n",
				    hash_sess->sess_id);
			break;
		}
	}
	if (0 == flag) {
		print_error("Hash session[%lx], guest[%d] NOT found\n",
			    qemu_cmd->u.hash.final_req.sess_id,
			    qemu_cmd->guest_id);
		/* print_sess_list(); */
		spin_unlock(&hash_sess_list_lock);
		return -1;
	}
	spin_unlock(&hash_sess_list_lock);

	digestsize = qemu_cmd->u.hash.final_req.digestsize;
#endif

	c_dev = c_sess->c_dev;
	r_id = c_sess->r_id;

	if (-1 == check_device(c_dev))
		return -1;

	crypto_ctx = get_crypto_ctx(c_dev->ctx_pool);
	print_debug("\t crypto_ctx addr :            :%0llx\n", crypto_ctx);

	if (unlikely(!crypto_ctx)) {
		print_error("Mem alloc failed....\n");
		ret = -ENOMEM;
		goto error;
	}

	crypto_ctx->ctx_pool = c_dev->ctx_pool;
	crypto_ctx->crypto_mem.dev = c_dev;
	crypto_ctx->crypto_mem.pool = c_dev->ring_pairs[r_id].ip_pool;
	print_debug("\t IP Buffer pool address          :%0x\n",
		    crypto_ctx->crypto_mem.pool);

	len.src_nents = 0;
	len.addon_nents = 0;
	len.output_len = digestsize;
	len.src_len = 0;
	len.buff_len = buflen;
	len.ctx_len = ctx->ctx_len;
	len.sh_desc_len = ctx->len_desc_fin * CAAM_CMD_SZ;

	if (buflen) {
		len.addon_nents = 2;
		options = LDST_SGF;
	}

	else
		len.src_len = ctx->ctx_len;

	hash_init_crypto_mem(&crypto_ctx->crypto_mem,
			     len.src_nents + len.addon_nents);
	if (-ENOMEM ==
	    hash_cp_req(req, &len, req->result, buf, state->ctx,
			ctx->sh_desc_fin, &crypto_ctx->crypto_mem)) {
		ret = -ENOMEM;
		goto error;
	}
	host_to_dev(&crypto_ctx->crypto_mem);
	create_sg_table(&crypto_ctx->crypto_mem,
			len.src_nents + len.addon_nents);
	mem = (hash_buffers_t *) (crypto_ctx->crypto_mem.buffers);

	desc = kzalloc(DESC_JOB_IO_LEN, GFP_KERNEL);
	hash_jobdesc(desc, mem->sh_desc_buff.dev_buffer.d_p_addr,
		     ctx->len_desc_fin, mem->sec_sg_buff.dev_buffer.d_p_addr,
		     ctx->ctx_len + buflen, options,
		     mem->output_buff.dev_buffer.d_p_addr, digestsize);
	change_desc_endianness((uint32_t *) mem->desc_buff.v_mem, desc,
			       desc_len(desc));
	kfree(desc);

	store_priv_data(crypto_ctx->crypto_mem.pool,
			mem->desc_buff.v_mem, (unsigned long)crypto_ctx);
	sec_dma = mem->desc_buff.dev_buffer.d_p_addr;

#ifndef HOST_TO_DEV_MEMCPY
	crypto_ctx->crypto_mem.dest_buff_dma =
	    crypto_ctx->crypto_mem.buffers[BT_DESC].dev_buffer.h_map_p_addr;
#endif
#ifdef HOST_TO_DEV_MEMCPY
	memcpy_to_dev(&crypto_ctx->crypto_mem);
#endif

	crypto_ctx->req.ahash = req;
	crypto_ctx->oprn = AHASH_FINAL_CTX;
	crypto_ctx->rid = r_id;
	crypto_ctx->op_done = hash_op_done;
	crypto_ctx->desc = sec_dma;
	crypto_ctx->c_dev = c_dev;
#ifdef VIRTIO_C2X0
	/* Initialise card status as Unfinished */
	crypto_ctx->card_status = -1;

	/* Updating crypto context to virtio
	   job structure for further refernce */
	virtio_job->ctx = crypto_ctx;
#endif

#ifndef HOST_TO_DEV_MEMCPY
	if (-1 ==
	    dma_to_dev(get_dma_chnl(), &crypto_ctx->crypto_mem,
		       dma_tx_complete_cb, crypto_ctx)) {
		print_error("DMA to dev failed....\n");
		ret = -1;
		goto error;
	}
#else
	sec_dma = set_sec_affinity(c_dev, r_id, sec_dma);
	atomic_dec(&c_dev->active_jobs);
	/* Now enqueue the job into the app ring */
	if (-1 == app_ring_enqueue(c_dev, r_id, sec_dma)) {
		print_error("Application Ring Enqueue Failed\n");
		ret = -1;
		goto error1;
	}
#endif
	return -EINPROGRESS;

error:
	atomic_dec(&c_dev->active_jobs);
#ifdef HOST_TO_DEV_MEMCPY
error1:
#endif
	if (crypto_ctx) {
		if (crypto_ctx->crypto_mem.buffers) {
			dealloc_crypto_mem(&crypto_ctx->crypto_mem);
		}
		kfree(crypto_ctx->crypto_mem.c_buffers.hash);
		free_crypto_ctx(c_dev->ctx_pool, crypto_ctx);
	}
	return ret;
}

#ifdef VIRTIO_C2X0
int ahash_final_no_ctx(struct ahash_request *req,
		       struct virtio_c2x0_job_ctx *virtio_job)
#else
int ahash_final_no_ctx(struct ahash_request *req)
#endif
{
	int32_t ret = 0;
	uint32_t r_id = 0;
	uint32_t *desc = NULL;
	hash_buffers_t *mem = NULL;
	crypto_op_ctx_t *crypto_ctx = NULL;
	fsl_crypto_dev_t *c_dev = NULL;
	dev_dma_addr_t sec_dma = 0;
	struct hash_lengths len;
#ifndef VIRTIO_C2X0
	struct crypto_ahash *ahash = crypto_ahash_reqtfm(req);
	crypto_dev_sess_t *c_sess = crypto_ahash_ctx(ahash);
	struct hash_ctx *ctx = &c_sess->u.hash;
	int digestsize = crypto_ahash_digestsize(ahash);
#endif
	struct hash_state *state = ahash_request_ctx(req);

	uint8_t *buf = state->current_buf ? state->buf_1 : state->buf_0;
	int buflen = state->current_buf ? state->buflen_1 : state->buflen_0;
#ifdef VIRTIO_C2X0
	crypto_dev_sess_t *c_sess = NULL;
	struct hash_ctx *ctx = NULL;
	struct virtio_c2x0_crypto_sess_ctx *hash_sess = NULL, *next_sess = NULL;
	struct virtio_c2x0_qemu_cmd *qemu_cmd = &virtio_job->qemu_cmd;
	int flag = 0;
	int digestsize = 0;

	spin_lock(&hash_sess_list_lock);
	list_for_each_entry_safe(hash_sess, next_sess,
				 &virtio_c2x0_hash_sess_list, list_entry) {
		if (hash_sess->sess_id == qemu_cmd->u.hash.final_req.sess_id
		    && hash_sess->guest_id == qemu_cmd->guest_id) {
			c_sess = &(hash_sess->c_sess);
			ctx = &c_sess->u.hash;
			flag = 1;
			print_debug("Hash session FOUND; sess_id = %x\n",
				    hash_sess->sess_id);
			break;
		}
	}
	if (0 == flag) {
		print_error("Hash session[%lx], guest[%d] NOT found\n",
			    qemu_cmd->u.hash.final_req.sess_id,
			    qemu_cmd->guest_id);
		/* print_sess_list(); */
		spin_unlock(&hash_sess_list_lock);
		return -1;
	}
	spin_unlock(&hash_sess_list_lock);

	digestsize = qemu_cmd->u.hash.final_req.digestsize;
#endif

	c_dev = c_sess->c_dev;
	r_id = c_sess->r_id;

	if (-1 == check_device(c_dev))
		return -1;

	crypto_ctx = get_crypto_ctx(c_dev->ctx_pool);
	print_debug("\t crypto_ctx addr :            :%0llx\n", crypto_ctx);

	if (unlikely(!crypto_ctx)) {
		print_error("Mem alloc failed....\n");
		ret = -ENOMEM;
		goto error;
	}

	crypto_ctx->ctx_pool = c_dev->ctx_pool;
	crypto_ctx->crypto_mem.dev = c_dev;
	crypto_ctx->crypto_mem.pool = c_dev->ring_pairs[r_id].ip_pool;
	print_debug("\t IP Buffer pool address          :%0x\n",
		    crypto_ctx->crypto_mem.pool);

	len.src_nents = 0;
	len.addon_nents = 0;
	len.output_len = digestsize;
	len.src_len = buflen;
	len.buff_len = buflen;
	len.ctx_len = 0;
	len.sh_desc_len = ctx->len_desc_digest * CAAM_CMD_SZ;

	hash_init_crypto_mem(&crypto_ctx->crypto_mem,
			     len.src_nents + len.addon_nents);

	if (-ENOMEM == hash_cp_req(req, &len, req->result, buf, NULL,
			      ctx->sh_desc_digest, &crypto_ctx->crypto_mem)) {
		ret = -ENOMEM;
		goto error;
	}
	host_to_dev(&crypto_ctx->crypto_mem);

	mem = (hash_buffers_t *) (crypto_ctx->crypto_mem.buffers);

	desc = kzalloc(DESC_JOB_IO_LEN, GFP_KERNEL);
	hash_jobdesc(desc, mem->sh_desc_buff.dev_buffer.d_p_addr,
		     ctx->len_desc_digest, mem->sec_sg_buff.dev_buffer.d_p_addr,
		     buflen, 0, mem->output_buff.dev_buffer.d_p_addr,
		     mem->output_buff.len);

	change_desc_endianness((uint32_t *) mem->desc_buff.v_mem, desc,
			       desc_len(desc));
	kfree(desc);

	store_priv_data(crypto_ctx->crypto_mem.pool,
			mem->desc_buff.v_mem, (unsigned long)crypto_ctx);
	sec_dma = mem->desc_buff.dev_buffer.d_p_addr;
#ifndef HOST_TO_DEV_MEMCPY
	crypto_ctx->crypto_mem.dest_buff_dma =
	    crypto_ctx->crypto_mem.buffers[BT_DESC].dev_buffer.h_map_p_addr;
#endif
#ifdef HOST_TO_DEV_MEMCPY
	memcpy_to_dev(&crypto_ctx->crypto_mem);
#endif

	crypto_ctx->req.ahash = req;
	crypto_ctx->oprn = AHASH_FINAL_NO_CTX;
	crypto_ctx->rid = r_id;
	crypto_ctx->op_done = hash_op_done;
	crypto_ctx->desc = sec_dma;
	crypto_ctx->c_dev = c_dev;
#ifdef VIRTIO_C2X0
	/* Initialise card status as Unfinished */
	crypto_ctx->card_status = -1;

	/* Updating crypto context to virtio
	   job structure for further refernce */
	virtio_job->ctx = crypto_ctx;
#endif

#ifndef HOST_TO_DEV_MEMCPY
	if (-1 ==
	    dma_to_dev(get_dma_chnl(), &crypto_ctx->crypto_mem,
		       dma_tx_complete_cb, crypto_ctx)) {
		print_error("DMA to dev failed....\n");
		ret = -1;
		goto error;
	}
#else
	sec_dma = set_sec_affinity(c_dev, r_id, sec_dma);
	atomic_dec(&c_dev->active_jobs);
	/* Now enqueue the job into the app ring */
	if (-1 == app_ring_enqueue(c_dev, r_id, sec_dma)) {
		print_error("Application Ring Enqueue Failed\n");
		ret = -1;
		goto error1;
	}
#endif
	return -EINPROGRESS;
error:
	atomic_dec(&c_dev->active_jobs);
#ifdef HOST_TO_DEV_MEMCPY
error1:
#endif
	if (crypto_ctx) {
		if (crypto_ctx->crypto_mem.buffers) {
			dealloc_crypto_mem(&crypto_ctx->crypto_mem);
		}
		kfree(crypto_ctx->crypto_mem.c_buffers.hash);
		free_crypto_ctx(c_dev->ctx_pool, crypto_ctx);
	}
	return ret;
}

#ifdef VIRTIO_C2X0
int ahash_finup_no_ctx(struct ahash_request *req,
		       struct virtio_c2x0_job_ctx *virtio_job)
#else
/* submit ahash finup if it the first job descriptor after update */
int ahash_finup_no_ctx(struct ahash_request *req)
#endif
{
	int32_t ret = 0;
	uint32_t r_id = 0;
	uint32_t *desc = NULL;
	bool chained = false;
	hash_buffers_t *mem = NULL;
	crypto_op_ctx_t *crypto_ctx = NULL;
	fsl_crypto_dev_t *c_dev = NULL;
	dev_dma_addr_t sec_dma = 0;
	struct hash_lengths len;
#ifndef VIRTIO_C2X0
	struct crypto_ahash *ahash = crypto_ahash_reqtfm(req);
	crypto_dev_sess_t *c_sess = crypto_ahash_ctx(ahash);
	struct hash_ctx *ctx = &c_sess->u.hash;
	int digestsize = crypto_ahash_digestsize(ahash);
#endif

	struct hash_state *state = ahash_request_ctx(req);

	uint8_t *buf = state->current_buf ? state->buf_1 : state->buf_0;
	int buflen = state->current_buf ? state->buflen_1 : state->buflen_0;
#ifdef VIRTIO_C2X0
	crypto_dev_sess_t *c_sess = NULL;
	struct hash_ctx *ctx = NULL;
	struct virtio_c2x0_crypto_sess_ctx *hash_sess = NULL, *next_sess = NULL;
	struct virtio_c2x0_qemu_cmd *qemu_cmd = &virtio_job->qemu_cmd;
	int digestsize = 0;
	int flag = 0;

	spin_lock(&hash_sess_list_lock);
	list_for_each_entry_safe(hash_sess, next_sess,
				 &virtio_c2x0_hash_sess_list, list_entry) {
		if (hash_sess->sess_id == qemu_cmd->u.hash.finup_req.sess_id
		    && hash_sess->guest_id == qemu_cmd->guest_id) {
			c_sess = &(hash_sess->c_sess);
			ctx = &c_sess->u.hash;
			flag = 1;
			break;
			print_debug("Hash session FOUND; sess_id = %x\n",
				    hash_sess->sess_id);
		}
	}
	if (0 == flag) {
		print_error("Hash session[%lx] NOT found\n",
			    qemu_cmd->u.hash.finup_req.sess_id);
		/* print_sess_list(); */
		spin_unlock(&hash_sess_list_lock);
		return -1;
	}
	spin_unlock(&hash_sess_list_lock);

	/* Denotes the size of output */
	digestsize = qemu_cmd->u.hash.finup_req.digestsize;
#endif

	c_dev = c_sess->c_dev;
	r_id = c_sess->r_id;

	if (-1 == check_device(c_dev))
		return -1;

	crypto_ctx = get_crypto_ctx(c_dev->ctx_pool);
	print_debug("\t crypto_ctx addr :            :%0llx\n", crypto_ctx);

	if (unlikely(!crypto_ctx)) {
		print_error("Mem alloc failed....\n");
		ret = -ENOMEM;
		goto error;
	}

	crypto_ctx->ctx_pool = c_dev->ctx_pool;
	crypto_ctx->crypto_mem.dev = c_dev;
	crypto_ctx->crypto_mem.pool = c_dev->ring_pairs[r_id].ip_pool;
	print_debug("\t IP Buffer pool address          :%0x\n",
		    crypto_ctx->crypto_mem.pool);

	len.src_nents = __sg_count(req->src, req->nbytes, &chained);
	len.addon_nents = 1;

	len.output_len = digestsize;
	len.src_len = 0;
	len.buff_len = buflen;
	len.ctx_len = 0;
	len.sh_desc_len = ctx->len_desc_digest * CAAM_CMD_SZ;

	hash_init_crypto_mem(&crypto_ctx->crypto_mem,
			     len.src_nents + len.addon_nents);

	if (-ENOMEM == hash_cp_req(req, &len, req->result, buf, NULL,
			      ctx->sh_desc_digest, &crypto_ctx->crypto_mem)) {
		ret = -ENOMEM;
		goto error;
	}

	host_to_dev(&crypto_ctx->crypto_mem);
	create_sg_table(&crypto_ctx->crypto_mem,
			len.src_nents + len.addon_nents);
	mem = (hash_buffers_t *) (crypto_ctx->crypto_mem.buffers);

	desc = kzalloc(DESC_JOB_IO_LEN, GFP_KERNEL);
	hash_jobdesc(desc, mem->sh_desc_buff.dev_buffer.d_p_addr,
		     ctx->len_desc_digest, mem->sec_sg_buff.dev_buffer.d_p_addr,
		     buflen + req->nbytes, LDST_SGF,
		     mem->output_buff.dev_buffer.d_p_addr,
		     mem->output_buff.len);

	change_desc_endianness((uint32_t *) mem->desc_buff.v_mem, desc,
			       desc_len(desc));
	kfree(desc);

	store_priv_data(crypto_ctx->crypto_mem.pool,
			mem->desc_buff.v_mem, (unsigned long)crypto_ctx);
	sec_dma = mem->desc_buff.dev_buffer.d_p_addr;

#ifndef HOST_TO_DEV_MEMCPY
	crypto_ctx->crypto_mem.dest_buff_dma =
	    crypto_ctx->crypto_mem.buffers[BT_DESC].dev_buffer.h_map_p_addr;
#endif
#ifdef HOST_TO_DEV_MEMCPY
	memcpy_to_dev(&crypto_ctx->crypto_mem);
#endif

	crypto_ctx->req.ahash = req;
	crypto_ctx->oprn = AHASH_FINUP_NO_CTX;
	crypto_ctx->rid = r_id;
	crypto_ctx->op_done = hash_op_done;
	crypto_ctx->desc = sec_dma;
	crypto_ctx->c_dev = c_dev;
#ifdef VIRTIO_C2X0
	/* Initialise card status as Unfinished */
	crypto_ctx->card_status = -1;

	/* Updating crypto context to virtio
	   job structure for further refernce */
	virtio_job->ctx = crypto_ctx;
#endif

#ifndef HOST_TO_DEV_MEMCPY
	if (-1 ==
	    dma_to_dev(get_dma_chnl(), &crypto_ctx->crypto_mem,
		       dma_tx_complete_cb, crypto_ctx)) {
		print_error("DMA to dev failed....\n");
		ret = -1;
		goto error;
	}
#else
	sec_dma = set_sec_affinity(c_dev, r_id, sec_dma);
	atomic_dec(&c_dev->active_jobs);
	/* Now enqueue the job into the app ring */
	if (-1 == app_ring_enqueue(c_dev, r_id, sec_dma)) {
		print_error("Application Ring Enqueue Failed\n");
		ret = -1;
		goto error1;
	}
#endif
	return -EINPROGRESS;
error:
	atomic_dec(&c_dev->active_jobs);
#ifdef HOST_TO_DEV_MEMCPY
error1:
#endif
	if (crypto_ctx) {
		if (crypto_ctx->crypto_mem.buffers) {
			dealloc_crypto_mem(&crypto_ctx->crypto_mem);
		}
		kfree(crypto_ctx->crypto_mem.c_buffers.hash);
		free_crypto_ctx(c_dev->ctx_pool, crypto_ctx);
	}
	return ret;
}

#ifdef VIRTIO_C2X0
int ahash_update_no_ctx(struct ahash_request *req,
			struct virtio_c2x0_job_ctx *virtio_job)
#else
int ahash_update_no_ctx(struct ahash_request *req)
#endif
{
	int32_t ret = 0;
	bool chained = false;
	hash_buffers_t *mem = NULL;
	crypto_op_ctx_t *crypto_ctx = NULL;
	uint32_t r_id = 0;
	fsl_crypto_dev_t *c_dev = NULL;
	uint32_t *desc = NULL;
	dev_dma_addr_t sec_dma = 0;
	struct hash_lengths len;
#ifndef VIRTIO_C2X0
	struct crypto_ahash *ahash = crypto_ahash_reqtfm(req);
	crypto_dev_sess_t *c_sess = crypto_ahash_ctx(ahash);
	struct hash_ctx *ctx = &c_sess->u.hash;
#endif

	struct hash_state *state = ahash_request_ctx(req);
	uint8_t *buf = state->current_buf ? state->buf_1 : state->buf_0;
	int *buflen = state->current_buf ? &state->buflen_1 : &state->buflen_0;
	uint8_t *next_buf = state->current_buf ? state->buf_0 : state->buf_1;
	int *next_buflen =
	    state->current_buf ? &state->buflen_0 : &state->buflen_1;
	int in_len = *buflen + req->nbytes, to_hash;

#ifdef VIRTIO_C2X0
	crypto_dev_sess_t *c_sess = NULL;
	struct hash_ctx *ctx = NULL;
	struct virtio_c2x0_crypto_sess_ctx *hash_sess = NULL, *next_sess = NULL;
	struct virtio_c2x0_qemu_cmd *qemu_cmd = &virtio_job->qemu_cmd;
	int flag = 0;

	spin_lock(&hash_sess_list_lock);
	list_for_each_entry_safe(hash_sess, next_sess,
				 &virtio_c2x0_hash_sess_list, list_entry) {
		if (hash_sess->sess_id == qemu_cmd->u.hash.update_req.sess_id
		    && hash_sess->guest_id == qemu_cmd->guest_id) {
			c_sess = &(hash_sess->c_sess);
			ctx = &c_sess->u.hash;
			flag = 1;
			print_debug("Hash session FOUND; sess_id = %x\n",
				    hash_sess->sess_id);
			break;
		}
	}
	if (0 == flag) {
		print_error("Hash session[%lx] NOT found\n",
			    qemu_cmd->u.hash.update_req.sess_id);
		/* print_sess_list(); */
		spin_unlock(&hash_sess_list_lock);
		return -1;
	}
	spin_unlock(&hash_sess_list_lock);

	/* Denotes the size of output */
	qemu_cmd->u.hash.update_req.ctxlen = ctx->ctx_len;

	*next_buflen = qemu_cmd->u.hash.update_req.next_buflen;
#else
	*next_buflen = in_len & (crypto_tfm_alg_blocksize(&ahash->base) - 1);
#endif
	to_hash = in_len - *next_buflen;

	if (to_hash) {
		c_dev = c_sess->c_dev;
		r_id = c_sess->r_id;

		if (-1 == check_device(c_dev))
			return -1;

		crypto_ctx = get_crypto_ctx(c_dev->ctx_pool);
		print_debug("\t crypto_ctx addr :            :%0llx\n",
			    crypto_ctx);

		if (unlikely(!crypto_ctx)) {
			print_error("Mem alloc failed....\n");
			ret = -ENOMEM;
			goto error;
		}

		crypto_ctx->ctx_pool = c_dev->ctx_pool;
		crypto_ctx->crypto_mem.dev = c_dev;
		crypto_ctx->crypto_mem.pool = c_dev->ring_pairs[r_id].ip_pool;
		print_debug("\t IP Buffer pool address          :%0x\n",
			    crypto_ctx->crypto_mem.pool);

		len.src_nents =
		    __sg_count(req->src, req->nbytes - (*next_buflen),
			       &chained);
		len.addon_nents = 1;
		len.output_len = ctx->ctx_len;
		len.src_len = 0;
		len.buff_len = *buflen;
		len.ctx_len = 0;
		len.sh_desc_len = ctx->len_desc_update_first * CAAM_CMD_SZ;

		hash_init_crypto_mem(&crypto_ctx->crypto_mem,
				     len.src_nents + len.addon_nents);
		if (-ENOMEM ==
		    hash_cp_req(req, &len, state->ctx, buf, NULL,
				ctx->sh_desc_update_first,
				&crypto_ctx->crypto_mem)) {
			ret = -ENOMEM;
			goto error;
		}
		host_to_dev(&crypto_ctx->crypto_mem);
		create_sg_table(&crypto_ctx->crypto_mem,
				len.src_nents + len.addon_nents);
		mem = (hash_buffers_t *) (crypto_ctx->crypto_mem.buffers);

		desc = kzalloc(DESC_JOB_IO_LEN, GFP_KERNEL);
		hash_jobdesc(desc, mem->sh_desc_buff.dev_buffer.d_p_addr,
			     ctx->len_desc_update_first,
			     mem->sec_sg_buff.dev_buffer.d_p_addr, to_hash,
			     LDST_SGF, mem->output_buff.dev_buffer.d_p_addr,
			     mem->output_buff.len);

		change_desc_endianness((uint32_t *) mem->desc_buff.v_mem, desc,
				       desc_len(desc));
		kfree(desc);

		store_priv_data(crypto_ctx->crypto_mem.pool,
				mem->desc_buff.v_mem,
				(unsigned long)crypto_ctx);
		sec_dma = mem->desc_buff.dev_buffer.d_p_addr;
#ifndef HOST_TO_DEV_MEMCPY
		crypto_ctx->crypto_mem.dest_buff_dma =
		    crypto_ctx->crypto_mem.buffers[BT_DESC].dev_buffer.
		    h_map_p_addr;
#endif
#ifdef HOST_TO_DEV_MEMCPY
		memcpy_to_dev(&crypto_ctx->crypto_mem);
#endif

		crypto_ctx->req.ahash = req;
		crypto_ctx->oprn = AHASH_UPDATE_NO_CTX;
		crypto_ctx->rid = r_id;
		crypto_ctx->op_done = hash_op_done;
		crypto_ctx->desc = sec_dma;
		crypto_ctx->c_dev = c_dev;
#ifdef VIRTIO_C2X0
		/* Initialise card status as Unfinished */
		crypto_ctx->card_status = -1;

		/* Updating crypto context to virtio
		   job structure for further refernce */
		virtio_job->ctx = crypto_ctx;
#endif

#ifndef HOST_TO_DEV_MEMCPY
		if (-1 ==
		    dma_to_dev(get_dma_chnl(), &crypto_ctx->crypto_mem,
			       dma_tx_complete_cb, crypto_ctx)) {
			print_error("DMA to dev failed....\n");
			ret = -1;
			goto error;
		}
#else
		sec_dma = set_sec_affinity(c_dev, r_id, sec_dma);
		atomic_dec(&c_dev->active_jobs);
		/* Now enqueue the job into the app ring */
		if (-1 == app_ring_enqueue(c_dev, r_id, sec_dma)) {
			print_error("Application Ring Enqueue Failed\n");
			ret = -1;
			goto error1;
		}
#endif
		if (*next_buflen) {
			scatterwalk_map_and_copy(next_buf, req->src,
						 to_hash - *buflen,
						 *next_buflen, 0);
			state->current_buf = !state->current_buf;
		}
#ifndef VIRTIO_C2X0
		state->update = ahash_update_ctx;
		state->finup = ahash_finup_ctx;
		state->final = ahash_final_ctx;
#endif
		atomic_dec(&c_dev->active_jobs);
		return -EINPROGRESS;

	} else if (*next_buflen) {
		scatterwalk_map_and_copy(buf + *buflen, req->src, 0,
					 req->nbytes, 0);
		*buflen = *next_buflen;
		*next_buflen = 0;
	}

	return ret;

error:
	atomic_dec(&c_dev->active_jobs);
#ifdef HOST_TO_DEV_MEMCPY
error1:
#endif
	if (crypto_ctx) {
		if (crypto_ctx->crypto_mem.buffers) {
			dealloc_crypto_mem(&crypto_ctx->crypto_mem);
		}
		kfree(crypto_ctx->crypto_mem.c_buffers.hash);
		free_crypto_ctx(c_dev->ctx_pool, crypto_ctx);
	}
	return ret;
}

#ifdef VIRTIO_C2X0
int ahash_update_first(struct ahash_request *req,
		       struct virtio_c2x0_job_ctx *virtio_job)
#else
int ahash_update_first(struct ahash_request *req)
#endif
{
	int32_t ret = 0;
	int32_t to_hash = 0;
	uint32_t r_id = 0;
	uint32_t *desc = NULL;
	bool chained = false;
	hash_buffers_t *mem = NULL;
	crypto_op_ctx_t *crypto_ctx = NULL;
	fsl_crypto_dev_t *c_dev = NULL;
	dev_dma_addr_t sec_dma = 0;
	uint32_t options = 0;
	struct hash_lengths len;
#ifndef VIRTIO_C2X0
	struct crypto_ahash *ahash = crypto_ahash_reqtfm(req);
	crypto_dev_sess_t *c_sess = crypto_ahash_ctx(ahash);
	struct hash_ctx *ctx = &c_sess->u.hash;
#endif
	struct hash_state *state = ahash_request_ctx(req);

	u8 *next_buf = state->current_buf ? state->buf_1 : state->buf_0;
	int *next_buflen =
	    state->current_buf ? &state->buflen_1 : &state->buflen_0;

#ifdef VIRTIO_C2X0
	crypto_dev_sess_t *c_sess = NULL;
	struct hash_ctx *ctx = NULL;
	struct virtio_c2x0_crypto_sess_ctx *hash_sess = NULL, *next_sess = NULL;
	struct virtio_c2x0_qemu_cmd *qemu_cmd = &virtio_job->qemu_cmd;
	int flag = 0;

	spin_lock(&hash_sess_list_lock);
	list_for_each_entry_safe(hash_sess, next_sess,
				 &virtio_c2x0_hash_sess_list, list_entry) {
		if (hash_sess->sess_id == qemu_cmd->u.hash.update_req.sess_id
		    && hash_sess->guest_id == qemu_cmd->guest_id) {
			c_sess = &(hash_sess->c_sess);
			ctx = &c_sess->u.hash;
			flag = 1;
			print_debug("Hash session FOUND; sess_id = %x\n",
				    hash_sess->sess_id);
			break;
		}
	}
	if (0 == flag) {
		print_error("Hash session[%lx] NOT found\n",
			    qemu_cmd->u.hash.update_req.sess_id);
		spin_unlock(&hash_sess_list_lock);
		return -1;
	}
	spin_unlock(&hash_sess_list_lock);

	/* Denotes the size of output */
	qemu_cmd->u.hash.update_req.ctxlen = ctx->ctx_len;
	*next_buflen = qemu_cmd->u.hash.update_req.next_buflen;
#else
	*next_buflen =
	    req->nbytes & (crypto_tfm_alg_blocksize(&ahash->base) - 1);
#endif
	to_hash = req->nbytes - *next_buflen;

	if (to_hash) {
		c_dev = c_sess->c_dev;
		r_id = c_sess->r_id;

		if (-1 == check_device(c_dev))
			return -1;

		crypto_ctx = get_crypto_ctx(c_dev->ctx_pool);
		print_debug("\t crypto_ctx addr :            :%0llx\n",
			    crypto_ctx);

		if (unlikely(!crypto_ctx)) {
			print_error("Mem alloc failed....\n");
			ret = -ENOMEM;
			goto error;
		}

		crypto_ctx->ctx_pool = c_dev->ctx_pool;
		crypto_ctx->crypto_mem.dev = c_dev;
		crypto_ctx->crypto_mem.pool = c_dev->ring_pairs[r_id].ip_pool;
		print_debug("\t IP Buffer pool address          :%0x\n",
			    crypto_ctx->crypto_mem.pool);

		len.src_nents =
		    sg_count(req->src, req->nbytes - (*next_buflen), &chained);
		len.addon_nents = 0;
		len.output_len = ctx->ctx_len;
		len.src_len = 0;
		len.buff_len = 0;
		len.ctx_len = 0;
		len.sh_desc_len = ctx->len_desc_update_first * CAAM_CMD_SZ;

		hash_init_crypto_mem(&crypto_ctx->crypto_mem,
				     len.src_nents + len.addon_nents);

		if (len.src_nents)
			options = LDST_SGF;
		else
			len.src_len = to_hash;

		if (-ENOMEM == hash_cp_req(req, &len, state->ctx, NULL, NULL,
				      ctx->sh_desc_update_first,
				      &crypto_ctx->crypto_mem)) {
			ret = -ENOMEM;
			goto error;
		}
		host_to_dev(&crypto_ctx->crypto_mem);
		create_sg_table(&crypto_ctx->crypto_mem,
				len.src_nents + len.addon_nents);
		mem = (hash_buffers_t *) (crypto_ctx->crypto_mem.buffers);

		desc = kzalloc(DESC_JOB_IO_LEN, GFP_KERNEL);
		hash_jobdesc(desc, mem->sh_desc_buff.dev_buffer.d_p_addr,
			     ctx->len_desc_update_first,
			     mem->sec_sg_buff.dev_buffer.d_p_addr, to_hash,
			     options, mem->output_buff.dev_buffer.d_p_addr,
			     mem->output_buff.len);
		change_desc_endianness((uint32_t *) mem->desc_buff.v_mem, desc,
				       desc_len(desc));
		kfree(desc);

		store_priv_data(crypto_ctx->crypto_mem.pool,
				mem->desc_buff.v_mem,
				(unsigned long)crypto_ctx);
		sec_dma = mem->desc_buff.dev_buffer.d_p_addr;
#ifndef HOST_TO_DEV_MEMCPY
		crypto_ctx->crypto_mem.dest_buff_dma =
		    crypto_ctx->crypto_mem.buffers[BT_DESC].dev_buffer.
		    h_map_p_addr;
#endif
#ifdef HOST_TO_DEV_MEMCPY
		memcpy_to_dev(&crypto_ctx->crypto_mem);
#endif

		crypto_ctx->req.ahash = req;
		crypto_ctx->oprn = AHASH_UPDATE_FIRST;
		crypto_ctx->rid = r_id;
		crypto_ctx->op_done = hash_op_done;
		crypto_ctx->desc = sec_dma;
		crypto_ctx->c_dev = c_dev;
#ifdef VIRTIO_C2X0
		/* Initialise card status as Unfinished */
		crypto_ctx->card_status = -1;

		/* Updating crypto context to virtio
		   job structure for further refernce */
		virtio_job->ctx = crypto_ctx;
#endif

#ifndef HOST_TO_DEV_MEMCPY
		if (-1 ==
		    dma_to_dev(get_dma_chnl(), &crypto_ctx->crypto_mem,
			       dma_tx_complete_cb, crypto_ctx)) {
			print_error("DMA to dev failed....\n");
			ret = -1;
			goto error;
		}
#else
		sec_dma = set_sec_affinity(c_dev, r_id, sec_dma);
		atomic_dec(&c_dev->active_jobs);
		/* Now enqueue the job into the app ring */
		if (-1 == app_ring_enqueue(c_dev, r_id, sec_dma)) {
			print_error("Application Ring Enqueue Failed\n");
			ret = -1;
			goto error1;
		}
#endif
		if (*next_buflen)
			scatterwalk_map_and_copy(next_buf, req->src, to_hash,
						 *next_buflen, 0);

#ifndef VIRTIO_C2X0
		state->update = ahash_update_ctx;
		state->finup = ahash_finup_ctx;
		state->final = ahash_final_ctx;
#endif
		return -EINPROGRESS;

	} else if (*next_buflen) {
#ifndef VIRTIO_C2X0
		state->update = ahash_update_no_ctx;
		state->finup = ahash_finup_no_ctx;
		state->final = ahash_final_no_ctx;
#endif
		scatterwalk_map_and_copy(next_buf, req->src, 0, req->nbytes, 0);
	}

	return 0;

error:
	atomic_dec(&c_dev->active_jobs);
#ifdef HOST_TO_DEV_MEMCPY
error1:
#endif
	if (crypto_ctx) {
		if (crypto_ctx->crypto_mem.buffers) {
			dealloc_crypto_mem(&crypto_ctx->crypto_mem);
		}
		kfree(crypto_ctx->crypto_mem.c_buffers.hash);
		free_crypto_ctx(c_dev->ctx_pool, crypto_ctx);
	}
	return ret;
}

#ifndef VIRTIO_C2X0
int ahash_init(struct ahash_request *req)
{
	struct hash_state *state = ahash_request_ctx(req);

	state->update = ahash_update_first;
	state->finup = ahash_finup_first;
	state->final = ahash_final_no_ctx;

	memset(state->ctx, 0, MAX_CTX_LEN);
	state->current_buf = 0;
	state->buflen_0 = 0;
	state->buflen_1 = 0;

	return 0;
}

int ahash_update(struct ahash_request *req)
{
	struct hash_state *state = ahash_request_ctx(req);

	return state->update(req);
}

int ahash_finup(struct ahash_request *req)
{
	struct hash_state *state = ahash_request_ctx(req);

	return state->finup(req);
}

int ahash_final(struct ahash_request *req)
{
	struct hash_state *state = ahash_request_ctx(req);

	return state->final(req);
}

int ahash_export(struct ahash_request *req, void *out)
{
	struct crypto_ahash *ahash = crypto_ahash_reqtfm(req);
	crypto_dev_sess_t *c_sess = crypto_ahash_ctx(ahash);
	struct hash_ctx *ctx = &c_sess->u.hash;
	struct hash_state *state = ahash_request_ctx(req);

	memcpy(out, ctx, sizeof(struct hash_ctx));
	memcpy(out + sizeof(struct hash_ctx), state, sizeof(struct hash_state));
	return 0;
}

int ahash_import(struct ahash_request *req, const void *in)
{
	struct crypto_ahash *ahash = crypto_ahash_reqtfm(req);
	crypto_dev_sess_t *c_sess = crypto_ahash_ctx(ahash);
	struct hash_ctx *ctx = &c_sess->u.hash;
	struct hash_state *state = ahash_request_ctx(req);

	memcpy(ctx, in, sizeof(struct hash_ctx));
	memcpy(state, in + sizeof(struct hash_ctx), sizeof(struct hash_state));
	return 0;
}
#endif /* VIRTIO_C2X0 */
