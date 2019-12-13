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
#include "desc_cnstr.h"
#include "algs.h"
#include "memmgr.h"
#include "sg_sw_sec4.h"
#include "crypto_ctx.h"
#ifdef VIRTIO_C2X0
#include <crypto/aes.h>
#include <crypto/sha.h>
#include "fsl_c2x0_virtio.h"
#endif

#include "dma.h"

#ifndef USE_HOST_DMA
#define HOST_TO_DEV_MEMCPY
#endif

static void ablk_op_done(void *ctx, int32_t res)
{
	bool dst_chained;
	uint32_t dst_sgcnt = 0;
	crypto_op_ctx_t *crypto_ctx = ctx;
	struct pci_dev *pci_dev = ((fsl_pci_dev_t *)
				   ((fsl_crypto_dev_t *) (crypto_ctx->c_dev))->
				   priv_dev)->dev;

	print_debug("ABLK OP DONE\n");
	dst_sgcnt = sg_count(crypto_ctx->req.ablk->dst,
			     crypto_ctx->req.ablk->nbytes, &dst_chained);

	dma_unmap_sg_chained(&pci_dev->dev,
			     crypto_ctx->req.ablk->dst,
			     dst_sgcnt ? : 1, DMA_BIDIRECTIONAL, dst_chained);

	dealloc_crypto_mem(&crypto_ctx->crypto_mem);
#if 0
	if (crypto_ctx->crypto_mem.ip_sg)
		kfree(crypto_ctx->crypto_mem.ip_sg);
	if (crypto_ctx->crypto_mem.op_sg)
		kfree(crypto_ctx->crypto_mem.op_sg);
#endif
	kfree(crypto_ctx->crypto_mem.c_buffers.symm_ablk);
#ifndef VIRTIO_C2X0
	ablkcipher_request_complete(crypto_ctx->req.ablk, res);
	free_crypto_ctx(crypto_ctx->ctx_pool, crypto_ctx);
#else
	/* Update the sec result to crypto job context */
	crypto_ctx->card_status = res;
	print_debug("Updated card status to %d\n", crypto_ctx->card_status);
#endif
}

#ifdef VIRTIO_C2X0
static void ablkcipher_setkey_desc(struct sym_ctx *ctx, int32_t ivsize,
					symm_ablk_buffers_t *ablk_ctx, bool encrypt)
#else
static void ablkcipher_setkey_desc(struct crypto_ablkcipher *ablkcipher,
					symm_ablk_buffers_t *ablk_ctx, bool encrypt)
#endif
{
#ifndef VIRTIO_C2X0
	struct ablkcipher_tfm *tfm = &ablkcipher->base.crt_ablkcipher;
	crypto_dev_sess_t *sess = crypto_ablkcipher_ctx(ablkcipher);
	struct sym_ctx *ctx = &sess->u.symm;
#endif
    uint32_t *key_jump_cmd, *jump_cmd;
    uint32_t *enc_desc = NULL, *dec_desc = NULL;

    if (encrypt) {
		enc_desc = kzalloc(DESC_MAX_USED_LEN * CAAM_CMD_SZ, GFP_KERNEL);
		/* ablkcipher_encrypt shared descriptor */
		init_sh_desc(enc_desc, HDR_SHARE_SERIAL);

		/* Skip if already shared */
		key_jump_cmd = append_jump(enc_desc, JUMP_JSL | JUMP_TEST_ALL |
				JUMP_COND_SHRD);

		/* Load class1 key only */
		append_key(enc_desc,
				ablk_ctx->key.dev_buffer.d_p_addr,
				ctx->keylen, CLASS_1 | KEY_DEST_CLASS_REG);

		set_jump_tgt_here(enc_desc, key_jump_cmd);

		/* Propagate errors from shared to job descriptor */
		append_cmd(enc_desc, SET_OK_NO_PROP_ERRORS | CMD_LOAD);

		/* Load iv */
#ifdef VIRTIO_C2X0
		append_cmd(enc_desc, CMD_SEQ_LOAD | LDST_SRCDST_BYTE_CONTEXT |
				LDST_CLASS_1_CCB | ivsize);
#else
		append_cmd(enc_desc, CMD_SEQ_LOAD | LDST_SRCDST_BYTE_CONTEXT |
				LDST_CLASS_1_CCB | tfm->ivsize);
#endif
		/* Load operation */
		append_operation(enc_desc, ctx->class1_alg_type |
				OP_ALG_AS_INITFINAL | OP_ALG_ENCRYPT);

		/* Perform operation */
		ablkcipher_append_src_dst(enc_desc);

		/* COPY THE DESCRIPTORS IN THE LOCAL MEMORY */
		change_desc_endianness((uint32_t *)ablk_ctx->sh_desc.v_mem,
				enc_desc, desc_len(enc_desc));

		ctx->sh_desc_len = desc_len(enc_desc);
		kfree(enc_desc);
	}
	else {
		dec_desc = kzalloc(DESC_MAX_USED_LEN * CAAM_CMD_SZ, GFP_KERNEL);

		init_sh_desc(dec_desc, HDR_SHARE_SERIAL);
		/* Skip if already shared */
		key_jump_cmd = append_jump(dec_desc, JUMP_JSL | JUMP_TEST_ALL |
				JUMP_COND_SHRD);

		/* Load class1 key only */
		append_key(dec_desc,
				ablk_ctx->key.dev_buffer.d_p_addr,
				ctx->keylen, CLASS_1 | KEY_DEST_CLASS_REG);

		/* For aead, only propagate error immediately if shared */
		jump_cmd = append_jump(dec_desc, JUMP_TEST_ALL);
		set_jump_tgt_here(dec_desc, key_jump_cmd);
		append_cmd(dec_desc, SET_OK_NO_PROP_ERRORS | CMD_LOAD);
		set_jump_tgt_here(dec_desc, jump_cmd);

		/* load IV */
#ifdef VIRTIO_C2X0
		append_cmd(dec_desc, CMD_SEQ_LOAD | LDST_SRCDST_BYTE_CONTEXT |
				LDST_CLASS_1_CCB | ivsize);
#else
		append_cmd(dec_desc, CMD_SEQ_LOAD | LDST_SRCDST_BYTE_CONTEXT |
				LDST_CLASS_1_CCB | tfm->ivsize);
#endif
		/* Choose operation */
		append_dec_op1(dec_desc, ctx->class1_alg_type);

		/* Perform operation */
		ablkcipher_append_src_dst(dec_desc);

		/* Wait for key to load before allowing propagating error */
		append_dec_shr_done(dec_desc);

		change_desc_endianness((uint32_t *)ablk_ctx->sh_desc.v_mem,
				dec_desc, desc_len(dec_desc));

		ctx->sh_desc_len = desc_len(dec_desc);
		kfree(dec_desc);
	}
}

#ifdef VIRTIO_C2X0
static void init_ablkcipher_jobdesc(int32_t len,
				    dev_dma_addr_t ptr,
				    int32_t *desc,
				    struct ablkcipher_request *req,
				    dev_dma_addr_t dst_dma,
				    dev_dma_addr_t src_dma,
				    uint32_t out_options, uint32_t in_options,
				    int32_t ivsize)
#else
static void init_ablkcipher_jobdesc(int32_t len,
				    dev_dma_addr_t ptr,
				    int32_t *desc,
				    struct ablkcipher_request *req,
				    dev_dma_addr_t dst_dma,
				    dev_dma_addr_t src_dma,
				    uint32_t out_options, uint32_t in_options)
#endif
{
#ifndef VIRTIO_C2X0
	struct crypto_ablkcipher *ablkcipher = crypto_ablkcipher_reqtfm(req);
	int32_t ivsize = crypto_ablkcipher_ivsize(ablkcipher);
#endif
	init_job_desc_shared(desc, ptr, len, HDR_SHARE_DEFER | HDR_REVERSE);

	append_seq_in_ptr(desc, src_dma, req->nbytes + ivsize, in_options);

	append_seq_out_ptr(desc, dst_dma, req->nbytes, out_options);

	print_debug("DONE init_ablkcipher_jobdesc\n");
}

#ifdef VIRTIO_C2X0
int32_t fsl_ablkcipher_setkey(struct virtio_c2x0_qemu_cmd *qemu_cmd,
			      const uint8_t *key, uint32_t keylen)
#else
int32_t fsl_ablkcipher_setkey(struct crypto_ablkcipher *ablkcipher,
			      const uint8_t *key, uint32_t keylen)
#endif
{
#ifndef VIRTIO_C2X0
	crypto_dev_sess_t *sess = crypto_ablkcipher_ctx(ablkcipher);
	struct sym_ctx *ctx = &sess->u.symm;
#else
    crypto_dev_sess_t *sess = NULL;
    struct sym_ctx    *ctx  = NULL;
    struct virtio_c2x0_crypto_sess_ctx *vc_sess = NULL, *next_sess = NULL;
    struct ablkcipher_setkey *setkey_req = &(qemu_cmd->u.symm.setkey_req);
    int flag = 0;

    spin_lock(&symm_sess_list_lock);
    list_for_each_entry_safe(vc_sess, next_sess,
            &virtio_c2x0_symm_sess_list, list_entry)
    {
        if(vc_sess->sess_id == setkey_req->sess_id
            && vc_sess->guest_id == qemu_cmd->guest_id) {
            sess  = &(vc_sess->c_sess);
            ctx     = &sess->u.symm;
            flag    = 1;
            print_debug("Crypto session FOUND; sess_id = %x\n", 
                    vc_sess->sess_id);
            break;
        }
    }
    spin_unlock(&symm_sess_list_lock);

    if(0 == flag) {
        print_error("Crypto session NOT found\n");
        return -1;
    }

#endif

	/* IT IS OBSERVED THAT SETKEY IS CALLED OFTEN WITHOUT
	 * SUCCEDDING ENCRYPT/DECRYPT. SO NOW PROCRASTINATING THE
	 * CREATION OF SETKEY CONTEXT IN ABULKCIPHER FUN
	 * DO WE REALLY NEED TO CREATE CONTEXT HERE ???? */

	print_debug("ABLK SETKEY\n");

	memcpy(ctx->key, key, keylen);
	ctx->keylen = keylen;

	return 0;
}

#ifdef VIRTIO_C2X0
static void create_setkey_ctx(struct sym_ctx *ctx, 
                symm_ablk_buffers_t *ablk_ctx,
				bool encrypt, int32_t ivsize)
#else
static void create_setkey_ctx(struct crypto_ablkcipher *ablkcipher,
				struct sym_ctx *ctx, symm_ablk_buffers_t *ablk_ctx,
				bool encrypt)
#endif
{
    /* THIS ONLY MATTERS FOR HOST_TO_DEV_MEMCPY
     * AS KEY IS TAKEN AS DESC BT TYPE
     * NEED TO COPY THE KEY IN LOCAL MEM
     * INSTEAD OF ONLY TAKING REQ POINTER */
    memcpy(ablk_ctx->key.v_mem, (void *)ctx->key, ctx->keylen);
#ifdef VIRTIO_C2X0
    ablkcipher_setkey_desc(ctx, ivsize, ablk_ctx, encrypt);
#else
    ablkcipher_setkey_desc(ablkcipher, ablk_ctx, encrypt);
#endif
}

static void create_src_sg_table(symm_ablk_buffers_t *ablk_ctx,
				struct scatterlist *sg, uint32_t sg_cnt)
{
	int32_t i = 0;
	struct sec4_sg_entry *sec4_sg_ptr =
	    (struct sec4_sg_entry *)ablk_ctx->src.v_mem;
	sec4_sg_ptr += 1;

	for (i = 0; i < sg_cnt; ++i) {
#ifndef HOST_TO_DEV_MEMCPY
		/* COPY SG BUFF IN LOCAL MEM */
		sg_map_copy(ablk_ctx->src_sg[i].v_mem, sg, sg->length,
			    sg->offset);
#else
		/* COPY REQ POINTER */
		/* FIXME: DO WE NEED TO KMAP OF SG PAGE ??? */
		ablk_ctx->src_sg[i].req_ptr =
		    (uint8_t *) sg_page(sg) + sg->offset;
#endif
		ASSIGN64(sec4_sg_ptr->ptr,
			 ablk_ctx->src_sg[i].dev_buffer.d_p_addr);
		ASSIGN32(sec4_sg_ptr->len, ablk_ctx->src_sg[i].len);
		ASSIGN8(sec4_sg_ptr->reserved, 0);
		ASSIGN8(sec4_sg_ptr->buf_pool_id, 0);
		ASSIGN16(sec4_sg_ptr->offset, 0);
		sec4_sg_ptr++;

		sg = sg_next(sg);
	}

	sec4_sg_ptr--;
	ASSIGN32(sec4_sg_ptr->len,
		 (ablk_ctx->src_sg[i - 1].len | SEC4_SG_LEN_FIN));
}

static void create_dst_sg_table(fsl_crypto_dev_t *c_dev,
				symm_ablk_buffers_t *ablk_ctx,
				struct scatterlist *sg, uint32_t sg_cnt)
{
	int32_t length = 0;
	dev_dma_addr_t dma_addr = 0;
	struct sec4_sg_entry *sec4_sg_ptr =
	    (struct sec4_sg_entry *)ablk_ctx->dst.v_mem;

	while (sg_cnt--) {
		dma_addr = (dev_dma_addr_t) sg_dma_address(sg) +
		    c_dev->mem[MEM_TYPE_DRIVER].dev_p_addr;
		length = sg_dma_len(sg);
		ASSIGN64(sec4_sg_ptr->ptr, dma_addr);
		ASSIGN32(sec4_sg_ptr->len, length);
		ASSIGN8(sec4_sg_ptr->reserved, 0);
		ASSIGN8(sec4_sg_ptr->buf_pool_id, 0);
		ASSIGN16(sec4_sg_ptr->offset, 0);
		sec4_sg_ptr++;

		sg = sg_next(sg);
	}

	sec4_sg_ptr--;
	ASSIGN32(sec4_sg_ptr->len, length | SEC4_SG_LEN_FIN);
}

static void fill_sg_len(symm_ablk_buffers_t *ablk_ctx, struct scatterlist *sg,
			uint32_t sg_cnt)
{
	uint32_t i = 0;
	while (sg_cnt--) {
		ablk_ctx->src_sg[i++].len = sg->length;
		sg = sg_next(sg);
	}
}

static int ablk_init_crypto_mem(crypto_mem_info_t *crypto_mem, uint32_t sgcnt)
{
	symm_ablk_buffers_t *ablk_ctx = NULL;

	/* WE NEED SPLITTED IP FOR SG LIST */
	crypto_mem->split_ip = 1;

	/* 1.DESC 2.INFO 3.SRC_SG_LIST 4.DST_SG_LIST 5.SH_DESC 6.KEY*/
	crypto_mem->count = 6 + sgcnt;
	print_debug("TOTAL COUNT : %d\n", crypto_mem->count);

	crypto_mem->c_buffers.symm_ablk =
	    kzalloc(crypto_mem->count * sizeof(buffer_info_t), GFP_KERNEL);

	if (!crypto_mem->c_buffers.symm_ablk) {
		print_error("MEMORY ALLOCATION FAILED!\n");
		return -ENOMEM;
	}

	ablk_ctx = crypto_mem->c_buffers.symm_ablk;

	/* DESC, INFO, SRC_SG_LIST, DST_SG_LIST, SH_DESC, KEY
		WILL BE ONE CONTIGUOUS CHUNCK OF MEM ARE OF TYPE BT_DESC */
	crypto_mem->buffers = (buffer_info_t *) ablk_ctx;
	ablk_ctx->desc.bt = BT_DESC;
	ablk_ctx->info.bt = ablk_ctx->src.bt = ablk_ctx->dst.bt = BT_DESC;
	/* SETKEY CTX */
	ablk_ctx->sh_desc.bt = ablk_ctx->key.bt = BT_DESC;

	/* INSIDE SG TABLE BUFFER WILL BE OF
	   TYPE BT_IP AND WILL BE SPLITTED      */
	while (sgcnt--)
		ablk_ctx->src_sg[sgcnt].bt = BT_IP;

	return 0;
}

#ifdef VIRTIO_C2X0
int32_t fsl_ablkcipher(struct ablkcipher_request *req, bool encrypt,
		       struct virtio_c2x0_job_ctx *virtio_job)
#else
static int32_t fsl_ablkcipher(struct ablkcipher_request *req, bool encrypt)
#endif
{
#ifndef VIRTIO_C2X0
	struct crypto_ablkcipher *ablkcipher = crypto_ablkcipher_reqtfm(req);
	crypto_dev_sess_t *c_sess = crypto_ablkcipher_ctx(ablkcipher);
	struct sym_ctx *ctx = &(c_sess->u.symm);
	int32_t ivsize = crypto_ablkcipher_ivsize(ablkcipher);
	uint32_t r_id = c_sess->r_id;
	fsl_crypto_dev_t *c_dev = c_sess->c_dev;
	struct pci_dev *pci_dev = ((fsl_pci_dev_t *) c_dev->priv_dev)->dev;
#endif
	crypto_op_ctx_t *crypto_ctx = NULL;
	crypto_mem_info_t *crypto_mem = NULL;
	symm_ablk_buffers_t *ablk_ctx = NULL;
	dev_dma_addr_t sec_dma = 0, src_dma = 0, dst_dma = 0;
	uint32_t out_options = 0, in_options = 0;
	uint32_t src_sgcnt = 0, dst_sgcnt = 0;
	bool src_chained = false, dst_chained = false;
	uint32_t *desc = NULL;
	int32_t ret = 0;
#ifdef VIRTIO_C2X0
	crypto_dev_sess_t *c_sess = NULL;
	struct sym_ctx *ctx = NULL;
	int32_t ivsize;
	struct virtio_c2x0_crypto_sess_ctx *vc_sess = NULL, *next_sess = NULL;
	struct virtio_c2x0_qemu_cmd *qemu_cmd = &virtio_job->qemu_cmd;
	int flag = 0;
	uint32_t r_id = 0;
	fsl_crypto_dev_t *c_dev = NULL;
	struct pci_dev *pci_dev = NULL;

	spin_lock(&symm_sess_list_lock);
	list_for_each_entry_safe(vc_sess, next_sess,
				 &virtio_c2x0_symm_sess_list, list_entry) {
		if (vc_sess->sess_id == qemu_cmd->u.symm.cmd_req.sess_id
		    && vc_sess->guest_id == qemu_cmd->guest_id) {
			c_sess = &(vc_sess->c_sess);
			ctx = &c_sess->u.symm;
			flag = 1;
			print_debug("Crypto session FOUND; sess_id = %x\n",
				    vc_sess->sess_id);
			break;
		}
	}
	spin_unlock(&symm_sess_list_lock);

	if (0 == flag) {
		print_error("Crypto session NOT found\n");
		return -1;
	}

	ivsize = qemu_cmd->u.symm.cmd_req.ivsize;
	r_id = c_sess->r_id;
	c_dev = c_sess->c_dev;

	pci_dev = ((fsl_pci_dev_t *) c_dev->priv_dev)->dev;
#endif

	if (-1 == check_device(c_dev))
		return -1;

	crypto_ctx = get_crypto_ctx(c_dev->ctx_pool);
	if (unlikely(!crypto_ctx)) {
		print_error("MEMORY ALLOCATION FAILED!\n");
		ret = -ENOMEM;
		goto error;
	}

	crypto_ctx->ctx_pool = c_dev->ctx_pool;
	crypto_ctx->crypto_mem.dev = c_dev;
	crypto_ctx->crypto_mem.pool = c_dev->ring_pairs[r_id].ip_pool;
	crypto_mem = &(crypto_ctx->crypto_mem);

	src_sgcnt = sg_count(req->src, req->nbytes, &src_chained);
	dst_sgcnt = sg_count(req->dst, req->nbytes, &dst_chained);

	/* INIT CRYPTO MEMORY */
	ret = ablk_init_crypto_mem(crypto_mem, src_sgcnt);
	if (-ENOMEM == ret)
		goto error;

	ablk_ctx = crypto_mem->c_buffers.symm_ablk;
	ablk_ctx->desc.len = DESC_JOB_IO_LEN * CAAM_CMD_SZ;
	ablk_ctx->sh_desc.len = DESC_MAX_USED_LEN * CAAM_CMD_SZ;
	ablk_ctx->key.len = CAAM_MAX_KEY_SIZE;

	if (src_sgcnt) {
		ablk_ctx->info.len = ivsize;
		/* SRC LEN = iv SG ENTRY + src SG COUNT */
		ablk_ctx->src.len =
		    (src_sgcnt + 1) * sizeof(struct sec4_sg_entry);
		/* FILL THE SG TABLE REQUIRED LENGTH */
		fill_sg_len(ablk_ctx, req->src, src_sgcnt);
	} else {
		ablk_ctx->info.len = ivsize + req->nbytes;
		ablk_ctx->src.len = 0;
	}

	if (dst_sgcnt)
		ablk_ctx->dst.len = dst_sgcnt * sizeof(struct sec4_sg_entry);
	else
		ablk_ctx->dst.len = 0;

	/* ALLOCATE MEMORY */
	if (-ENOMEM == alloc_crypto_mem(crypto_mem)) {
		ret = -ENOMEM;
		goto error;
	}

	/* COVERT THE ADDRESSES */
	host_to_dev(crypto_mem);

	/* CREATE SETKEY CONTEXT */
#ifndef VIRTIO_C2X0
	create_setkey_ctx(ablkcipher, ctx, ablk_ctx, encrypt);
#else
	create_setkey_ctx(ctx, ablk_ctx, encrypt, ivsize);
#endif

	if (!src_sgcnt) {
		/* NO SRC SG SO COPY INFO AND SRC DIRECT */
		memcpy(ablk_ctx->info.v_mem, req->info, ivsize);
		scatterwalk_map_and_copy(ablk_ctx->info.v_mem + ivsize,
					 req->src, 0, req->nbytes, 0);

		/* SRC DMA WILL BE INFO DMA */
		src_dma = ablk_ctx->info.dev_buffer.d_p_addr;
		in_options = 0;
	} else {
		/* CREATE SG TABLE */
		memcpy(ablk_ctx->info.v_mem, req->info, ivsize);
		dev_dma_to_sec4_sg_one((struct sec4_sg_entry *)ablk_ctx->src.
				       v_mem,
				       ablk_ctx->info.dev_buffer.d_p_addr,
				       ivsize, 0);

		create_src_sg_table(ablk_ctx, req->src, src_sgcnt);
		src_dma = ablk_ctx->src.dev_buffer.d_p_addr;
		in_options = LDST_SGF;
	}

	/* PCI MAP THE DEST ADDS */
	dma_map_sg_chained(&pci_dev->dev,
			   req->dst, dst_sgcnt ? : 1,
			   DMA_BIDIRECTIONAL, dst_chained);

	if (!dst_sgcnt) {
		/* NO NEED TO CREATE SG TABLE FOR DEST */
		dst_dma = (dev_dma_addr_t) sg_dma_address(req->dst);
		dst_dma = c_dev->mem[MEM_TYPE_DRIVER].dev_p_addr + dst_dma;
		out_options = 0;
	} else {
		/* CREATE DEST SG TABLE */
		create_dst_sg_table(c_dev, ablk_ctx, req->dst, dst_sgcnt);
		dst_dma = ablk_ctx->dst.dev_buffer.d_p_addr;
		out_options = LDST_SGF;
	}

	sec_dma = ablk_ctx->desc.dev_buffer.d_p_addr;
	/* LOCAL JDESC */
	desc = (uint32_t *)kzalloc(DESC_JOB_IO_LEN * CAAM_CMD_SZ, GFP_KERNEL);
	if (NULL == desc) {
		print_error("MEMORY ALLOCATION FAILED!\n");
		ret = -ENOMEM;
		goto error;
	}

	/* Create and submit job descriptor */
#ifdef VIRTIO_C2X0
	init_ablkcipher_jobdesc(ctx->sh_desc_len,
				ablk_ctx->sh_desc.dev_buffer.d_p_addr,
				desc, req, dst_dma, src_dma,
				out_options, in_options, ivsize);
#else
	init_ablkcipher_jobdesc(ctx->sh_desc_len,
				ablk_ctx->sh_desc.dev_buffer.d_p_addr,
				desc, req, dst_dma, src_dma,
				out_options, in_options);
#endif

	/* CONVERT THE DESC TO BE */
	change_desc_endianness((uint32_t *) ablk_ctx->desc.v_mem,
			       (uint32_t *) desc, desc_len(desc));
	kfree(desc);

	store_priv_data(crypto_ctx->crypto_mem.pool,
			ablk_ctx->desc.v_mem, (unsigned long)crypto_ctx);

	/* STORE CRYPTO CTX */
	crypto_ctx->req.ablk = req;
	crypto_ctx->oprn = encrypt ? ABLK_ENCRYPT : ABLK_DECRYPT;
	crypto_ctx->rid = r_id;
	crypto_ctx->op_done = ablk_op_done;
	crypto_ctx->desc = sec_dma;
	crypto_ctx->c_dev = c_dev;
#ifdef VIRTIO_C2X0
	/* Initialise card status as Unfinished */
	crypto_ctx->card_status = -1;

	/* Updating crypto context to virtio
	   job structure for further refernce */
	virtio_job->ctx = crypto_ctx;
#endif

#ifdef HOST_TO_DEV_MEMCPY
	memcpy_to_dev(crypto_mem);
	sec_dma = set_sec_affinity(c_dev, r_id, sec_dma);
	atomic_dec(&c_dev->active_jobs);

    if (app_ring_enqueue(c_dev, r_id, sec_dma)) {
		ret = -1;
		goto error1;
	}

#else
	crypto_mem->dest_buff_dma = ablk_ctx->desc.dev_buffer.h_map_p_addr;

	if (-1 ==
	    dma_to_dev(get_dma_chnl(), crypto_mem,
		       dma_tx_complete_cb, crypto_ctx)) {
		print_error("DMA TO DEV FAILED\n");
		ret = -1;
		goto error;
	}
#endif

	return -EINPROGRESS;

error:
	atomic_dec(&c_dev->active_jobs);
#ifdef HOST_TO_DEV_MEMCPY
error1:
#endif
	dma_unmap_sg_chained(&pci_dev->dev,
			     req->dst,
			     dst_sgcnt ? : 1, DMA_BIDIRECTIONAL, dst_chained);

	if (crypto_ctx) {
		dealloc_crypto_mem(crypto_mem);
		if (crypto_ctx->crypto_mem.ip_sg)
			kfree(crypto_ctx->crypto_mem.ip_sg);
		if (crypto_ctx->crypto_mem.op_sg)
			kfree(crypto_ctx->crypto_mem.op_sg);
		if (crypto_ctx->crypto_mem.c_buffers.symm_ablk)
			kfree(crypto_ctx->crypto_mem.c_buffers.symm_ablk);
		free_crypto_ctx(c_dev->ctx_pool, crypto_ctx);
	}
	return ret;
}

#ifndef VIRTIO_C2X0
int32_t fsl_ablkcipher_encrypt(struct ablkcipher_request *req)
{
	return fsl_ablkcipher(req, true);
}

int32_t fsl_ablkcipher_decrypt(struct ablkcipher_request *req)
{
	return fsl_ablkcipher(req, false);
}
#endif /* VIRTIO_C2X0 */
