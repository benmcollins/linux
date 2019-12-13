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
#include "pkc_desc.h"
#include "desc.h"
#include "memmgr.h"
#include "crypto_ctx.h"
#ifdef VIRTIO_C2X0
#include "fsl_c2x0_virtio.h"
#endif
#include "dma.h"

/*
#define DUMP_DESC_WORDS
#define PERFORMANCE_BUILD
#define DUMP_DEBUG_V_INFO
*/

#ifndef USE_HOST_DMA
#define HOST_TO_DEV_MEMCPY
#endif

/* Callback test functions */
typedef void (*rsa_op_cb) (struct pkc_request *, int32_t result);
/* #ifdef KCAPI_INTEG_BUILD
rsa_op_cb rsa_completion_cb = pkc_request_complete;
#else */
rsa_op_cb rsa_completion_cb;
/* #endif */

static void rsa_op_done(void *ctx, int32_t res)
{
	crypto_op_ctx_t *crypto_ctx = ctx;

	print_debug("[RSA OP DONE ]\n");

	dealloc_crypto_mem(&(crypto_ctx->crypto_mem));

#ifndef VIRTIO_C2X0
	rsa_completion_cb(crypto_ctx->req.pkc, res);

	free_crypto_ctx(crypto_ctx->ctx_pool, crypto_ctx);
#endif
#ifdef VIRTIO_C2X0
	/* Update the sec result to crypto job context */
	crypto_ctx->card_status = res;
	print_debug("Updated card status to %d\n", crypto_ctx->card_status);
#endif
}

static void rsa_keygen_op_init_len(struct rsa_keygen_req_s *keygen_req,
					crypto_mem_info_t *mem_info)
{
	rsa_keygen_op_buffers_t *mem =
		(rsa_keygen_op_buffers_t *)mem_info->buffers;

	mem->n_buff.len = keygen_req->n_len;
}

static int rsa_keygen_op_cp_req(struct rsa_keygen_req_s *keygen_req,
					crypto_mem_info_t *mem_info)
{
	rsa_keygen_op_buffers_t *mem =
		(rsa_keygen_op_buffers_t *)mem_info->buffers;
	rsa_keygen_op_init_len(keygen_req, mem_info);

	/* Alloc mem requrd for crypto operation */
	print_debug("\t \t Calling alloc_crypto_mem\n");
	if (-ENOMEM == alloc_crypto_mem(mem_info))
		return -ENOMEM;

	mem->n_buff.v_mem = keygen_req->n;
	print_debug("\t\t get buffer pointer\n");
	memset(keygen_req->p, 0xff, keygen_req->p_len);
	memset(keygen_req->q, 0xff, keygen_req->q_len);
	memset(keygen_req->d, 0xff, keygen_req->d_len);
	memset(keygen_req->dp, 0xff, keygen_req->dp_len);
	memset(keygen_req->dq, 0xff, keygen_req->dq_len);
	memset(keygen_req->c, 0xff, keygen_req->c_len);

	return 0;
}

/* Memory copy functions */
static void rsa_pub_op_init_len(struct rsa_pub_req_s *pub_req,
				crypto_mem_info_t *mem_info)
{
	rsa_pub_op_buffers_t *mem =
	    (rsa_pub_op_buffers_t *) (mem_info->buffers);

	mem->n_buff.len = pub_req->n_len;
	mem->e_buff.len = pub_req->e_len;
	mem->f_buff.len = pub_req->f_len;
	mem->g_buff.len = pub_req->g_len;

}

static int rsa_pub_op_cp_req(struct rsa_pub_req_s *pub_req,
			     crypto_mem_info_t *mem_info)
{
	rsa_pub_op_buffers_t *mem =
	    (rsa_pub_op_buffers_t *) (mem_info->buffers);
	rsa_pub_op_init_len(pub_req, mem_info);
#ifdef DUMP_DEBUG_V_INFO
	int i = 0;
#endif
	/* Alloc mem requrd for crypto operation */
	print_debug("\t \t Calling alloc_crypto_mem\n");
	if (-ENOMEM == alloc_crypto_mem(mem_info))
		return -ENOMEM;

	mem->f_buff.v_mem = pub_req->f;
	mem->e_buff.v_mem = pub_req->e;
	mem->n_buff.v_mem = pub_req->n;
	mem->g_buff.v_mem = pub_req->g;

#ifdef DUMP_DEBUG_V_INFO
	print_debug("\n [RSA PUB OP]	Request Details :\n");
	print_debug("\t \t	N Len		:%d\n", mem->n_buff.len);
	print_debug("\t \t E Len       :%d\n", mem->e_buff.len);
	print_debug("\t \t F Len       :%d\n", mem->f_buff.len);
	print_debug("\t \t G Len       :%d\n", mem->g_buff.len);
	print_debug("\t \t Desc Len	:%d\n", mem->desc_buff.len);
	print_debug("\t \t G Buff addr	:%0x\n", mem->g_buff.v_mem);
	print_debug("\n [RSA PUB OP]\n");

	print_debug("[RSA_PUB_OP]	: Allocated memory details\n");
	print_debug("\t N Buffer		:%0x\n", mem->n_buff.v_mem);
	print_debug("\t E Buffer       :%0x\n", mem->e_buff.v_mem);
	print_debug("\t F Buffer       :%0x\n", mem->f_buff.v_mem);
	print_debug("\t G Buffer       :%0x\n", mem->g_buff.v_mem);
	print_debug("\t DESC Buffer       :%0x\n", mem->desc_buff.v_mem);

	print_debug("N:\n");
	for (i = 0; i < mem->n_buff.len; i++) {
		if (pub_req->n[i] != mem->n_buff.v_mem[i])
			print_debug("pub_req %0x buff %0x index %d ",
				    pub_req->n[i], mem->n_buff.v_mem[i], i);

	}
	print_debug("E:\n");
	for (i = 0; i < mem->e_buff.len; i++) {
		if (pub_req->e[i] != mem->e_buff.v_mem[i])
			print_debug("pub_req %0x buff %0x index %d ",
				    pub_req->e[i], mem->e_buff.v_mem[i], i);
	}
	print_debug("F:\n");
	for (i = 0; i < mem->f_buff.len; i++) {
		if (pub_req->f[i] != mem->f_buff.v_mem[i])
			print_debug("pub_req %0x buff %0x index %d ",
				    pub_req->f[i], mem->f_buff.v_mem[i], i);
	}
#endif
	return 0;
}

static void rsa_keygen_init_crypto_mem(crypto_mem_info_t *crypto_mem)
{
	rsa_keygen_op_buffers_t *keygen_op_buffs = NULL;
	crypto_mem->count =
		sizeof(rsa_keygen_op_buffers_t) / sizeof(buffer_info_t);
	crypto_mem->buffers =
		(buffer_info_t *) (&(crypto_mem->c_buffers.rsa_keygen_op));
	memset(crypto_mem->buffers, 0, sizeof(rsa_keygen_op_buffers_t));

	keygen_op_buffs = (rsa_keygen_op_buffers_t *)crypto_mem->buffers;
	keygen_op_buffs->n_buff.bt = BT_OP;
}

static void rsa_pub_op_init_crypto_mem(crypto_mem_info_t *crypto_mem)
{
	rsa_pub_op_buffers_t *pub_op_buffs = NULL;

	crypto_mem->count =
	    sizeof(rsa_pub_op_buffers_t) / sizeof(buffer_info_t);
	crypto_mem->buffers =
	    (buffer_info_t *) (&(crypto_mem->c_buffers.rsa_pub_op));
	memset(crypto_mem->buffers, 0, sizeof(rsa_pub_op_buffers_t));

	/* Mark the op buffer */
	pub_op_buffs = (rsa_pub_op_buffers_t *) crypto_mem->buffers;
	pub_op_buffs->n_buff.bt = pub_op_buffs->e_buff.bt =
	    pub_op_buffs->f_buff.bt = BT_IP;
	pub_op_buffs->g_buff.bt = BT_OP;
}

/* PRIV FORM1 functions */
static void constr_rsa_priv1_op_desc(crypto_mem_info_t *mem_info)
{
	uint32_t desc_size =
	    sizeof(struct rsa_priv_frm1_desc_s) / sizeof(uint32_t);
	uint32_t start_idx = desc_size - 1;
	uint32_t desc_hdr = 0;

	rsa_priv1_op_buffers_t *mem =
	    (rsa_priv1_op_buffers_t *) (mem_info->buffers);
	struct rsa_priv_frm1_desc_s *rsa_priv_desc =
	    (struct rsa_priv_frm1_desc_s *)mem->desc_buff.v_mem;

	start_idx &= HDR_START_IDX_MASK;
	init_job_desc(&desc_hdr,
		      (start_idx << HDR_START_IDX_SHIFT) | (desc_size &
							    HDR_DESCLEN_MASK) |
		      HDR_ONE);

	ASSIGN64(rsa_priv_desc->n_dma, mem->n_buff.dev_buffer.d_p_addr);
	ASSIGN64(rsa_priv_desc->d_dma, mem->d_buff.dev_buffer.d_p_addr);
	ASSIGN64(rsa_priv_desc->g_dma, mem->g_buff.dev_buffer.d_p_addr);
	ASSIGN64(rsa_priv_desc->f_dma, mem->f_buff.dev_buffer.d_p_addr);

	ASSIGN32(rsa_priv_desc->sgf_flg,
		 ((mem->d_buff.len << 12) | mem->n_buff.len));
	ASSIGN32(rsa_priv_desc->op,
		 (CMD_OPERATION | OP_TYPE_UNI_PROTOCOL | OP_PCLID_RSADEC_PRVKEY
		  | RSA_PRIV_KEY_FRM_1));
}

static void rsa_priv1_op_init_len(struct rsa_priv_frm1_req_s *priv1_req,
				  crypto_mem_info_t *mem_info)
{
	rsa_priv1_op_buffers_t *mem =
	    (rsa_priv1_op_buffers_t *) (mem_info->buffers);

	mem->n_buff.len = priv1_req->n_len;
	mem->d_buff.len = priv1_req->d_len;
	mem->g_buff.len = priv1_req->g_len;
	mem->f_buff.len = priv1_req->f_len;

	mem->desc_buff.len = sizeof(struct rsa_priv_frm1_desc_s);
}

static int rsa_priv1_op_cp_req(struct rsa_priv_frm1_req_s *priv1_req,
			       crypto_mem_info_t *mem_info)
{
	rsa_priv1_op_buffers_t *mem =
	    (rsa_priv1_op_buffers_t *) (mem_info->buffers);

	rsa_priv1_op_init_len(priv1_req, mem_info);

	/* Alloc mem requrd for crypto operation */
	print_debug("\t \t Calling alloc_crypto_mem\n");
	if (-ENOMEM == alloc_crypto_mem(mem_info))
		return -ENOMEM;
#ifndef HOST_TO_DEV_MEMCPY
	memcpy(mem->n_buff.v_mem, priv1_req->n, mem->n_buff.len);
	memcpy(mem->d_buff.v_mem, priv1_req->d, mem->d_buff.len);
	memcpy(mem->g_buff.v_mem, priv1_req->g, mem->g_buff.len);
#else
	mem->n_buff.req_ptr = priv1_req->n;
	mem->d_buff.req_ptr = priv1_req->d;
	mem->g_buff.req_ptr = priv1_req->g;
#endif

	mem->f_buff.v_mem = priv1_req->f;
#ifdef DUMP_DEBUG_V_INFO
	print_debug("\n[RSA PUB OP]	Request Details :\n");
	print_debug("\t \t	N Len		:%d\n", mem->n_buff.len);
	print_debug("\t \t D Len       :%d\n", mem->d_buff.len);
	print_debug("\t \t G Len       :%d\n", mem->g_buff.len);
	print_debug("\t \t F Len       :%d\n", mem->f_buff.len);
	print_debug("\t \t Desc Len	:%d\n", mem->desc_buff.len);
	print_debug("\t \t F Buff addr	:%0x\n", mem->f_buff.v_mem);
	print_debug("\n[RSA PUB OP]\n");
#endif
	return 0;
}

static void rsa_priv1_op_init_crypto_mem(crypto_mem_info_t *crypto_mem)
{
	rsa_priv1_op_buffers_t *priv1_op_buffs = NULL;

	crypto_mem->count =
	    sizeof(rsa_priv1_op_buffers_t) / sizeof(buffer_info_t);
	crypto_mem->buffers =
	    (buffer_info_t *) (&(crypto_mem->c_buffers.rsa_priv1_op));
	memset(crypto_mem->buffers, 0, sizeof(rsa_priv1_op_buffers_t));

	/* Mark the op buffer */
	priv1_op_buffs = (rsa_priv1_op_buffers_t *) crypto_mem->buffers;
	priv1_op_buffs->n_buff.bt = priv1_op_buffs->d_buff.bt =
	    priv1_op_buffs->g_buff.bt = BT_IP;
	priv1_op_buffs->f_buff.bt = BT_OP;
}

/* PRIV FORM2 functions */
static void constr_rsa_priv2_op_desc(crypto_mem_info_t *mem_info)
{
	uint32_t desc_size =
	    sizeof(struct rsa_priv_frm2_desc_s) / sizeof(uint32_t);
	uint32_t start_idx = desc_size - 1;

	rsa_priv2_op_buffers_t *mem =
	    (rsa_priv2_op_buffers_t *) (mem_info->buffers);
	struct rsa_priv_frm2_desc_s *rsa_priv_desc =
	    (struct rsa_priv_frm2_desc_s *)mem->desc_buff.v_mem;
	uint32_t *desc_buff = (uint32_t *) mem->desc_buff.v_mem;

	start_idx &= HDR_START_IDX_MASK;
	init_job_desc(desc_buff,
		      (start_idx << HDR_START_IDX_SHIFT) | (desc_size &
							    HDR_DESCLEN_MASK) |
		      HDR_ONE);

	ASSIGN64(rsa_priv_desc->p_dma, mem->p_buff.dev_buffer.d_p_addr);
	ASSIGN64(rsa_priv_desc->q_dma, mem->q_buff.dev_buffer.d_p_addr);
	ASSIGN64(rsa_priv_desc->d_dma, mem->d_buff.dev_buffer.d_p_addr);
	ASSIGN64(rsa_priv_desc->f_dma, mem->f_buff.dev_buffer.d_p_addr);
	ASSIGN64(rsa_priv_desc->g_dma, mem->g_buff.dev_buffer.d_p_addr);
	ASSIGN64(rsa_priv_desc->tmp1_dma, mem->tmp1_buff.dev_buffer.d_p_addr);
	ASSIGN64(rsa_priv_desc->tmp2_dma, mem->tmp2_buff.dev_buffer.d_p_addr);

	ASSIGN32(rsa_priv_desc->sgf_flg,
		 ((mem->d_buff.len << 12) | mem->f_buff.len));
	ASSIGN32(rsa_priv_desc->p_q_len,
		 ((mem->q_buff.len << 12) | (mem->p_buff.len)));
	ASSIGN32(rsa_priv_desc->op,
		 (CMD_OPERATION | OP_TYPE_UNI_PROTOCOL | OP_PCLID_RSADEC_PRVKEY
		  | RSA_PRIV_KEY_FRM_2));
}

static void rsa_priv2_op_init_len(struct rsa_priv_frm2_req_s *priv2_req,
				  crypto_mem_info_t *mem_info)
{
	rsa_priv2_op_buffers_t *mem =
	    (rsa_priv2_op_buffers_t *) (mem_info->buffers);

	mem->p_buff.len = priv2_req->p_len;
	mem->q_buff.len = priv2_req->q_len;
	mem->d_buff.len = priv2_req->d_len;
	mem->f_buff.len = priv2_req->f_len;
	mem->g_buff.len = priv2_req->g_len;
	mem->tmp1_buff.len = priv2_req->p_len;
	mem->tmp2_buff.len = priv2_req->q_len;

	mem->desc_buff.len = sizeof(struct rsa_priv_frm2_desc_s);
}

static int rsa_priv2_op_cp_req(struct rsa_priv_frm2_req_s *priv2_req,
			       crypto_mem_info_t *mem_info)
{
	rsa_priv2_op_buffers_t *mem =
	    (rsa_priv2_op_buffers_t *) (mem_info->buffers);
#ifdef DUMP_DEBUG_V_INFO
	rsa_priv2_op_buffers_t *priv2_op_buffs = mem;
#endif
	rsa_priv2_op_init_len(priv2_req, mem_info);

	/* Alloc mem requrd for crypto operation */
	print_debug("\t \t Calling alloc_crypto_mem\n");
	if (-ENOMEM == alloc_crypto_mem(mem_info))
		return -ENOMEM;
#ifndef HOST_TO_DEV_MEMCPY
	memcpy(mem->p_buff.v_mem, priv2_req->p, mem->p_buff.len);
	memcpy(mem->q_buff.v_mem, priv2_req->q, mem->q_buff.len);
	memcpy(mem->d_buff.v_mem, priv2_req->d, mem->d_buff.len);
	memcpy(mem->g_buff.v_mem, priv2_req->g, mem->g_buff.len);
#else
	mem->p_buff.req_ptr = priv2_req->p;
	mem->q_buff.req_ptr = priv2_req->q;
	mem->d_buff.req_ptr = priv2_req->d;
	mem->g_buff.req_ptr = priv2_req->g;
#endif
	mem->f_buff.v_mem = priv2_req->f;

#ifdef DUMP_DEBUG_V_INFO
	print_debug("\n[RSA PRIV2 OP]	Request Details :\n");
	print_debug("\t \t	P Len		:%d\n", mem->p_buff.len);
	print_debug("\t \t Q Len       :%d\n", mem->q_buff.len);
	print_debug("\t \t D Len       :%d\n", mem->d_buff.len);
	print_debug("\t \t G Len       :%d\n", mem->g_buff.len);
	print_debug("\t \t TMP1 Len    :%d\n", mem->tmp1_buff.len);
	print_debug("\t \t TMP2 Le     :%d\n", mem->tmp2_buff.len);
	print_debug("\t \t Desc Len	:%d\n", mem->desc_buff.len);
	print_debug("\t \t F Buff addr	:%0x\n", mem->f_buff.v_mem);
	print_debug("\n[RSA PRIV2 OP]\n");

	print_debug("[RSA_PUB_OP]	: Allocated memory details\n");
	print_debug("\t P Buffer		:%0x\n",
		    priv2_op_buffs->p_buff.v_mem);
	print_debug("\t Q Buffer       :%0x\n", priv2_op_buffs->q_buff.v_mem);
	print_debug("\t D Buffer       :%0x\n", priv2_op_buffs->d_buff.v_mem);
	print_debug("\t G Buffer       :%0x\n", priv2_op_buffs->g_buff.v_mem);
	print_debug("\t TMP1 Buffer    :%0x\n",
		    priv2_op_buffs->tmp1_buff.v_mem);
	print_debug("\t TMP2 Buffer    :%0x\n",
		    priv2_op_buffs->tmp2_buff.v_mem);
	print_debug("\t F Buffer       :%0x\n", priv2_op_buffs->f_buff.v_mem);
	print_debug("\t DESC Buffer       :%0x\n",
		    priv2_op_buffs->desc_buff.v_mem);
#endif
	return 0;
}

static void rsa_priv2_op_init_crypto_mem(crypto_mem_info_t *crypto_mem)
{
	rsa_priv2_op_buffers_t *priv2_op_buffs = NULL;

	crypto_mem->count =
	    sizeof(rsa_priv2_op_buffers_t) / sizeof(buffer_info_t);
	crypto_mem->buffers =
	    (buffer_info_t *) (&(crypto_mem->c_buffers.rsa_priv1_op));
	memset(crypto_mem->buffers, 0, sizeof(rsa_priv1_op_buffers_t));

	/* Mark the op buffer */
	priv2_op_buffs = (rsa_priv2_op_buffers_t *) crypto_mem->buffers;
	priv2_op_buffs->p_buff.bt = priv2_op_buffs->q_buff.bt =
	    priv2_op_buffs->d_buff.bt = priv2_op_buffs->g_buff.bt =
	    priv2_op_buffs->tmp1_buff.bt = priv2_op_buffs->tmp2_buff.bt = BT_IP;
	priv2_op_buffs->f_buff.bt = BT_OP;
}

static void rsa_priv3_op_init_len(struct rsa_priv_frm3_req_s *priv3_req,
				  crypto_mem_info_t *mem_info)
{
	rsa_priv3_op_buffers_t *mem =
	    (rsa_priv3_op_buffers_t *) (mem_info->buffers);

	mem->g_buff.len = priv3_req->g_len;
	mem->f_buff.len = priv3_req->f_len;
}

static int rsa_priv3_op_cp_req(struct rsa_priv_frm3_req_s *priv3_req,
			       crypto_mem_info_t *mem_info)
{
	rsa_priv3_op_buffers_t *mem =
	    (rsa_priv3_op_buffers_t *) (mem_info->buffers);
#ifdef DUMP_DEBUG_V_INFO
	rsa_priv3_op_buffers_t *priv3_op_buffs = mem;
#endif
	rsa_priv3_op_init_len(priv3_req, mem_info);

	/* Alloc mem requrd for crypto operation */
	print_debug("\t \t Calling alloc_crypto_mem\n");
	if (-ENOMEM == alloc_crypto_mem(mem_info))
		return -ENOMEM;

	mem->f_buff.v_mem = priv3_req->f;
	mem->g_buff.v_mem = priv3_req->g;

#ifdef DUMP_DEBUG_V_INFO
	print_debug("\n[RSA PRIV3 OP]	Request Details :\n");
	print_debug("\t \t	P Len		:%d\n", mem->p_buff.len);
	print_debug("\t \t Q Len       :%d\n", mem->q_buff.len);
	print_debug("\t \t G Len       :%d\n", mem->g_buff.len);
	print_debug("\t \t C Len       :%d\n", mem->c_buff.len);
	print_debug("\t \t DPLen       :%d\n", mem->dp_buff.len);
	print_debug("\t \t DQLen       :%d\n", mem->dq_buff.len);
	print_debug("\t \t TMP1 Len    :%d\n", mem->tmp1_buff.len);
	print_debug("\t \t TMP2 Le     :%d\n", mem->tmp2_buff.len);
	print_debug("\t \t Desc Len	:%d\n", mem->desc_buff.len);
	print_debug("\t \t F Buff addr	:%0x\n", mem->f_buff.v_mem);
	print_debug("\n[RSA PRIV3 OP]\n");

	print_debug("[RSA3_PRIV_OP]	: Allocated memory details\n");
	print_debug("\t P Buffer		:%0x\n",
		    priv3_op_buffs->p_buff.v_mem);
	print_debug("\t Q Buffer       :%0x\n", priv3_op_buffs->q_buff.v_mem);
	print_debug("\t G Buffer       :%0x\n", priv3_op_buffs->g_buff.v_mem);
	print_debug("\t C Buffer       :%0x\n", priv3_op_buffs->c_buff.v_mem);
	print_debug("\t DPBuffer       :%0x\n", priv3_op_buffs->dp_buff.v_mem);
	print_debug("\t DQBuffer       :%0x\n", priv3_op_buffs->dq_buff.v_mem);
	print_debug("\t TMP1 Buffer    :%0x\n",
		    priv3_op_buffs->tmp1_buff.v_mem);
	print_debug("\t TMP2 Buffer    :%0x\n",
		    priv3_op_buffs->tmp2_buff.v_mem);
	print_debug("\t F Buffer       :%0x\n", priv3_op_buffs->f_buff.v_mem);
	print_debug("\t DESC Buffer    :%0x\n",
		    priv3_op_buffs->desc_buff.v_mem);
#endif
	return 0;
}

static void rsa_priv3_op_init_crypto_mem(crypto_mem_info_t *crypto_mem)
{
	rsa_priv3_op_buffers_t *priv3_op_buffs = NULL;

	crypto_mem->count =
	    sizeof(rsa_priv3_op_buffers_t) / sizeof(buffer_info_t);

	crypto_mem->buffers =
	    (buffer_info_t *) (&(crypto_mem->c_buffers.rsa_priv3_op));
	memset(crypto_mem->buffers, 0, sizeof(rsa_priv3_op_buffers_t));

	/* Mark the op buffer */
	priv3_op_buffs = (rsa_priv3_op_buffers_t *) crypto_mem->buffers;

	priv3_op_buffs->g_buff.bt = BT_IP;

	priv3_op_buffs->f_buff.bt = BT_OP;
}

#ifdef VIRTIO_C2X0
int rsa_op(struct pkc_request *req, struct virtio_c2x0_job_ctx *virtio_job)
#else
int rsa_op(struct pkc_request *req)
#endif
{
	int32_t ret = 0;
	crypto_dev_sess_t *c_sess = NULL;
	crypto_op_ctx_t *crypto_ctx = NULL;
	fsl_crypto_dev_t *c_dev = NULL;

	dev_dma_addr_t sec_dma = 0;
	uint32_t r_id = 0;
	rsa_keygen_op_buffers_t *keygen_op_buffs = NULL;
	rsa_pub_op_buffers_t *pub_op_buffs = NULL;
	rsa_priv1_op_buffers_t *priv1_op_buffs = NULL;
	rsa_priv2_op_buffers_t *priv2_op_buffs = NULL;
	rsa_priv3_op_buffers_t *priv3_op_buffs = NULL;

	/* #ifdef KCAPI_INTEG_BUILD */
#ifndef VIRTIO_C2X0
	if (NULL != req->base.tfm) {
		rsa_completion_cb = pkc_request_complete;
		/* Get the session context from input request */
		c_sess =
		    (crypto_dev_sess_t *)
		    crypto_pkc_ctx(crypto_pkc_reqtfm(req));
		c_dev = c_sess->c_dev;
		r_id = c_sess->r_id;
#ifndef HIGH_PERF
		if (-1 == check_device(c_dev))
			return -1;
#endif
	}
	/* #else */
	else
#endif
    {
        c_sess = c_sess;
        /* By default using first device --
         * Logic here will be replaced with LB */
#ifdef VIRTIO_C2X0
        if(NULL == (c_dev = get_device_rr()))
            return -1;
#else
        c_dev = get_crypto_dev(1);
#endif  
#ifndef HIGH_PERF    
        if(0 == (r_id = get_ring_rr(c_dev)))
            return -1;

        atomic_inc(&c_dev->active_jobs);
#else
        r_id =
            ((atomic_inc_return(&c_dev->crypto_dev_sess_cnt) -
                1) % (c_dev->num_of_rings - 1)) + 1;
#endif
    }

	/* #endif */

	crypto_ctx = get_crypto_ctx(c_dev->ctx_pool);
	print_debug("\t crypto_ctx addr :			:%p\n",
		    crypto_ctx);

	if (unlikely(!crypto_ctx)) {
		print_debug("Mem alloc failed....\n");
		ret = -ENOMEM;
		goto error;
	}

	print_debug("\t Ring selected			:%d\n", r_id);
	crypto_ctx->ctx_pool = c_dev->ctx_pool;
	crypto_ctx->crypto_mem.dev = c_dev;
	crypto_ctx->crypto_mem.pool = c_dev->ring_pairs[r_id].ip_pool;
	print_debug("\t IP Buffer pool address		:%p\n",
		    crypto_ctx->crypto_mem.pool);

	switch (req->type) {
	case RSA_KEYGEN:
		rsa_keygen_init_crypto_mem(&crypto_ctx->crypto_mem);
		keygen_op_buffs =
			(rsa_keygen_op_buffers_t *)crypto_ctx->crypto_mem.buffers;

		if (-ENOMEM == rsa_keygen_op_cp_req(&req->req_u.rsa_keygen,
					&crypto_ctx->crypto_mem)) {
			ret = -ENOMEM;
			goto error;
		}
		print_debug("\t \t \t Rsa keygen op init mem complete.....\n");

		/* Convert the buffers to dev */
		host_to_dev(&crypto_ctx->crypto_mem);

		print_debug("\t \t \t Host to dev convert complete....\n");

		break;
	case RSA_PUB:
		rsa_pub_op_init_crypto_mem(&crypto_ctx->crypto_mem);
		pub_op_buffs =
		    (rsa_pub_op_buffers_t *) crypto_ctx->crypto_mem.buffers;

		if (-ENOMEM ==
		    rsa_pub_op_cp_req(&req->req_u.rsa_pub_req,
				      &crypto_ctx->crypto_mem)) {
			ret = -ENOMEM;
			goto error;
		}
		print_debug("\t \t \t Rsa pub op init mem complete.....\n");

		/* Convert the buffers to dev */
		host_to_dev(&crypto_ctx->crypto_mem);

		print_debug("\t \t \t Host to dev convert complete....\n");

		break;
	case RSA_PRIV_FORM1:
		rsa_priv1_op_init_crypto_mem(&crypto_ctx->crypto_mem);
		priv1_op_buffs =
		    (rsa_priv1_op_buffers_t *) crypto_ctx->crypto_mem.buffers;

		if (-ENOMEM ==
		    rsa_priv1_op_cp_req(&req->req_u.rsa_priv_f1,
					&crypto_ctx->crypto_mem)) {
			ret = -ENOMEM;
			goto error;
		}
		print_debug("\t \t \t Rsa pub op init mem complete....\n");

		/* Convert the buffers to dev */
		host_to_dev(&crypto_ctx->crypto_mem);

		print_debug("\t \t \t Host to dev convert complete....\n");

		/* Constr the hw desc */
		constr_rsa_priv1_op_desc(&crypto_ctx->crypto_mem);
		print_debug("\t \t \t Desc constr complete...\n");

		sec_dma = priv1_op_buffs->desc_buff.dev_buffer.d_p_addr;

		/* Store the context */
		print_debug(KERN_ERR
			    "[Enq] Desc addr	:%0llx Hbuffer addr	"
			    ":%p	Crypto ctx		:%p\n",
			    priv1_op_buffs->desc_buff.
			    dev_buffer.d_p_addr,
			    priv1_op_buffs->desc_buff.v_mem, crypto_ctx);

		store_priv_data(crypto_ctx->crypto_mem.pool,
				priv1_op_buffs->desc_buff.v_mem,
				(unsigned long)crypto_ctx);
		break;

	case RSA_PRIV_FORM2:
		rsa_priv2_op_init_crypto_mem(&crypto_ctx->crypto_mem);
		priv2_op_buffs =
		    (rsa_priv2_op_buffers_t *) crypto_ctx->crypto_mem.buffers;

		if (-ENOMEM ==
		    rsa_priv2_op_cp_req(&req->req_u.rsa_priv_f2,
					&crypto_ctx->crypto_mem)) {
			ret = -ENOMEM;
			goto error;
		}
		print_debug("\t \t \t Rsa pub op init mem complete.....\n");

		/* Convert the buffers to dev */
		host_to_dev(&crypto_ctx->crypto_mem);

		print_debug("\t \t \t Host to dev convert complete....\n");

		/* Constr the hw desc */
		constr_rsa_priv2_op_desc(&crypto_ctx->crypto_mem);
		print_debug("\t \t \t Desc constr complete...\n");

		sec_dma = priv2_op_buffs->desc_buff.dev_buffer.d_p_addr;

		/* Store the context */
		print_debug(KERN_ERR
			    "[Enq] Desc addr	:%0llx Hbuffer addr	"
			    ":%p	Crypto ctx	:%p\n",
			    priv2_op_buffs->desc_buff.
			    dev_buffer.d_p_addr,
			    priv2_op_buffs->desc_buff.v_mem, crypto_ctx);

		store_priv_data(crypto_ctx->crypto_mem.pool,
				priv2_op_buffs->desc_buff.v_mem,
				(unsigned long)crypto_ctx);
		break;

	case RSA_PRIV_FORM3:
		rsa_priv3_op_init_crypto_mem(&crypto_ctx->crypto_mem);
		priv3_op_buffs =
		    (rsa_priv3_op_buffers_t *) crypto_ctx->crypto_mem.buffers;

		if (-ENOMEM ==
		    rsa_priv3_op_cp_req(&req->req_u.rsa_priv_f3,
					&crypto_ctx->crypto_mem)) {
			ret = -ENOMEM;
			goto error;
		}
		print_debug("\t \t \t Rsa pub op init mem complete.....\n");

		/* Convert the buffers to dev */
		host_to_dev(&crypto_ctx->crypto_mem);

		print_debug("\t \t \t Host to dev convert complete....\n");

		break;
	default:
		ret = -EINVAL;
		break;
	}

#ifdef HOST_TO_DEV_MEMCPY
#endif

	/* constructure abstract request */
	constr_abs_req(&crypto_ctx->crypto_mem, req);

	sec_dma = get_abs_req_p_addr(&crypto_ctx->crypto_mem);

	store_priv_data(crypto_ctx->crypto_mem.pool,
				crypto_ctx->crypto_mem.abs_req,
				(unsigned long)crypto_ctx);

	print_debug("%llx, %p\n", sec_dma, crypto_ctx->crypto_mem.abs_req);
	crypto_ctx->req.pkc = req;
	crypto_ctx->oprn = RSA;
	crypto_ctx->rid = r_id;
	crypto_ctx->op_done = rsa_op_done;
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
#if 0
	if (-1 ==
	    dma_to_dev(get_dma_chnl(), &crypto_ctx->crypto_mem,
		       dma_tx_complete_cb, crypto_ctx)) {
		print_error("DMA to dev failed....\n");
		ret = -1;
		goto error;
	}
#endif
	if (-1 == dma_abs_req(get_dma_chnl(), &crypto_ctx->crypto_mem,
				dma_tx_complete_cb, crypto_ctx)) {
		print_error("DMA to dev failed....\n");
		ret = -1;
		goto error;
	}

	return -EINPROGRESS;
#else

	print_debug(KERN_ERR "Before app_ring_enqueue\n");
	sec_dma = set_sec_affinity(c_dev, r_id, sec_dma);
#ifndef HIGH_PERF
	atomic_dec(&c_dev->active_jobs);
#endif
	/* Now enqueue the job into the app ring */
	if (app_ring_enqueue(c_dev, r_id, sec_dma)) {
		ret = -1;
		goto error1;
	}
#endif
	return -EINPROGRESS;

error:
#ifndef HIGH_PERF
	atomic_dec(&c_dev->active_jobs);
#endif
#ifdef HOST_TO_DEV_MEMCPY
error1:
#endif
	if (crypto_ctx) {
		if (crypto_ctx->crypto_mem.buffers) {
			dealloc_crypto_mem(&crypto_ctx->crypto_mem);
			/*kfree(crypto_ctx->crypto_mem.buffers); */
		}
		free_crypto_ctx(c_dev->ctx_pool, crypto_ctx);
		/*kfree(crypto_ctx); */
	}
	return ret;
}

#ifdef VIRTIO_C2X0
int test_rsa_op(struct pkc_request *req,
		void (*cb) (struct pkc_request *, int32_t result),
		struct virtio_c2x0_job_ctx *virtio_job)
#else
int test_rsa_op(struct pkc_request *req,
		void (*cb) (struct pkc_request *, int32_t result))
#endif
{
    int32_t ret = 0;
	rsa_completion_cb = cb;
#ifdef VIRTIO_C2X0
	ret = rsa_op(req, virtio_job);
#else
	ret = rsa_op(req);
#endif
    if (-EINPROGRESS == ret)
        ret = 0;
    if (0 > ret)
        ret = -1;

    return ret;
}
EXPORT_SYMBOL(test_rsa_op);
