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

#ifndef __HASH_H__
#define __HASH_H__

#include "symdesc.h"

struct split_key_result {
	struct completion completion;
	int err;
};

struct hash_lengths {
	uint32_t src_nents;
	uint32_t addon_nents;
	uint32_t output_len;
	uint32_t src_len;
	uint32_t buff_len;
	uint32_t ctx_len;
	uint32_t sh_desc_len;
};
struct hash_state {
	uint8_t buf_0[CAAM_MAX_HASH_BLOCK_SIZE] ____cacheline_aligned;
	int buflen_0;
	uint8_t buf_1[CAAM_MAX_HASH_BLOCK_SIZE] ____cacheline_aligned;
	int buflen_1;
	uint8_t ctx[MAX_CTX_LEN];
	int (*update) (struct ahash_request *req);
	int (*final) (struct ahash_request *req);
	int (*finup) (struct ahash_request *req);
	int current_buf;
};

/* ahash per-session context */
struct hash_ctx {
	uint32_t sh_desc_update[DESC_HASH_MAX_USED_LEN];
	uint32_t sh_desc_update_first[DESC_HASH_MAX_USED_LEN];
	uint32_t sh_desc_fin[DESC_HASH_MAX_USED_LEN];
	uint32_t sh_desc_digest[DESC_HASH_MAX_USED_LEN];
	uint32_t sh_desc_finup[DESC_HASH_MAX_USED_LEN];
	uint32_t len_desc_update;
	uint32_t len_desc_update_first;
	uint32_t len_desc_fin;
	uint32_t len_desc_digest;
	uint32_t len_desc_finup;

	uint32_t alg_type;
	uint32_t alg_op;
	uint8_t key[CAAM_MAX_HASH_KEY_SIZE];
	int ctx_len;
	unsigned int split_key_len;
	unsigned int split_key_pad_len;
};

/* Append key if it has been set */
static inline void init_sh_desc_key_ahash(u32 *desc, struct hash_ctx *ctx)
{
	u32 *key_jump_cmd;

	init_sh_desc(desc, HDR_SHARE_SERIAL);

	if (ctx->split_key_len) {
		/* Skip if already shared */
		key_jump_cmd = append_jump(desc, JUMP_JSL | JUMP_TEST_ALL |
					   JUMP_COND_SHRD);

		append_key_as_imm(desc, ctx->key, ctx->split_key_pad_len,
				  ctx->split_key_len, CLASS_2 |
				  KEY_DEST_MDHA_SPLIT | KEY_ENC);

		set_jump_tgt_here(desc, key_jump_cmd);
	}

	/* Propagate errors from shared to job descriptor */
	append_cmd(desc, SET_OK_NO_PROP_ERRORS | CMD_LOAD);
}

/*
 * For ahash read data from seqin following state->caam_ctx,
 * and write resulting class2 context to seqout, which may be state->caam_ctx
 * or req->result
 */
static inline void ahash_append_load_str(u32 *desc, int digestsize)
{
	/* Calculate remaining bytes to read */
	append_math_add(desc, VARSEQINLEN, SEQINLEN, REG0, CAAM_CMD_SZ);

	/* Read remaining bytes */
	append_seq_fifo_load(desc, 0, FIFOLD_CLASS_CLASS2 | FIFOLD_TYPE_LAST2 |
			     FIFOLD_TYPE_MSG | KEY_VLF);

	/* Store class2 context bytes */
	append_seq_store(desc, digestsize, LDST_CLASS_2_CCB |
			 LDST_SRCDST_BYTE_CONTEXT);
}

/* For ahash update, final and finup, import context,
 * read and write to seqout */
static inline void ahash_ctx_data_to_out(u32 *desc, u32 op, u32 state,
					 int digestsize, struct hash_ctx *ctx)
{

	init_sh_desc_key_ahash(desc, ctx);

	/* Import context from software */
	append_cmd(desc, CMD_SEQ_LOAD | LDST_SRCDST_BYTE_CONTEXT |
		   LDST_CLASS_2_CCB | ctx->ctx_len);

	/* Class 2 operation */
	append_operation(desc, op | state | OP_ALG_ENCRYPT);

	/*
	 * Load from buf and/or src and write to req->result or state->context
	 */
	ahash_append_load_str(desc, digestsize);
}

/* For ahash first digest, read and write to seqout */
static inline void ahash_data_to_out(u32 *desc, u32 op, u32 state,
				     int digestsize, struct hash_ctx *ctx)
{
	init_sh_desc_key_ahash(desc, ctx);

	/* Class 2 operation */
	append_operation(desc, op | state | OP_ALG_ENCRYPT);

	/* Load from buf and/or src, write to req->result or state->context */
	ahash_append_load_str(desc, digestsize);
}

/* Descriptor for ahash Update Descriptor */
static inline void ahash_update_desc(u32 *desc, struct hash_ctx *ctx)
{
	init_sh_desc(desc, HDR_SHARE_SERIAL);

	/* Import context from software */
	append_cmd(desc, CMD_SEQ_LOAD | LDST_SRCDST_BYTE_CONTEXT |
		   LDST_CLASS_2_CCB | ctx->ctx_len);

	/* Class 2 operation */
	append_operation(desc, ctx->alg_type | OP_ALG_AS_UPDATE |
			 OP_ALG_ENCRYPT);

	/* Load data and write to result or context */
	ahash_append_load_str(desc, ctx->ctx_len);
}

/* Job Descriptor for Hash */
static inline void hash_jobdesc(u32 *desc, dev_dma_addr_t sh_desc,
				u32 sh_len, dev_dma_addr_t in, uint32_t in_len,
				u32 in_options, dev_dma_addr_t out,
				uint32_t out_len)
{
	init_job_desc_shared(desc, sh_desc,
			     sh_len, HDR_SHARE_DEFER | HDR_REVERSE);

	append_seq_in_ptr(desc, in, in_len, in_options);
	append_seq_out_ptr(desc, out, out_len, 0);
}

/* Job descriptor to perform unkeyed hash on key_in */
static inline void hash_digestkey_desc(u32 *desc, u32 alg_type,
				       dev_dma_addr_t in, u32 in_len,
				       dev_dma_addr_t out, u32 out_len)
{
	init_sym_job_desc(desc, 0);
	append_operation(desc, alg_type | OP_ALG_ENCRYPT | OP_ALG_AS_INITFINAL);
	append_seq_in_ptr(desc, in, in_len, 0);
	append_seq_fifo_load(desc, in_len, FIFOLD_CLASS_CLASS2 |
			     FIFOLD_TYPE_LAST2 | FIFOLD_TYPE_MSG);
	append_seq_out_ptr(desc, out, out_len, 0);
	append_seq_store(desc, out_len, LDST_CLASS_2_CCB |
			 LDST_SRCDST_BYTE_CONTEXT);
}

static inline void hash_splitkey_jobdesc(u32 *desc, u32 alg_op,
					 dev_dma_addr_t in, u32 in_len,
					 dev_dma_addr_t out, u32 out_len)
{
	init_sym_job_desc(desc, 0);
	append_key(desc, in, in_len, CLASS_2 | KEY_DEST_CLASS_REG);

	/* Sets MDHA up into an HMAC-INIT */
	append_operation(desc, alg_op | OP_ALG_DECRYPT | OP_ALG_AS_INIT);

	/*
	 * do a FIFO_LOAD of zero, this will trigger the internal key expansion
	 * into both pads inside MDHA
	 */
	append_fifo_load_as_imm(desc, NULL, 0, LDST_CLASS_2_CCB |
				FIFOLD_TYPE_MSG | FIFOLD_TYPE_LAST2);

	append_fifo_store(desc, out, out_len,
			  LDST_CLASS_2_CCB | FIFOST_TYPE_SPLIT_KEK);
}

#ifndef VIRTIO_C2X0
int ahash_set_sh_desc(struct crypto_ahash *ahash);
#endif
#endif
