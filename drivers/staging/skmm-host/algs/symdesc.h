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

#ifndef __SYMDESC__
#define __SYMDESC__

#include "compat.h"
#include "desc_constr.h"

#if 0
#include "regs.h"
#include "intern.h"
#include "desc_constr.h"
#include "jr.h"
#include "error.h"
#include "sg_sw_sec4.h"
#include "key_gen.h"
#endif
#define CAAM_CRA_PRIORITY              3000

/* max hash key is max split key size */
#define CAAM_MAX_HASH_KEY_SIZE         (SHA512_DIGEST_SIZE * 2)

#define CAAM_MAX_HASH_BLOCK_SIZE       SHA512_BLOCK_SIZE
#define CAAM_MAX_HASH_DIGEST_SIZE      SHA512_DIGEST_SIZE

/* length of descriptors text */
#define DESC_JOB_IO_LEN                (CAAM_CMD_SZ * 5 + CAAM_PTR_SZ * 3)

#define DESC_AHASH_BASE                (4 * CAAM_CMD_SZ)
#define DESC_AHASH_UPDATE_LEN          (6 * CAAM_CMD_SZ)
#define DESC_AHASH_UPDATE_FIRST_LEN    (DESC_AHASH_BASE + 4 * CAAM_CMD_SZ)
#define DESC_AHASH_FINAL_LEN           (DESC_AHASH_BASE + 5 * CAAM_CMD_SZ)
#define DESC_AHASH_FINUP_LEN           (DESC_AHASH_BASE + 5 * CAAM_CMD_SZ)
#define DESC_AHASH_DIGEST_LEN          (DESC_AHASH_BASE + 4 * CAAM_CMD_SZ)

#define DESC_HASH_MAX_USED_BYTES       (DESC_AHASH_FINAL_LEN + \
					CAAM_MAX_HASH_KEY_SIZE)
#define DESC_HASH_MAX_USED_LEN         (DESC_HASH_MAX_USED_BYTES / CAAM_CMD_SZ)

/* caam context sizes for hashes: running digest + 8 */
#define HASH_MSG_LEN                   8
#define MAX_CTX_LEN                    (HASH_MSG_LEN + SHA512_DIGEST_SIZE)

/*
 * crypto alg
 */
/* max key is sum of AES_MAX_KEY_SIZE, max split key size */
#define CAAM_MAX_KEY_SIZE              (AES_MAX_KEY_SIZE + \
					SHA512_DIGEST_SIZE * 2)
/* max IV is max of AES_BLOCK_SIZE, DES3_EDE_BLOCK_SIZE */
#define CAAM_MAX_IV_LENGTH             16

#define DESC_AEAD_BASE                 (4 * CAAM_CMD_SZ)
#define DESC_AEAD_ENC_LEN              (DESC_AEAD_BASE + 16 * CAAM_CMD_SZ)
#define DESC_AEAD_DEC_LEN              (DESC_AEAD_BASE + 21 * CAAM_CMD_SZ)
#define DESC_AEAD_GIVENC_LEN           (DESC_AEAD_ENC_LEN + 7 * CAAM_CMD_SZ)

#define DESC_ABLKCIPHER_BASE           (3 * CAAM_CMD_SZ)
#define DESC_ABLKCIPHER_ENC_LEN        (DESC_ABLKCIPHER_BASE + \
					20 * CAAM_CMD_SZ)
#define DESC_ABLKCIPHER_DEC_LEN        (DESC_ABLKCIPHER_BASE + \
					15 * CAAM_CMD_SZ)

#define DESC_MAX_USED_BYTES            (DESC_AEAD_GIVENC_LEN + \
					CAAM_MAX_KEY_SIZE)
#define DESC_MAX_USED_LEN              (DESC_MAX_USED_BYTES / CAAM_CMD_SZ)

#define DESC_AEAD_ENC_LEN               (DESC_AEAD_BASE + 16 * CAAM_CMD_SZ)

/*
 * Encrypted - Key is encrypted either with the KEK, or
 * with the TDKEK if TK is set
 */
#define KEY_ENC         0x00400000

#define GIV_SRC_CONTIG      1
#define GIV_DST_CONTIG      (1 << 1)

/*
 * per-session context
 */
struct sym_ctx {
	char key[CAAM_MAX_KEY_SIZE];
	uint32_t keylen;

	uint32_t class1_alg_type;
	uint32_t class2_alg_type;
	uint32_t alg_op;

	uint32_t sh_desc_len;
};

typedef struct ablkcipher_dev_mem {
	crypto_mem_info_t ablk_ctx;
#if 0
	uint8_t **src_dev_sg;
	struct sec4_sg_entry *src;
	bool src_chained;
	uint32_t src_sgcnt;

	uint8_t *info;
	dev_dma_addr_t info_dma;

	struct sec4_sg_entry *dst;
	bool dst_chained;
	uint32_t dst_sgcnt;

	dev_dma_addr_t sec4_sg_dma;

	uint32_t *hw_desc;
#endif
} ablkcipher_dev_mem_t;

/*
 * Wait for completion of class 1 key loading before allowing
 * error propagation
 */
static inline void append_dec_shr_done(u32 *desc)
{
	u32 *jump_cmd;

	jump_cmd = append_jump(desc, JUMP_CLASS_CLASS1 | JUMP_TEST_ALL);
	set_jump_tgt_here(desc, jump_cmd);
	append_cmd(desc, SET_OK_NO_PROP_ERRORS | CMD_LOAD);
}

/* Cipher Descriptor Helper functions */
/* Set DK bit in class 1 operation if shared */
static inline void append_dec_op1(u32 *desc, u32 type)
{
	u32 *jump_cmd, *uncond_jump_cmd;

	jump_cmd = append_jump(desc, JUMP_TEST_ALL | JUMP_COND_SHRD);
	append_operation(desc, type | OP_ALG_AS_INITFINAL | OP_ALG_DECRYPT);
	uncond_jump_cmd = append_jump(desc, JUMP_TEST_ALL);
	set_jump_tgt_here(desc, jump_cmd);
	append_operation(desc, type | OP_ALG_AS_INITFINAL |
			 OP_ALG_DECRYPT | OP_ALG_AAI_DK);
	set_jump_tgt_here(desc, uncond_jump_cmd);
}

static inline void ablkcipher_append_src_dst(u32 *desc)
{
	append_math_add(desc, VARSEQOUTLEN, SEQINLEN, REG0, CAAM_CMD_SZ);
	append_math_add(desc, VARSEQINLEN, SEQINLEN, REG0, CAAM_CMD_SZ);
	append_seq_fifo_load(desc, 0, FIFOLD_CLASS_CLASS1 |
			     KEY_VLF | FIFOLD_TYPE_MSG | FIFOLD_TYPE_LAST1);
	append_seq_fifo_store(desc, 0, FIFOST_TYPE_MESSAGE_DATA | KEY_VLF);
}

#endif
