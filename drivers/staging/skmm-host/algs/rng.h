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

#ifndef __RNG_H__
#define __RNG_H__
#include "symdesc.h"

/* length of descriptors */
#define DESC_JOB_O_LEN  (CAAM_CMD_SZ * 2 + CAAM_PTR_SZ * 2)
#define DESC_RNG_LEN    (10 * CAAM_CMD_SZ)

/*
 * Maximum buffer size: maximum number of random, cache-aligned bytes that
 * will be generated and moved to seq out ptr (extlen not allowed)
 */

#define RN_BUF_SIZE     (0xffff / L1_CACHE_BYTES * L1_CACHE_BYTES)
struct buf_data {
	u8 buf[RN_BUF_SIZE];
	struct completion filled;
#define BUF_NOT_EMPTY 0
#define BUF_EMPTY 1
#define BUF_PENDING 2	/* Empty,but with job pending -don't submit another */
	atomic_t empty;
};

/* rng per-device context */
struct rng_ctx {
	fsl_crypto_dev_t *c_dev;
	u32 *sh_desc;
	u32 sh_desc_len;
	unsigned int cur_buf_idx;
	int current_buf;
	struct buf_data bufs[2];
	spinlock_t ctx_lock;
};

extern atomic_t selected_devices;
/**
 note: Job Descriptor for Random Number Generation
 desc: Job Descriptor pointer
 sh_desc_dma: DMA address of RNG Shared Descriptor
 sh_len: Shared Descriptor Length
 buf_addr: Output buffer length
 */
static inline void init_rng_job_desc(u32 *desc, dev_dma_addr_t sh_desc_dma,
				     int sh_len, dev_dma_addr_t buf_addr)
{
	init_job_desc_shared(desc, sh_desc_dma, sh_len, HDR_SHARE_DEFER |
			     HDR_REVERSE);

	append_seq_out_ptr_intlen(desc, buf_addr, RN_BUF_SIZE, 0);
}

/**
 note : Creates Shared descriptor for Random Number Generation
 desc : Descriptor containing shared descriptor for RNG
 */
static inline void init_rng_sh_desc(u32 *desc)
{
	init_sh_desc(desc, HDR_SHARE_SERIAL);

	/* Propagate errors from shared to job descriptor */
	append_cmd(desc, SET_OK_NO_PROP_ERRORS | CMD_LOAD);

	/* Generate random bytes */
	append_operation(desc, OP_ALG_ALGSEL_RNG | OP_TYPE_CLASS1_ALG);

	/* Store bytes */
	append_seq_fifo_store(desc, RN_BUF_SIZE, FIFOST_TYPE_RNGSTORE);
}

int rng_init(void);
void rng_exit(void);

#endif
