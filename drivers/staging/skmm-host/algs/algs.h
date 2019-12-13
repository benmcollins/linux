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

#ifndef _ALG_H_
#define _ALG_H_

#include "desc_cnstr.h"
/* #ifdef KCAPI_STUB
#include "crypto.h"
#else
*/
#include <linux/crypto.h>
#include <crypto/algapi.h>
#ifdef VIRTIO_C2X0
#include <crypto/hash.h>	/* VIRTIO_C2X0 */
#endif
#include "hash.h"
#include "rng.h"

/* #endif */

#include "common.h"
#include "desc_constr.h"
#include "rsa.h"
#include "dsa.h"
#include "dh.h"
#include "error.h"
#include "abs_req.h"

/* extern struct instantiate_result; */
/* Enum identifying the type of operation :- Symmetric/Asymmetric */
typedef enum crypto_op_type {
	SYMMETRIC,
	ASYMMETRIC
} crypto_op_type_t;

/* Enum identifying the Crypto operations */
typedef enum crypto_op {
	RSA,
	DSA,
	DH,
	HASH_SPLIT_KEY,
	HASH_DIGEST_KEY,
	AHASH_DIGEST,
	AHASH_UPDATE_CTX,
	AHASH_FINUP_CTX,
	AHASH_FINAL_CTX,
	AHASH_FINAL_NO_CTX,
	AHASH_FINUP_NO_CTX,
	AHASH_UPDATE_NO_CTX,
	AHASH_UPDATE_FIRST,
	AEAD_SETKEY,
	AEAD_ENCRYPT,
	AEAD_DECRYPT,
	ABLK_ENCRYPT,
	ABLK_DECRYPT,
	RNG,
	RNG_INIT,
	RNG_SELF_TEST,
#ifdef VIRTIO_C2X0
	VIRTIO_C2X0_HASH_CRA_INIT = 100,
	VIRTIO_C2X0_HASH_CRA_EXIT = 101,
	VIRTIO_C2X0_SYMM_CRA_INIT = 102,
	VIRTIO_C2X0_SYMM_CRA_EXIT = 103,
	VIRTIO_C2X0_ABLK_SETKEY = 104,
#endif
} crypto_op_t;

/*******************************************************************************
Description :   Defines the crypto dev session context. This context is created
		at the time of new crypto dev session.
Fields      :   c_dev:	Crypto device instance to which this session belongs
		r_id :	Id of the ring to which this session belongs
		sec_eng:Id of the sec engine to which this session belongs.
			Used only in case of Symmetric algorithms
*******************************************************************************/
typedef struct crypto_dev_sess {
	fsl_crypto_dev_t *c_dev;
	uint32_t r_id;
	uint8_t sec_eng;
/* #ifndef KCAPI_STUB */
	union {
		struct hash_ctx hash;
		struct sym_ctx symm;
	} u;
/* #endif */
} crypto_dev_sess_t;

#ifdef VIRTIO_C2X0
struct virtio_c2x0_crypto_sess_ctx {
	crypto_dev_sess_t c_sess;
	unsigned long sess_id;
	int32_t guest_id;

	struct list_head list_entry;
} __packed;

#if 0
struct virtio_c2x0_hash_sess_ctx {
	crypto_dev_sess_t c_sess;
	unsigned long sess_id;
	int32_t guest_id;

	struct list_head list_entry;
} __packed;
#endif
#endif
/******************************************************************************
Description :	Defines the context for the crypto job
Fields      :	pci_dev:PCI device instance to which this job belongs to.
		pool   :Buffer pool from which memory for this job is
			allocated
		req_mem:Pointer to the complete request memory
		oprn   :Identifies the crypto operation
		req    :Union of different crypto req mem from KCAPI
		dev_mem:Union of different crypto
		done   :Callback to be called on completion of the request
*******************************************************************************/
typedef struct crypto_job_ctx {
	void *pci_dev;		
	void *pool;
	void *req_mem;

	crypto_op_t oprn;
	union {
		struct pkc_request *pkc;
		struct ahash_request *ahash;
		struct aead_request *aead;
		struct ablkcipher_request *ablk;
	} req;
	union {
		rsa_dev_mem_t *rsa;
		dsa_dev_mem_t *dsa;
		dh_key_dev_mem_t *dh;
		struct instantiate_result *rng_init;
/* #ifndef KCAPI_STUB */
		/* ahash_dev_mem_t *ahash; */
		ablkcipher_dev_mem_t *ablk;
		struct buf_data *rng;
/* #endif */
	} dev_mem;
	struct split_key_result *result;
	void (*done) (struct pkc_request *req, int32_t result);
#ifdef VIRTIO_C2X0
	int32_t card_status;
#endif

} crypto_job_ctx_t;

typedef struct crypto_op_ctx {
	void *ctx_pool;
	crypto_mem_info_t crypto_mem;
	crypto_op_t oprn;
	uint32_t rid;
	dev_dma_addr_t desc;
	void *c_dev;

	atomic_t maxreqs;
	atomic_t reqcnt;

	union {
		struct pkc_request *pkc;
		struct rng_init_compl *rng_init;
		struct buf_data *rng;
		struct ahash_request *ahash;
		struct ablkcipher_request *ablk;
	} req;
	struct split_key_result *result;
	void (*op_done) (void *ctx, int32_t result);
#ifdef VIRTIO_C2X0
	int32_t card_status;
#endif
} crypto_op_ctx_t;

/*******************************************************************************
Description :   Defines the context for application request entry.
		This will be use by firmware in response processing.
Fields      :   r_offset:	Offset of the ring to which this req belongs.
*******************************************************************************/
typedef struct app_req_job_ctx {
	dev_p_addr_t r_offset;
} app_req_job_ctx_t;

void change_desc_endianness(uint32_t *dev_mem,
			    uint32_t *host_mem, int32_t words);
void dma_tx_complete_cb(void *ctx);
int32_t check_device(fsl_crypto_dev_t *c_dev);
void crypto_op_done(fsl_crypto_dev_t *c_dev,
		    crypto_job_ctx_t *ctx, int32_t sec_result);
dev_dma_addr_t set_sec_affinity(fsl_crypto_dev_t *c_dev, uint32_t rid,
								dev_dma_addr_t desc);
uint32_t get_ring_rr(fsl_crypto_dev_t *c_dev);
fsl_crypto_dev_t *get_device_rr(void);

#endif
