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

#ifndef __FSL_C2X0_VIRTIO_H_
#define __FSL_C2X0_VIRTIO_H_

/*** VIRTIO_C2X0 ***/

#include "algs.h"

/*
struct virtio_c2x0_hash_sess_ctx {
    crypto_dev_sess_t c_sess;
    unsigned long sess_id;

    struct list_head list_entry;
}__packed;
*/
typedef enum cmd_block_type {
	NONBLOCKING,
	BLOCKING
} cmd_block_type_t;

struct vc_hash_cra_init {
	int op_type;
	int alg_type;
	int alg_op;
	uint32_t fsl_crypto_alg_len;
	int digestsize;
	unsigned long sess_id;
} __packed;

struct ahash_setkey_request {
	int blocksize;
	int digestsize;
	uint8_t *key;
	unsigned int keylen;
	unsigned long sess_id;
} __packed;

struct virtio_sg_info {
	int sg_count;		/* No of sg entries */
	unsigned int nbytes;
} __packed;

struct ahash_digest_request {
	uint8_t **src;
	uint32_t *src_len;
	uint8_t *result;
	int digestsize;
	struct virtio_sg_info sg_info;
	unsigned long sess_id;
} __packed;

struct ahash_update_request {
	uint8_t **src;
	uint32_t *src_len;
	struct hash_state *state;
	uint8_t *ctx;
	int ctxlen;
	int next_buflen;
	struct virtio_sg_info sg_info;
	unsigned long sess_id;
} __packed;

struct ahash_final_request {
    /*** NOT USED IN VM. Only used in Qemu and Host */
	struct hash_state *state;
	uint8_t *result;
    /*************/
	int digestsize;
	unsigned long sess_id;
} __packed;

struct ahash_finup_request {
    /*** NOT USED IN VM. Only used in Qemu and Host */
	uint8_t **src;
	uint32_t *src_len;
	struct hash_state *state;
	uint8_t *result;
    /*************/
	int digestsize;
	struct virtio_sg_info sg_info;
	unsigned long sess_id;
} __packed;

struct vc_hash_cra_exit {
	unsigned long sess_id;
} __packed;

struct vc_symm_cra_init {
	int op_type;
	int alg_op;
	int class1_alg_type;
	int class2_alg_type;
	unsigned long sess_id;
} __packed;

struct vc_symm_cra_exit {
	unsigned long sess_id;
} __packed;

struct ablkcipher_setkey {
	uint8_t *key;
	uint32_t keylen;
	unsigned int ivsize;
	unsigned long sess_id;
} __packed;

struct ablkcipher_cmd {
	uint8_t **src;
	uint32_t *src_len;
	uint8_t **dst;
	uint32_t *dst_len;
	uint8_t *info;
	int32_t ivsize;
	struct virtio_sg_info src_sg_info;
	struct virtio_sg_info dst_sg_info;
	unsigned long sess_id;
} __packed;

struct rng_cmd {
	uint8_t *buf;
	unsigned int cur_buf_idx;
	int current_buf;
	int to_current;
} __packed;

/* VIRTIO_C2X0 */
struct virtio_c2x0_qemu_cmd {
	crypto_op_t op;
	crypto_op_type_t op_type;
	cmd_block_type_t block_type;
	union {
		union {
			struct pkc_request pkc_req;
		} pkc;
		union {
			struct vc_hash_cra_init init;
			struct vc_hash_cra_exit exit;
			struct ahash_setkey_request setkey_req;
			struct ahash_digest_request digest_req;
			struct ahash_update_request update_req;
			struct ahash_final_request final_req;
			struct ahash_finup_request finup_req;
		} hash;
		union {
			struct vc_symm_cra_init init;
			struct vc_symm_cra_exit exit;
			struct ablkcipher_setkey setkey_req;
			struct ablkcipher_cmd cmd_req;
		} symm;
		union {
			struct rng_cmd rng_req;
		} rng;
	} u;
	int32_t *host_status;
	int32_t guest_id;
	uint32_t cmd_index;
} __packed;

struct virtio_c2x0_job_ctx {
	struct virtio_c2x0_qemu_cmd qemu_cmd;
	/*
	 * Only either of job_ctx or op_ctx should be present.
	 */
	/* crypto_job_ctx_t *ctx; */
	crypto_op_ctx_t *ctx;
	struct list_head list_entry;
} __packed;

struct virtio_c2x0_cmd_status {
	uint32_t cmd_index;
	int32_t guest_id;
	int32_t status;
} __packed;

/*********************************************************************
 *                 FUNCTION PROTOTYPES                               *
 ********************************************************************/
int32_t process_virtio_app_req(struct virtio_c2x0_job_ctx *qemu_cmd);

#if 0
int test_rsa_op(struct pkc_request *req,
		void (*cb) (struct pkc_request *, int32_t result),
		struct virtio_c2x0_job_ctx *virtio_job);

int test_dsa_op(struct pkc_request *req,
		void (*cb) (struct pkc_request *, int32_t result),
		struct virtio_c2x0_job_ctx *virtio_job);

int test_dh_op(struct pkc_request *req,
	       void (*cb) (struct pkc_request *, int32_t result),
	       struct virtio_c2x0_job_ctx *virtio_job);
#endif

int ahash_set_sh_desc(crypto_dev_sess_t *c_sess, int digestsize);

int rsa_op(struct pkc_request *req, struct virtio_c2x0_job_ctx *virtio_job);
int dsa_op(struct pkc_request *req, struct virtio_c2x0_job_ctx *virtio_job);
int dh_op(struct pkc_request *req, struct virtio_c2x0_job_ctx *virtio_job);

/* HASH */
int ahash_setkey(const uint8_t *key, struct virtio_c2x0_qemu_cmd *qemu_cmd);
int ahash_update_ctx(struct ahash_request *req,
		     struct virtio_c2x0_job_ctx *virtio_job);
int ahash_update_no_ctx(struct ahash_request *req,
			struct virtio_c2x0_job_ctx *virtio_job);
int ahash_update_first(struct ahash_request *req,
		       struct virtio_c2x0_job_ctx *virtio_job);
int ahash_final_ctx(struct ahash_request *req,
		    struct virtio_c2x0_job_ctx *virtio_job);
int ahash_final_no_ctx(struct ahash_request *req,
		       struct virtio_c2x0_job_ctx *virtio_job);
int ahash_finup_ctx(struct ahash_request *req,
		    struct virtio_c2x0_job_ctx *virtio_job);
int ahash_finup_no_ctx(struct ahash_request *req,
		       struct virtio_c2x0_job_ctx *virtio_job);
int ahash_digest(struct ahash_request *req,
		 struct virtio_c2x0_job_ctx *virtio_job);
int virtio_c2x0_ahash_setkey(const uint8_t *key,
			     struct virtio_c2x0_qemu_cmd *qemu_cmd);
/* HASH */

int32_t fsl_ablkcipher_setkey(struct virtio_c2x0_qemu_cmd *qemu_cmd,
			      const uint8_t *key, uint32_t keylen);
int32_t fsl_ablkcipher(struct ablkcipher_request *req,
		       bool encrypt, struct virtio_c2x0_job_ctx *virtio_job);

/* RNG Functions */
int rng_init(void);
int32_t process_virtio_rng_job(struct virtio_c2x0_job_ctx *virtio_job);

int virtio_c2x0_hash_cra_init(struct virtio_c2x0_job_ctx *virtio_job);
int virtio_c2x0_hash_cra_exit(struct virtio_c2x0_qemu_cmd *qemu_cmd);
int hash_cra_init(struct virtio_c2x0_job_ctx *virtio_job);
void hash_cra_exit(crypto_dev_sess_t *c_sess);

int virtio_c2x0_symm_cra_init(struct virtio_c2x0_job_ctx *virtio_job);
int virtio_c2x0_symm_cra_exit(struct virtio_c2x0_qemu_cmd *qemu_cmd);
int sym_cra_init(struct virtio_c2x0_job_ctx *virtio_job);
void sym_cra_exit(crypto_dev_sess_t *ctx);

void print_sess_list(void);	/* Debug */

void cleanup_virtio_pkc_buffers(struct pkc_request *req);

void process_virtio_job_response(struct virtio_c2x0_job_ctx *virtio_job);
/*********************************************************************
 *                 EXTERN  VARIABLES                                 *
 ********************************************************************/
/* List Variable */
extern struct list_head virtio_c2x0_hash_sess_list;
extern struct list_head virtio_c2x0_symm_sess_list;
extern spinlock_t hash_sess_list_lock;
extern spinlock_t symm_sess_list_lock;

#endif /* __FSL_C2X0_VIRTIO_H_ */
