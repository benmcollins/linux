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

#ifndef __DESC_CNSTR_H__
#define __DESC_CNSTR_H__

typedef enum buffer_type {
	BT_DESC,
	BT_IP,
	BT_OP
} buffer_type_t;

typedef struct dev_buffer {
	/* Device related fields */
	unsigned long d_v_addr;
	dev_p_addr_t d_p_addr;
	phys_addr_t h_map_p_addr;

	/* Host related fields */
	unsigned long h_v_addr;
	phys_addr_t h_p_addr;
	dma_addr_t h_dma_addr;
} dev_buffer_t;

struct buffer_info {
	buffer_type_t bt;
	uint32_t len;

	uint8_t *v_mem;
	uint8_t *req_ptr;
	dev_buffer_t dev_buffer;
	unsigned long priv;
} __packed;

typedef struct buffer_info buffer_info_t;

typedef struct rsa_keygen_op_buffers {
	buffer_info_t n_buff;
} rsa_keygen_op_buffers_t;

typedef struct rsa_pub_op_buffers {
	buffer_info_t n_buff;
	buffer_info_t e_buff;
	buffer_info_t f_buff;
	buffer_info_t g_buff;
} rsa_pub_op_buffers_t;

typedef struct rsa_priv1_op_buffers {
	buffer_info_t desc_buff;
	buffer_info_t n_buff;
	buffer_info_t d_buff;
	buffer_info_t g_buff;
	buffer_info_t f_buff;
} rsa_priv1_op_buffers_t;

typedef struct rsa_priv2_op_buffers {
	buffer_info_t desc_buff;
	buffer_info_t p_buff;
	buffer_info_t q_buff;
	buffer_info_t d_buff;
	buffer_info_t f_buff;
	buffer_info_t g_buff;
	buffer_info_t tmp1_buff;
	buffer_info_t tmp2_buff;
} rsa_priv2_op_buffers_t;

typedef struct rsa_priv3_op_buffers {
	buffer_info_t f_buff;
	buffer_info_t g_buff;
} rsa_priv3_op_buffers_t;

typedef struct dsa_sign_buffers {
	buffer_info_t q_buff;
	buffer_info_t r_buff;
	buffer_info_t g_buff;
	buffer_info_t priv_key_buff;
	buffer_info_t m_buff;
	buffer_info_t tmp_buff;
	buffer_info_t c_buff;
	buffer_info_t d_buff;
	buffer_info_t ab_buff;
} dsa_sign_buffers_t;

typedef struct dsa_verify_buffers {
	buffer_info_t q_buff;
	buffer_info_t r_buff;
	buffer_info_t g_buff;
	buffer_info_t pub_key_buff;
	buffer_info_t m_buff;
	buffer_info_t tmp_buff;
	buffer_info_t c_buff;
	buffer_info_t d_buff;
	buffer_info_t ab_buff;
} dsa_verify_buffers_t;

typedef struct keygen_buffers {
	buffer_info_t q_buff;
	buffer_info_t r_buff;
	buffer_info_t g_buff;
	buffer_info_t prvkey_buff;
	buffer_info_t pubkey_buff;
	buffer_info_t ab_buff;
} keygen_buffers_t;

typedef struct keygen_buffers  dsa_keygen_buffers_t;

typedef struct keygen_buffers dh_keygen_buffers_t;

typedef struct dh_key_buffers {
	buffer_info_t q_buff;
	buffer_info_t w_buff;
	buffer_info_t s_buff;
	buffer_info_t z_buff;
	buffer_info_t ab_buff;
} dh_key_buffers_t;


typedef struct rng_init_buffers {
	buffer_info_t desc_buff;
	buffer_info_t pers_str_buff;
} rng_init_buffers_t;

typedef struct rng_self_test_buffers {
	buffer_info_t desc_buff;
	buffer_info_t output_buff;
} rng_self_test_buffers_t;

typedef struct rng_buffers {
	buffer_info_t desc_buff;
	buffer_info_t output_buff;
	buffer_info_t sh_desc_buff;
} rng_buffers_t;

typedef struct hash_buffers {
	buffer_info_t desc_buff;
	buffer_info_t sh_desc_buff;
	buffer_info_t output_buff;
	buffer_info_t sec_sg_buff;
	buffer_info_t input_buffs[0];
} hash_buffers_t;

typedef struct hash_key_buffers {
	buffer_info_t desc_buff;
	buffer_info_t output_buff;
	buffer_info_t input_buff;
} hash_key_buffers_t;

typedef struct symm_ablk_buffers {
	buffer_info_t desc;
	buffer_info_t info;
	buffer_info_t src;
	buffer_info_t dst;
	/* SETKEY CTX */
	buffer_info_t sh_desc;
	buffer_info_t key;
	/* ---------- */
	buffer_info_t src_sg[0];
} symm_ablk_buffers_t;

typedef union crypto_buffers {
	rsa_keygen_op_buffers_t rsa_keygen_op;
	rsa_pub_op_buffers_t rsa_pub_op;
	rsa_priv1_op_buffers_t rsa_priv1_op;
	rsa_priv2_op_buffers_t rsa_priv2_op;
	rsa_priv3_op_buffers_t rsa_priv3_op;
	dsa_sign_buffers_t dsa_sign;
	dsa_verify_buffers_t dsa_verify;
	dsa_keygen_buffers_t dsa_keygen;
	dh_key_buffers_t dh_key;
    dh_keygen_buffers_t dh_keygen;
	rng_init_buffers_t rng_init;
	rng_self_test_buffers_t rng_self_test;
	rng_buffers_t rng;
	hash_buffers_t *hash;
	hash_key_buffers_t hash_key;
	symm_ablk_buffers_t *symm_ablk;
} crypto_buffers_t;

typedef struct crypto_mem_info {
	uint32_t count;
	uint32_t alloc_len;
	uint32_t split_ip;
	uint32_t sg_cnt;
	struct scatterlist *ip_sg;
	struct scatterlist *op_sg;
	void *src_buff;
	dma_addr_t dest_buff_dma;
	buffer_info_t *buffers;
	void *abs_req;
	dma_addr_t abs_p_h_map_addr;
	void *pool;
	void *dev;
	crypto_buffers_t c_buffers;
} crypto_mem_info_t;

int32_t memcpy_to_dev(crypto_mem_info_t *mem);
int32_t host_to_dev(crypto_mem_info_t *mem_info);
int32_t dealloc_crypto_mem(crypto_mem_info_t *mem_info);
int32_t alloc_crypto_mem(crypto_mem_info_t *mem_info);
extern per_core_struct_t __percpu *per_core;
#endif
