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
#ifndef ABS_REQ_H
#define ABS_REQ_H

struct rsa_keygen {
	dev_p_addr_t n;
	u32 n_len;
};

struct rsa_pub {
	dev_p_addr_t n;
	dev_p_addr_t e;
	dev_p_addr_t f;
	dev_p_addr_t g;
	u32 n_len;
	u32 e_len;
	u32 f_len;
};

struct rsa_priv3 {
	dev_p_addr_t f;
	dev_p_addr_t g;
	u32 n_len;
};

struct keygen {
	dev_p_addr_t q;
	dev_p_addr_t r;
	dev_p_addr_t g;
	dev_p_addr_t pub_key;
	dev_p_addr_t ab;
	u32 q_len;
	u32 r_len;
};

struct dsa_verify {
	dev_p_addr_t q;
	dev_p_addr_t r;
	dev_p_addr_t g;
	dev_p_addr_t pub_key;
	dev_p_addr_t m;
	dev_p_addr_t c;
	dev_p_addr_t d;
	dev_p_addr_t ab;

	u32 q_len;
	u32 r_len;
};

struct dsa_sign {
	dev_p_addr_t q;
	dev_p_addr_t r;
	dev_p_addr_t g;
	dev_p_addr_t f;
	dev_p_addr_t c;
	dev_p_addr_t d;
	dev_p_addr_t ab;

	u32 q_len;
	u32 r_len;
};

struct dh_key {
	dev_p_addr_t w;
	dev_p_addr_t z;
	dev_p_addr_t ab;
};

struct abs_req {
	int req_type;
	union {
		struct rsa_keygen rsa_keygen;
		struct rsa_pub rsa_pub;
		struct rsa_priv3 rsa_priv3;
		struct dsa_sign dsa_sign;
		struct dsa_verify dsa_verify;
		struct dh_key dh_key;
		struct keygen keygen;
	} req_data;
};

#include <linux/crypto.h>
dev_dma_addr_t get_abs_req_p_addr(crypto_mem_info_t *c_mem);
void *get_abs_req_v_addr(crypto_mem_info_t *c_mem);
void constr_abs_req(crypto_mem_info_t *c_mem, struct pkc_request *req);
#endif
