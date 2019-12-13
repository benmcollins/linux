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

#ifndef _RSA_H_
#define _RSA_H_

typedef struct rsa_pub_dev_mem {
	uint8_t *n;
	uint8_t *e;
	uint8_t *f;

	dev_dma_addr_t n_dma;
	dev_dma_addr_t e_dma;
	dev_dma_addr_t f_dma;

	dev_dma_addr_t g_dma;

	dma_addr_t g_host_dma;

	uint32_t n_len;
	uint32_t e_len;
	uint32_t f_len;
	uint32_t g_len;
} rsa_pub_dev_mem_t;

typedef struct rsa_prv1_dev_mem {
	uint8_t *n;
	uint8_t *d;
	uint8_t *g;

	dev_dma_addr_t n_dma;
	dev_dma_addr_t d_dma;
	dev_dma_addr_t g_dma;

	dev_dma_addr_t f_dma;

	dma_addr_t f_host_dma;

	uint32_t d_len;
	uint32_t n_len;
	uint32_t f_len;
} rsa_prv1_dev_mem_t;

typedef struct rsa_prv2_dev_mem {
	uint8_t *g;
	uint8_t *d;
	uint8_t *p;
	uint8_t *q;
	uint8_t *tmp1;
	uint8_t *tmp2;

	dev_dma_addr_t g_dma;
	dev_dma_addr_t d_dma;
	dev_dma_addr_t p_dma;
	dev_dma_addr_t q_dma;
	dev_dma_addr_t tmp1_dma;
	dev_dma_addr_t tmp2_dma;

	dev_dma_addr_t f_dma;

	dma_addr_t f_host_dma;

	uint32_t d_len;
	uint32_t n_len;
	uint32_t p_len;
	uint32_t q_len;
	uint32_t f_len;
} rsa_prv2_dev_mem_t;

typedef struct rsa_prv3_dev_mem {
	uint8_t *g;
	uint8_t *c;
	uint8_t *p;
	uint8_t *q;
	uint8_t *dp;
	uint8_t *dq;
	uint8_t *tmp1;
	uint8_t *tmp2;

	dev_dma_addr_t g_dma;
	dev_dma_addr_t c_dma;
	dev_dma_addr_t p_dma;
	dev_dma_addr_t q_dma;
	dev_dma_addr_t dp_dma;
	dev_dma_addr_t dq_dma;
	dev_dma_addr_t tmp1_dma;
	dev_dma_addr_t tmp2_dma;

	dev_dma_addr_t f_dma;

	dma_addr_t f_host_dma;

	uint32_t n_len;
	uint32_t f_len;
	uint32_t p_len;
	uint32_t q_len;
} rsa_prv3_dev_mem_t;

typedef struct rsa_dev_mem {
	enum pkc_req_type req_type;
	union {
		rsa_pub_dev_mem_t pub;
		rsa_prv1_dev_mem_t priv1;
		rsa_prv2_dev_mem_t priv2;
		rsa_prv3_dev_mem_t priv3;
	} u;
	uint8_t *buffer;
	uint32_t *drv_desc;
	uint32_t *hw_desc;
} rsa_dev_mem_t;

#ifndef VIRTIO_C2X0
int test_rsa_op(struct pkc_request *req,
		void (*cb) (struct pkc_request *, int32_t result));
#endif

#endif
