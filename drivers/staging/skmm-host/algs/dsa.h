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

#ifndef _DSA_H_
#define _DSA_H_

#define DSA_L_SHIFT		7
#define DSA_L_MASK		(0x3ff << DSA_L_SHIFT)

typedef struct dsa_sign_dev_mem {
	uint8_t *q;
	uint8_t *r;
	uint8_t *g;
	uint8_t *priv_key;
	uint8_t *m;
	uint8_t *ab;
	uint32_t q_len;
	uint32_t r_len;
	uint32_t g_len;
	uint32_t priv_key_len;
	uint32_t m_len;
	uint32_t d_len;
	uint32_t ab_len;

	dev_dma_addr_t q_dma;
	dev_dma_addr_t r_dma;
	dev_dma_addr_t g_dma;
	dev_dma_addr_t priv_key_dma;
	dev_dma_addr_t m_dma;
	dev_dma_addr_t ab_dma;

	dev_dma_addr_t c_dma;
	dev_dma_addr_t d_dma;

	dma_addr_t c_host_dma;
	dma_addr_t d_host_dma;

} dsa_sign_dev_mem_t;

typedef struct dsa_verify_dev_mem {
	uint8_t *q;
	uint8_t *r;
	uint8_t *g;
	uint8_t *pub_key;
	uint8_t *m;
	uint8_t *c;
	uint8_t *d;
	uint8_t *temp;
	uint8_t *ab;
	uint32_t q_len;
	uint32_t r_len;
	uint32_t g_len;
	uint32_t pub_key_len;
	uint32_t m_len;
	uint32_t d_len;
	uint32_t ab_len;

	dev_dma_addr_t q_dma;
	dev_dma_addr_t r_dma;
	dev_dma_addr_t g_dma;
	dev_dma_addr_t pub_key_dma;
	dev_dma_addr_t m_dma;
	dev_dma_addr_t temp_dma;
	dev_dma_addr_t ab_dma;
	dev_dma_addr_t c_dma;
	dev_dma_addr_t d_dma;

} dsa_verify_dev_mem_t;

typedef struct dsa_dev_mem {
	enum pkc_req_type req_type;
	enum curve_t curve_type;
	union {
		dsa_sign_dev_mem_t dsa_sign;
		dsa_verify_dev_mem_t dsa_verify;
	} u;
	uint32_t *hw_desc;
} dsa_dev_mem_t;

#ifndef VIRTIO_C2X0
int test_dsa_op(struct pkc_request *req,
		void (*cb) (struct pkc_request *, int32_t result));
#endif

#endif
