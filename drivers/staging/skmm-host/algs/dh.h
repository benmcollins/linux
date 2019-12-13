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

#ifndef _DH_H_
#define _DH_H_

#define DH_PDB_L_SHIFT         7
#define DH_PDB_L_MASK          (0x3ff << DH_PDB_L_SHIFT)
#define DH_PDB_N_MASK          0x7f
#define DH_PDB_SGF_SHIFT       24
#define DH_PDB_SGF_MASK        (0xff << DH_PDB_SGF_SHIFT)
#define DH_PDB_SGF_Q           (0x80 << DH_PDB_SGF_SHIFT)
#define DH_PDB_SGF_R           (0x40 << DH_PDB_SGF_SHIFT)
#define DH_PDB_SGF_W           (0x20 << DH_PDB_SGF_SHIFT)
#define DH_PDB_SGF_S           (0x10 << DH_PDB_SGF_SHIFT)
#define DH_PDB_SGF_Z           (0x08 << DH_PDB_SGF_SHIFT)
#define DH_PDB_SGF_AB          (0x04 << DH_PDB_SGF_SHIFT)

typedef struct dh_key_dev_mem {
	enum pkc_req_type req_type;
	enum curve_t curve_type;
	uint8_t *q;
	uint8_t *ab;
	uint8_t *w;
	uint8_t *s;
	uint32_t q_len;
	uint32_t ab_len;
	uint32_t w_len;
	uint32_t s_len;
	uint32_t z_len;

	dev_dma_addr_t q_dma;
	dev_dma_addr_t ab_dma;
	dev_dma_addr_t w_dma;
	dev_dma_addr_t s_dma;
	dev_dma_addr_t z_dma;
	dma_addr_t z_host_dma;
	u32 *hw_desc;
} dh_key_dev_mem_t;

#ifndef VIRTIO_C2X0
int test_dh_op(struct pkc_request *req,
	       void (*cb) (struct pkc_request *, int32_t result));
#endif

#endif
