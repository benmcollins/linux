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

#ifndef __PKC_DESC_H__
#define __PKC_DESC_H__

#define RSA_PRIV_KEY_FRM_1     0
#define RSA_PRIV_KEY_FRM_2     1
#define RSA_PRIV_KEY_FRM_3     2

struct rsa_pub_desc_s {
	uint32_t desc_hdr;
	uint32_t sgf_flg;
	dev_dma_addr_t f_dma;
	dev_dma_addr_t g_dma;
	dev_dma_addr_t n_dma;
	dev_dma_addr_t e_dma;
	uint32_t msg_len;
	uint32_t op;
} __packed;

struct rsa_priv_frm1_desc_s {
	uint32_t desc_hdr;
	uint32_t sgf_flg;
	dev_dma_addr_t g_dma;
	dev_dma_addr_t f_dma;
	dev_dma_addr_t n_dma;
	dev_dma_addr_t d_dma;
	uint32_t op;
} __packed;

struct rsa_priv_frm2_desc_s {
	uint32_t desc_hdr;
	uint32_t sgf_flg;
	dev_dma_addr_t g_dma;
	dev_dma_addr_t f_dma;
	dev_dma_addr_t d_dma;
	dev_dma_addr_t p_dma;
	dev_dma_addr_t q_dma;
	dev_dma_addr_t tmp1_dma;
	dev_dma_addr_t tmp2_dma;
	uint32_t p_q_len;
	uint32_t op;
} __packed;

struct rsa_priv_frm3_desc_s {
	uint32_t desc_hdr;
	uint32_t sgf_flg;
	dev_dma_addr_t g_dma;
	dev_dma_addr_t f_dma;
	dev_dma_addr_t c_dma;
	dev_dma_addr_t p_dma;
	dev_dma_addr_t q_dma;
	dev_dma_addr_t dp_dma;
	dev_dma_addr_t dq_dma;
	dev_dma_addr_t tmp1_dma;
	dev_dma_addr_t tmp2_dma;
	uint32_t p_q_len;
	uint32_t op;
} __packed;

struct dsa_sign_desc_s {
	uint32_t desc_hdr;
	uint32_t sgf_ln;
	dev_dma_addr_t q_dma;
	dev_dma_addr_t r_dma;
	dev_dma_addr_t g_dma;
	dev_dma_addr_t s_dma;
	dev_dma_addr_t f_dma;
	dev_dma_addr_t c_dma;
	dev_dma_addr_t d_dma;
	uint32_t op[12];
} __packed;

struct dsa_verify_desc_s {
	uint32_t desc_hdr;
	uint32_t sgf_ln;
	dev_dma_addr_t q_dma;
	dev_dma_addr_t r_dma;
	dev_dma_addr_t g_dma;
	dev_dma_addr_t w_dma;
	dev_dma_addr_t f_dma;
	dev_dma_addr_t c_dma;
	dev_dma_addr_t d_dma;
	dev_dma_addr_t tmp_dma;
	uint32_t op;
} __packed;

struct dsa_keygen_desc_s {
	uint32_t desc_hdr;
	uint32_t sgf_ln;
	dev_dma_addr_t q_dma;
	dev_dma_addr_t r_dma;
	dev_dma_addr_t g_dma;
	dev_dma_addr_t s_dma;
	dev_dma_addr_t w_dma;
	uint32_t op;
} __packed;

struct ecdsa_sign_desc_s {
	uint32_t desc_hdr;
	uint32_t sgf_ln;
	dev_dma_addr_t q_dma;
	dev_dma_addr_t r_dma;
	dev_dma_addr_t g_dma;
	dev_dma_addr_t s_dma;
	dev_dma_addr_t f_dma;
	dev_dma_addr_t c_dma;
	dev_dma_addr_t d_dma;
	dev_dma_addr_t ab_dma;
	uint32_t op[12];
} __packed;

struct ecdsa_verify_desc_s {
	uint32_t desc_hdr;
	uint32_t sgf_ln;
	dev_dma_addr_t q_dma;
	dev_dma_addr_t r_dma;
	dev_dma_addr_t g_dma;
	dev_dma_addr_t w_dma;
	dev_dma_addr_t f_dma;
	dev_dma_addr_t c_dma;
	dev_dma_addr_t d_dma;
	dev_dma_addr_t tmp_dma;
	dev_dma_addr_t ab_dma;
	uint32_t op;
} __packed;

struct ecdsa_keygen_desc_s {
	uint32_t desc_hdr;
	uint32_t sgf_ln;
	dev_dma_addr_t q_dma;
	dev_dma_addr_t r_dma;
	dev_dma_addr_t g_dma;
	dev_dma_addr_t s_dma;
	dev_dma_addr_t w_dma;
	dev_dma_addr_t ab_dma;
	uint32_t op;
} __packed;

struct dh_key_desc_s {
	uint32_t desc_hdr;
	uint32_t sgf_ln;
	dev_dma_addr_t q_dma;
	dev_dma_addr_t r_dma;
	dev_dma_addr_t w_dma;
	dev_dma_addr_t s_dma;
	dev_dma_addr_t z_dma;
	uint32_t op;
} __packed;

struct dh_keygen_desc_s {
    uint32_t    desc_hdr;
    uint32_t sgf_ln;
    dev_dma_addr_t q_dma;
    dev_dma_addr_t r_dma;
    dev_dma_addr_t g_dma;
    dev_dma_addr_t prvkey_dma;
    dev_dma_addr_t pubkey_dma;
    uint32_t    op;
} __packed;

struct ecdh_key_desc_s {
	uint32_t desc_hdr;
	uint32_t sgf_ln;
	dev_dma_addr_t q_dma;
	dev_dma_addr_t r_dma;
	dev_dma_addr_t w_dma;
	dev_dma_addr_t s_dma;
	dev_dma_addr_t z_dma;
	dev_dma_addr_t ab_dma;
	uint32_t op;
} __packed;

struct ecdh_keygen_desc_s {
    uint32_t    desc_hdr;
    uint32_t sgf_ln;
    dev_dma_addr_t q_dma;
    dev_dma_addr_t r_dma;
    dev_dma_addr_t g_dma;
    dev_dma_addr_t prvkey_dma;
    dev_dma_addr_t pubkey_dma;
    dev_dma_addr_t ab_dma;
    uint32_t    op;
} __packed;

#endif
