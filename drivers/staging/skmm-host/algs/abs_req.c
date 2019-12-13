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
#include "common.h"
#include "fsl_c2x0_crypto_layer.h"
#include "fsl_c2x0_driver.h"
#include "algs.h"
#include "pkc_desc.h"
#include "desc.h"
#include "memmgr.h"
#include "abs_req.h"

enum {
	SKMM_RSA_KEYGEN,
	SKMM_RSA_PUB_OP,
	SKMM_RSA_PRV_OP_1K,
	SKMM_RSA_PRV_OP_2K,
	SKMM_RSA_PRV_OP_4K,
	SKMM_DSA_VERIFY,
	SKMM_DSA_SIGN_512,
	SKMM_DSA_SIGN_1K,
	SKMM_DSA_SIGN_2K,
	SKMM_DSA_SIGN_4K,
	SKMM_DSA_SIGN_VERIFY,
	SKMM_DSA_KEYGEN,
	SKMM_ECDSA_KEYGEN,
	SKMM_DH_KEYGEN,
	SKMM_ECDH,
	SKMM_ECDSA_VERIFY,
	SKMM_ECDSA_SIGN,
	SKMM_ECP_SIGN_256,
	SKMM_ECP_VERIFY_256,
	SKMM_ECP_SIGN_384,
	SKMM_ECP_VERIFY_384,
	SKMM_ECP_SIGN_521,
	SKMM_ECP_VERIFY_521,
	SKMM_ECPBN_SIGN_283,
	SKMM_ECPBN_VERIFY_283,
	SKMM_ECPBN_SIGN_409,
	SKMM_ECPBN_VERIFY_409,
	SKMM_ECPBN_SIGN_571,
	SKMM_ECPBN_VERIFY_571,
	SKMM_DH_1K,
	SKMM_DH_2K,
	SKMM_DH_4K,
	SKMM_ECDH_KEYGEN_P256,
	SKMM_ECDH_KEYGEN_P384,
	SKMM_ECDH_KEYGEN_P521,
	SKMM_ECDH_KEYGEN_B283,
	SKMM_ECDH_KEYGEN_B409,
	SKMM_ECDH_KEYGEN_B571
};

dev_dma_addr_t get_abs_req_p_addr(crypto_mem_info_t *c_mem)
{
	fsl_crypto_dev_t *dev = c_mem->dev;
	unsigned long offset;

	offset = (unsigned long)c_mem->abs_req -
		(unsigned long)dev->ip_pool.drv_map_pool.v_addr;
	return (dev_dma_addr_t)(dev->ip_pool.fw_pool.dev_p_addr + offset);
}

void *get_abs_req_v_addr(crypto_mem_info_t *c_mem)
{
	fsl_crypto_dev_t *dev = c_mem->dev;
	unsigned long offset;

	offset = (unsigned long)c_mem->abs_req -
		(unsigned long)dev->ip_pool.drv_map_pool.v_addr;
	return (void *)(dev->ip_pool.fw_pool.host_map_v_addr + offset);
}

static int get_abs_req_type(struct pkc_request *req, void *buffer)
{
	struct rsa_priv_frm3_req_s *priv3_req;
	struct dsa_sign_req_s *dsa_sign;
	struct dh_key_req_s *dh_key;

	int type = req->type;

	print_debug("req->type : %d\n", type);
	switch (type) {
	case RSA_KEYGEN:
		return SKMM_RSA_KEYGEN;
	case RSA_PUB:
		return SKMM_RSA_PUB_OP;
	case RSA_PRIV_FORM1:
	case RSA_PRIV_FORM2:
		break;
	case RSA_PRIV_FORM3:
		priv3_req = &req->req_u.rsa_priv_f3;

		if (priv3_req->q_len == 64)
			return SKMM_RSA_PRV_OP_1K;
		else if (priv3_req->q_len == 128)
			return SKMM_RSA_PRV_OP_2K;
		else if (priv3_req->q_len == 256)
			return SKMM_RSA_PRV_OP_4K;
		else {
			print_error("Invalid key size %d\n",
					priv3_req->q_len);
			return -EINVAL;
		}
	case DSA_VERIFY:
		return SKMM_DSA_VERIFY;
	case ECDSA_VERIFY:
		return SKMM_ECDSA_VERIFY;
	case DSA_SIGN:
		dsa_sign = &req->req_u.dsa_sign;

		if (dsa_sign->q_len == 64)
			return SKMM_DSA_SIGN_512;
		else if (dsa_sign->q_len == 128)
			return SKMM_DSA_SIGN_1K;
		else if (dsa_sign->q_len == 256)
			return SKMM_DSA_SIGN_2K;
		else if (dsa_sign->q_len == 512)
			return SKMM_DSA_SIGN_4K;
		else {
			print_error("Invalid key size %d\n",
					dsa_sign->q_len);
			return -EINVAL;
		}
	case ECDSA_SIGN:
		return SKMM_ECDSA_SIGN;
	case DH_COMPUTE_KEY:
		dh_key = &req->req_u.dh_req;

		print_debug("key size is %d\n", dh_key->z_len);
		if (dh_key->z_len == 128)
			return SKMM_DH_1K;
		else if (dh_key->z_len == 256)
			return SKMM_DH_2K;
		else if (dh_key->z_len == 512)
			return SKMM_DH_4K;
		else {
			print_error("Invalid key size %d\n",
					dh_key->z_len);
			return -EINVAL;
		}
	case ECDH_COMPUTE_KEY:
		return SKMM_ECDH;
	case DLC_KEYGEN:
		return SKMM_DSA_KEYGEN;
	}

	return 0;
}

void constr_abs_req(crypto_mem_info_t *c_mem, struct pkc_request *req)
{
	rsa_keygen_op_buffers_t *rsa_keygen_buf;
	rsa_pub_op_buffers_t *rsa_pub_buf;
	rsa_priv3_op_buffers_t *rsa_priv3_buf;
	struct rsa_keygen *rsa_keygen;
	struct rsa_pub *rsa_pub;
	struct rsa_priv3 *rsa_priv3;

	dsa_sign_buffers_t *dsa_sign_buf;
	dsa_verify_buffers_t *dsa_verify_buf;
	struct dsa_sign *dsa_sign;
	struct dsa_verify *dsa_verify;

	keygen_buffers_t *keygen_buf;
	struct keygen *keygen;

	dh_key_buffers_t *dh_key_buf;
	struct dh_key *dh_key;

	int abs_req_type, type = req->type;
#ifndef USE_HOST_DMA
	struct abs_req *abs_req = get_abs_req_v_addr(c_mem);
#else
	struct abs_req *abs_req = c_mem->abs_req;
#endif

	print_debug("abs_req addr is %p\n", abs_req);

	abs_req_type = get_abs_req_type(req, c_mem->buffers);
	print_debug("type is %d\n", abs_req_type);

	ASSIGN32(abs_req->req_type, abs_req_type);

	switch (type) {
	case RSA_KEYGEN:
		rsa_keygen = &abs_req->req_data.rsa_keygen;
		rsa_keygen_buf = (rsa_keygen_op_buffers_t *)c_mem->buffers;

		ASSIGN64(rsa_keygen->n,
				rsa_keygen_buf->n_buff.dev_buffer.d_p_addr);
		ASSIGN32(rsa_keygen->n_len, rsa_keygen_buf->n_buff.len);
		break;
	case RSA_PUB:
		rsa_pub = &abs_req->req_data.rsa_pub;
		rsa_pub_buf = (rsa_pub_op_buffers_t *)c_mem->buffers;

		ASSIGN64(rsa_pub->n, rsa_pub_buf->n_buff.dev_buffer.d_p_addr);
		ASSIGN32(rsa_pub->n_len, rsa_pub_buf->n_buff.len);

		ASSIGN64(rsa_pub->e, rsa_pub_buf->e_buff.dev_buffer.d_p_addr);
		ASSIGN32(rsa_pub->e_len, rsa_pub_buf->e_buff.len);

		ASSIGN64(rsa_pub->f, rsa_pub_buf->f_buff.dev_buffer.d_p_addr);
		ASSIGN32(rsa_pub->f_len, rsa_pub_buf->f_buff.len);

		ASSIGN64(rsa_pub->g, rsa_pub_buf->g_buff.dev_buffer.d_p_addr);

		break;
	case RSA_PRIV_FORM3:
		rsa_priv3 = &abs_req->req_data.rsa_priv3;
		rsa_priv3_buf = (rsa_priv3_op_buffers_t *)c_mem->buffers;

		ASSIGN64(rsa_priv3->f,
				rsa_priv3_buf->f_buff.dev_buffer.d_p_addr);
		ASSIGN32(rsa_priv3->n_len, rsa_priv3_buf->f_buff.len);

		ASSIGN64(rsa_priv3->g,
				rsa_priv3_buf->g_buff.dev_buffer.d_p_addr);

		break;

	case DSA_SIGN:
	case ECDSA_SIGN:
		dsa_sign = &abs_req->req_data.dsa_sign;
		dsa_sign_buf = (dsa_sign_buffers_t *)c_mem->buffers;

		ASSIGN64(dsa_sign->q, dsa_sign_buf->q_buff.dev_buffer.d_p_addr);
		ASSIGN64(dsa_sign->r, dsa_sign_buf->r_buff.dev_buffer.d_p_addr);
		ASSIGN64(dsa_sign->g, dsa_sign_buf->g_buff.dev_buffer.d_p_addr);
		ASSIGN64(dsa_sign->f, dsa_sign_buf->m_buff.dev_buffer.d_p_addr);
		ASSIGN64(dsa_sign->c, dsa_sign_buf->c_buff.dev_buffer.d_p_addr);
		ASSIGN64(dsa_sign->d, dsa_sign_buf->d_buff.dev_buffer.d_p_addr);

		ASSIGN32(dsa_sign->q_len, dsa_sign_buf->q_buff.len);
		ASSIGN32(dsa_sign->r_len, dsa_sign_buf->r_buff.len);

		if (type == ECDSA_SIGN)
			ASSIGN64(dsa_sign->ab,
				dsa_sign_buf->ab_buff.dev_buffer.d_p_addr);
		break;
	case DSA_VERIFY:
	case ECDSA_VERIFY:
		dsa_verify = &abs_req->req_data.dsa_verify;
		dsa_verify_buf = (dsa_verify_buffers_t *)c_mem->buffers;

		ASSIGN64(dsa_verify->q,
				dsa_verify_buf->q_buff.dev_buffer.d_p_addr);
		ASSIGN64(dsa_verify->r,
				dsa_verify_buf->r_buff.dev_buffer.d_p_addr);
		ASSIGN64(dsa_verify->g,
				dsa_verify_buf->g_buff.dev_buffer.d_p_addr);
		ASSIGN64(dsa_verify->pub_key,
			dsa_verify_buf->pub_key_buff.dev_buffer.d_p_addr);
		ASSIGN64(dsa_verify->m,
				dsa_verify_buf->m_buff.dev_buffer.d_p_addr);
		ASSIGN64(dsa_verify->c,
				dsa_verify_buf->c_buff.dev_buffer.d_p_addr);
		ASSIGN64(dsa_verify->d,
				dsa_verify_buf->d_buff.dev_buffer.d_p_addr);
		if (type == ECDSA_VERIFY)
			ASSIGN64(dsa_verify->ab,
				dsa_verify_buf->ab_buff.dev_buffer.d_p_addr);
		ASSIGN32(dsa_verify->q_len, dsa_verify_buf->q_buff.len);
		ASSIGN32(dsa_verify->r_len, dsa_verify_buf->r_buff.len);

		break;
	case DLC_KEYGEN:
		keygen = &abs_req->req_data.keygen;
		keygen_buf = (keygen_buffers_t *)c_mem->buffers;

		ASSIGN64(keygen->q, keygen_buf->q_buff.dev_buffer.d_p_addr);
		ASSIGN64(keygen->r, keygen_buf->r_buff.dev_buffer.d_p_addr);
		ASSIGN64(keygen->g, keygen_buf->g_buff.dev_buffer.d_p_addr);
		ASSIGN64(keygen->pub_key,
				keygen_buf->pubkey_buff.dev_buffer.d_p_addr);
		ASSIGN32(keygen->q_len, keygen_buf->q_buff.len);
		ASSIGN32(keygen->r_len, keygen_buf->r_buff.len);

		break;
	case DH_COMPUTE_KEY:
	case ECDH_COMPUTE_KEY:
		dh_key = &abs_req->req_data.dh_key;
		dh_key_buf = (dh_key_buffers_t *)c_mem->buffers;

		ASSIGN64(dh_key->w, dh_key_buf->w_buff.dev_buffer.d_p_addr);
		ASSIGN64(dh_key->z, dh_key_buf->z_buff.dev_buffer.d_p_addr);
		if (type == ECDH_COMPUTE_KEY)
			ASSIGN64(dh_key->ab,
				dh_key_buf->ab_buff.dev_buffer.d_p_addr);
		break;
	}

	print_debug("abstract request offloaded\n");
}
