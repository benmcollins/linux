/* Copyright 2013 Freescale Semiconductor, Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
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

#include <linux/completion.h>
#include "common.h"
#include "fsl_c2x0_crypto_layer.h"
#include "fsl_c2x0_driver.h"
#include "algs.h"
#include "pkc_desc.h"
#include "desc.h"
#include "memmgr.h"
#include "desc_cnstr.h"

#include "test.h"
#include "dsa_test.h"


static u32 priv_key_len_2048=sizeof(R_2048);
int dsa_keygen_sign_test(struct pkc_request *ireq, struct pkc_request *);
int dsa_keygen_verify_test(struct pkc_request *ireq, struct pkc_request *ireq1,
			   struct pkc_request *);

typedef void (*cb) (struct pkc_request *req, int32_t sec_result);
/*
static DECLARE_COMPLETION(jobs_done);
static int count;
*/
atomic_t dsa_enq_count;
atomic_t dsa_deq_count;
struct pkc_request g_dsaverifyreq_1k;
struct pkc_request g_dsasignreq_1k;
struct pkc_request g_dsaverifyreq_2k;
struct pkc_request g_dsasignreq_2k;
struct pkc_request g_dsaverifyreq_4k;
struct pkc_request g_dsasignreq_4k;

struct completion serialize_keygen;

void dsa_done(struct pkc_request *req, int32_t sec_result)
{
	common_dec_count();
}

void dsa_keygen_done(struct pkc_request *req, int32_t sec_result)
{
	kfree(req->req_u.keygen.q);
	kfree(req->req_u.keygen.r);
	kfree(req->req_u.keygen.g);

	print_debug(KERN_ERR "%s( ): Req :%p, result: %x \n", __func__,
		    req, sec_result);
	complete(&serialize_keygen);
}

void dsa_sign_verify_sign_done(struct pkc_request *req, int32_t sec_result)
{
	dsa_sign_verify_verify_test(req);
	kfree(req->req_u.dsa_sign.q);
	kfree(req->req_u.dsa_sign.r);
	kfree(req->req_u.dsa_sign.g);
	kfree(req->req_u.dsa_sign.m);
	kfree(req->req_u.dsa_sign.c);
	kfree(req->req_u.dsa_sign.d);
	kfree(req);
}

void dsa_sign_verify_verify_done(struct pkc_request *req, int32_t sec_result)
{
	kfree(req->req_u.dsa_verify.q);
	kfree(req->req_u.dsa_verify.r);
	kfree(req->req_u.dsa_verify.g);
	kfree(req->req_u.dsa_verify.pub_key);
	kfree(req->req_u.dsa_verify.m);
	kfree(req->req_u.dsa_verify.c);
	kfree(req->req_u.dsa_verify.d);
	kfree(req);
	common_dec_count();
}

void init_dsa_verify_test_1k(void)
{
	struct dsa_verify_req_s *dsa_verify;
	u32 len;
	void *buf;

	len = ALIGN_LEN_TO_DMA(q_len) + ALIGN_LEN_TO_DMA(r_len) +
		ALIGN_LEN_TO_DMA(g_len) + ALIGN_LEN_TO_DMA(pub_key_len) +
		ALIGN_LEN_TO_DMA(m_len) + ALIGN_LEN_TO_DMA(d) * 2;

	buf = kzalloc(len, GFP_DMA);
	if (!buf) {
		print_error("NO MEM\n");
		return;
	}

	dsa_verify = &g_dsaverifyreq_1k.req_u.dsa_verify;
	g_dsaverifyreq_1k.type = DSA_VERIFY;

	dsa_verify->q = buf;
	memcpy(dsa_verify->q, Q_1024, q_len);
	dsa_verify->q_len = (q_len);
	buf += ALIGN_LEN_TO_DMA(q_len);

	dsa_verify->r = buf;
	memcpy(dsa_verify->r, R_1024, r_len);
	dsa_verify->r_len = (r_len);
	buf += ALIGN_LEN_TO_DMA(r_len);

	dsa_verify->g = buf;
	memcpy(dsa_verify->g, G_1024, g_len);
	dsa_verify->g_len = (g_len);
	buf += ALIGN_LEN_TO_DMA(g_len);

	dsa_verify->pub_key = buf;
	memcpy(dsa_verify->pub_key, PUB_KEY_1024, pub_key_len);
	dsa_verify->pub_key_len = (pub_key_len);
	buf += ALIGN_LEN_TO_DMA(pub_key_len);

	dsa_verify->m = buf;
	memcpy(dsa_verify->m, M_1024, m_len);
	dsa_verify->m_len = (m_len);
	buf += ALIGN_LEN_TO_DMA(m_len);

	dsa_verify->c = buf;
	memcpy(dsa_verify->c, C, d);
	buf += ALIGN_LEN_TO_DMA(d);

	dsa_verify->d = buf;
	memcpy(dsa_verify->d, D, d);
	dsa_verify->d_len = d;
}

void init_dsa_sign_test_1k(void)
{
	struct dsa_sign_req_s *dsa_sign = &g_dsasignreq_1k.req_u.dsa_sign;
	void *buf;
	u32 len;

	g_dsasignreq_1k.type = DSA_SIGN;

	len = ALIGN_LEN_TO_DMA(q_len) + ALIGN_LEN_TO_DMA(r_len) +
		ALIGN_LEN_TO_DMA(g_len) + ALIGN_LEN_TO_DMA(m_len) +
		ALIGN_LEN_TO_DMA(d_len) * 2;

	buf = kzalloc(len, GFP_DMA);
	if (!buf) {
		print_error("NO MEM\n");
		return;
	}

	dsa_sign->q = buf;
	memcpy(dsa_sign->q, Q_1024, q_len);
	dsa_sign->q_len = (q_len);
	buf += ALIGN_LEN_TO_DMA(q_len);

	dsa_sign->r = buf;
	memcpy(dsa_sign->r, R_1024, r_len);
	dsa_sign->r_len = (r_len);
	buf += ALIGN_LEN_TO_DMA(r_len);

	dsa_sign->g = buf;
	memcpy(dsa_sign->g, G_1024, g_len);
	dsa_sign->g_len = (g_len);
	buf += ALIGN_LEN_TO_DMA(g_len);

	dsa_sign->m = buf;
	memcpy(dsa_sign->m, M_1024, m_len);
	dsa_sign->m_len = (m_len);
	buf += ALIGN_LEN_TO_DMA(m_len);

	dsa_sign->c = buf;
	buf += ALIGN_LEN_TO_DMA(r_len);
	dsa_sign->d = buf;
	dsa_sign->d_len = r_len;
}

void init_dsa_verify_test_2k(void)
{
	struct dsa_verify_req_s *dsa_verify;
	void *buf;
	u32 len;

	len = ALIGN_LEN_TO_DMA(q_len_2048) + ALIGN_LEN_TO_DMA(r_len_2048) +
		ALIGN_LEN_TO_DMA(g_len_2048) +
		ALIGN_LEN_TO_DMA(pub_key_len_2048) +
		ALIGN_LEN_TO_DMA(m_len_2048) +
		ALIGN_LEN_TO_DMA(d_2048) * 2;

	buf = kzalloc(len, GFP_DMA);
	if (!buf) {
		print_error("NO MEM\n");
		return;
	}

	dsa_verify = &g_dsaverifyreq_2k.req_u.dsa_verify;
	g_dsaverifyreq_2k.type = DSA_VERIFY;

	dsa_verify->q = buf;
	memcpy(dsa_verify->q, Q_2048, q_len_2048);
	dsa_verify->q_len = (q_len_2048);
	buf += ALIGN_LEN_TO_DMA(q_len_2048);

	dsa_verify->r = buf;
	memcpy(dsa_verify->r, R_2048, r_len_2048);
	dsa_verify->r_len = (r_len_2048);
	buf += ALIGN_LEN_TO_DMA(r_len_2048);

	dsa_verify->g = buf;
	memcpy(dsa_verify->g, G_2048, g_len_2048);
	dsa_verify->g_len = (g_len_2048);
	buf += ALIGN_LEN_TO_DMA(g_len_2048);

	dsa_verify->pub_key = buf;
	memcpy(dsa_verify->pub_key, PUB_KEY_2048, pub_key_len_2048);
	dsa_verify->pub_key_len = (pub_key_len_2048);
	buf += ALIGN_LEN_TO_DMA(pub_key_len_2048);

	dsa_verify->m = buf;
	memcpy(dsa_verify->m, M_2048, m_len_2048);
	dsa_verify->m_len = (m_len_2048);
	buf += ALIGN_LEN_TO_DMA(m_len_2048);

	dsa_verify->c = buf;
	memcpy(dsa_verify->c, C_2048, d_2048);
	buf += ALIGN_LEN_TO_DMA(d_2048);

	dsa_verify->d = buf;
	memcpy(dsa_verify->d, D_2048, d_2048);
	dsa_verify->d_len = d_2048;
}

void init_dsa_sign_test_2k(void)
{
	struct dsa_sign_req_s *dsa_sign = &g_dsasignreq_2k.req_u.dsa_sign;
	void *buf;
	u32 len;

	len = ALIGN_LEN_TO_DMA(q_len_2048) + ALIGN_LEN_TO_DMA(r_len_2048) +
		ALIGN_LEN_TO_DMA(g_len_2048) + ALIGN_LEN_TO_DMA(m_len_2048) +
		ALIGN_LEN_TO_DMA(d_len_2048) * 2;

	buf = kzalloc(len, GFP_DMA);
	if (!buf) {
		print_error("NO MEM\n");
		return;
	}

	g_dsasignreq_2k.type = DSA_SIGN;

	dsa_sign->q = buf;
	memcpy(dsa_sign->q, Q_2048, q_len_2048);
	dsa_sign->q_len = (q_len_2048);
	buf += ALIGN_LEN_TO_DMA(q_len_2048);

	dsa_sign->r = buf;
	memcpy(dsa_sign->r, R_2048, r_len_2048);
	dsa_sign->r_len = (r_len_2048);
	buf += ALIGN_LEN_TO_DMA(r_len_2048);

	dsa_sign->g = buf;
	memcpy(dsa_sign->g, G_2048, g_len_2048);
	dsa_sign->g_len = (g_len_2048);
	buf += ALIGN_LEN_TO_DMA(g_len_2048);

	dsa_sign->m = buf;
	memcpy(dsa_sign->m, M_2048, m_len_2048);
	dsa_sign->m_len = (m_len_2048);
	buf += ALIGN_LEN_TO_DMA(m_len_2048);

	dsa_sign->c = buf;
	buf += ALIGN_LEN_TO_DMA(r_len_2048);
	dsa_sign->d = buf;
	dsa_sign->d_len = r_len_2048;
}

void init_dsa_verify_test_4k(void)
{
	struct dsa_verify_req_s *dsa_verify;
	void *buf;
	u32 len;

	len = ALIGN_LEN_TO_DMA(q_len_4096) + ALIGN_LEN_TO_DMA(r_len_4096) +
		ALIGN_LEN_TO_DMA(g_len_4096) +
		ALIGN_LEN_TO_DMA(pub_key_len_4096) +
		ALIGN_LEN_TO_DMA(m_len_4096) +
		ALIGN_LEN_TO_DMA(d_4096) * 2;

	buf = kzalloc(len, GFP_DMA);
	if (!buf) {
		print_error("NO MEM\n");
		return;
	}

	dsa_verify = &g_dsaverifyreq_4k.req_u.dsa_verify;
	g_dsaverifyreq_4k.type = DSA_VERIFY;

	dsa_verify->q = buf;
	memcpy(dsa_verify->q, Q_4096, q_len_4096);
	dsa_verify->q_len = (q_len_4096);
	buf += ALIGN_LEN_TO_DMA(q_len_4096);

	dsa_verify->r = buf;
	memcpy(dsa_verify->r, R_4096, r_len_4096);
	dsa_verify->r_len = (r_len_4096);
	buf += ALIGN_LEN_TO_DMA(r_len_4096);

	dsa_verify->g = buf;
	memcpy(dsa_verify->g, G_4096, g_len_4096);
	dsa_verify->g_len = (g_len_4096);
	buf += ALIGN_LEN_TO_DMA(g_len_4096);

	dsa_verify->pub_key = buf;
	memcpy(dsa_verify->pub_key, PUB_KEY_4096, pub_key_len_4096);
	dsa_verify->pub_key_len = (pub_key_len_4096);
	buf += ALIGN_LEN_TO_DMA(pub_key_len_4096);

	dsa_verify->m = buf;
	memcpy(dsa_verify->m, M_4096, m_len_4096);
	dsa_verify->m_len = (m_len_4096);
	buf += ALIGN_LEN_TO_DMA(m_len_4096);

	dsa_verify->c = buf;
	memcpy(dsa_verify->c, C_4096, d_4096);
	buf += ALIGN_LEN_TO_DMA(d_4096);

	dsa_verify->d = buf;
	memcpy(dsa_verify->d, D_4096, d_4096);
	dsa_verify->d_len = d_4096;
}

void init_dsa_sign_test_4k(void)
{
	struct dsa_sign_req_s *dsa_sign = &g_dsasignreq_4k.req_u.dsa_sign;

	void *buf;
	u32 len;

	len = ALIGN_LEN_TO_DMA(q_len_4096) + ALIGN_LEN_TO_DMA(r_len_4096) +
		ALIGN_LEN_TO_DMA(g_len_4096) + ALIGN_LEN_TO_DMA(m_len_4096) +
		ALIGN_LEN_TO_DMA(d_len_4096) * 2;

	buf = kzalloc(len, GFP_DMA);
	if (!buf) {
		print_error("NO MEM\n");
		return;
	}

	g_dsasignreq_4k.type = DSA_SIGN;

	dsa_sign->q = buf;
	memcpy(dsa_sign->q, Q_4096, q_len_4096);
	dsa_sign->q_len = (q_len_4096);
	buf += ALIGN_LEN_TO_DMA(q_len_4096);

	dsa_sign->r = buf;
	memcpy(dsa_sign->r, R_4096, r_len_4096);
	dsa_sign->r_len = (r_len_4096);
	buf += ALIGN_LEN_TO_DMA(r_len_4096);

	dsa_sign->g = buf;
	memcpy(dsa_sign->g, G_4096, g_len_4096);
	dsa_sign->g_len = (g_len_4096);
	buf += ALIGN_LEN_TO_DMA(g_len_4096);

	dsa_sign->m = buf;
	memcpy(dsa_sign->m, M_4096, m_len_4096);
	dsa_sign->m_len = (m_len_4096);
	buf += ALIGN_LEN_TO_DMA(m_len_4096);

	dsa_sign->c = buf;
	buf += ALIGN_LEN_TO_DMA(r_len_4096);
	dsa_sign->d = buf;
	dsa_sign->d_len = r_len_4096;
}

void cleanup_dsa_test(void)
{
	struct dsa_verify_req_s *dsa_verify_1k;
	struct dsa_verify_req_s *dsa_verify_2k;
	struct dsa_verify_req_s *dsa_verify_4k;

	dsa_verify_1k = &g_dsaverifyreq_1k.req_u.dsa_verify;
	dsa_verify_2k = &g_dsaverifyreq_2k.req_u.dsa_verify;
	dsa_verify_4k = &g_dsaverifyreq_4k.req_u.dsa_verify;


	kfree(g_dsasignreq_1k.req_u.dsa_sign.q);
	kfree(g_dsasignreq_2k.req_u.dsa_sign.q);
	kfree(g_dsasignreq_4k.req_u.dsa_sign.q);

	kfree(dsa_verify_1k->q);

	kfree(dsa_verify_2k->q);

	kfree(dsa_verify_4k->q);
}

int dsa_verify_test_1k(void)
{
	if (-1 == test_dsa_op(&g_dsaverifyreq_1k, dsa_done))
		return -1;

	return 0;
}

int dsa_sign_test_1k(void)
{
	if (-1 == test_dsa_op(&g_dsasignreq_1k, dsa_done))
		return -1;

	return 0;
}

int dsa_verify_test_2k(void)
{
	if (-1 == test_dsa_op(&g_dsaverifyreq_2k, dsa_done))
		return -1;

	return 0;
}

int dsa_sign_test_2k(void)
{
	if (-1 == test_dsa_op(&g_dsasignreq_2k, dsa_done))
		return -1;

	return 0;
}

int dsa_verify_test_4k(void)
{
	if (-1 == test_dsa_op(&g_dsaverifyreq_4k, dsa_done))
		return -1;

	return 0;
}

int dsa_sign_test_4k(void)
{
	if (-1 == test_dsa_op(&g_dsasignreq_4k, dsa_done))
		return -1;

	return 0;
}

int dsa_keygen_verify_test(struct pkc_request *genreq,
			   struct pkc_request *signreq, struct pkc_request *req)
{
	int ret = 0;

	print_debug(KERN_ERR
		    "%s( ): genReq: %p, signreq: %p, verify req: %p\n",
		    __func__, genreq, signreq, req);

	req->type = DSA_VERIFY;

	req->req_u.dsa_verify.q = kzalloc(q_len_2048, GFP_DMA);
	memcpy(req->req_u.dsa_verify.q, Q_2048, q_len_2048);
	req->req_u.dsa_verify.q_len = (q_len_2048);

	req->req_u.dsa_verify.r = kzalloc(r_len_2048, GFP_DMA);
	memcpy(req->req_u.dsa_verify.r, R_2048, r_len_2048);
	req->req_u.dsa_verify.r_len = (r_len_2048);

	req->req_u.dsa_verify.g = kzalloc(g_len_2048, GFP_DMA);
	memcpy(req->req_u.dsa_verify.g, G_2048, g_len_2048);
	req->req_u.dsa_verify.g_len = (g_len_2048);

	req->req_u.dsa_verify.pub_key = kzalloc(pub_key_len_2048, GFP_DMA);
	memcpy(req->req_u.dsa_verify.pub_key, genreq->req_u.keygen.pub_key,
	       pub_key_len_2048);
	req->req_u.dsa_verify.pub_key_len = (pub_key_len_2048);

	req->req_u.dsa_verify.m = kzalloc(m_len_2048, GFP_DMA);
	memcpy(req->req_u.dsa_verify.m, M_2048, m_len_2048);
	req->req_u.dsa_verify.m_len = (m_len_2048);

	req->req_u.dsa_verify.c = kzalloc(d_len_2048, GFP_DMA);
	if (!req->req_u.dsa_verify.c)
		goto error;
	memcpy(req->req_u.dsa_verify.c, signreq->req_u.dsa_sign.c, d_len_2048);

	req->req_u.dsa_verify.d = kzalloc(d_len_2048, GFP_DMA);
	if (!req->req_u.dsa_verify.d)
		goto error;
	memcpy(req->req_u.dsa_verify.d, signreq->req_u.dsa_sign.d, d_len_2048);
	req->req_u.dsa_verify.d_len = d_len_2048;

	ret = test_dsa_op(req, dsa_keygen_done);
	return ret;
error:
	return -1;
}

int dsa_keygen_sign_test(struct pkc_request *ireq, struct pkc_request *req)
{
	int ret = 0;
	print_debug(KERN_ERR "%s( ): genreq: %p req : %p\n", __func__,
		    ireq, req);

	req->type = DSA_SIGN;

	req->req_u.dsa_sign.q = kzalloc(q_len, GFP_DMA);
	memcpy(req->req_u.dsa_sign.q, Q_2048, q_len);
	req->req_u.dsa_sign.q_len = (q_len);

	req->req_u.dsa_sign.r = kzalloc(r_len, GFP_DMA);
	memcpy(req->req_u.dsa_sign.r, R_2048, r_len);
	req->req_u.dsa_sign.r_len = (r_len);

	req->req_u.dsa_sign.g = kzalloc(g_len, GFP_DMA);
	memcpy(req->req_u.dsa_sign.g, G_2048, g_len);
	req->req_u.dsa_sign.g_len = (g_len);

	req->req_u.dsa_sign.priv_key = kzalloc(priv_key_len, GFP_DMA);
	memcpy(req->req_u.dsa_sign.priv_key, ireq->req_u.keygen.priv_key,
	       priv_key_len);
	req->req_u.dsa_sign.priv_key_len = (priv_key_len);

	req->req_u.dsa_sign.m = kzalloc(m_len, GFP_DMA);
	memcpy(req->req_u.dsa_sign.m, M_2048, m_len);
	req->req_u.dsa_sign.m_len = (m_len);

	req->req_u.dsa_sign.c = kzalloc(d_len, GFP_DMA | GFP_DMA);
	if (!req->req_u.dsa_sign.c)
		goto error;

	req->req_u.dsa_sign.d = kzalloc(d_len, GFP_DMA | GFP_DMA);
	if (!req->req_u.dsa_sign.d)
		goto error;
	req->req_u.dsa_sign.d_len = d_len;

	ret = test_dsa_op(req, dsa_keygen_done);

	return ret;
error:
	return -1;
}

int dsa_keygen_test(void)
{
	int ret = 0;
	struct pkc_request *genreq =
	    kzalloc(sizeof(struct pkc_request), GFP_DMA);
	struct pkc_request *signreq =
	    kzalloc(sizeof(struct pkc_request), GFP_DMA);
	struct pkc_request *verifyreq =
	    kzalloc(sizeof(struct pkc_request), GFP_DMA);

	if (!genreq || !signreq || !verifyreq) {
		print_error(KERN_ERR "(%d) mem alloc failed.... \n", __LINE__);
		return -1;
	}

	init_completion(&serialize_keygen);

	print_debug(KERN_ERR "%s( ): pkc_request size: %lu req ptr: %p \n",
		    __func__, sizeof(struct pkc_request), genreq);

	genreq->type = DSA_KEYGEN;

	genreq->req_u.keygen.q = kzalloc(q_len_2048, GFP_DMA | GFP_DMA);
	memcpy(genreq->req_u.keygen.q, Q_2048, q_len_2048);
	genreq->req_u.keygen.q_len = (q_len_2048);

	genreq->req_u.keygen.r = kzalloc(r_len_2048, GFP_DMA | GFP_DMA);
	memcpy(genreq->req_u.keygen.r, R_2048, r_len_2048);
	genreq->req_u.keygen.r_len = (r_len_2048);

	genreq->req_u.keygen.g = kzalloc(g_len_2048, GFP_DMA | GFP_DMA);
	memcpy(genreq->req_u.keygen.g, G_2048, g_len_2048);
	genreq->req_u.keygen.g_len = (g_len_2048);

	genreq->req_u.keygen.pub_key =
	    kzalloc(pub_key_len_2048, GFP_DMA | GFP_DMA);
	if (!genreq->req_u.keygen.pub_key)
		goto error;
	genreq->req_u.keygen.pub_key_len = (pub_key_len_2048);

	genreq->req_u.keygen.priv_key =
	    kzalloc(priv_key_len_2048, GFP_DMA | GFP_DMA);
	if (!genreq->req_u.keygen.priv_key)
		goto error;
	genreq->req_u.keygen.priv_key_len = (priv_key_len_2048);

	ret = test_dsa_op(genreq, dsa_keygen_done);
	if (-1 == ret)
		goto error;

	wait_for_completion(&serialize_keygen);

	ret = dsa_keygen_sign_test(genreq, signreq);
	if (-1 == ret)
		goto error;
	wait_for_completion(&serialize_keygen);
	ret = dsa_keygen_verify_test(genreq, signreq, verifyreq);
	if (-1 == ret)
		goto error;
	wait_for_completion(&serialize_keygen);
	common_dec_count();

error:
	if (genreq) {
		if (genreq->req_u.keygen.pub_key)
			kfree(genreq->req_u.keygen.pub_key);
		if (genreq->req_u.keygen.priv_key)
			kfree(genreq->req_u.keygen.priv_key);
		kfree(genreq);
	}

	if (signreq) {
		if (signreq->req_u.dsa_sign.c)
			kfree(signreq->req_u.dsa_sign.c);
		if (signreq->req_u.dsa_sign.d)
			kfree(signreq->req_u.dsa_sign.d);
		if (signreq->req_u.dsa_sign.priv_key)
			kfree(signreq->req_u.dsa_sign.priv_key);

		kfree(signreq);
	}
	if (verifyreq) {
		if (verifyreq->req_u.dsa_verify.c)
			kfree(verifyreq->req_u.dsa_verify.c);
		if (verifyreq->req_u.dsa_verify.d)
			kfree(verifyreq->req_u.dsa_verify.d);
		if (verifyreq->req_u.dsa_verify.pub_key)
			kfree(verifyreq->req_u.dsa_verify.pub_key);

		kfree(verifyreq);
	}

	return ret;
}

int dsa_sign_verify_verify_test(struct pkc_request *ireq)
{
	int ret = 0;
	struct pkc_request *req =
	    kzalloc(sizeof(struct pkc_request), GFP_DMA);

	req->type = DSA_VERIFY;

	req->req_u.dsa_verify.q = kzalloc(q_len_4096, GFP_DMA);
	memcpy(req->req_u.dsa_verify.q, Q_4096, q_len_4096);
	req->req_u.dsa_verify.q_len = (q_len_4096);

	req->req_u.dsa_verify.r = kzalloc(r_len_4096, GFP_DMA);
	memcpy(req->req_u.dsa_verify.r, R_4096, r_len_4096);
	req->req_u.dsa_verify.r_len = (r_len_4096);

	req->req_u.dsa_verify.g = kzalloc(g_len_4096, GFP_DMA);
	memcpy(req->req_u.dsa_verify.g, G_4096, g_len_4096);
	req->req_u.dsa_verify.g_len = (g_len_4096);

	req->req_u.dsa_verify.pub_key = kzalloc(pub_key_len_4096, GFP_DMA);
	memcpy(req->req_u.dsa_verify.pub_key,  PUB_KEY_4096, pub_key_len_4096);
	req->req_u.dsa_verify.pub_key_len = (pub_key_len_4096);

	req->req_u.dsa_verify.m = kzalloc(m_len_4096, GFP_DMA);
	memcpy(req->req_u.dsa_verify.m, M_4096, m_len_4096);
	req->req_u.dsa_verify.m_len = (m_len_4096);

	req->req_u.dsa_verify.c = kzalloc(d_len_4096, GFP_DMA | GFP_DMA);
	memcpy(req->req_u.dsa_verify.c, ireq->req_u.dsa_sign.c, d_len_4096);

	req->req_u.dsa_verify.d = kzalloc(d_len_4096, GFP_DMA | GFP_DMA);
	req->req_u.dsa_verify.d_len = d_len_4096;
	memcpy(req->req_u.dsa_verify.d, ireq->req_u.dsa_sign.d, d_len_4096);

	ret = test_dsa_op(req, dsa_sign_verify_verify_done);

	if (-1 == ret) {
		atomic_dec(&total_enq_cnt);
		kfree(req->req_u.dsa_verify.q);
		kfree(req->req_u.dsa_verify.r);
		kfree(req->req_u.dsa_verify.g);
		kfree(req->req_u.dsa_verify.pub_key);
		kfree(req->req_u.dsa_verify.m);
		kfree(req->req_u.dsa_verify.c);
		kfree(req->req_u.dsa_verify.d);
		kfree(req);
	}

	return ret;
}

int dsa_sign_verify_test(void)
{
	struct pkc_request *req = kzalloc(sizeof(struct pkc_request), GFP_DMA);
	int ret = 0;

	req->type = DSA_SIGN;

	req->req_u.dsa_sign.q = kzalloc(q_len_4096, GFP_DMA);
	memcpy(req->req_u.dsa_sign.q, Q_4096, q_len_4096);
	req->req_u.dsa_sign.q_len = (q_len_4096);

	req->req_u.dsa_sign.r = kzalloc(r_len_4096, GFP_DMA);
	memcpy(req->req_u.dsa_sign.r, R_4096, r_len_4096);
	req->req_u.dsa_sign.r_len = (r_len_4096);

	req->req_u.dsa_sign.g = kzalloc(g_len_4096, GFP_DMA);
	memcpy(req->req_u.dsa_sign.g, G_4096, g_len_4096);
	req->req_u.dsa_sign.g_len = (g_len_4096);

	req->req_u.dsa_sign.m = kzalloc(m_len_4096, GFP_DMA);
	memcpy(req->req_u.dsa_sign.m, M_4096, m_len_4096);
	req->req_u.dsa_sign.m_len = (m_len_4096);

	req->req_u.dsa_sign.c = kzalloc(d_len_4096, GFP_DMA | GFP_DMA);

	req->req_u.dsa_sign.d = kzalloc(d_len_4096, GFP_DMA | GFP_DMA);
	req->req_u.dsa_sign.d_len = d_len_4096;

	ret = test_dsa_op(req, dsa_sign_verify_sign_done);

	if (-1 == ret) {
		kfree(req->req_u.dsa_sign.q);
		kfree(req->req_u.dsa_sign.r);
		kfree(req->req_u.dsa_sign.g);
		kfree(req->req_u.dsa_sign.m);
		kfree(req->req_u.dsa_sign.c);
		kfree(req->req_u.dsa_sign.d);
		kfree(req);
	}

	return ret;
}
