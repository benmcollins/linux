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

#include "common.h"
#include "fsl_c2x0_crypto_layer.h"
#include "fsl_c2x0_driver.h"
#include "algs.h"
#include "pkc_desc.h"
#include "desc.h"
#include "memmgr.h"

#include"test.h"
#include"ecpbn_test.h"

typedef void (*cb) (struct pkc_request *req, int32_t sec_result);

atomic_t ecpbn_enq_count;
atomic_t ecpbn_deq_count;

struct pkc_request g_ecpbnverifyreq_283; 
struct pkc_request g_ecpbnsignreq_283;
struct pkc_request g_ecpbnverifyreq_409; 
struct pkc_request g_ecpbnsignreq_409;
struct pkc_request g_ecpbnverifyreq_571; 
struct pkc_request g_ecpbnsignreq_571;

/*
static struct completion keygen_control_completion_var;
*/

void ecpbn_done(struct pkc_request *req, int32_t sec_result)
{
#ifndef SIMPLE_TEST_ENABLE
#ifndef PERF_TEST
	uint32_t i = 0;
#endif
	print_debug("ECDSA REQ TYPE [%d]\n", req->type);
	print_debug("RESULT : %d\n ", sec_result);
	switch (req->type) {
	case ECDSA_SIGN:
#ifndef PERF_TEST
		print_debug(" C/D\n");
		print_debug("Length : %d\n", req->req_u.dsa_sign.d_len);

		print_debug(" C\n");
		for (i = 0; i < req->req_u.dsa_sign.d_len; i++)
			print_debug("0x%0x,\t", req->req_u.dsa_sign.c[i]);

		print_debug(" D\n");
		for (i = 0; i < req->req_u.dsa_sign.d_len; i++)
			print_debug("0x%0x,\t", req->req_u.dsa_sign.d[i]);

#endif
		kfree(req->req_u.dsa_sign.c);
		kfree(req->req_u.dsa_sign.d);
		kfree(req);
		break;
	case ECDSA_VERIFY:
		kfree(req);
		break;
	default:
		break;
	}
	dec_count();
    uint32_t i = 0;
    printk("ECDSA REQ TYPE [%d]\n", req->type);
    printk("RESULT : %d\n ", sec_result);
    switch (req->type) {
        case ECDSA_SIGN:
            printk(" C/D\n");
            printk("Length : %d\n", req->req_u.dsa_sign.d_len);

            printk("\n C\n");
            for (i = 0; i < req->req_u.dsa_sign.d_len; i++)
                printk("0x%x, ", req->req_u.dsa_sign.c[i]);

            printk("\n D\n");
            for (i = 0; i < req->req_u.dsa_sign.d_len; i++)
                printk("0x%x, ", req->req_u.dsa_sign.d[i]);
            break;
	    case ECDSA_VERIFY:
            printk("Ecp Verify Done\n");
            break;
        default:
            printk("Wrong test\n");
            break;
    }
#endif
    common_dec_count();
}

void init_ecpbn_verify_test_283(void)
{
	g_ecpbnverifyreq_283.type = ECDSA_VERIFY;
    g_ecpbnverifyreq_283.curve_type = ECC_BINARY;

	g_ecpbnverifyreq_283.req_u.dsa_verify.q = Q_283;
	g_ecpbnverifyreq_283.req_u.dsa_verify.q_len = (q_283_len);

	g_ecpbnverifyreq_283.req_u.dsa_verify.r = R_283;
	g_ecpbnverifyreq_283.req_u.dsa_verify.r_len = (r_283_len);

	g_ecpbnverifyreq_283.req_u.dsa_verify.ab = AB_283;
	g_ecpbnverifyreq_283.req_u.dsa_verify.ab_len = (ab_283_len);

	g_ecpbnverifyreq_283.req_u.dsa_verify.g = G_283;
	g_ecpbnverifyreq_283.req_u.dsa_verify.g_len = (g_283_len);

	g_ecpbnverifyreq_283.req_u.dsa_verify.pub_key = PUB_KEY_EC_283;
	g_ecpbnverifyreq_283.req_u.dsa_verify.pub_key_len = (pub_key_ec_283_len);

	g_ecpbnverifyreq_283.req_u.dsa_verify.m = M_283;
	g_ecpbnverifyreq_283.req_u.dsa_verify.m_len = (m_283_len);

	g_ecpbnverifyreq_283.req_u.dsa_verify.c = C;

	g_ecpbnverifyreq_283.req_u.dsa_verify.d = D;
	g_ecpbnverifyreq_283.req_u.dsa_verify.d_len = d_len;
}

void init_ecpbn_sign_test_283(void)
{
	g_ecpbnsignreq_283.type = ECDSA_SIGN;
    g_ecpbnsignreq_283.curve_type = ECC_BINARY;

	g_ecpbnsignreq_283.req_u.dsa_sign.q = Q_283;
	g_ecpbnsignreq_283.req_u.dsa_sign.q_len = (q_283_len);

	g_ecpbnsignreq_283.req_u.dsa_sign.r = R_283;
	g_ecpbnsignreq_283.req_u.dsa_sign.r_len = (r_283_len);

	g_ecpbnsignreq_283.req_u.dsa_sign.ab = AB_283;
	g_ecpbnsignreq_283.req_u.dsa_sign.ab_len = (ab_283_len);

	g_ecpbnsignreq_283.req_u.dsa_sign.g = G_283;
	g_ecpbnsignreq_283.req_u.dsa_sign.g_len = (g_283_len);

	g_ecpbnsignreq_283.req_u.dsa_sign.priv_key = PRIV_KEY_EC_283;
	g_ecpbnsignreq_283.req_u.dsa_sign.priv_key_len = (priv_key_ec_283_len);

	g_ecpbnsignreq_283.req_u.dsa_sign.m = M_283;
	g_ecpbnsignreq_283.req_u.dsa_sign.m_len = (m_283_len);

	g_ecpbnsignreq_283.req_u.dsa_sign.c = kzalloc(r_283_len, GFP_KERNEL | GFP_DMA);

	g_ecpbnsignreq_283.req_u.dsa_sign.d = kzalloc(r_283_len, GFP_KERNEL | GFP_DMA);
	g_ecpbnsignreq_283.req_u.dsa_sign.d_len = r_283_len;
}

int ecpbn_verify_test_283(void)
{
	if (-1 == test_dsa_op(&g_ecpbnverifyreq_283, ecpbn_done))
		return -1;

	return 0;
}

int ecpbn_sign_test_283(void)
{
	if (-1 == test_dsa_op(&g_ecpbnsignreq_283, ecpbn_done))
		return -1;

	return 0;
}


void init_ecpbn_verify_test_409(void)
{
	g_ecpbnverifyreq_409.type = ECDSA_VERIFY;
    g_ecpbnverifyreq_409.curve_type = ECC_BINARY;

	g_ecpbnverifyreq_409.req_u.dsa_verify.q = Q_409;
	g_ecpbnverifyreq_409.req_u.dsa_verify.q_len = (q_409_len);

	g_ecpbnverifyreq_409.req_u.dsa_verify.r = R_409;
	g_ecpbnverifyreq_409.req_u.dsa_verify.r_len = (r_409_len);

	g_ecpbnverifyreq_409.req_u.dsa_verify.ab = AB_409;
	g_ecpbnverifyreq_409.req_u.dsa_verify.ab_len = (ab_409_len);

	g_ecpbnverifyreq_409.req_u.dsa_verify.g = G_409;
	g_ecpbnverifyreq_409.req_u.dsa_verify.g_len = (g_409_len);

	g_ecpbnverifyreq_409.req_u.dsa_verify.pub_key = PUB_KEY_EC_409;
	g_ecpbnverifyreq_409.req_u.dsa_verify.pub_key_len = (pub_key_ec_409_len);

	g_ecpbnverifyreq_409.req_u.dsa_verify.m = M_409;
	g_ecpbnverifyreq_409.req_u.dsa_verify.m_len = (m_409_len);

	g_ecpbnverifyreq_409.req_u.dsa_verify.c = C_409;

	g_ecpbnverifyreq_409.req_u.dsa_verify.d = D_409;
	g_ecpbnverifyreq_409.req_u.dsa_verify.d_len = d_409_len;
}

void init_ecpbn_sign_test_409(void)
{
	g_ecpbnsignreq_409.type = ECDSA_SIGN;
    g_ecpbnsignreq_409.curve_type = ECC_BINARY;

	g_ecpbnsignreq_409.req_u.dsa_sign.q = Q_409;
	g_ecpbnsignreq_409.req_u.dsa_sign.q_len = (q_409_len);

	g_ecpbnsignreq_409.req_u.dsa_sign.r = R_409;
	g_ecpbnsignreq_409.req_u.dsa_sign.r_len = (r_409_len);

	g_ecpbnsignreq_409.req_u.dsa_sign.ab = AB_409;
	g_ecpbnsignreq_409.req_u.dsa_sign.ab_len = (ab_409_len);

	g_ecpbnsignreq_409.req_u.dsa_sign.g = G_409;
	g_ecpbnsignreq_409.req_u.dsa_sign.g_len = (g_409_len);

	g_ecpbnsignreq_409.req_u.dsa_sign.priv_key = PRIV_KEY_EC_409;
	g_ecpbnsignreq_409.req_u.dsa_sign.priv_key_len = (priv_key_ec_409_len);

	g_ecpbnsignreq_409.req_u.dsa_sign.m = M_409;
	g_ecpbnsignreq_409.req_u.dsa_sign.m_len = (m_409_len);

	g_ecpbnsignreq_409.req_u.dsa_sign.c = kzalloc(r_409_len, GFP_KERNEL | GFP_DMA);

	g_ecpbnsignreq_409.req_u.dsa_sign.d = kzalloc(r_409_len, GFP_KERNEL | GFP_DMA);
	g_ecpbnsignreq_409.req_u.dsa_sign.d_len = r_409_len;
}

int ecpbn_verify_test_409(void)
{
	if (-1 == test_dsa_op(&g_ecpbnverifyreq_409, ecpbn_done))
		return -1;

	return 0;
}

int ecpbn_sign_test_409(void)
{
	if (-1 == test_dsa_op(&g_ecpbnsignreq_409, ecpbn_done))
		return -1;

	return 0;
}



void init_ecpbn_verify_test_571(void)
{
	g_ecpbnverifyreq_571.type = ECDSA_VERIFY;
    g_ecpbnverifyreq_571.curve_type = ECC_BINARY;

	g_ecpbnverifyreq_571.req_u.dsa_verify.q = Q_571;
	g_ecpbnverifyreq_571.req_u.dsa_verify.q_len = (q_571_len);

	g_ecpbnverifyreq_571.req_u.dsa_verify.r = R_571;
	g_ecpbnverifyreq_571.req_u.dsa_verify.r_len = (r_571_len);

	g_ecpbnverifyreq_571.req_u.dsa_verify.ab = AB_571;
	g_ecpbnverifyreq_571.req_u.dsa_verify.ab_len = (ab_571_len);

	g_ecpbnverifyreq_571.req_u.dsa_verify.g = G_571;
	g_ecpbnverifyreq_571.req_u.dsa_verify.g_len = (g_571_len);

	g_ecpbnverifyreq_571.req_u.dsa_verify.pub_key = PUB_KEY_EC_571;
	g_ecpbnverifyreq_571.req_u.dsa_verify.pub_key_len = (pub_key_ec_571_len);

	g_ecpbnverifyreq_571.req_u.dsa_verify.m = M_571;
	g_ecpbnverifyreq_571.req_u.dsa_verify.m_len = (m_571_len);

	g_ecpbnverifyreq_571.req_u.dsa_verify.c = C_571;

	g_ecpbnverifyreq_571.req_u.dsa_verify.d = D_571;
	g_ecpbnverifyreq_571.req_u.dsa_verify.d_len = d_571_len;
}

void init_ecpbn_sign_test_571(void)
{
	g_ecpbnsignreq_571.type = ECDSA_SIGN;
    g_ecpbnsignreq_571.curve_type = ECC_BINARY;

	g_ecpbnsignreq_571.req_u.dsa_sign.q = Q_571;
	g_ecpbnsignreq_571.req_u.dsa_sign.q_len = (q_571_len);

	g_ecpbnsignreq_571.req_u.dsa_sign.r = R_571;
	g_ecpbnsignreq_571.req_u.dsa_sign.r_len = (r_571_len);

	g_ecpbnsignreq_571.req_u.dsa_sign.ab = AB_571;
	g_ecpbnsignreq_571.req_u.dsa_sign.ab_len = (ab_571_len);

	g_ecpbnsignreq_571.req_u.dsa_sign.g = G_571;
	g_ecpbnsignreq_571.req_u.dsa_sign.g_len = (g_571_len);

	g_ecpbnsignreq_571.req_u.dsa_sign.priv_key = PRIV_KEY_EC_571;
	g_ecpbnsignreq_571.req_u.dsa_sign.priv_key_len = (priv_key_ec_571_len);

	g_ecpbnsignreq_571.req_u.dsa_sign.m = M_571;
	g_ecpbnsignreq_571.req_u.dsa_sign.m_len = (m_571_len);

	g_ecpbnsignreq_571.req_u.dsa_sign.c = kzalloc(r_571_len, GFP_KERNEL | GFP_DMA);

	g_ecpbnsignreq_571.req_u.dsa_sign.d = kzalloc(r_571_len, GFP_KERNEL | GFP_DMA);
	g_ecpbnsignreq_571.req_u.dsa_sign.d_len = r_571_len;
}

int ecpbn_verify_test_571(void)
{
	if (-1 == test_dsa_op(&g_ecpbnverifyreq_571, ecpbn_done))
		return -1;

	return 0;
}

int ecpbn_sign_test_571(void)
{
	if (-1 == test_dsa_op(&g_ecpbnsignreq_571, ecpbn_done))
		return -1;

	return 0;
}

void cleanup_ecpbn_test(void)
{
	if(g_ecpbnsignreq_283.req_u.dsa_sign.c)
		kfree(g_ecpbnsignreq_283.req_u.dsa_sign.c);
	if(g_ecpbnsignreq_283.req_u.dsa_sign.d)
		kfree(g_ecpbnsignreq_283.req_u.dsa_sign.d);
	if(g_ecpbnsignreq_409.req_u.dsa_sign.c)
		kfree(g_ecpbnsignreq_409.req_u.dsa_sign.c);
	if(g_ecpbnsignreq_409.req_u.dsa_sign.d)
		kfree(g_ecpbnsignreq_409.req_u.dsa_sign.d);
	if(g_ecpbnsignreq_571.req_u.dsa_sign.c)
		kfree(g_ecpbnsignreq_571.req_u.dsa_sign.c);
	if(g_ecpbnsignreq_571.req_u.dsa_sign.d)
		kfree(g_ecpbnsignreq_571.req_u.dsa_sign.d);
}

/*
int ecdsa_keygen_verify_test(struct pkc_request *genreq,
			     struct pkc_request *signreq,
			     struct pkc_request *req)
{
	int ret = 0;

	req->type = ECDSA_VERIFY;

	req->req_u.dsa_verify.q = Q;
	req->req_u.dsa_verify.q_len = (q_len);

	req->req_u.dsa_verify.r = R;
	req->req_u.dsa_verify.r_len = (r_len);

	req->req_u.dsa_verify.ab = AB;
	req->req_u.dsa_verify.ab_len = (ab_len);

	req->req_u.dsa_verify.g = G;
	req->req_u.dsa_verify.g_len = (g_len);

	req->req_u.dsa_verify.pub_key = kzalloc(pub_key_len, GFP_KERNEL);
	memcpy(req->req_u.dsa_verify.pub_key, genreq->req_u.dsa_keygen.pubkey,
	       pub_key_len);
	req->req_u.dsa_verify.pub_key_len = (pub_key_len);

	req->req_u.dsa_verify.m = M;
	req->req_u.dsa_verify.m_len = (m_len);

	req->req_u.dsa_verify.c = kzalloc(d_len, GFP_KERNEL);
	memcpy(req->req_u.dsa_verify.c, signreq->req_u.dsa_sign.c, d_len);

	req->req_u.dsa_verify.d = kzalloc(d_len, GFP_KERNEL);
	memcpy(req->req_u.dsa_verify.d, signreq->req_u.dsa_sign.d, d_len);
	req->req_u.dsa_verify.d_len = d_len;

	ret = test_dsa_op(req, ecdsa_keygen_done);

	return ret;
}

int ecdsa_keygen_sign_test(struct pkc_request *genreq, struct pkc_request *req)
{
	int ret = 0;

	req->type = ECDSA_SIGN;

	req->req_u.dsa_sign.q = Q;
	req->req_u.dsa_sign.q_len = (q_len);

	req->req_u.dsa_sign.r = R;
	req->req_u.dsa_sign.r_len = (r_len);

	req->req_u.dsa_sign.ab = AB;
	req->req_u.dsa_sign.ab_len = (ab_len);

	req->req_u.dsa_sign.g = G;
	req->req_u.dsa_sign.g_len = (g_len);

	req->req_u.dsa_sign.priv_key = kzalloc(priv_key_len, GFP_KERNEL);
	memcpy(req->req_u.dsa_sign.priv_key, genreq->req_u.dsa_keygen.prvkey,
	       priv_key_len);
	req->req_u.dsa_sign.priv_key_len = (priv_key_len);

	req->req_u.dsa_sign.m = M;
	req->req_u.dsa_sign.m_len = (m_len);

	req->req_u.dsa_sign.c = kzalloc(d_len, GFP_KERNEL | GFP_DMA);

	req->req_u.dsa_sign.d = kzalloc(d_len, GFP_KERNEL | GFP_DMA);
	req->req_u.dsa_sign.d_len = d_len;

	ret = test_dsa_op(req, ecdsa_keygen_done);

	return ret;
}

int ecdsa_keygen_test(void)
{
	int ret = 0;
	struct pkc_request *genreq =
	    kzalloc(sizeof(struct pkc_request), GFP_KERNEL);
	struct pkc_request *signreq =
	    kzalloc(sizeof(struct pkc_request), GFP_KERNEL);
	struct pkc_request *verifyreq =
	    kzalloc(sizeof(struct pkc_request), GFP_KERNEL);

	genreq->type = ECDSA_KEYGEN;
	init_completion(&keygen_control_completion_var);

	genreq->req_u.dsa_keygen.q = Q;
	genreq->req_u.dsa_keygen.q_len = (q_len);

	genreq->req_u.dsa_keygen.r = R;
	genreq->req_u.dsa_keygen.r_len = (r_len);

	genreq->req_u.dsa_keygen.g = G;
	genreq->req_u.dsa_keygen.g_len = (g_len);

	genreq->req_u.dsa_keygen.ab = AB;
	genreq->req_u.dsa_keygen.ab_len = (ab_len);

	genreq->req_u.dsa_keygen.pubkey =
	    kzalloc(sizeof(PUB_KEY), GFP_KERNEL | GFP_DMA);
	genreq->req_u.dsa_keygen.pubkey_len = (pub_key_len);

	genreq->req_u.dsa_keygen.prvkey =
	    kzalloc(sizeof(PRIV_KEY), GFP_KERNEL | GFP_DMA);
	genreq->req_u.dsa_keygen.prvkey_len = (priv_key_len);

	ret = test_dsa_op(genreq, ecdsa_keygen_done);
	if (-1 == ret)
		goto error;

	wait_for_completion(&keygen_control_completion_var);

	ret = ecdsa_keygen_sign_test(genreq, signreq);
	if (-1 == ret)
		goto error;

	wait_for_completion(&keygen_control_completion_var);

	ret = ecdsa_keygen_verify_test(genreq, signreq, verifyreq);
	if (-1 == ret)
		goto error;

	wait_for_completion(&keygen_control_completion_var);

	common_dec_count();

error:
	if (genreq) {
		if (genreq->req_u.dsa_keygen.pubkey)
			kfree(genreq->req_u.dsa_keygen.pubkey);
		if (genreq->req_u.dsa_keygen.prvkey)
			kfree(genreq->req_u.dsa_keygen.prvkey);
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

*/
