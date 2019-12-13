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
#include"ecp_test.h"

typedef void (*cb) (struct pkc_request *req, int32_t sec_result);

atomic_t ecp_enq_count;
atomic_t ecp_deq_count;

struct pkc_request g_ecpverifyreq_256; 
struct pkc_request g_ecpsignreq_256;
struct pkc_request g_ecpverifyreq_384; 
struct pkc_request g_ecpsignreq_384;
struct pkc_request g_ecpverifyreq_521; 
struct pkc_request g_ecpsignreq_521;

/*
static struct completion keygen_control_completion_var;
*/

void ecp_done(struct pkc_request *req, int32_t sec_result)
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
#endif

    common_dec_count();
}

void init_ecp_verify_test_256(void)
{
	g_ecpverifyreq_256.type = ECDSA_VERIFY;

	g_ecpverifyreq_256.req_u.dsa_verify.q = Q_256;
	g_ecpverifyreq_256.req_u.dsa_verify.q_len = (q_256_len);

	g_ecpverifyreq_256.req_u.dsa_verify.r = R_256;
	g_ecpverifyreq_256.req_u.dsa_verify.r_len = (r_256_len);

	g_ecpverifyreq_256.req_u.dsa_verify.ab = AB_256;
	g_ecpverifyreq_256.req_u.dsa_verify.ab_len = (ab_256_len);

	g_ecpverifyreq_256.req_u.dsa_verify.g = G_256;
	g_ecpverifyreq_256.req_u.dsa_verify.g_len = (g_256_len);

	g_ecpverifyreq_256.req_u.dsa_verify.pub_key = PUB_KEY_EC_256;
	g_ecpverifyreq_256.req_u.dsa_verify.pub_key_len = (pub_key_ec_256_len);

	g_ecpverifyreq_256.req_u.dsa_verify.m = M_256;
	g_ecpverifyreq_256.req_u.dsa_verify.m_len = (m_256_len);

	g_ecpverifyreq_256.req_u.dsa_verify.c = C;

	g_ecpverifyreq_256.req_u.dsa_verify.d = D;
	g_ecpverifyreq_256.req_u.dsa_verify.d_len = d_len;
}

void init_ecp_sign_test_256(void)
{
	g_ecpsignreq_256.type = ECDSA_SIGN;

	g_ecpsignreq_256.req_u.dsa_sign.q = Q_256;
	g_ecpsignreq_256.req_u.dsa_sign.q_len = (q_256_len);

	g_ecpsignreq_256.req_u.dsa_sign.r = R_256;
	g_ecpsignreq_256.req_u.dsa_sign.r_len = (r_256_len);

	g_ecpsignreq_256.req_u.dsa_sign.ab = AB_256;
	g_ecpsignreq_256.req_u.dsa_sign.ab_len = (ab_256_len);

	g_ecpsignreq_256.req_u.dsa_sign.g = G_256;
	g_ecpsignreq_256.req_u.dsa_sign.g_len = (g_256_len);

	g_ecpsignreq_256.req_u.dsa_sign.priv_key = PRIV_KEY_EC_256;
	g_ecpsignreq_256.req_u.dsa_sign.priv_key_len = (priv_key_ec_256_len);

	g_ecpsignreq_256.req_u.dsa_sign.m = M_256;
	g_ecpsignreq_256.req_u.dsa_sign.m_len = (m_256_len);

	g_ecpsignreq_256.req_u.dsa_sign.c = kzalloc(d_len, GFP_KERNEL | GFP_DMA);

	g_ecpsignreq_256.req_u.dsa_sign.d = kzalloc(d_len, GFP_KERNEL | GFP_DMA);
	g_ecpsignreq_256.req_u.dsa_sign.d_len = d_len;
}

int ecp_verify_test_256(void)
{
	if (-1 == test_dsa_op(&g_ecpverifyreq_256, ecp_done))
		return -1;

	return 0;
}

int ecp_sign_test_256(void)
{
	if (-1 == test_dsa_op(&g_ecpsignreq_256, ecp_done))
		return -1;

	return 0;
}


void init_ecp_verify_test_384(void)
{
	g_ecpverifyreq_384.type = ECDSA_VERIFY;

	g_ecpverifyreq_384.req_u.dsa_verify.q = Q_384;
	g_ecpverifyreq_384.req_u.dsa_verify.q_len = (q_384_len);

	g_ecpverifyreq_384.req_u.dsa_verify.r = R_384;
	g_ecpverifyreq_384.req_u.dsa_verify.r_len = (r_384_len);

	g_ecpverifyreq_384.req_u.dsa_verify.ab = AB_384;
	g_ecpverifyreq_384.req_u.dsa_verify.ab_len = (ab_384_len);

	g_ecpverifyreq_384.req_u.dsa_verify.g = G_384;
	g_ecpverifyreq_384.req_u.dsa_verify.g_len = (g_384_len);

	g_ecpverifyreq_384.req_u.dsa_verify.pub_key = PUB_KEY_EC_384;
	g_ecpverifyreq_384.req_u.dsa_verify.pub_key_len = (pub_key_ec_384_len);

	g_ecpverifyreq_384.req_u.dsa_verify.m = M_384;
	g_ecpverifyreq_384.req_u.dsa_verify.m_len = (m_384_len);

	g_ecpverifyreq_384.req_u.dsa_verify.c = C_384;

	g_ecpverifyreq_384.req_u.dsa_verify.d = D_384;
	g_ecpverifyreq_384.req_u.dsa_verify.d_len = d_384_len;
}

void init_ecp_sign_test_384(void)
{
	g_ecpsignreq_384.type = ECDSA_SIGN;

	g_ecpsignreq_384.req_u.dsa_sign.q = Q_384;
	g_ecpsignreq_384.req_u.dsa_sign.q_len = (q_384_len);

	g_ecpsignreq_384.req_u.dsa_sign.r = R_384;
	g_ecpsignreq_384.req_u.dsa_sign.r_len = (r_384_len);

	g_ecpsignreq_384.req_u.dsa_sign.ab = AB_384;
	g_ecpsignreq_384.req_u.dsa_sign.ab_len = (ab_384_len);

	g_ecpsignreq_384.req_u.dsa_sign.g = G_384;
	g_ecpsignreq_384.req_u.dsa_sign.g_len = (g_384_len);

	g_ecpsignreq_384.req_u.dsa_sign.priv_key = PRIV_KEY_EC_384;
	g_ecpsignreq_384.req_u.dsa_sign.priv_key_len = (priv_key_ec_384_len);

	g_ecpsignreq_384.req_u.dsa_sign.m = M_384;
	g_ecpsignreq_384.req_u.dsa_sign.m_len = (m_384_len);

	g_ecpsignreq_384.req_u.dsa_sign.c = kzalloc(d_384_len, GFP_KERNEL | GFP_DMA);

	g_ecpsignreq_384.req_u.dsa_sign.d = kzalloc(d_384_len, GFP_KERNEL | GFP_DMA);
	g_ecpsignreq_384.req_u.dsa_sign.d_len = d_384_len;
}

int ecp_verify_test_384(void)
{
	if (-1 == test_dsa_op(&g_ecpverifyreq_384, ecp_done))
		return -1;

	return 0;
}

int ecp_sign_test_384(void)
{
	if (-1 == test_dsa_op(&g_ecpsignreq_384, ecp_done))
		return -1;

	return 0;
}



void init_ecp_verify_test_521(void)
{
	g_ecpverifyreq_521.type = ECDSA_VERIFY;

	g_ecpverifyreq_521.req_u.dsa_verify.q = Q_521;
	g_ecpverifyreq_521.req_u.dsa_verify.q_len = (q_521_len);

	g_ecpverifyreq_521.req_u.dsa_verify.r = R_521;
	g_ecpverifyreq_521.req_u.dsa_verify.r_len = (r_521_len);

	g_ecpverifyreq_521.req_u.dsa_verify.ab = AB_521;
	g_ecpverifyreq_521.req_u.dsa_verify.ab_len = (ab_521_len);

	g_ecpverifyreq_521.req_u.dsa_verify.g = G_521;
	g_ecpverifyreq_521.req_u.dsa_verify.g_len = (g_521_len);

	g_ecpverifyreq_521.req_u.dsa_verify.pub_key = PUB_KEY_EC_521;
	g_ecpverifyreq_521.req_u.dsa_verify.pub_key_len = (pub_key_ec_521_len);

	g_ecpverifyreq_521.req_u.dsa_verify.m = M_521;
	g_ecpverifyreq_521.req_u.dsa_verify.m_len = (m_521_len);

	g_ecpverifyreq_521.req_u.dsa_verify.c = C_521;

	g_ecpverifyreq_521.req_u.dsa_verify.d = D_521;
	g_ecpverifyreq_521.req_u.dsa_verify.d_len = d_521_len;
}

void init_ecp_sign_test_521(void)
{
	g_ecpsignreq_521.type = ECDSA_SIGN;

	g_ecpsignreq_521.req_u.dsa_sign.q = Q_521;
	g_ecpsignreq_521.req_u.dsa_sign.q_len = (q_521_len);

	g_ecpsignreq_521.req_u.dsa_sign.r = R_521;
	g_ecpsignreq_521.req_u.dsa_sign.r_len = (r_521_len);

	g_ecpsignreq_521.req_u.dsa_sign.ab = AB_521;
	g_ecpsignreq_521.req_u.dsa_sign.ab_len = (ab_521_len);

	g_ecpsignreq_521.req_u.dsa_sign.g = G_521;
	g_ecpsignreq_521.req_u.dsa_sign.g_len = (g_521_len);

	g_ecpsignreq_521.req_u.dsa_sign.priv_key = PRIV_KEY_EC_521;
	g_ecpsignreq_521.req_u.dsa_sign.priv_key_len = (priv_key_ec_521_len);

	g_ecpsignreq_521.req_u.dsa_sign.m = M_521;
	g_ecpsignreq_521.req_u.dsa_sign.m_len = (m_521_len);

	g_ecpsignreq_521.req_u.dsa_sign.c = kzalloc(d_521_len, GFP_KERNEL | GFP_DMA);

	g_ecpsignreq_521.req_u.dsa_sign.d = kzalloc(d_521_len, GFP_KERNEL | GFP_DMA);
	g_ecpsignreq_521.req_u.dsa_sign.d_len = d_521_len;
}

int ecp_verify_test_521(void)
{
	if (-1 == test_dsa_op(&g_ecpverifyreq_521, ecp_done))
		return -1;

	return 0;
}

int ecp_sign_test_521(void)
{
	if (-1 == test_dsa_op(&g_ecpsignreq_521, ecp_done))
		return -1;

	return 0;
}

void cleanup_ecp_test(void)
{
	if(g_ecpsignreq_256.req_u.dsa_sign.c)
		kfree(g_ecpsignreq_256.req_u.dsa_sign.c);
	if(g_ecpsignreq_256.req_u.dsa_sign.d)
		kfree(g_ecpsignreq_256.req_u.dsa_sign.d);
	if(g_ecpsignreq_384.req_u.dsa_sign.c)
		kfree(g_ecpsignreq_384.req_u.dsa_sign.c);
	if(g_ecpsignreq_384.req_u.dsa_sign.d)
		kfree(g_ecpsignreq_384.req_u.dsa_sign.d);
	if(g_ecpsignreq_521.req_u.dsa_sign.c)
		kfree(g_ecpsignreq_521.req_u.dsa_sign.c);
	if(g_ecpsignreq_521.req_u.dsa_sign.d)
		kfree(g_ecpsignreq_521.req_u.dsa_sign.d);

}
