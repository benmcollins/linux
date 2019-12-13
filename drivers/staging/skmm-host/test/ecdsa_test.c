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

typedef void (*cb) (struct pkc_request *req, int32_t sec_result);

atomic_t ecdsa_enq_count;
atomic_t ecdsa_deq_count;

struct pkc_request g_ecdsaverifyreq;
struct pkc_request g_ecdsasignreq;

static uint8_t Q[] = {
	0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF,
	0XFF, 0XFF, 0XFF, 0XFE,
	0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF
};

static int q_len = sizeof(Q);

static uint8_t R[] = {
	0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF,
	0X99, 0XDE, 0XF8, 0X36,
	0X14, 0X6B, 0XC9, 0XB1, 0XB4, 0XD2, 0X28, 0X31
};

static int r_len = sizeof(R);

static uint8_t AB[] = {
	0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF,
	0XFF, 0XFF, 0XFF, 0XFE,
	0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFC, 0X64, 0X21, 0X05, 0X19,
	0XE5, 0X9C, 0X80, 0XE7,
	0X0F, 0XA7, 0XE9, 0XAB, 0X72, 0X24, 0X30, 0X49, 0XFE, 0XB8, 0XDE, 0XEC,
	0XC1, 0X46, 0XB9, 0XB1
};

static int ab_len = sizeof(AB);

static uint8_t G[] = {
	0X18, 0X8D, 0XA8, 0X0E, 0XB0, 0X30, 0X90, 0XF6, 0X7C, 0XBF, 0X20, 0XEB,
	0X43, 0XA1, 0X88, 0X00,
	0XF4, 0XFF, 0X0A, 0XFD, 0X82, 0XFF, 0X10, 0X12, 0X07, 0X19, 0X2B, 0X95,
	0XFF, 0XC8, 0XDA, 0X78,
	0X63, 0X10, 0X11, 0XED, 0X6B, 0X24, 0XCD, 0XD5, 0X73, 0XF9, 0X77, 0XA1,
	0X1E, 0X79, 0X48, 0X11
};

static int g_len = sizeof(G);

static uint8_t PRIV_KEY[] = {
	0X13, 0XBD, 0XA6, 0XFE, 0X20, 0XE2, 0X8F, 0X2C, 0X7F, 0X17, 0X7D, 0X27,
	0XBC, 0X1D, 0XDF, 0X69,
	0X73, 0X3C, 0XD3, 0XFC, 0X51, 0X70, 0X4F, 0X34
};

static int priv_key_len = sizeof(PRIV_KEY);

static uint8_t PUB_KEY[] = {
	0XCF, 0X69, 0XC4, 0XA4, 0XE7, 0X13, 0XD3, 0XC1, 0X1D, 0XEC, 0X21, 0XC8,
	0XA7, 0XBC, 0XD6, 0X16,
	0X6D, 0XA9, 0X4D, 0XE4, 0XF1, 0XB1, 0X23, 0XA5, 0X34, 0XBC, 0XEE, 0X9E,
	0X75, 0XE5, 0X80, 0X99,
	0X89, 0XA7, 0X3B, 0X82, 0X48, 0XE1, 0XBE, 0XDF, 0XF5, 0X5F, 0X95, 0X5A,
	0X09, 0X43, 0X8B, 0X3D
};

static int pub_key_len = sizeof(PUB_KEY);

static uint8_t M[] = {
	0X0F, 0X67, 0XCB, 0XF2, 0X0E, 0XB4, 0X3A, 0X18, 0X80, 0X0F, 0X19, 0X2B,
	0X95, 0XFF, 0XC2, 0X24,
	0X30, 0X42, 0X80, 0X8A, 0X78, 0X27, 0X3D, 0X3C, 0X0F, 0X67, 0XCB, 0XF2,
	0X0E, 0XB4, 0X3A, 0X18,
	0X80, 0X0F, 0X19, 0X2B, 0X95, 0XFF, 0XC2, 0X24, 0X30, 0X42, 0X80, 0X8A,
	0X78, 0X27, 0X3D, 0X3C,
	0X0F, 0X67, 0XCB, 0XF2, 0X0E, 0XB4, 0X3A, 0X18, 0X80, 0X0F, 0X19, 0X2B,
	0X95, 0XFF, 0XC2, 0X24,
	0X30, 0X42, 0X80, 0X8A, 0X78, 0X27, 0X3D, 0X3C, 0X0F, 0X67, 0XCB, 0XF2,
	0X0E, 0XB4, 0X3A, 0X18,
	0X80, 0X0F, 0X19, 0X2B, 0X95, 0XFF, 0XC2, 0X24, 0X30, 0X42, 0X80, 0X8A,
	0X78, 0X27, 0X3D, 0X3C,
	0X0F, 0X67, 0XCB, 0XF2, 0X0E, 0XB4, 0X3A, 0X18, 0X80, 0X0F, 0X19, 0X2B,
	0X95, 0XFF, 0XC2, 0X24,
	0X30, 0X42, 0X80, 0X8A, 0X78, 0X27, 0X3D, 0X3C, 0X0F, 0X67, 0XCB, 0XF2,
	0X0E, 0XB4, 0X3A, 0X18,
	0X80, 0X0F, 0X19, 0X2B, 0X95, 0XFF, 0XC2, 0X24, 0X30, 0X42, 0X80, 0X8A,
	0X78, 0X27, 0X3D, 0X3C,
	0X0F, 0X67, 0XCB, 0XF2, 0X0E, 0XB4, 0X3A, 0X18, 0X80, 0X0F, 0X19, 0X2B,
	0X95, 0XFF, 0XC2, 0X24,
	0X30, 0X42, 0X80, 0X8A, 0X78, 0X27, 0X3D, 0X3C, 0X0F, 0X67, 0XCB, 0XF2,
	0X0E, 0XB4, 0X3A, 0X18,
	0X80, 0X0F, 0X19, 0X2B, 0X95, 0XFF, 0XC2, 0X24, 0X30, 0X42, 0X80, 0X8A,
	0X78, 0X27, 0X3D, 0X3C,
	0X0F, 0X67, 0XCB, 0XF2, 0X0E, 0XB4, 0X3A, 0X18, 0X80, 0X0F, 0X19, 0X2B,
	0X95, 0XFF, 0XC2, 0X24,
	0X30, 0X42, 0X80, 0X8A, 0X78, 0X27, 0X3D, 0X3C, 0X0F, 0X67, 0XCB, 0XF2,
	0X0E, 0XB4, 0X3A, 0X18,
	0X80, 0X0F, 0X19, 0X2B, 0X95, 0XFF, 0XC2, 0X24, 0X30, 0X42, 0X80, 0X8A,
	0X78, 0X27, 0X3D, 0X3C,
	0X0F, 0X67, 0XCB, 0XF2, 0X0E, 0XB4, 0X3A, 0X18, 0X80, 0X0F, 0X19, 0X2B,
	0X95, 0XFF, 0XC2, 0X24,
	0X30, 0X42, 0X80, 0X8A, 0X78, 0X27, 0X3D, 0X3C, 0X0F, 0X67, 0XCB, 0XF2,
	0X0E, 0XB4, 0X3A, 0X18,
	0X80
};

static int m_len = sizeof(M);

#if 0
static uint8_t C[] = {
	0X0F, 0X67, 0XCB, 0XF2, 0X0E, 0XB4, 0X3A, 0X18, 0X80, 0X0F, 0X19, 0X2B,
	0X95, 0XFF, 0XC2, 0X24,
	0X30, 0X42, 0X80, 0X8A, 0X78, 0X27, 0X3D, 0X3C
};

static int c_len = sizeof(C);

static uint8_t D[] = {
	0X0F, 0X67, 0XCB, 0XF2, 0X0E, 0XB4, 0X3A, 0X18, 0X80, 0X0F, 0X19, 0X2B,
	0X95, 0XFF, 0XC2, 0X24,
	0X30, 0X42, 0X80, 0X8A, 0X78, 0X27, 0X3D, 0X3C
};

static int d_len = sizeof(D);
#endif
#if 1
static uint8_t C[] = {
	0x3b, 0x6e, 0xcc, 0x31, 0xc, 0x95, 0xb9, 0x12, 0x53, 0x16, 0x1, 0x36,
	0xee, 0x2, 0xad, 0x8d, 0x8d, 0x21, 0x96, 0x4b, 0x69, 0x25, 0x29,
	0xa1
};

/*
static uint8_t C[] =
{
0x1e,	0xdc,	0xb0,	0x65,	0xc8,	0x67,	0xee,	0xaf,	0x3f,	0xb0,
0x86,	0xf2,	0x9a,	0xf3,	0xd3,	0x97,	0xd1,0x11,	0x9c,	0x2e,
0x23,	0x49,	0x51,	0xf1
};
*/
/*static int c_len = sizeof(C);*/
static uint8_t D[] = {
	0x9b, 0x55, 0xab, 0x3, 0x4, 0x4d, 0xfe, 0x1c, 0x82, 0x46, 0x92, 0x22,
	0x3b, 0xcd, 0x4b, 0xbf, 0x3a, 0xb8, 0xfd, 0xb0, 0x1b, 0xc7, 0x7c,
	0xf5
};
#endif
/*
static uint8_t D[] =
{
0x54,	0x36,	0xd1,	0xbf,	0xfc,	0x74,	0xcf,	0xbc,	0x6e,	0x03,
0x0f,	0xe9,	0x30,	0x87,	0xbb,	0x32,	0xba,0x86,	0x3f,	0xf6,
0x8d,	0xf7,	0x99,	0x7e
};
*/
static int d_len = sizeof(D);

static struct completion keygen_control_completion_var;
#ifndef SIMPLE_TEST_ENABLE
static void dec_count(void)
{
#ifndef PERF_TEST
	int32_t d_cnt = 0;
	d_cnt = atomic_inc_return(&ecdsa_deq_count);

	print_debug("Deq cnt... :%d\n", d_cnt);
#endif
	atomic_inc(&total_deq_cnt);
}
#endif

void ecdsa_keygen_done(struct pkc_request *req, int32_t sec_result)
{
	print_debug(KERN_ERR "%s( ): req:%p, sec_result:%0x \n", __func__,
		    req, sec_result);
	complete(&keygen_control_completion_var);
}

void ecdsa_done(struct pkc_request *req, int32_t sec_result)
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

void init_ecdsa_verify_test(void)
{
	g_ecdsaverifyreq.type = ECDSA_VERIFY;

	g_ecdsaverifyreq.req_u.dsa_verify.q = kzalloc(q_len, GFP_DMA);
	memcpy(g_ecdsaverifyreq.req_u.dsa_verify.q, Q, q_len);
	g_ecdsaverifyreq.req_u.dsa_verify.q_len = (q_len);

	g_ecdsaverifyreq.req_u.dsa_verify.r = kzalloc(r_len, GFP_DMA);
	memcpy(g_ecdsaverifyreq.req_u.dsa_verify.r, R, r_len);
	g_ecdsaverifyreq.req_u.dsa_verify.r_len = (r_len);

	g_ecdsaverifyreq.req_u.dsa_verify.ab = kzalloc(ab_len, GFP_DMA);
	memcpy(g_ecdsaverifyreq.req_u.dsa_verify.ab, AB, ab_len);
	g_ecdsaverifyreq.req_u.dsa_verify.ab_len = (ab_len);

	g_ecdsaverifyreq.req_u.dsa_verify.g = kzalloc(g_len, GFP_DMA);
	memcpy(g_ecdsaverifyreq.req_u.dsa_verify.g, G, g_len);
	g_ecdsaverifyreq.req_u.dsa_verify.g_len = (g_len);

	g_ecdsaverifyreq.req_u.dsa_verify.pub_key = kzalloc(pub_key_len,
							GFP_DMA);
	memcpy(g_ecdsaverifyreq.req_u.dsa_verify.pub_key, PUB_KEY, pub_key_len);
	g_ecdsaverifyreq.req_u.dsa_verify.pub_key_len = (pub_key_len);

	g_ecdsaverifyreq.req_u.dsa_verify.m = kzalloc(m_len, GFP_DMA);
	memcpy(g_ecdsaverifyreq.req_u.dsa_verify.m, M, m_len);
	g_ecdsaverifyreq.req_u.dsa_verify.m_len = (m_len);

	g_ecdsaverifyreq.req_u.dsa_verify.c = kzalloc(sizeof(C), GFP_DMA);
	memcpy(g_ecdsaverifyreq.req_u.dsa_verify.c, C, sizeof(C));

	g_ecdsaverifyreq.req_u.dsa_verify.d = kzalloc(sizeof(D), GFP_DMA);
	memcpy(g_ecdsaverifyreq.req_u.dsa_verify.d, D, d_len);
	g_ecdsaverifyreq.req_u.dsa_verify.d_len = d_len;
}

void init_ecdsa_sign_test(void)
{
	g_ecdsasignreq.type = ECDSA_SIGN;

	g_ecdsasignreq.req_u.dsa_sign.ab = kzalloc(ab_len, GFP_DMA);
	memcpy(g_ecdsasignreq.req_u.dsa_sign.ab, AB, ab_len);
	g_ecdsasignreq.req_u.dsa_sign.ab_len = (ab_len);

	g_ecdsasignreq.req_u.dsa_sign.m = kzalloc(m_len, GFP_DMA);
	memcpy(g_ecdsasignreq.req_u.dsa_sign.m, M, m_len);
	g_ecdsasignreq.req_u.dsa_sign.m_len = (m_len);

	g_ecdsasignreq.req_u.dsa_sign.c = kzalloc(d_len, GFP_DMA | GFP_DMA);

	g_ecdsasignreq.req_u.dsa_sign.d = kzalloc(d_len, GFP_DMA | GFP_DMA);
	g_ecdsasignreq.req_u.dsa_sign.d_len = d_len;
}

void cleanup_ecdsa_test(void)
{
	kfree(g_ecdsasignreq.req_u.dsa_sign.ab);
	kfree(g_ecdsasignreq.req_u.dsa_sign.m);
	kfree(g_ecdsasignreq.req_u.dsa_sign.c);
	kfree(g_ecdsasignreq.req_u.dsa_sign.d);


	kfree(g_ecdsaverifyreq.req_u.dsa_verify.q);
	kfree(g_ecdsaverifyreq.req_u.dsa_verify.r);
	kfree(g_ecdsaverifyreq.req_u.dsa_verify.g);
	kfree(g_ecdsaverifyreq.req_u.dsa_verify.pub_key);
	kfree(g_ecdsaverifyreq.req_u.dsa_verify.c);
	kfree(g_ecdsaverifyreq.req_u.dsa_verify.d);
	kfree(g_ecdsaverifyreq.req_u.dsa_verify.ab);
}

int ecdsa_verify_test(void)
{
	if (-1 == test_dsa_op(&g_ecdsaverifyreq, ecdsa_done))
		return -1;

	return 0;
}

int ecdsa_sign_test(void)
{
	if (-1 == test_dsa_op(&g_ecdsasignreq, ecdsa_done))
		return -1;

	return 0;
}

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

	req->req_u.dsa_verify.pub_key = kzalloc(pub_key_len, GFP_DMA);
	memcpy(req->req_u.dsa_verify.pub_key, genreq->req_u.dsa_keygen.pubkey,
	       pub_key_len);
	req->req_u.dsa_verify.pub_key_len = (pub_key_len);

	req->req_u.dsa_verify.m = M;
	req->req_u.dsa_verify.m_len = (m_len);

	req->req_u.dsa_verify.c = kzalloc(d_len, GFP_DMA);
	memcpy(req->req_u.dsa_verify.c, signreq->req_u.dsa_sign.c, d_len);

	req->req_u.dsa_verify.d = kzalloc(d_len, GFP_DMA);
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

	req->req_u.dsa_sign.priv_key = kzalloc(priv_key_len, GFP_DMA);
	memcpy(req->req_u.dsa_sign.priv_key, genreq->req_u.dsa_keygen.prvkey,
	       priv_key_len);
	req->req_u.dsa_sign.priv_key_len = (priv_key_len);

	req->req_u.dsa_sign.m = M;
	req->req_u.dsa_sign.m_len = (m_len);

	req->req_u.dsa_sign.c = kzalloc(d_len, GFP_DMA | GFP_DMA);

	req->req_u.dsa_sign.d = kzalloc(d_len, GFP_DMA | GFP_DMA);
	req->req_u.dsa_sign.d_len = d_len;

	ret = test_dsa_op(req, ecdsa_keygen_done);

	return ret;
}

int ecdsa_keygen_test(void)
{
	int ret = 0;
	struct pkc_request *genreq =
	    kzalloc(sizeof(struct pkc_request), GFP_DMA);
	struct pkc_request *signreq =
	    kzalloc(sizeof(struct pkc_request), GFP_DMA);
	struct pkc_request *verifyreq =
	    kzalloc(sizeof(struct pkc_request), GFP_DMA);

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
	    kzalloc(sizeof(PUB_KEY), GFP_DMA | GFP_DMA);
	genreq->req_u.dsa_keygen.pubkey_len = (pub_key_len);

	genreq->req_u.dsa_keygen.prvkey =
	    kzalloc(sizeof(PRIV_KEY), GFP_DMA | GFP_DMA);
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

#if 0
int ecdsa_init_module(void)
{
	int loop = 0;
	print_debug("ECDSA test module inserted\n");

	while (loop++ < 1500)
		ecdsa_verify_test();

	return 0;
}

void ecdsa_cleanup_module(void)
{
	print_debug("ECDSA test module removed\n");
}

module_init(ecdsa_init_module);
module_exit(ecdsa_cleanup_module);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("TEST ECDSA algorithm");
MODULE_AUTHOR("FSL");
#endif
