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
#include "test.h"
#include "ecdh_keygen_test.h"

struct pkc_request p256;
struct pkc_request p384;
struct pkc_request p521;
struct pkc_request b283;
struct pkc_request b409;
struct pkc_request b571;

void ecdh_keygen_done(struct pkc_request *req, int32_t sec_result)
{
#if 0 
    int i = 0;
    printk(KERN_ERR "Result... :%d \n", sec_result);
	printk(KERN_ERR "pubkey_len : %d\n",req->req_u.dh_keygenreq.pubkey_len);
	printk(KERN_ERR "prvkey_len : %d\n",req->req_u.dh_keygenreq.prvkey_len);

    for(i=0; i<req->req_u.dh_keygenreq.pubkey_len; i++)
        printk(KERN_ERR "%0x",req->req_u.dh_keygenreq.pubkey[i]);
    printk(KERN_ERR "\n\n");        
    for(i=0; i<req->req_u.dh_keygenreq.prvkey_len; i++)
        printk(KERN_ERR "%0x",req->req_u.dh_keygenreq.prvkey[i]);
                
    printk(KERN_ERR "\n\n");        
#endif

	common_dec_count();
}

void init_ecdh_keygen_test_p256(void)
{
	struct dh_keygen_req_s *req = &p256.req_u.dh_keygenreq;
	p256.type = ECDH_KEYGEN;

	req->q = Q_256;
	req->r = R_256;
	req->g = G_256;
	req->ab = AB_256;
    req->q_len = q_256_len;
    req->r_len = r_256_len;
    req->g_len = g_256_len;
    req->ab_len = ab_256_len;

    req->prvkey_len = req->r_len;
    req->pubkey_len = req->g_len;

	req->pubkey = kzalloc(req->pubkey_len, GFP_KERNEL|GFP_DMA);
	req->prvkey = kzalloc(req->prvkey_len, GFP_KERNEL|GFP_DMA);
}

void init_ecdh_keygen_test_p384(void)
{
    struct dh_keygen_req_s *req = &p384.req_u.dh_keygenreq;
    p384.type = ECDH_KEYGEN;
   
    req->q = Q_384;
    req->r = R_384;
    req->g = G_384;
    req->ab = AB_384;
    req->q_len = q_384_len;
    req->r_len = r_384_len;
    req->g_len = g_384_len;
    req->ab_len = ab_384_len;
    req->prvkey_len = req->r_len;
    req->pubkey_len = req->g_len;

    req->pubkey = kzalloc(req->pubkey_len, GFP_KERNEL|GFP_DMA);
    req->prvkey = kzalloc(req->prvkey_len, GFP_KERNEL|GFP_DMA);
}

void init_ecdh_keygen_test_p521(void)
{
    struct dh_keygen_req_s *req = &p521.req_u.dh_keygenreq;
    p521.type = ECDH_KEYGEN;
   
    req->q = Q_521;
    req->r = R_521;
    req->g = G_521;
    req->ab = AB_521;
    req->q_len = q_521_len;
    req->r_len = r_521_len;
    req->g_len = g_521_len;
    req->ab_len = ab_521_len;
    req->prvkey_len = req->r_len;
    req->pubkey_len = req->g_len;

    req->pubkey = kzalloc(req->pubkey_len, GFP_KERNEL|GFP_DMA);
    req->prvkey = kzalloc(req->prvkey_len, GFP_KERNEL|GFP_DMA);
}

void init_ecdh_keygen_test_b283(void)
{
    struct dh_keygen_req_s *req = &b283.req_u.dh_keygenreq;
    b283.type = ECDH_KEYGEN;
  	b283.curve_type = ECC_BINARY; 

    req->q = Q_283;
    req->r = R_283;
    req->g = G_283;
    req->ab = AB_283;
    req->q_len = q_283_len;
    req->r_len = r_283_len;
    req->g_len = g_283_len;
    req->ab_len = ab_283_len;
    req->prvkey_len = req->r_len;
    req->pubkey_len = req->g_len;

    req->pubkey = kzalloc(req->pubkey_len, GFP_KERNEL|GFP_DMA);
    req->prvkey = kzalloc(req->prvkey_len, GFP_KERNEL|GFP_DMA);
}

void init_ecdh_keygen_test_b409(void)
{
    struct dh_keygen_req_s *req = &b409.req_u.dh_keygenreq;
    b409.type = ECDH_KEYGEN;
    b409.curve_type = ECC_BINARY; 

    req->q = Q_409;
    req->r = R_409;
    req->g = G_409;
    req->ab = AB_409;
    req->q_len = q_409_len;
    req->r_len = r_409_len;
    req->g_len = g_409_len;
    req->ab_len = ab_409_len;
    req->prvkey_len = req->r_len;
    req->pubkey_len = req->g_len;

    req->pubkey = kzalloc(req->pubkey_len, GFP_KERNEL|GFP_DMA);
    req->prvkey = kzalloc(req->prvkey_len, GFP_KERNEL|GFP_DMA);
}

void init_ecdh_keygen_test_b571(void)
{
    struct dh_keygen_req_s *req = &b571.req_u.dh_keygenreq;
    b571.type = ECDH_KEYGEN;
    b571.curve_type = ECC_BINARY; 

    req->q = Q_571;
    req->r = R_571;
    req->g = G_571;
    req->ab = AB_571;
    req->q_len = q_571_len;
    req->r_len = r_571_len;
    req->g_len = g_571_len;
    req->ab_len = ab_571_len;
    req->prvkey_len = req->r_len;
    req->pubkey_len = req->g_len;

    req->pubkey = kzalloc(req->pubkey_len, GFP_KERNEL|GFP_DMA);
    req->prvkey = kzalloc(req->prvkey_len, GFP_KERNEL|GFP_DMA);
}

void cleanup_ecdh_keygen_test(void)
{
	if(p256.req_u.dh_keygenreq.pubkey)
		kfree(p256.req_u.dh_keygenreq.pubkey);
	if(p256.req_u.dh_keygenreq.prvkey)
		kfree(p256.req_u.dh_keygenreq.prvkey);
	if(p384.req_u.dh_keygenreq.pubkey)
		kfree(p384.req_u.dh_keygenreq.pubkey);
	if(p384.req_u.dh_keygenreq.prvkey)
		kfree(p384.req_u.dh_keygenreq.prvkey);
	if(p521.req_u.dh_keygenreq.pubkey)
		kfree(p521.req_u.dh_keygenreq.pubkey);
	if(p521.req_u.dh_keygenreq.prvkey)
		kfree(p521.req_u.dh_keygenreq.prvkey);

	if(b283.req_u.dh_keygenreq.pubkey)
		kfree(b283.req_u.dh_keygenreq.pubkey);
	if(b283.req_u.dh_keygenreq.prvkey)
		kfree(b283.req_u.dh_keygenreq.prvkey);
	if(b409.req_u.dh_keygenreq.pubkey)
		kfree(b409.req_u.dh_keygenreq.pubkey);
	if(b409.req_u.dh_keygenreq.prvkey)
		kfree(b409.req_u.dh_keygenreq.prvkey);
	if(b571.req_u.dh_keygenreq.pubkey)
		kfree(b571.req_u.dh_keygenreq.pubkey);
	if(b571.req_u.dh_keygenreq.prvkey)
		kfree(b571.req_u.dh_keygenreq.prvkey);
}

int ecdh_keygen_test_b409(void)
{
	int32_t ret = -1;

	(test_dh_op(&b409, ecdh_keygen_done))? : (ret = 0);
	return ret;
}
int ecdh_keygen_test_b283(void)
{
	int32_t ret = -1;
    (test_dh_op(&b283, ecdh_keygen_done))? : (ret = 0);
	return ret;
}

int ecdh_keygen_test_b571(void)
{
	int32_t ret = -1;
    (test_dh_op(&b571, ecdh_keygen_done))? : (ret = 0);
	return ret;
}

int ecdh_keygen_test_p521(void)
{
	int32_t ret = -1;
    (test_dh_op(&p521, ecdh_keygen_done))? : (ret = 0);
	return ret;
}

int ecdh_keygen_test_p384(void)
{
	int32_t ret = -1;
    (test_dh_op(&p384, ecdh_keygen_done))? : (ret = 0);
	return ret;
}

int ecdh_keygen_test_p256(void)
{
	int32_t ret = -1;
    (test_dh_op(&p256, ecdh_keygen_done))? : (ret = 0);
	return ret;
}

