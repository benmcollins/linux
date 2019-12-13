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

#include "test.h"
#include "dh_test.h"

typedef void (*cb) (struct pkc_request *req, int32_t sec_result);
/*
static DECLARE_COMPLETION(jobs_done);
static int count;
*/
atomic_t dh_enq_count;
atomic_t dh_deq_count;
struct pkc_request g_dhreq_1k;
struct pkc_request g_dhreq_2k;
struct pkc_request g_dhreq_4k;

uint8_t q[ ] = 
{   0x97,0x5D,0x12,0x75,0x70,0xEE,0x37,0x85,0x2F,0x4C,0x30,0x94,0xD1,0x7C,0x30,0x07,0xE9,0xC4,0x81,
    0xF9,0x60,0x36,0x39,0x1E,0x72,0x10,0x81,0x65,0x7C,0xDE,0x64,0x98,0x18,0x5C,0x18,0x29,0xF9,0xD9,
    0xA4,0xBC,0xEA,0xEB,0xC4,0xF4,0x59,0x26,0x02,0xDA,0x66,0x79,0xCA,0x9C,0xB5,0xAD,0xAE,0x39,0x9B,
    0x61,0x99,0xD8,0x06,0x14,0x0D,0x06,0x69,0x1E,0x5D,0x0C,0x7A,0xD3,0xFF,0xA1,0x40,0x76,0x62,0x97,
    0x5A,0xD7,0xD0,0x6A,0x7C,0xD7,0xF8,0xCA,0xFD,0x90,0x5B,0x64,0xE1,0xEB,0xBB,0x7E,0xA4,0x80,0xED,
    0xF2,0x6C,0x87,0x3E,0x3D,0xD9,0xE7,0x21,0x25,0x6E,0xF2,0xD9,0x15,0xDA,0x81,0x62,0x43,0x4F,0x3C,
    0x3B,0xA0,0x2F,0x25,0x56,0x0E,0x1A,0xDE,0x80,0x40,0x0C,0x34,0xCE,0x69
};

uint8_t r[ ] =
{
    0x9d,0x04,0x19,0x22,0x5a,0x8d,0x1b,0xf3,0xa9,0xe6,0x6e,0x01,0x37,0xab,0xe1,0x81,0x18,0x2a,0x37,0xd3            
};
uint8_t g[ ] =
{
    0x3B,0xF0,0x62,0x8B,0xB8,0x9A,0x6A,0x76,0x40,0x94,0xF2,0xDD,0xE7,0x0C,0x7A,0xEA,0x40,0xAD,0xF2,0x49,
    0x08,0xF8,0xC3,0x08,0x63,0x17,0x37,0x7E,0x0A,0xA5,0x76,0x00,0x6E,0x5E,0xFE,0x3F,0xBA,0x04,0xC1,0x7A,
    0x35,0x7B,0xCB,0x5A,0x06,0xBE,0x41,0x87,0xB1,0x4A,0xE7,0xEA,0x43,0x67,0xFC,0x5A,0x9F,0xEA,0x81,0x1D,
    0x17,0x86,0x7F,0x62,0xEF,0xB1,0x33,0x0C,0x06,0x77,0x81,0x44,0xC7,0xDE,0x09,0x55,0xED,0xD9,0xE4,0xFE,
    0xC4,0x08,0x91,0xBB,0xC2,0x17,0x1E,0x06,0x22,0x70,0x70,0xD1,0x41,0x07,0x42,0x83,0xD4,0x69,0x23,0x4F,
    0x98,0xC9,0x9E,0xC9,0x2E,0x82,0xC9,0xEC,0xEA,0x78,0xED,0xC0,0xE3,0x6D,0xB6,0xCF,0x48,0x5E,0xA6,0xEF,
    0x3E,0xF1,0x21,0x08,0x45,0x43,0x7F,0xBC
};

/* static struct completion serialize_keygen;*/
void dh_done(struct pkc_request *req, int32_t sec_result)
{
	common_dec_count();
}
void dh_keygen_done(struct pkc_request *req, int32_t sec_result)
{
#if 0    
    int i = 0;
    printk(KERN_ERR "Result... :%d \n", sec_result);
    for(i=0; i<req->req_u.dh_keygenreq.pubkey_len; i++)
        printk(KERN_ERR "%0x",req->req_u.dh_keygenreq.pubkey[i]);
    printk(KERN_ERR "\n\n");        
    for(i=0; i<req->req_u.dh_keygenreq.prvkey_len; i++)
        printk(KERN_ERR "%0x",req->req_u.dh_keygenreq.prvkey[i]);
                
    printk(KERN_ERR "\n\n");        
#endif    
    kfree(req->req_u.dh_keygenreq.pubkey);
    kfree(req->req_u.dh_keygenreq.prvkey);
    kfree(req);
    //complete(&serialize_keygen);
    common_dec_count();
}
void init_dh_test_1k(void)
{
	g_dhreq_1k.type = DH_COMPUTE_KEY;

	g_dhreq_1k.req_u.dh_req.pub_key = kzalloc(w1_len, GFP_KERNEL | GFP_DMA);
	memcpy(g_dhreq_1k.req_u.dh_req.pub_key, W1, w1_len);
	g_dhreq_1k.req_u.dh_req.pub_key_len = (w1_len);

	g_dhreq_1k.req_u.dh_req.z = kzalloc(q_len, GFP_KERNEL | GFP_DMA);
	g_dhreq_1k.req_u.dh_req.z_len = q_len;
}

void init_dh_test_2k(void)
{
	g_dhreq_2k.type = DH_COMPUTE_KEY;

	g_dhreq_2k.req_u.dh_req.pub_key = kzalloc(w1_len_2048,
						GFP_KERNEL | GFP_DMA);
	memcpy(g_dhreq_2k.req_u.dh_req.pub_key, W1_2048, w1_len_2048);
	g_dhreq_2k.req_u.dh_req.pub_key_len = (w1_len_2048);


	g_dhreq_2k.req_u.dh_req.z = kzalloc(q_len_2048, GFP_KERNEL | GFP_DMA);
	g_dhreq_2k.req_u.dh_req.z_len = q_len_2048;
}

void init_dh_test_4k(void)
{
	g_dhreq_4k.type = DH_COMPUTE_KEY;


	g_dhreq_4k.req_u.dh_req.pub_key = kzalloc(w1_len_4096,
						GFP_KERNEL | GFP_DMA);
	memcpy(g_dhreq_4k.req_u.dh_req.pub_key, W1_4096, w1_len_4096);
	g_dhreq_4k.req_u.dh_req.pub_key_len = (w1_len_4096);


	g_dhreq_4k.req_u.dh_req.z = kzalloc(q_len_4096, GFP_KERNEL | GFP_DMA);
	g_dhreq_4k.req_u.dh_req.z_len = q_len_4096;
}

void cleanup_dh_test(void)
{
	if(g_dhreq_1k.req_u.dh_req.z)
		kfree(g_dhreq_1k.req_u.dh_req.z);
	if(g_dhreq_2k.req_u.dh_req.z)
		kfree(g_dhreq_2k.req_u.dh_req.z);
	if(g_dhreq_4k.req_u.dh_req.z)
		kfree(g_dhreq_4k.req_u.dh_req.z);

	kfree(g_dhreq_1k.req_u.dh_req.pub_key);
	kfree(g_dhreq_2k.req_u.dh_req.pub_key);
	kfree(g_dhreq_4k.req_u.dh_req.pub_key);
}

int dh_test_1k(void)
{
	if (-1 == test_dh_op(&g_dhreq_1k, dh_done))
		return -1;

	return 0;
}

int dh_test_2k(void)
{
	if (-1 == test_dh_op(&g_dhreq_2k, dh_done))
		return -1;

	return 0;
}

int dh_test_4k(void)
{
	if (-1 == test_dh_op(&g_dhreq_4k, dh_done))
		return -1;

	return 0;
}

int dh_keygen_test(void)
{
    uint8_t *prvkey = kzalloc(20, GFP_KERNEL|GFP_DMA);
    uint8_t *pubkey = kzalloc(128, GFP_KERNEL|GFP_DMA);

    struct pkc_request *req = kzalloc(sizeof(struct pkc_request), GFP_KERNEL);

    uint32_t q_len = sizeof(q);
    uint32_t r_len = sizeof(r);
    uint32_t g_len = sizeof(g);
    uint32_t prvkey_len = 20;
    uint32_t pubkey_len = 128;
    /* Issue the key gen command */
    req->type = DH_KEYGEN;
    req->req_u.dh_keygenreq.q = q;
    req->req_u.dh_keygenreq.r = r;
    req->req_u.dh_keygenreq.g = g;
    req->req_u.dh_keygenreq.ab = NULL;
    req->req_u.dh_keygenreq.pubkey = pubkey;
    req->req_u.dh_keygenreq.prvkey = prvkey;
    req->req_u.dh_keygenreq.q_len = q_len;
    req->req_u.dh_keygenreq.r_len = r_len;
    req->req_u.dh_keygenreq.g_len = g_len;
    req->req_u.dh_keygenreq.ab_len = 0;
    req->req_u.dh_keygenreq.pubkey_len = pubkey_len;
    req->req_u.dh_keygenreq.prvkey_len = prvkey_len;

    //init_completion(&serialize_keygen);

    test_dh_op(req, dh_keygen_done);

    /* Wait for the response */
    //wait_for_completion(&serialize_keygen);

    /* Issue another key gen command */
    /* Wait for the response */

    /* Issue compute key command with prv1 pub2 */
    /* Wait for the response */

    /* Issue compute key command with prv2 pub1 */
    /* Wait for the response */

    /* Compare both the responses */
    return 0;
}
