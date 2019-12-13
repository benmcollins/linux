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

#define PERF_TEST
#define SIMPLE_TEST_ENABLE

/* #include "rsa_test.h" */
extern fsl_pci_dev_t *g_fsl_pci_dev;
extern int test_rsa_pub_op_1k(void);
extern int test_rsa_pub_op_2k(void);
extern int test_rsa_pub_op_4k(void);
extern int rsa_priv2_op_test(void);
extern int test_rsa_priv_op_1k(void);
extern int test_rsa_priv_op_2k(void);
extern int test_rsa_priv_op_4k(void);
extern int dsa_verify_test_1k(void);
extern int dsa_sign_test_1k(void);
extern int dsa_verify_test_2k(void);
extern int dsa_sign_test_2k(void);
extern int dsa_verify_test_4k(void);
extern int dsa_sign_test_4k(void);
extern int dsa_sign_verify_verify_test(struct pkc_request *req);
extern int dsa_sign_verify_test(void);
extern int dsa_keygen_test(void);
extern int ecdsa_verify_test(void);
extern int ecdsa_sign_test(void);
extern int ecp_sign_test_256(void);
extern int ecp_verify_test_256(void);
extern int ecp_sign_test_384(void);
extern int ecp_verify_test_384(void);
extern int ecp_sign_test_521(void);
extern int ecp_verify_test_521(void);
extern int ecpbn_sign_test_283(void);
extern int ecpbn_verify_test_283(void);
extern int ecpbn_sign_test_409(void);
extern int ecpbn_verify_test_409(void);
extern int ecpbn_sign_test_571(void);
extern int ecpbn_verify_test_571(void);
extern int ecdsa_keygen_test(void);
extern int ecdh_test(void);
extern int dh_keygen_test(void);
extern int dh_test_1k(void);
extern int dh_test_2k(void);
extern int dh_test_4k(void);
extern int ecdh_keygen_test_p256(void);
extern int ecdh_keygen_test_p384(void);
extern int ecdh_keygen_test_p521(void);
extern int ecdh_keygen_test_b283(void);
extern int ecdh_keygen_test_b409(void);
extern int ecdh_keygen_test_b571(void);
extern void init_1k_rsa_pub_op_req(void);
extern void init_2k_rsa_pub_op_req(void);
extern void init_4k_rsa_pub_op_req(void);
extern void init_1k_rsa_prv3_op_req(void);
extern void init_2k_rsa_prv3_op_req(void);
extern void init_4k_rsa_prv3_op_req(void);
extern void init_dsa_verify_test_1k(void);
extern void init_dsa_sign_test_1k(void);
extern void init_dsa_verify_test_2k(void);
extern void init_dsa_sign_test_2k(void);
extern void init_dsa_verify_test_4k(void);
extern void init_dsa_sign_test_4k(void);
extern void init_ecdh_test(void);
extern void init_ecdsa_verify_test(void);
extern void init_ecdsa_sign_test(void);
extern void init_ecp_sign_test_256(void);
extern void init_ecp_verify_test_256(void);
extern void init_ecp_sign_test_384(void);
extern void init_ecp_verify_test_384(void);
extern void init_ecp_sign_test_521(void);
extern void init_ecp_verify_test_521(void);
extern void init_ecpbn_sign_test_283(void);
extern void init_ecpbn_verify_test_283(void);
extern void init_ecpbn_sign_test_409(void);
extern void init_ecpbn_verify_test_409(void);
extern void init_ecpbn_sign_test_571(void);
extern void init_ecpbn_verify_test_571(void);
extern void init_dh_test_1k(void);
extern void init_dh_test_2k(void);
extern void init_dh_test_4k(void);
extern void init_ecdh_keygen_test_p256(void);
extern void init_ecdh_keygen_test_p384(void);
extern void init_ecdh_keygen_test_p521(void);
extern void init_ecdh_keygen_test_b283(void);
extern void init_ecdh_keygen_test_b409(void);
extern void init_ecdh_keygen_test_b571(void);

extern void cleanup_rsa_test(void);
extern void cleanup_dsa_test(void);
extern void cleanup_ecdh_test(void);
extern void cleanup_ecdsa_test(void);
extern void cleanup_dh_test(void);
extern void cleanup_ecp_test(void);
extern void cleanup_ecpbn_test(void);
extern void cleanup_ecdh_keygen_test(void);

/* extern inline void check_test_done(void); */
extern void common_dec_count(void);
extern void timer_test_done_check(void);
extern void init_all_test(void);
extern void clean_all_test(void);
/* extern void check_test_done(void); */
extern atomic_t total_deq_cnt;
extern atomic_t total_enq_cnt;
