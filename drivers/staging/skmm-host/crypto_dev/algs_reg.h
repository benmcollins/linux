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

#ifndef __ALGS_REG_H__
#define __ALGS_REG_H__

#include "compat.h"
#include "desc.h"

#define FSL_CRA_PRIORITY 4000

#ifndef VIRTIO_C2X0
extern int32_t fsl_algapi_init(void);
extern void fsl_algapi_exit(void);

extern int rsa_op(struct pkc_request *req);
extern int dsa_op(struct pkc_request *req);
extern int dh_op(struct pkc_request *req);

extern int ahash_import(struct ahash_request *req, const void *in);
extern int ahash_export(struct ahash_request *req, void *out);
extern int ahash_final(struct ahash_request *req);
extern int ahash_finup(struct ahash_request *req);
extern int ahash_update(struct ahash_request *req);
extern int ahash_init(struct ahash_request *req);
extern int ahash_digest(struct ahash_request *req);
extern int ahash_setkey(struct crypto_ahash *ahash,
			const uint8_t *key, unsigned int keylen);

extern int fsl_ablkcipher_setkey(struct crypto_ablkcipher *ablkcipher,
				 const u8 *key, unsigned int keylen);
extern int fsl_ablkcipher_decrypt(struct ablkcipher_request *req);
extern int fsl_ablkcipher_encrypt(struct ablkcipher_request *req);
#endif

/*struct list_head alg_list;*/

struct fsl_crypto_alg {
	struct list_head entry;
	int op_type;
	int alg_type;
	int alg_op;
	int class1_alg_type;
	int class2_alg_type;
	bool ahash;
	union {
		struct crypto_alg crypto_alg;
		struct ahash_alg ahash_alg;
	} u;
};

struct alg_template {
	char name[CRYPTO_MAX_ALG_NAME];
	char driver_name[CRYPTO_MAX_ALG_NAME];
	char hmac_name[CRYPTO_MAX_ALG_NAME];
	char hmac_driver_name[CRYPTO_MAX_ALG_NAME];

	uint32_t blocksize;
	uint32_t type;
	union {
		struct pkc_alg pkc;
		struct ahash_alg ahash;
		struct aead_alg aead;
		struct ablkcipher_alg blkcipher;
	} u;
	uint32_t alg_type;
	uint32_t alg_op;
	uint32_t class1_alg_type;
	uint32_t class2_alg_type;
};
#if 0
static struct alg_template driver_algs[] = {
	{
	 .name = "pkc(rsa)",
	 .driver_name = "pkc-rsa-fsl",
	 .blocksize = 0,
	 .type = CRYPTO_ALG_TYPE_PKC_RSA,
	 .u.pkc = {
		   .pkc_op = rsa_op,
		   .min_keysize = 512,
		   .max_keysize = 4096,
		   },
	 },

	{
	 .name = "pkc(dsa)",
	 .driver_name = "pkc-dsa-fsl",
	 .blocksize = 0,
	 .type = CRYPTO_ALG_TYPE_PKC_DSA,
	 .u.pkc = {
		   .pkc_op = dsa_op,
		   .min_keysize = 512,
		   .max_keysize = 4096,
		   },
	 },
	{
	 .name = "pkc(dh)",
	 .driver_name = "pkc-dh-fsl",
	 .type = CRYPTO_ALG_TYPE_PKC_DH,
	 .u.pkc = {
		   .pkc_op = dh_op,
		   .min_keysize = 512,
		   .max_keysize = 4096,
		   },
	 },
#if 0
	{
	 .name = "sha1",
	 .driver_name = "sha1-fsl",
	 .hmac_name = "hmac(sha1)",
	 .hmac_driver_name = "hmac-sha1-fsl",
	 .blocksize = SHA1_BLOCK_SIZE,
	 .type = CRYPTO_ALG_TYPE_AHASH,
	 .u.ahash = {
		     .init = ahash_init,
		     .update = ahash_update,
		     .final = ahash_final,
		     .finup = ahash_finup,
		     .digest = ahash_digest,
		     .export = ahash_export,
		     .import = ahash_import,
		     .setkey = ahash_setkey,
		     .halg = {
			      .digestsize = SHA1_DIGEST_SIZE,
			      },
		     },
	 .alg_type = OP_ALG_ALGSEL_SHA1,
	 .alg_op = OP_ALG_ALGSEL_SHA1 | OP_ALG_AAI_HMAC,
	 }, {
	     .name = "sha224",
	     .driver_name = "sha224-fsl",
	     .hmac_name = "hmac(sha224)",
	     .hmac_driver_name = "hmac-sha224-fsl",
	     .blocksize = SHA224_BLOCK_SIZE,
	     .type = CRYPTO_ALG_TYPE_AHASH,
	     .u.ahash = {
			 .init = ahash_init,
			 .update = ahash_update,
			 .final = ahash_final,
			 .finup = ahash_finup,
			 .digest = ahash_digest,
			 .export = ahash_export,
			 .import = ahash_import,
			 .setkey = ahash_setkey,
			 .halg = {
				  .digestsize = SHA224_DIGEST_SIZE,
				  },
			 },
	     .alg_type = OP_ALG_ALGSEL_SHA224,
	     .alg_op = OP_ALG_ALGSEL_SHA224 | OP_ALG_AAI_HMAC,
	     }, {
		 .name = "sha256",
		 .driver_name = "sha256-fsl",
		 .hmac_name = "hmac(sha256)",
		 .hmac_driver_name = "hmac-sha256-fsl",
		 .blocksize = SHA256_BLOCK_SIZE,
		 .type = CRYPTO_ALG_TYPE_AHASH,
		 .u.ahash = {
			     .init = ahash_init,
			     .update = ahash_update,
			     .final = ahash_final,
			     .finup = ahash_finup,
			     .digest = ahash_digest,
			     .export = ahash_export,
			     .import = ahash_import,
			     .setkey = ahash_setkey,
			     .halg = {
				      .digestsize = SHA256_DIGEST_SIZE,
				      },
			     },
		 .alg_type = OP_ALG_ALGSEL_SHA256,
		 .alg_op = OP_ALG_ALGSEL_SHA256 | OP_ALG_AAI_HMAC,
		 }, {
		     .name = "sha384",
		     .driver_name = "sha384-fsl",
		     .hmac_name = "hmac(sha384)",
		     .hmac_driver_name = "hmac-sha384-fsl",
		     .blocksize = SHA384_BLOCK_SIZE,
		     .type = CRYPTO_ALG_TYPE_AHASH,
		     .u.ahash = {
				 .init = ahash_init,
				 .update = ahash_update,
				 .final = ahash_final,
				 .finup = ahash_finup,
				 .digest = ahash_digest,
				 .export = ahash_export,
				 .import = ahash_import,
				 .setkey = ahash_setkey,
				 .halg = {
					  .digestsize = SHA384_DIGEST_SIZE,
					  },
				 },
		     .alg_type = OP_ALG_ALGSEL_SHA384,
		     .alg_op = OP_ALG_ALGSEL_SHA384 | OP_ALG_AAI_HMAC,
		     }, {
			 .name = "sha512",
			 .driver_name = "sha512-fsl",
			 .hmac_name = "hmac(sha512)",
			 .hmac_driver_name = "hmac-sha512-fsl",
			 .blocksize = SHA512_BLOCK_SIZE,
			 .type = CRYPTO_ALG_TYPE_AHASH,
			 .u.ahash = {
				     .init = ahash_init,
				     .update = ahash_update,
				     .final = ahash_final,
				     .finup = ahash_finup,
				     .digest = ahash_digest,
				     .export = ahash_export,
				     .import = ahash_import,
				     .setkey = ahash_setkey,
				     .halg = {
					      .digestsize = SHA512_DIGEST_SIZE,
					      },
				     },
			 .alg_type = OP_ALG_ALGSEL_SHA512,
			 .alg_op = OP_ALG_ALGSEL_SHA512 | OP_ALG_AAI_HMAC,
			 }, {
			     .name = "md5",
			     .driver_name = "md5-fsl",
			     .hmac_name = "hmac(md5)",
			     .hmac_driver_name = "hmac-md5-fsl",
			     .blocksize = MD5_BLOCK_WORDS * 4,
			     .type = CRYPTO_ALG_TYPE_AHASH,
			     .u.ahash = {
					 .init = ahash_init,
					 .update = ahash_update,
					 .final = ahash_final,
					 .finup = ahash_finup,
					 .digest = ahash_digest,
					 .export = ahash_export,
					 .import = ahash_import,
					 .setkey = ahash_setkey,
					 .halg = {
						  .digestsize = MD5_DIGEST_SIZE,
						  },
					 },
			     .alg_type = OP_ALG_ALGSEL_MD5,
			     .alg_op = OP_ALG_ALGSEL_MD5 | OP_ALG_AAI_HMAC,
			     },
	/* single-pass ipsec_esp descriptor */
	{
	 .name = "authenc(hmac(md5),cbc(aes))",
	 .driver_name = "authenc-hmac-md5-cbc-aes-fsl",
	 .blocksize = AES_BLOCK_SIZE,
	 .type = CRYPTO_ALG_TYPE_AEAD,
	 .u.aead = {
		    .setkey = fsl_aead_setkey,
		    .setauthsize = fsl_aead_setauthsize,
		    .encrypt = fsl_aead_encrypt,
		    .decrypt = aead_decrypt,
		    .givencrypt = aead_givencrypt,
		    .geniv = "<built-in>",
		    .ivsize = AES_BLOCK_SIZE,
		    .maxauthsize = MD5_DIGEST_SIZE,
		    },
	 .class1_alg_type = OP_ALG_ALGSEL_AES | OP_ALG_AAI_CBC,
	 .class2_alg_type = OP_ALG_ALGSEL_MD5 | OP_ALG_AAI_HMAC_PRECOMP,
	 .alg_op = OP_ALG_ALGSEL_MD5 | OP_ALG_AAI_HMAC,
	 },
	{
	 .name = "authenc(hmac(sha1),cbc(aes))",
	 .driver_name = "authenc-hmac-sha1-cbc-aes-fsl",
	 .blocksize = AES_BLOCK_SIZE,
	 .type = CRYPTO_ALG_TYPE_AEAD,
	 .u.aead = {
		    .setkey = fsl_aead_setkey,
		    .setauthsize = fsl_aead_setauthsize,
		    .encrypt = fsl_aead_encrypt,
		    .decrypt = aead_decrypt,
		    .givencrypt = aead_givencrypt,
		    .geniv = "<built-in>",
		    .ivsize = AES_BLOCK_SIZE,
		    .maxauthsize = SHA1_DIGEST_SIZE,
		    },
	 .class1_alg_type = OP_ALG_ALGSEL_AES | OP_ALG_AAI_CBC,
	 .class2_alg_type = OP_ALG_ALGSEL_SHA1 | OP_ALG_AAI_HMAC_PRECOMP,
	 .alg_op = OP_ALG_ALGSEL_SHA1 | OP_ALG_AAI_HMAC,
	 },
	{
	 .name = "authenc(hmac(sha224),cbc(aes))",
	 .driver_name = "authenc-hmac-sha224-cbc-aes-fsl",
	 .blocksize = AES_BLOCK_SIZE,
	 .u.aead = {
		    .setkey = fsl_aead_setkey,
		    .setauthsize = fsl_aead_setauthsize,
		    .encrypt = fsl_aead_encrypt,
		    .decrypt = aead_decrypt,
		    .givencrypt = aead_givencrypt,
		    .geniv = "<built-in>",
		    .ivsize = AES_BLOCK_SIZE,
		    .maxauthsize = SHA224_DIGEST_SIZE,
		    },
	 .class1_alg_type = OP_ALG_ALGSEL_AES | OP_ALG_AAI_CBC,
	 .class2_alg_type = OP_ALG_ALGSEL_SHA224 | OP_ALG_AAI_HMAC_PRECOMP,
	 .alg_op = OP_ALG_ALGSEL_SHA224 | OP_ALG_AAI_HMAC,
	 },
	{
	 .name = "authenc(hmac(sha256),cbc(aes))",
	 .driver_name = "authenc-hmac-sha256-cbc-aes-fsl",
	 .blocksize = AES_BLOCK_SIZE,
	 .type = CRYPTO_ALG_TYPE_AEAD,
	 .u.aead = {
		    .setkey = fsl_aead_setkey,
		    .setauthsize = fsl_aead_setauthsize,
		    .encrypt = fsl_aead_encrypt,
		    .decrypt = aead_decrypt,
		    .givencrypt = aead_givencrypt,
		    .geniv = "<built-in>",
		    .ivsize = AES_BLOCK_SIZE,
		    .maxauthsize = SHA256_DIGEST_SIZE,
		    },
	 .class1_alg_type = OP_ALG_ALGSEL_AES | OP_ALG_AAI_CBC,
	 .class2_alg_type = OP_ALG_ALGSEL_SHA256 | OP_ALG_AAI_HMAC_PRECOMP,
	 .alg_op = OP_ALG_ALGSEL_SHA256 | OP_ALG_AAI_HMAC,
	 },
	{
	 .name = "authenc(hmac(sha384),cbc(aes))",
	 .driver_name = "authenc-hmac-sha384-cbc-aes-fsl",
	 .blocksize = AES_BLOCK_SIZE,
	 .u.aead = {
		    .setkey = fsl_aead_setkey,
		    .setauthsize = fsl_aead_setauthsize,
		    .encrypt = fsl_aead_encrypt,
		    .decrypt = aead_decrypt,
		    .givencrypt = aead_givencrypt,
		    .geniv = "<built-in>",
		    .ivsize = AES_BLOCK_SIZE,
		    .maxauthsize = SHA384_DIGEST_SIZE,
		    },
	 .class1_alg_type = OP_ALG_ALGSEL_AES | OP_ALG_AAI_CBC,
	 .class2_alg_type = OP_ALG_ALGSEL_SHA384 | OP_ALG_AAI_HMAC_PRECOMP,
	 .alg_op = OP_ALG_ALGSEL_SHA384 | OP_ALG_AAI_HMAC,
	 },

	{
	 .name = "authenc(hmac(sha512),cbc(aes))",
	 .driver_name = "authenc-hmac-sha512-cbc-aes-fsl",
	 .blocksize = AES_BLOCK_SIZE,
	 .type = CRYPTO_ALG_TYPE_AEAD,
	 .u.aead = {
		    .setkey = fsl_aead_setkey,
		    .setauthsize = fsl_aead_setauthsize,
		    .encrypt = fsl_aead_encrypt,
		    .decrypt = aead_decrypt,
		    .givencrypt = aead_givencrypt,
		    .geniv = "<built-in>",
		    .ivsize = AES_BLOCK_SIZE,
		    .maxauthsize = SHA512_DIGEST_SIZE,
		    },
	 .class1_alg_type = OP_ALG_ALGSEL_AES | OP_ALG_AAI_CBC,
	 .class2_alg_type = OP_ALG_ALGSEL_SHA512 | OP_ALG_AAI_HMAC_PRECOMP,
	 .alg_op = OP_ALG_ALGSEL_SHA512 | OP_ALG_AAI_HMAC,
	 },
	{
	 .name = "authenc(hmac(md5),cbc(des3_ede))",
	 .driver_name = "authenc-hmac-md5-cbc-des3_ede-fsl",
	 .blocksize = DES3_EDE_BLOCK_SIZE,
	 .type = CRYPTO_ALG_TYPE_AEAD,
	 .u.aead = {
		    .setkey = fsl_aead_setkey,
		    .setauthsize = fsl_aead_setauthsize,
		    .encrypt = fsl_aead_encrypt,
		    .decrypt = aead_decrypt,
		    .givencrypt = aead_givencrypt,
		    .geniv = "<built-in>",
		    .ivsize = DES3_EDE_BLOCK_SIZE,
		    .maxauthsize = MD5_DIGEST_SIZE,
		    },
	 .class1_alg_type = OP_ALG_ALGSEL_3DES | OP_ALG_AAI_CBC,
	 .class2_alg_type = OP_ALG_ALGSEL_MD5 | OP_ALG_AAI_HMAC_PRECOMP,
	 .alg_op = OP_ALG_ALGSEL_MD5 | OP_ALG_AAI_HMAC,
	 },
	{
	 .name = "authenc(hmac(sha1),cbc(des3_ede))",
	 .driver_name = "authenc-hmac-sha1-cbc-des3_ede-fsl",
	 .blocksize = DES3_EDE_BLOCK_SIZE,
	 .type = CRYPTO_ALG_TYPE_AEAD,
	 .u.aead = {
		    .setkey = fsl_aead_setkey,
		    .setauthsize = fsl_aead_setauthsize,
		    .encrypt = fsl_aead_encrypt,
		    .decrypt = aead_decrypt,
		    .givencrypt = aead_givencrypt,
		    .geniv = "<built-in>",
		    .ivsize = DES3_EDE_BLOCK_SIZE,
		    .maxauthsize = SHA1_DIGEST_SIZE,
		    },
	 .class1_alg_type = OP_ALG_ALGSEL_3DES | OP_ALG_AAI_CBC,
	 .class2_alg_type = OP_ALG_ALGSEL_SHA1 | OP_ALG_AAI_HMAC_PRECOMP,
	 .alg_op = OP_ALG_ALGSEL_SHA1 | OP_ALG_AAI_HMAC,
	 },
	{
	 .name = "authenc(hmac(sha224),cbc(des3_ede))",
	 .driver_name = "authenc-hmac-sha224-cbc-des3_ede-fsl",
	 .blocksize = DES3_EDE_BLOCK_SIZE,
	 .u.aead = {
		    .setkey = fsl_aead_setkey,
		    .setauthsize = fsl_aead_setauthsize,
		    .encrypt = fsl_aead_encrypt,
		    .decrypt = aead_decrypt,
		    .givencrypt = aead_givencrypt,
		    .geniv = "<built-in>",
		    .ivsize = DES3_EDE_BLOCK_SIZE,
		    .maxauthsize = SHA224_DIGEST_SIZE,
		    },
	 .class1_alg_type = OP_ALG_ALGSEL_3DES | OP_ALG_AAI_CBC,
	 .class2_alg_type = OP_ALG_ALGSEL_SHA224 | OP_ALG_AAI_HMAC_PRECOMP,
	 .alg_op = OP_ALG_ALGSEL_SHA224 | OP_ALG_AAI_HMAC,
	 },
	{
	 .name = "authenc(hmac(sha256),cbc(des3_ede))",
	 .driver_name = "authenc-hmac-sha256-cbc-des3_ede-fsl",
	 .blocksize = DES3_EDE_BLOCK_SIZE,
	 .type = CRYPTO_ALG_TYPE_AEAD,
	 .u.aead = {
		    .setkey = fsl_aead_setkey,
		    .setauthsize = fsl_aead_setauthsize,
		    .encrypt = fsl_aead_encrypt,
		    .decrypt = aead_decrypt,
		    .givencrypt = aead_givencrypt,
		    .geniv = "<built-in>",
		    .ivsize = DES3_EDE_BLOCK_SIZE,
		    .maxauthsize = SHA256_DIGEST_SIZE,
		    },
	 .class1_alg_type = OP_ALG_ALGSEL_3DES | OP_ALG_AAI_CBC,
	 .class2_alg_type = OP_ALG_ALGSEL_SHA256 | OP_ALG_AAI_HMAC_PRECOMP,
	 .alg_op = OP_ALG_ALGSEL_SHA256 | OP_ALG_AAI_HMAC,
	 },
	{
	 .name = "authenc(hmac(sha384),cbc(des3_ede))",
	 .driver_name = "authenc-hmac-sha384-cbc-des3_ede-fsl",
	 .blocksize = DES3_EDE_BLOCK_SIZE,
	 .u.aead = {
		    .setkey = fsl_aead_setkey,
		    .setauthsize = fsl_aead_setauthsize,
		    .encrypt = fsl_aead_encrypt,
		    .decrypt = aead_decrypt,
		    .givencrypt = aead_givencrypt,
		    .geniv = "<built-in>",
		    .ivsize = DES3_EDE_BLOCK_SIZE,
		    .maxauthsize = SHA384_DIGEST_SIZE,
		    },
	 .class1_alg_type = OP_ALG_ALGSEL_3DES | OP_ALG_AAI_CBC,
	 .class2_alg_type = OP_ALG_ALGSEL_SHA384 | OP_ALG_AAI_HMAC_PRECOMP,
	 .alg_op = OP_ALG_ALGSEL_SHA384 | OP_ALG_AAI_HMAC,
	 },
	{
	 .name = "authenc(hmac(sha512),cbc(des3_ede))",
	 .driver_name = "authenc-hmac-sha512-cbc-des3_ede-fsl",
	 .blocksize = DES3_EDE_BLOCK_SIZE,
	 .type = CRYPTO_ALG_TYPE_AEAD,
	 .u.aead = {
		    .setkey = fsl_aead_setkey,
		    .setauthsize = fsl_aead_setauthsize,
		    .encrypt = fsl_aead_encrypt,
		    .decrypt = aead_decrypt,
		    .givencrypt = aead_givencrypt,
		    .geniv = "<built-in>",
		    .ivsize = DES3_EDE_BLOCK_SIZE,
		    .maxauthsize = SHA512_DIGEST_SIZE,
		    },
	 .class1_alg_type = OP_ALG_ALGSEL_3DES | OP_ALG_AAI_CBC,
	 .class2_alg_type = OP_ALG_ALGSEL_SHA512 | OP_ALG_AAI_HMAC_PRECOMP,
	 .alg_op = OP_ALG_ALGSEL_SHA512 | OP_ALG_AAI_HMAC,
	 },
	{
	 .name = "authenc(hmac(md5),cbc(des))",
	 .driver_name = "authenc-hmac-md5-cbc-des-fsl",
	 .blocksize = DES_BLOCK_SIZE,
	 .type = CRYPTO_ALG_TYPE_AEAD,
	 .u.aead = {
		    .setkey = fsl_aead_setkey,
		    .setauthsize = fsl_aead_setauthsize,
		    .encrypt = fsl_aead_encrypt,
		    .decrypt = aead_decrypt,
		    .givencrypt = aead_givencrypt,
		    .geniv = "<built-in>",
		    .ivsize = DES_BLOCK_SIZE,
		    .maxauthsize = MD5_DIGEST_SIZE,
		    },
	 .class1_alg_type = OP_ALG_ALGSEL_DES | OP_ALG_AAI_CBC,
	 .class2_alg_type = OP_ALG_ALGSEL_MD5 | OP_ALG_AAI_HMAC_PRECOMP,
	 .alg_op = OP_ALG_ALGSEL_MD5 | OP_ALG_AAI_HMAC,
	 },
	{
	 .name = "authenc(hmac(sha1),cbc(des))",
	 .driver_name = "authenc-hmac-sha1-cbc-des-fsl",
	 .blocksize = DES_BLOCK_SIZE,
	 .type = CRYPTO_ALG_TYPE_AEAD,
	 .u.aead = {
		    .setkey = fsl_aead_setkey,
		    .setauthsize = fsl_aead_setauthsize,
		    .encrypt = fsl_aead_encrypt,
		    .decrypt = aead_decrypt,
		    .givencrypt = aead_givencrypt,
		    .geniv = "<built-in>",
		    .ivsize = DES_BLOCK_SIZE,
		    .maxauthsize = SHA1_DIGEST_SIZE,
		    },
	 .class1_alg_type = OP_ALG_ALGSEL_DES | OP_ALG_AAI_CBC,
	 .class2_alg_type = OP_ALG_ALGSEL_SHA1 | OP_ALG_AAI_HMAC_PRECOMP,
	 .alg_op = OP_ALG_ALGSEL_SHA1 | OP_ALG_AAI_HMAC,
	 },
	{
	 .name = "authenc(hmac(sha224),cbc(des))",
	 .driver_name = "authenc-hmac-sha224-cbc-des-fsl",
	 .blocksize = DES_BLOCK_SIZE,
	 .u.aead = {
		    .setkey = fsl_aead_setkey,
		    .setauthsize = fsl_aead_setauthsize,
		    .encrypt = fsl_aead_encrypt,
		    .decrypt = aead_decrypt,
		    .givencrypt = aead_givencrypt,
		    .geniv = "<built-in>",
		    .ivsize = DES_BLOCK_SIZE,
		    .maxauthsize = SHA224_DIGEST_SIZE,
		    },
	 .class1_alg_type = OP_ALG_ALGSEL_DES | OP_ALG_AAI_CBC,
	 .class2_alg_type = OP_ALG_ALGSEL_SHA224 | OP_ALG_AAI_HMAC_PRECOMP,
	 .alg_op = OP_ALG_ALGSEL_SHA224 | OP_ALG_AAI_HMAC,
	 },
	{
	 .name = "authenc(hmac(sha256),cbc(des))",
	 .driver_name = "authenc-hmac-sha256-cbc-des-fsl",
	 .blocksize = DES_BLOCK_SIZE,
	 .type = CRYPTO_ALG_TYPE_AEAD,
	 .u.aead = {
		    .setkey = fsl_aead_setkey,
		    .setauthsize = fsl_aead_setauthsize,
		    .encrypt = fsl_aead_encrypt,
		    .decrypt = aead_decrypt,
		    .givencrypt = aead_givencrypt,
		    .geniv = "<built-in>",
		    .ivsize = DES_BLOCK_SIZE,
		    .maxauthsize = SHA256_DIGEST_SIZE,
		    },
	 .class1_alg_type = OP_ALG_ALGSEL_DES | OP_ALG_AAI_CBC,
	 .class2_alg_type = OP_ALG_ALGSEL_SHA256 | OP_ALG_AAI_HMAC_PRECOMP,
	 .alg_op = OP_ALG_ALGSEL_SHA256 | OP_ALG_AAI_HMAC,
	 },
	{
	 .name = "authenc(hmac(sha384),cbc(des))",
	 .driver_name = "authenc-hmac-sha384-cbc-des-fsl",
	 .blocksize = DES_BLOCK_SIZE,
	 .u.aead = {
		    .setkey = fsl_aead_setkey,
		    .setauthsize = fsl_aead_setauthsize,
		    .encrypt = fsl_aead_encrypt,
		    .decrypt = aead_decrypt,
		    .givencrypt = aead_givencrypt,
		    .geniv = "<built-in>",
		    .ivsize = DES_BLOCK_SIZE,
		    .maxauthsize = SHA384_DIGEST_SIZE,
		    },
	 .class1_alg_type = OP_ALG_ALGSEL_DES | OP_ALG_AAI_CBC,
	 .class2_alg_type = OP_ALG_ALGSEL_SHA384 | OP_ALG_AAI_HMAC_PRECOMP,
	 .alg_op = OP_ALG_ALGSEL_SHA384 | OP_ALG_AAI_HMAC,
	 },
	{
	 .name = "authenc(hmac(sha512),cbc(des))",
	 .driver_name = "authenc-hmac-sha512-cbc-des-fsl",
	 .blocksize = DES_BLOCK_SIZE,
	 .type = CRYPTO_ALG_TYPE_AEAD,
	 .u.aead = {
		    .setkey = fsl_aead_setkey,
		    .setauthsize = fsl_aead_setauthsize,
		    .encrypt = fsl_aead_encrypt,
		    .decrypt = aead_decrypt,
		    .givencrypt = aead_givencrypt,
		    .geniv = "<built-in>",
		    .ivsize = DES_BLOCK_SIZE,
		    .maxauthsize = SHA512_DIGEST_SIZE,
		    },
	 .class1_alg_type = OP_ALG_ALGSEL_DES | OP_ALG_AAI_CBC,
	 .class2_alg_type = OP_ALG_ALGSEL_SHA512 | OP_ALG_AAI_HMAC_PRECOMP,
	 .alg_op = OP_ALG_ALGSEL_SHA512 | OP_ALG_AAI_HMAC,
	 },

	/* ablkcipher descriptor */
	{
	 .name = "cbc(aes)",
	 .driver_name = "cbc-aes-fsl",
	 .blocksize = AES_BLOCK_SIZE,
	 .type = CRYPTO_ALG_TYPE_ABLKCIPHER,
	 .u.blkcipher = {
			 .setkey = fsl_ablkcipher_setkey,
			 .encrypt = fsl_ablkcipher_encrypt,
			 .decrypt = fsl_ablkcipher_decrypt,
			 .geniv = "eseqiv",
			 .min_keysize = AES_MIN_KEY_SIZE,
			 .max_keysize = AES_MAX_KEY_SIZE,
			 .ivsize = AES_BLOCK_SIZE,
			 },
	 .class1_alg_type = OP_ALG_ALGSEL_AES | OP_ALG_AAI_CBC,
	 },
	{
	 .name = "cbc(des3_ede)",
	 .driver_name = "cbc-3des-fsl",
	 .blocksize = DES3_EDE_BLOCK_SIZE,
	 .type = CRYPTO_ALG_TYPE_ABLKCIPHER,
	 .u.blkcipher = {
			 .setkey = fsl_ablkcipher_setkey,
			 .encrypt = fsl_ablkcipher_encrypt,
			 .decrypt = fsl_ablkcipher_decrypt,
			 .geniv = "eseqiv",
			 .min_keysize = DES3_EDE_KEY_SIZE,
			 .max_keysize = DES3_EDE_KEY_SIZE,
			 .ivsize = DES3_EDE_BLOCK_SIZE,
			 },
	 .class1_alg_type = OP_ALG_ALGSEL_3DES | OP_ALG_AAI_CBC,
	 },
	{
	 .name = "cbc(des)",
	 .driver_name = "cbc-des-fsl",
	 .blocksize = DES_BLOCK_SIZE,
	 .type = CRYPTO_ALG_TYPE_ABLKCIPHER,
	 .u.blkcipher = {
			 .setkey = fsl_ablkcipher_setkey,
			 .encrypt = fsl_ablkcipher_encrypt,
			 .decrypt = fsl_ablkcipher_decrypt,
			 .geniv = "eseqiv",
			 .min_keysize = DES_KEY_SIZE,
			 .max_keysize = DES_KEY_SIZE,
			 .ivsize = DES_BLOCK_SIZE,
			 },
	 .class1_alg_type = OP_ALG_ALGSEL_DES | OP_ALG_AAI_CBC,
	 }
#endif
};
#endif
#endif
