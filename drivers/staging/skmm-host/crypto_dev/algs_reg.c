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

#include "algs_reg.h"
#include "common.h"
#include "fsl_c2x0_crypto_layer.h"
#include "fsl_c2x0_driver.h"
#include "algs.h"
#include "memmgr.h"
#ifdef VIRTIO_C2X0
#include "fsl_c2x0_virtio.h"
#endif

/* Global Varibales*/
atomic_t selected_devices;
struct list_head alg_list;

#ifndef VIRTIO_C2X0
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
#ifdef HASH_OFFLOAD
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
#endif
#ifdef SYMMETRIC_OFFLOAD
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
#endif /* VIRTIO_C2X0 */

/*****************************************************************************
 * Function     : fill_crypto_dev_sess_ctx
 *
 * Arguments    : ctx
 *              : op_type
 *
 * Return Value : void
 *
 * Description  : Fill the cryptodev context.
 *
 *****************************************************************************/

int fill_crypto_dev_sess_ctx(crypto_dev_sess_t *ctx, uint32_t op_type)
{
	fsl_h_rsrc_ring_pair_t *rp = NULL;
	uint32_t no_of_app_rings = 0;
	uint32_t no_of_devices = 0;
#ifndef HIGH_PERF
	uint32_t  new_device = 0;
	int device_status = 0, count = 0, cpu = 0;
	per_dev_struct_t *dev_stat = NULL;
	uint32_t loop_cnt = 0;
#endif

	no_of_devices = get_no_of_devices();
	if (0 >= no_of_devices) {
		print_error("No Device configured\n");
		return -1;
	}

#ifndef HIGH_PERF
	while (!device_status && count < no_of_devices) {
		new_device =
		    ((atomic_inc_return(&selected_devices) -
		      1) % no_of_devices) + 1;
		ctx->c_dev = get_crypto_dev(new_device);
		if (!ctx->c_dev) {
			print_error
			    ("Could not retrieve the device structure.\n");
			return -1;
		}
		cpu = get_cpu();
		dev_stat = per_cpu_ptr(ctx->c_dev->dev_status, cpu);
		put_cpu();

		device_status = atomic_read(&(dev_stat->device_status));
		if (device_status) {
			count = 0;
			break;
		}
		count++;
		if (++loop_cnt > 1000000) {
			print_error("Could not get an active device\n");
			return -1;
		}
	}
	if (!device_status) {
		print_error("No Device is ALIVE\n");
		return -1;
	}
#else
    ctx->c_dev = get_crypto_dev(1);
#endif

	no_of_app_rings = ctx->c_dev->num_of_rings - 1;

	/* Select the ring in which this job has to be posted. */

	if (0 < no_of_app_rings)
		ctx->r_id =
		    ((atomic_inc_return(&ctx->c_dev->crypto_dev_sess_cnt) -
		      1) % no_of_app_rings) + 1;
	else {
		print_error("No application ring configured\n");
		return -1;
	}

	print_debug("C dev num of rings [%d] r_id [%d]\n",
		    ctx->c_dev->num_of_rings, ctx->r_id);

	/* For symmetric algos all the job under same session should
	 * go to same sec engine. Hence selecting one of the sec engine
	 * for the ring pair. This sec engine selection will be passed
	 * to firmware and firmware will enqueue the job to selected sec engine
	 */
#define NO_SEC_ENGINE_ASSIGNED          -1

	if (SYMMETRIC == op_type) {
		rp = (&ctx->c_dev->ring_pairs[ctx->r_id]);
		if (ctx->sec_eng == NO_SEC_ENGINE_ASSIGNED) {
			ctx->sec_eng =
			    atomic_inc_return(&(rp->sec_eng_sel)) &
			    (rp->num_of_sec_engines);
		}
	}
	return 0;
}

#ifdef HASH_OFFLOAD
/*****************************************************************************
 * Function     : hash_cra_init
 *
 * Arguments    : tfm
 *
 * Return Value : Error code
 *
 * Description  : cra_init for crypto_alg to setup the context.
 *
 ****************************************************************************/
#ifdef VIRTIO_C2X0
int hash_cra_init(struct virtio_c2x0_job_ctx *virtio_job)
#else
static int hash_cra_init(struct crypto_tfm *tfm)
#endif
{
	fsl_crypto_dev_t *c_dev = NULL;
	uint32_t r_id = 0;
	void *mempool = NULL;
#ifdef VIRTIO_C2X0
	struct virtio_c2x0_crypto_sess_ctx *hash_sess = NULL;
	crypto_dev_sess_t *ctx = NULL;
	struct hash_ctx *hctx = NULL;
	struct virtio_c2x0_qemu_cmd *qemu_cmd = &virtio_job->qemu_cmd;
	struct virtio_c2x0_crypto_sess_ctx *cur_sess = NULL, *next_sess = NULL;
#else
	struct crypto_ahash *ahash = __crypto_ahash_cast(tfm);
	struct crypto_alg *base = tfm->__crt_alg;
	struct hash_alg_common *halg =
	    container_of(base, struct hash_alg_common, base);
	struct ahash_alg *alg = container_of(halg, struct ahash_alg, halg);
	struct fsl_crypto_alg *fsl_alg =
	    container_of(alg, struct fsl_crypto_alg, u.ahash_alg);
	crypto_dev_sess_t *ctx = crypto_tfm_ctx(tfm);
	struct hash_ctx *hctx = &ctx->u.hash;
#endif

	/* Sizes for MDHA running digests: MD5, SHA1, 224, 256, 384, 512 */
	static const u8 runninglen[] = { HASH_MSG_LEN + MD5_DIGEST_SIZE,
		HASH_MSG_LEN + SHA1_DIGEST_SIZE,
		HASH_MSG_LEN + 32,
		HASH_MSG_LEN + SHA256_DIGEST_SIZE,
		HASH_MSG_LEN + 64,
		HASH_MSG_LEN + SHA512_DIGEST_SIZE
	};
#ifdef VIRTIO_C2X0
	/*
	 * Creating a special hash session
	 * context for each hash operation from VM
	 */
	hash_sess = (struct virtio_c2x0_crypto_sess_ctx *)
	    kzalloc(sizeof(struct virtio_c2x0_crypto_sess_ctx), GFP_KERNEL);
	if (!hash_sess) {
		print_error("virtio_c2x0_crypto_sess_ctx alloc failed\n");
		return -1;
	}
	/*
	 * Storing the crypto_dev_ctx in VM as the session index
	 * to uniquely identify defirrent cryptodev hash sessions
	 */
	hash_sess->sess_id = qemu_cmd->u.hash.init.sess_id;
	hash_sess->guest_id = qemu_cmd->guest_id;
	ctx = &hash_sess->c_sess;
	hctx = &ctx->u.hash;

	/*  Adding job to pending job list  */
	spin_lock(&hash_sess_list_lock);

	/* Checking for presence of prior hash sess */
	list_for_each_entry_safe(cur_sess, next_sess,
				 &virtio_c2x0_hash_sess_list, list_entry) {
		if (cur_sess->sess_id == qemu_cmd->u.hash.init.sess_id
		    && cur_sess->guest_id == qemu_cmd->guest_id) {
			print_error("Deletin already existing hash sess\n");
			list_del(&cur_sess->list_entry);
			kfree(cur_sess);
		}
	}

	list_add_tail(&hash_sess->list_entry, &virtio_c2x0_hash_sess_list);
	spin_unlock(&hash_sess_list_lock);

	if (-1 == fill_crypto_dev_sess_ctx(ctx, qemu_cmd->u.hash.init.op_type))
		return -1;
#else

	if (-1 == fill_crypto_dev_sess_ctx(ctx, fsl_alg->op_type))
		return -1;
#endif

	c_dev = ctx->c_dev;
	r_id = ctx->r_id;
	mempool = c_dev->ring_pairs[r_id].ip_pool;

	/* copy descriptor header template value */
#ifdef VIRTIO_C2X0
	hctx->alg_type = OP_TYPE_CLASS2_ALG | qemu_cmd->u.hash.init.alg_type;
	hctx->alg_op = OP_TYPE_CLASS2_ALG | qemu_cmd->u.hash.init.alg_op;
#else
	hctx->alg_type = OP_TYPE_CLASS2_ALG | fsl_alg->alg_type;
	hctx->alg_op = OP_TYPE_CLASS2_ALG | fsl_alg->alg_op;
#endif

	hctx->ctx_len = runninglen[(hctx->alg_op & OP_ALG_ALGSEL_SUBMASK) >>
				   OP_ALG_ALGSEL_SHIFT];

#ifdef VIRTIO_C2X0
	if (ahash_set_sh_desc(ctx, qemu_cmd->u.hash.init.digestsize))
		goto error;
	print_debug("New hash_sess\
				with sess_id %x:%x created;\n",
			    hash_sess->sess_id,
				qemu_cmd->u.hash.init.sess_id);
#else
	crypto_ahash_set_reqsize(__crypto_ahash_cast(tfm),
				 sizeof(struct hash_state));

	if (ahash_set_sh_desc(ahash))
		goto error;
#endif

	return 0;

error:
	return -1;
}

/*******************************************************************************
 * Function     : hash_cra_exit
 *
 * Arguments    : tfm
 *
 * Return Value : void
 *
 * Description  : cra_exit for crypto_alg.
 *
 ******************************************************************************/
#ifdef VIRTIO_C2X0
void hash_cra_exit(crypto_dev_sess_t *c_sess)
#else
static void hash_cra_exit(struct crypto_tfm *tfm)
#endif
{
	/* Nothing to be done */
}
#endif

#if !defined(VIRTIO_C2X0) && !defined(NO_PKC)
/*******************************************************************************
 * Function     : pkc_cra_init
 *
 * Arguments    : tfm
 *
 * Return Value : Error code
 *
 * Description  : cra_init for crypto_alg to setup the context.
 *
 ******************************************************************************/
static int pkc_cra_init(struct crypto_tfm *tfm)
{
	struct crypto_alg *alg = tfm->__crt_alg;
	struct fsl_crypto_alg *fsl_alg =
	    container_of(alg, struct fsl_crypto_alg, u.crypto_alg);

	crypto_dev_sess_t *ctx = crypto_tfm_ctx(tfm);
	if (-1 == fill_crypto_dev_sess_ctx(ctx, fsl_alg->op_type))
		return -1;

	return 0;
}

/*******************************************************************************
 * Function     : pkc_cra_exit
 *
 * Arguments    : tfm
 *
 * Return Value : void
 *
 * Description  : cra_exit for crypto_alg.
 *
 ******************************************************************************/
static void pkc_cra_exit(struct crypto_tfm *tfm)
{

	/* Nothing to be done */

}
#endif

#ifdef SYMMETRIC_OFFLOAD
#ifdef VIRTIO_C2X0
int sym_cra_init(struct virtio_c2x0_job_ctx *virtio_job)
#else
static int sym_cra_init(struct crypto_tfm *tfm)
#endif
{
#ifndef VIRTIO_C2X0
	struct crypto_alg *alg = tfm->__crt_alg;

	struct fsl_crypto_alg *fsl_alg =
	    container_of(alg, struct fsl_crypto_alg, u.crypto_alg);

	crypto_dev_sess_t *ctx = crypto_tfm_ctx(tfm);
	struct sym_ctx *sym_ctx = &(ctx->u.symm);

	print_debug("SYM_CRA_INIT\n");

	if (-1 == fill_crypto_dev_sess_ctx(ctx, fsl_alg->op_type))
		return -1;

	/* copy descriptor header template value */
	sym_ctx->class1_alg_type =
	    OP_TYPE_CLASS1_ALG | fsl_alg->class1_alg_type;
	sym_ctx->class2_alg_type =
	    OP_TYPE_CLASS2_ALG | fsl_alg->class2_alg_type;
	sym_ctx->alg_op = OP_TYPE_CLASS2_ALG | fsl_alg->alg_op;

	return 0;
#else
	struct virtio_c2x0_crypto_sess_ctx *vc_sess = NULL;
	crypto_dev_sess_t *ctx = NULL;
	struct sym_ctx *sym_ctx = NULL;
	struct vc_symm_cra_init *init = NULL;
	struct virtio_c2x0_qemu_cmd *qemu_cmd = &virtio_job->qemu_cmd;

	/*
	 * Creating a special cipher session context
	 * for each cipher operation from VM
	 */
	vc_sess = (struct virtio_c2x0_crypto_sess_ctx *)
	    kzalloc(sizeof(struct virtio_c2x0_crypto_sess_ctx), GFP_KERNEL);
	if (!vc_sess) {
		print_error("virtio_c2x0_crypto_sess_ctx alloc failed\n");
		return -1;
	}
	/*
	 * Storing the crypto_dev_ctx in VM as the session index
	 * to uniquely identify defirrent cryptodev hash sessions
	 */
	vc_sess->sess_id = qemu_cmd->u.symm.init.sess_id;
	vc_sess->guest_id = qemu_cmd->guest_id;
	ctx = &vc_sess->c_sess;
	sym_ctx = &(ctx->u.symm);
	print_debug("****** SYMMETRIC CONTEXT ADDRESS FOR OPERATION : %0lx\n",
		    sym_ctx);

	init = &(qemu_cmd->u.symm.init);

	if (-1 == fill_crypto_dev_sess_ctx(ctx, init->op_type))
		return -1;

	print_debug("SYM_CRA_INIT\n");

	sym_ctx->class1_alg_type = OP_TYPE_CLASS1_ALG | init->class1_alg_type;
	sym_ctx->class2_alg_type = OP_TYPE_CLASS2_ALG | init->class2_alg_type;
	sym_ctx->alg_op = OP_TYPE_CLASS2_ALG | init->alg_op;

	/*  Adding job to pending job list  */
	spin_lock(&symm_sess_list_lock);
	list_add_tail(&vc_sess->list_entry, &virtio_c2x0_symm_sess_list);
	spin_unlock(&symm_sess_list_lock);

	return 0;
#endif
}

#ifdef VIRTIO_C2X0
void sym_cra_exit(crypto_dev_sess_t *ctx)
#else
static void sym_cra_exit(struct crypto_tfm *tfm)
#endif
{
	/* Nothing to be done */
}
#endif
#ifndef VIRTIO_C2X0
static struct fsl_crypto_alg *fsl_alg_alloc(struct alg_template *template,
					    bool keyed)
{
	struct crypto_alg *alg = NULL;
	struct fsl_crypto_alg *f_alg =
	    kzalloc(sizeof(struct fsl_crypto_alg), GFP_KERNEL);
	if (!f_alg) {
		print_error("failed to allocate fsl_crypto_alg\n");
		return NULL;
	}

	/* Fill the 'fsl_crypto_alg' */
	if (CRYPTO_ALG_TYPE_AHASH == template->type) {
		f_alg->u.ahash_alg = template->u.ahash;
		alg = &f_alg->u.ahash_alg.halg.base;
	} else
		alg = &f_alg->u.crypto_alg;

	if (keyed && (CRYPTO_ALG_TYPE_AHASH == template->type)) {
		snprintf(alg->cra_name, CRYPTO_MAX_ALG_NAME, "%s",
			 template->hmac_name);
		snprintf(alg->cra_driver_name, CRYPTO_MAX_ALG_NAME, "%s",
			 template->hmac_driver_name);
	} else {
		snprintf(alg->cra_name, CRYPTO_MAX_ALG_NAME, "%s",
			 template->name);
		snprintf(alg->cra_driver_name, CRYPTO_MAX_ALG_NAME, "%s",
			 template->driver_name);
	}
	alg->cra_module = THIS_MODULE;
	alg->cra_priority = FSL_CRA_PRIORITY;
	alg->cra_blocksize = template->blocksize;
	alg->cra_alignmask = 0;
	alg->cra_ctxsize = sizeof(crypto_dev_sess_t);
	alg->cra_flags = CRYPTO_ALG_ASYNC | template->type;

	switch (template->type) {
#ifndef NO_PKC
	case CRYPTO_ALG_TYPE_PKC_RSA:
	case CRYPTO_ALG_TYPE_PKC_DSA:
	case CRYPTO_ALG_TYPE_PKC_DH:
		alg->cra_init = pkc_cra_init;
		alg->cra_exit = pkc_cra_exit;
		alg->cra_type = &crypto_pkc_type;
		alg->cra_u.pkc = template->u.pkc;
		f_alg->ahash = false;
		f_alg->op_type = ASYMMETRIC;
		break;
#endif
	case CRYPTO_ALG_TYPE_AHASH:
#ifdef HASH_OFFLOAD
		alg->cra_init = hash_cra_init;
		alg->cra_exit = hash_cra_exit;
		alg->cra_type = &crypto_ahash_type;
		f_alg->alg_type = template->alg_type;
		f_alg->alg_op = template->alg_op;
		f_alg->ahash = true;
		f_alg->op_type = SYMMETRIC;
#endif
		break;

	case CRYPTO_ALG_TYPE_AEAD:
	case CRYPTO_ALG_TYPE_ABLKCIPHER:
#ifdef SYMMETRIC_OFFLOAD
		alg->cra_init = sym_cra_init;
		alg->cra_exit = sym_cra_exit;

		switch (template->type) {
#if 0
		case CRYPTO_ALG_TYPE_AEAD:
			alg->cra_type = &crypto_aead_type;
			alg->cra_aead = template->u.aead;
			break;
#endif
		case CRYPTO_ALG_TYPE_ABLKCIPHER:
			alg->cra_type = &crypto_ablkcipher_type;
			alg->cra_ablkcipher = template->u.blkcipher;
			break;
		}
		f_alg->class1_alg_type = template->class1_alg_type;
		f_alg->class2_alg_type = template->class2_alg_type;
		f_alg->alg_op = template->alg_op;
		f_alg->ahash = false;
		f_alg->op_type = SYMMETRIC;
#endif
		break;
	}

	return f_alg;
}

/*******************************************************************************
 * Function     : fsl_algapi_init
 *
 * Arguments    : void
 *
 * Return Value : Error code
 *
 * Description  : Registering Algorithms with kernel crypto API.
 *
 ******************************************************************************/

int32_t fsl_algapi_init(void)
{
	int loop, err;
	char *driver_alg_name;
	struct fsl_crypto_alg *f_alg;
	/*
	 * keyed == false: base algorithm, cipher or digest
	 * keyed == true : hashed digest
	 */
	bool keyed;

	INIT_LIST_HEAD(&alg_list);

	for (loop = 0; loop < ARRAY_SIZE(driver_algs); loop++) {
		keyed = false;
l_start:
		f_alg = fsl_alg_alloc(&driver_algs[loop], keyed);

		if (!f_alg) {
			err = -ENOMEM;
			print_error("%s alg allocation failed\n",
				    driver_algs[loop].driver_name);
			goto out_err;
		}

		if (keyed) {
			print_debug("%s alg allocation successful\n",
				    driver_algs[loop].hmac_driver_name);
		} else {
			print_debug("%s alg allocation successful\n",
				    driver_algs[loop].driver_name);
		}
		if (f_alg->ahash) {
			err = crypto_register_ahash(&f_alg->u.ahash_alg);
			driver_alg_name =
			    f_alg->u.ahash_alg.halg.base.cra_driver_name;
		} else {
			err = crypto_register_alg(&f_alg->u.crypto_alg);
			driver_alg_name = f_alg->u.crypto_alg.cra_driver_name;
		}

		if (err) {
			print_error("%s alg registration failed\n",
				    driver_alg_name);
			kfree(f_alg);
			goto out_err;
		}

		print_debug("%s alg registration successful\n", driver_alg_name);
		list_add_tail(&f_alg->entry, &alg_list);

		/*
		 * after registering a digest algorithm, loop again to register
		 * the hashed (keyed) version of the same algorithm
		 */
		if (f_alg->ahash && !keyed) {
			keyed = true;
			goto l_start;
		}

	}

	return 0;

out_err:
	fsl_algapi_exit();
	return err;
}

/*******************************************************************************
 * Function     : fsl_algapi_exit
 *
 * Arguments    : void
 *
 * Return Value : None
 *
 * Description  : Deregistering Algorithms from kernel crypto API.
 *
 ******************************************************************************/

void fsl_algapi_exit(void)
{
	struct fsl_crypto_alg *f_alg, *temp;
	struct crypto_alg *alg = NULL;

	if (!alg_list.next)
		return;

	list_for_each_entry_safe(f_alg, temp, &alg_list, entry) {
		if (f_alg->ahash)
			alg = &f_alg->u.ahash_alg.halg.base;
		else
			alg = &f_alg->u.crypto_alg;

		crypto_unregister_alg(alg);
		list_del(&f_alg->entry);
		kfree(f_alg);
	}
}
#endif /* VIRTIO_C2X0 */
