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
#include "memmgr.h"
/* #ifdef KCAPI_INTEG_BUILD */
#include "sg_sw_sec4.h"
/* #endif */

#define MAX_ERROR_STRING 302

/*******************************************************************************
 * Function     : crypto_op_done
 *
 * Arguments    : ctx
 *                sec_result
 *
 * Return Value : None
 *
 * Description  : Called when a crypto operation completes. Sends the results
 *                back to the kernel crypto framework and does the cleanup.
 *
 ******************************************************************************/

void crypto_op_done(fsl_crypto_dev_t *c_dev, crypto_job_ctx_t *ctx,
		    int32_t sec_result)
{
	enum pkc_req_type crypto_req_type = 0;
	char outstr[MAX_ERROR_STRING];
/* #ifdef KCAPI_INTEG_BUILD */
/*      uint32_t dev_sg_count = 0;	*/
/* #endif */
	print_debug("Crypto operation complete\n");

	/* For certain commands like SEC-RESET, RESET-DEV for smooth exit,
	 * pending reqs will be discarded by firmware.
	 * And it sends the following error code as sec_result
	 */
#define JOB_DISCARDED	-1
	if (JOB_DISCARDED == sec_result) {
		print_debug("Job is discarded in the firmware\n");
	} else {
		sec_jr_strstatus(outstr, sec_result);
		if (0 != sec_result)
			print_error("STATUS FROM SEC ENGINE :%s\n", outstr);
	}

	switch (ctx->oprn) {
	case RSA:
	case DSA:
	case DH:
		crypto_req_type = ctx->req.pkc->type;

		/* Free the memory allocated from the memory pool manager */
		switch (crypto_req_type) {
		case RSA_PUB:
			print_debug("\t Request Type: RSA_PUB\n");

			put_buffer(c_dev, ctx->pool, ctx->dev_mem.rsa->u.pub.n);

			pci_unmap_single(ctx->pci_dev,
					 ctx->dev_mem.rsa->u.pub.g_host_dma,
					 ctx->dev_mem.rsa->u.pub.g_len,
					 PCI_DMA_BIDIRECTIONAL);

			put_buffer(c_dev, ctx->pool, ctx->req_mem);

			kfree(ctx->dev_mem.rsa);

			break;

		case RSA_PRIV_FORM1:
			print_debug("\t Request Type: RSA_PRIV_FORM1\n");

			put_buffer(c_dev, ctx->pool,
				   ctx->dev_mem.rsa->u.priv1.n);

			pci_unmap_single(ctx->pci_dev,
					 ctx->dev_mem.rsa->u.priv1.f_host_dma,
					 ctx->dev_mem.rsa->u.priv1.f_len,
					 PCI_DMA_BIDIRECTIONAL);

			put_buffer(c_dev, ctx->pool, ctx->req_mem);

			kfree(ctx->dev_mem.rsa);

			break;

		case RSA_PRIV_FORM2:
			print_debug("\t Request Type: RSA_PRIV_FORM2\n");

			put_buffer(c_dev, ctx->pool,
				   ctx->dev_mem.rsa->u.priv2.g);

			pci_unmap_single(ctx->pci_dev,
					 ctx->dev_mem.rsa->u.priv2.f_host_dma,
					 ctx->dev_mem.rsa->u.priv2.f_len,
					 PCI_DMA_BIDIRECTIONAL);

			put_buffer(c_dev, ctx->pool, ctx->req_mem);

			kfree(ctx->dev_mem.rsa);

			break;

		case RSA_PRIV_FORM3:
			print_debug("\t Request Type: RSA_PRIV_FORM3\n");

			put_buffer(c_dev, ctx->pool,
				   ctx->dev_mem.rsa->u.priv3.g);

			pci_unmap_single(ctx->pci_dev,
					 ctx->dev_mem.rsa->u.priv3.f_host_dma,
					 ctx->dev_mem.rsa->u.priv3.f_len,
					 PCI_DMA_BIDIRECTIONAL);

			put_buffer(c_dev, ctx->pool, ctx->req_mem);

			kfree(ctx->dev_mem.rsa);

			break;

		case DSA_SIGN:
		case ECDSA_SIGN:
			print_debug("\t Request Type: %d\n",
				    ctx->dev_mem.dsa->req_type);

			put_buffer(c_dev, ctx->pool,
				   ctx->dev_mem.dsa->u.dsa_sign.q);

			pci_unmap_single(ctx->pci_dev,
					 ctx->dev_mem.dsa->u.
					 dsa_sign.c_host_dma,
					 ctx->dev_mem.dsa->u.dsa_sign.d_len,
					 PCI_DMA_BIDIRECTIONAL);
			pci_unmap_single(ctx->pci_dev,
					 ctx->dev_mem.dsa->u.
					 dsa_sign.d_host_dma,
					 ctx->dev_mem.dsa->u.dsa_sign.d_len,
					 PCI_DMA_BIDIRECTIONAL);

			put_buffer(c_dev, ctx->pool, ctx->req_mem);

			kfree(ctx->dev_mem.dsa);

			break;

		case DSA_VERIFY:
		case ECDSA_VERIFY:
			print_debug("\t Request Type: %d\n",
				    ctx->dev_mem.dsa->req_type);

			put_buffer(c_dev, ctx->pool,
				   ctx->dev_mem.dsa->u.dsa_verify.q);

			put_buffer(c_dev, ctx->pool, ctx->req_mem);

			kfree(ctx->dev_mem.dsa);

			break;

		case DH_COMPUTE_KEY:
		case ECDH_COMPUTE_KEY:
			print_debug("\t Request Type: %d\n",
				    ctx->dev_mem.dh->req_type);

			put_buffer(c_dev, ctx->pool, ctx->dev_mem.dh->q);

			pci_unmap_single(ctx->pci_dev,
					 ctx->dev_mem.dh->z_host_dma,
					 ctx->dev_mem.dh->z_len,
					 PCI_DMA_BIDIRECTIONAL);

			put_buffer(c_dev, ctx->pool, ctx->req_mem);

			kfree(ctx->dev_mem.dh);

			break;

		default:
			break;
		}
/* #ifdef KCAPI_INTEG_BUILD */
#ifndef VIRTIO_C2X0
		if (NULL != ctx->req.pkc->base.tfm)
			pkc_request_complete(ctx->req.pkc, sec_result);
		else
			ctx->done(ctx->req.pkc, sec_result);

		kfree(ctx);
#endif
		break;
	case HASH_SPLIT_KEY:
	case HASH_DIGEST_KEY:
#if 0
#ifdef KCAPI_INTEG_BUILD
		if (ctx->dev_mem.ahash->src)
			put_buffer(c_dev, ctx->pool, ctx->dev_mem.ahash->src);
		if (ctx->dev_mem.ahash->dst_host_dma)
			pci_unmap_single(ctx->pci_dev,
					 ctx->dev_mem.ahash->dst_host_dma,
					 ctx->dev_mem.ahash->dst_len,
					 PCI_DMA_BIDIRECTIONAL);

		ctx->result->err = sec_result;
		complete(&ctx->result->completion);

		put_buffer(c_dev, ctx->pool, ctx->req_mem);

		kfree(ctx->dev_mem.ahash);
		kfree(ctx);
#endif
#endif
		break;
	case AHASH_DIGEST:
	case AHASH_UPDATE_CTX:
	case AHASH_FINUP_CTX:
	case AHASH_FINAL_CTX:
	case AHASH_FINAL_NO_CTX:
	case AHASH_FINUP_NO_CTX:
	case AHASH_UPDATE_NO_CTX:
	case AHASH_UPDATE_FIRST:
#if 0
#ifdef KCAPI_INTEG_BUILD
		if (ctx->dev_mem.ahash->src) {
			if (ctx->dev_mem.ahash->req_dma)
				kfree(ctx->dev_mem.ahash->src);
			else
				put_buffer(c_dev, ctx->pool,
					   ctx->dev_mem.ahash->src);
		}
		if (ctx->dev_mem.ahash->dst_host_dma)
			pci_unmap_single(ctx->pci_dev,
					 ctx->dev_mem.ahash->dst_host_dma,
					 ctx->dev_mem.ahash->dst_len,
					 PCI_DMA_BIDIRECTIONAL);

		if (ctx->dev_mem.ahash->src_host_dma)
			pci_unmap_single(ctx->pci_dev,
					 ctx->dev_mem.ahash->src_host_dma,
					 ctx->dev_mem.ahash->src_len,
					 PCI_DMA_BIDIRECTIONAL);

		if (ctx->dev_mem.ahash->req_dma)
			pci_unmap_sg_chained(ctx->pci_dev, ctx->req.ahash->src,
					     ctx->dev_mem.
					     ahash->src_nents ? : 1,
					     PCI_DMA_TODEVICE,
					     ctx->dev_mem.ahash->chained);

		dev_sg_count = ctx->dev_mem.ahash->dev_sg_count;

		while (dev_sg_count) {
			put_buffer(c_dev, ctx->pool,
				   ctx->dev_mem.ahash->dev_sg[--dev_sg_count]);
		}

		kfree(ctx->dev_mem.ahash->dev_sg);

		ctx->req.ahash->base.complete(&ctx->req.ahash->base,
					      sec_result);
		put_buffer(c_dev, ctx->pool, ctx->req_mem);

		kfree(ctx->dev_mem.ahash);
		kfree(ctx);
#endif
#endif
		break;

	case AEAD_SETKEY:
	case AEAD_ENCRYPT:
	case AEAD_DECRYPT:
	case ABLK_ENCRYPT:
	case ABLK_DECRYPT:
		break;

	case RNG:
#if 0
#ifdef KCAPI_INTEG_BUILD
		rng_done(ctx->dev_mem.rng);
#endif
#endif
		break;

		/* AVOID WARNINGS */
	case RNG_INIT:
	case RNG_SELF_TEST:
		break;
#ifdef VIRTIO_C2X0
	default:
		print_error("Invalid OP\n");
		break;
#endif
	}
}

int32_t check_device(fsl_crypto_dev_t *c_dev)
{
	int cpu = 0;
	per_dev_struct_t *dev_stat = NULL;

	cpu = get_cpu();
	dev_stat = per_cpu_ptr(c_dev->dev_status, cpu);
	put_cpu();

	if (0 == atomic_read(&(dev_stat->device_status))) {
		print_error("DEVICE IS DEAD\n");
		return -1;
	} else {
		atomic_inc(&c_dev->active_jobs);
	}
	return 0;
}

fsl_crypto_dev_t *get_device_rr(void)
{
	uint32_t no_of_devices = 0, new_device = 0;
	int device_status = 0, count = 0, cpu = 0;
	per_dev_struct_t *dev_stat = NULL;
	fsl_crypto_dev_t *c_dev = NULL;

    no_of_devices = get_no_of_devices();
    if (0 >= no_of_devices) {
        print_error("No Device configured\n");
        return NULL;
    }

	while (!device_status && count < no_of_devices) {
		new_device =
			((atomic_inc_return(&selected_devices) -
				1) % no_of_devices) + 1;
		c_dev = get_crypto_dev(new_device);
		if (!c_dev) {
			print_error
				("Could not retrieve the device structure.\n");
			return NULL;
		}

		cpu = get_cpu();
		dev_stat = per_cpu_ptr(c_dev->dev_status, cpu);
		put_cpu();

		device_status = atomic_read(&(dev_stat->device_status));
		count++;
	}

	if (!device_status) {
		print_error("No Device is ALIVE\n");
		return NULL;		
	}

	return c_dev;
}

uint32_t get_ring_rr(fsl_crypto_dev_t *c_dev)
{
	uint32_t no_of_app_rings = 0;
	int32_t r_id = 0;
	no_of_app_rings = c_dev->num_of_rings - 1;

	if (0 < no_of_app_rings)
		r_id =
			((atomic_inc_return(&c_dev->crypto_dev_sess_cnt) -
				1) % no_of_app_rings) + 1;
	else 
		print_error("No application ring configured\n");

	return r_id;
}

#ifndef HIGH_PERF
dev_dma_addr_t set_sec_affinity(fsl_crypto_dev_t *c_dev, uint32_t rid,
								dev_dma_addr_t desc)
{
	uint32_t sec_no = 0;
	sec_no = ((c_dev->ring_pairs[rid].info.flags &
				APP_RING_PROP_AFFINE_MASK) >>
				APP_RING_PROP_AFFINE_SHIFT);
	return (desc | (uint64_t) sec_no);
}
#else
dev_dma_addr_t set_sec_affinity(fsl_crypto_dev_t *c_dev, uint32_t rid,
                                dev_dma_addr_t desc)
{
    return desc;
}

#endif

void dma_tx_complete_cb(void *ctx)
{
	crypto_op_ctx_t *crypto_ctx = ctx;
	fsl_crypto_dev_t *c_dev = crypto_ctx->c_dev;
#ifndef HIGH_PERF
	if (atomic_inc_return(&crypto_ctx->reqcnt) <
	    atomic_read(&crypto_ctx->maxreqs))
		return;

	kfree(crypto_ctx->crypto_mem.ip_sg);
	kfree(crypto_ctx->crypto_mem.op_sg);

	atomic_dec(&c_dev->active_jobs);
#endif
RETRY:
	if (app_ring_enqueue(c_dev, crypto_ctx->rid, 
			set_sec_affinity(c_dev, crypto_ctx->rid, crypto_ctx->desc))) {
		print_error("App ring enqueue failed...\n");
		set_current_state(TASK_INTERRUPTIBLE);
		schedule_timeout(usecs_to_jiffies(10));
		goto RETRY;
	}
}

void change_desc_endianness(uint32_t *dev_mem,
			    uint32_t *host_mem, int32_t words)
{
	while (words) {
		ASSIGN32_PTR(dev_mem, (*host_mem));
		dev_mem++;
		host_mem++;
		words--;
	}
}
