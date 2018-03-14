/*
 * \file - prf_desc.c
 * \brief - Freescale FSL CAAM support for Psuedo random function descriptor
 * Copyright 2012 Freescale Semiconductor, Inc.
 * There is no shared descriptor for PRF but Job descriptor must carry
 * all the desired key parameters, input and output pointers
 *
 */
#include "prf_desc.h"

/* Descriptor for prf operation */
/* PRF MS/FINISH/SESSION KEY CAAM descriptor */
void *caam_prf_gen_ms_desc(struct prf_req_s *req, struct prf_edesc *edesc)
{
	u32 start_idx, desc_size;
	void *desc;
	struct gen_master_secret_s *gen_ms;
#ifdef CAAM_DEBUG
	uint32_t i;
	uint32_t *buf;
#endif

	struct prf_gen_ms_desc_s *prf_desc =
		(struct prf_gen_ms_desc_s *)edesc->hw_desc;

	gen_ms = &req->req_u.gen_ms;
	desc_size = sizeof(struct prf_gen_ms_desc_s) / sizeof(u32);
	memset(prf_desc, 0, desc_size);
	start_idx = desc_size - 1;
	start_idx &= HDR_START_IDX_MASK;
	init_job_desc(edesc->hw_desc,
			(start_idx << HDR_START_IDX_SHIFT) |
			(start_idx & HDR_DESCLEN_MASK) | HDR_ONE);
	if (!(gen_ms->pre_master_secret.black_key))
		prf_desc->desc_op |= (PRF_IEOV_NO_ENC);
	if (!(gen_ms->out_master_secret.black_key))
		prf_desc->desc_op |= (PRF_OEOV_NO_ENC);

	prf_desc->ip_ref_ctrl =
		((gen_ms->pre_master_secret.len << PRF_SECRET_OFFSET) |
		(gen_ms->label.len << PRF_LABEL_OFFSET) |
		(gen_ms->server_rand.len << PRF_SEED_PART1_OFFSET) |
		(gen_ms->client_rand.len << PRF_SEED_PART2_OFFSET));
	prf_desc->op_ref_ctrl =
		(gen_ms->out_master_secret.len << PRF_OUT_LEN_OFFSET);
	prf_desc->secret = edesc->dma_u.ms_edesc.secret;
	prf_desc->label = edesc->dma_u.ms_edesc.label;
	prf_desc->seed_part1 = edesc->dma_u.ms_edesc.seed_part1;
	prf_desc->seed_part2 = edesc->dma_u.ms_edesc.seed_part2;
	prf_desc->ms = edesc->dma_u.ms_edesc.ms;
	if (req->tls_version == TLS1_VERSION)
		prf_desc->op = CMD_OPERATION | OP_TYPE_UNI_PROTOCOL |
			OP_PCLID_TLS10_PRF | OP_PCL_TLS10_PRF;
	else
		return NULL;
	desc = (void *)prf_desc;
#ifdef CAAM_DEBUG
	buf = desc;
	pr_debug("PRF Keygen Descriptor is:");
	for (i = 0; i < desc_size; i++)
		pr_debug("[%d] %x ", i, buf[i]);
	pr_debug("\n");
#endif

	return desc;
}

void *caam_prf_session_keys_desc(struct prf_req_s *req, struct prf_edesc *edesc)
{
	u32 start_idx, desc_size;
	void *desc;
	struct gen_session_keys_s *gen_session_key;
#ifdef CAAM_DEBUG
	uint32_t i;
	uint32_t *buf;
#endif

	struct prf_gen_session_desc_s *prf_desc =
		(struct prf_gen_session_desc_s *)edesc->hw_desc;

	gen_session_key = &req->req_u.gen_session_key;
	desc_size = sizeof(struct prf_gen_session_desc_s) / sizeof(u32);
	memset(prf_desc, 0, desc_size);
	start_idx = desc_size - 1;
	start_idx &= HDR_START_IDX_MASK;
	init_job_desc(edesc->hw_desc,
			(start_idx << HDR_START_IDX_SHIFT) |
			(start_idx & HDR_DESCLEN_MASK) | HDR_ONE);
	if (!(gen_session_key->master_secret.black_key))
		prf_desc->desc_op |= (PRF_IEOV_NO_ENC);
	if (gen_session_key->master_secret.len != TLS_MS_LEN) {
		pr_err("master secret len should be of 48 bytes!!\n");
		return NULL;
	}
	prf_desc->ip_ref_ctrl =
		((gen_session_key->label.len << PRF_LABEL_OFFSET) |
		(gen_session_key->server_rand.len << PRF_SEED_PART1_OFFSET) |
		(gen_session_key->client_rand.len << PRF_SEED_PART2_OFFSET));
	prf_desc->op_ref_ctrl = 0; /* field ignored for sesssion desc */
	prf_desc->secret = edesc->dma_u.session_key_edesc.secret;
	prf_desc->label = edesc->dma_u.session_key_edesc.label;
	prf_desc->seed_part1 = edesc->dma_u.session_key_edesc.seed_part1;
	prf_desc->seed_part2 = edesc->dma_u.session_key_edesc.seed_part2;
	prf_desc->client_mac_key =
			edesc->dma_u.session_key_edesc.client_mac_key;
	prf_desc->server_mac_key =
			edesc->dma_u.session_key_edesc.server_mac_key;
	prf_desc->client_crypto_key =
			edesc->dma_u.session_key_edesc.client_crypto_key;
	prf_desc->server_crypto_key =
			edesc->dma_u.session_key_edesc.server_crypto_key;
	prf_desc->client_iv = edesc->dma_u.session_key_edesc.client_iv;
	prf_desc->server_iv = edesc->dma_u.session_key_edesc.server_iv;
	if (req->tls_version == TLS1_VERSION)
		prf_desc->op = CMD_OPERATION | OP_TYPE_UNI_PROTOCOL |
			OP_PCLID_TLS10_PRF | gen_session_key->cipher;
	else {
		pr_err("tls version not supported!!\n");
		return NULL;
	}

	desc = (void *)prf_desc;
#ifdef CAAM_DEBUG
	buf = desc;
	pr_debug("PRF Keygen Descriptor is:");
	for (i = 0; i < desc_size; i++)
		pr_debug("[%d] %x ", i, buf[i]);
	pr_debug("\n");
#endif

	return desc;
}

void *caam_prf_gen_finish_desc(struct prf_req_s *req, struct prf_edesc *edesc)
{
	u32 start_idx, desc_size;
	void *desc;
	struct gen_finish_random_s *gen_finish_rand;
#ifdef CAAM_DEBUG
	uint32_t i;
	uint32_t *buf;
#endif

	struct prf_gen_finish_desc_s *prf_desc =
		(struct prf_gen_finish_desc_s *)edesc->hw_desc;

	gen_finish_rand = &req->req_u.gen_finish_rand;
	desc_size = sizeof(struct prf_gen_finish_desc_s) / sizeof(u32);
	memset(prf_desc, 0, desc_size);
	start_idx = desc_size - 1;
	start_idx &= HDR_START_IDX_MASK;
	init_job_desc(edesc->hw_desc,
			(start_idx << HDR_START_IDX_SHIFT) |
			(start_idx & HDR_DESCLEN_MASK) | HDR_ONE);
	if (!(gen_finish_rand->master_secret.black_key))
		prf_desc->desc_op |= (PRF_IEOV_NO_ENC);

	prf_desc->desc_op |= (PRF_OEOV_NO_ENC); /* verify should
						always be in plain */
	prf_desc->ip_ref_ctrl =
		((gen_finish_rand->master_secret.len << PRF_SECRET_OFFSET) |
		(gen_finish_rand->label.len << PRF_LABEL_OFFSET) |
		(gen_finish_rand->seed2.len << PRF_SEED_PART2_OFFSET) |
		(gen_finish_rand->seed1.len << PRF_SEED_PART1_OFFSET));
	prf_desc->op_ref_ctrl =
		(gen_finish_rand->out_data.len << PRF_OUT_LEN_OFFSET);
	prf_desc->secret = edesc->dma_u.finish_edesc.secret;
	prf_desc->label = edesc->dma_u.finish_edesc.label;
	prf_desc->seed_part1 = edesc->dma_u.finish_edesc.seed_part1;
	prf_desc->seed_part2 = edesc->dma_u.finish_edesc.seed_part2;
	prf_desc->verify = edesc->dma_u.finish_edesc.verify;
	prf_desc->op = CMD_OPERATION | OP_TYPE_UNI_PROTOCOL |
			OP_PCLID_TLS10_PRF | OP_PCL_TLS10_PRF;
	if (req->tls_version == TLS1_VERSION)
		prf_desc->op = CMD_OPERATION | OP_TYPE_UNI_PROTOCOL |
			OP_PCLID_TLS10_PRF | OP_PCL_TLS10_PRF;
	else {
		pr_err("tls version not supported!!\n");
		return NULL;
	}

	desc = (void *)prf_desc;
#ifdef CAAM_DEBUG
	buf = desc;
	pr_debug("PRF Keygen Descriptor is:");
	for (i = 0; i < desc_size; i++)
		pr_debug("[%d] %x ", i, buf[i]);
	pr_debug("\n");
#endif

	return desc;
}


