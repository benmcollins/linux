/*
 * \file - caamprf.c
 * \brief - Freescale FSL CAAM support for pseudorandom function
 * Copyright 2015 Freescale Semiconductor, Inc.
 * There is no shared descriptor for PRF but Job descriptor must carry
 * all the desired secret parameters, input and output pointers
 *
 */

#include "prf_desc.h"

#ifdef DEBUG
/* for print_hex_dumps with line references */
#define debug(format, arg...) pr_debug(format, arg)
#else
#define debug(format, arg...)
#endif

static struct device *prfdev;

static void prf_unmap(struct device *dev,
		      struct prf_edesc *edesc, struct prf_req_s *req)
{

	switch (req->prf_op) {
	case GEN_MASTER_SECRET:
	{
		struct gen_master_secret_s *gen_ms;
		gen_ms = &req->req_u.gen_ms;

		dma_unmap_single(dev, edesc->dma_u.ms_edesc.secret,
				gen_ms->pre_master_secret.len, DMA_TO_DEVICE);
		dma_unmap_single(dev, edesc->dma_u.ms_edesc.label,
				gen_ms->label.len, DMA_TO_DEVICE);
		dma_unmap_single(dev, edesc->dma_u.ms_edesc.seed_part1,
				gen_ms->client_rand.len, DMA_TO_DEVICE);
		dma_unmap_single(dev, edesc->dma_u.ms_edesc.seed_part2,
				gen_ms->server_rand.len, DMA_TO_DEVICE);
		dma_unmap_single(dev, edesc->dma_u.ms_edesc.ms,
				gen_ms->out_master_secret.len, DMA_FROM_DEVICE);
		break;
	}
	case GEN_SESSION_KEYS:
	{
		struct gen_session_keys_s *key;
		struct gen_session_keys_edesc_s *ses_key_edesc =
					&edesc->dma_u.session_key_edesc;

		key = &req->req_u.gen_session_key;

		dma_unmap_single(dev, ses_key_edesc->server_iv,
				key->out_server_write_iv.len, DMA_FROM_DEVICE);
		dma_unmap_single(dev, ses_key_edesc->client_iv,
				key->out_client_write_iv.len, DMA_FROM_DEVICE);
		dma_unmap_single(dev, ses_key_edesc->server_crypto_key,
				key->out_server_write_key.len, DMA_FROM_DEVICE);
		dma_unmap_single(dev, ses_key_edesc->client_crypto_key,
				key->out_client_write_key.len, DMA_FROM_DEVICE);
		dma_unmap_single(dev, ses_key_edesc->server_mac_key,
			key->out_server_mac_secret.len, DMA_FROM_DEVICE);
		dma_unmap_single(dev, ses_key_edesc->client_mac_key,
			key->out_client_mac_secret.len, DMA_FROM_DEVICE);
		dma_unmap_single(dev, ses_key_edesc->seed_part2,
				key->client_rand.len, DMA_TO_DEVICE);
		dma_unmap_single(dev, ses_key_edesc->seed_part1,
				key->server_rand.len, DMA_TO_DEVICE);
		dma_unmap_single(dev, ses_key_edesc->label,
				key->label.len, DMA_TO_DEVICE);
		dma_unmap_single(dev, ses_key_edesc->secret,
				key->master_secret.len, DMA_TO_DEVICE);
		break;
	}
	case GEN_FINISH_RAND:
	{
		struct gen_finish_random_s *gen_finish_rand;
		gen_finish_rand = &req->req_u.gen_finish_rand;

		dma_unmap_single(dev, edesc->dma_u.finish_edesc.seed_part1,
				gen_finish_rand->seed1.len, DMA_TO_DEVICE);
		dma_unmap_single(dev, edesc->dma_u.finish_edesc.seed_part2,
				gen_finish_rand->seed2.len, DMA_TO_DEVICE);
		dma_unmap_single(dev, edesc->dma_u.finish_edesc.label,
				gen_finish_rand->label.len, DMA_TO_DEVICE);
		dma_unmap_single(dev, edesc->dma_u.finish_edesc.secret,
			gen_finish_rand->master_secret.len, DMA_TO_DEVICE);
		dma_unmap_single(dev, edesc->dma_u.finish_edesc.verify,
			gen_finish_rand->out_data.len, DMA_FROM_DEVICE);
		break;
	}

	default:
		dev_err(dev, "Unable to find request type\n");
		break;
	}
}

/* prf Job Completion handler */
static void prf_op_done(struct device *dev, u32 *desc, u32 err, void *context)
{
	struct prf_req_s *req = context;
	struct prf_edesc *edesc;

	edesc = (struct prf_edesc *)((char *)desc -
				     offsetof(struct prf_edesc, hw_desc));

	if (err) {
		dev_err(dev, "prf op done err: %x\n", err);
		caam_jr_strstatus(dev, err);
	}
	prf_unmap(dev, edesc, req);
	kfree(edesc);
	req->ret = err;
	complete(&req->comp);
}

static int caam_prf_finish_edesc(struct device *dev, struct prf_req_s *req,
				struct prf_edesc *edesc)
{
	struct gen_finish_random_s *gen_finish_rand;

	gen_finish_rand = &req->req_u.gen_finish_rand;
	edesc->prf_op = req->prf_op;
	edesc->dma_u.finish_edesc.secret = dma_map_single(dev,
			gen_finish_rand->master_secret.param,
			gen_finish_rand->master_secret.len, DMA_TO_DEVICE);
	if (dma_mapping_error(dev, edesc->dma_u.finish_edesc.secret)) {
		dev_err(dev, "Unable to map memory\n");
		goto prf_secret_fail;
	}
	edesc->dma_u.finish_edesc.label = dma_map_single(dev,
			gen_finish_rand->label.param,
			gen_finish_rand->label.len, DMA_TO_DEVICE);
	if (dma_mapping_error(dev, edesc->dma_u.finish_edesc.label)) {
		dev_err(dev, "Unable to map memory\n");
		goto prf_label_fail;
	}
	edesc->dma_u.finish_edesc.seed_part1 = dma_map_single(dev,
			gen_finish_rand->seed1.param,
			gen_finish_rand->seed1.len, DMA_TO_DEVICE);
	if (dma_mapping_error(dev, edesc->dma_u.finish_edesc.seed_part1)) {
		dev_err(dev, "Unable to map memory\n");
		goto prf_seed_part1_fail;
	}
	edesc->dma_u.finish_edesc.seed_part2 = dma_map_single(dev,
			gen_finish_rand->seed2.param,
			gen_finish_rand->seed2.len, DMA_TO_DEVICE);
	if (dma_mapping_error(dev, edesc->dma_u.finish_edesc.seed_part2)) {
		dev_err(dev, "Unable to map memory\n");
		goto prf_seed_part2_fail;
	}
	edesc->dma_u.finish_edesc.verify = dma_map_single(dev,
			gen_finish_rand->out_data.param,
			gen_finish_rand->out_data.len, DMA_FROM_DEVICE);
	if (dma_mapping_error(dev, edesc->dma_u.finish_edesc.verify)) {
		dev_err(dev, "Unable to map memory\n");
		goto prf_verify_fail;
	}

	return 0;

prf_verify_fail:
	dma_unmap_single(dev, edesc->dma_u.finish_edesc.verify,
			gen_finish_rand->out_data.len, DMA_FROM_DEVICE);

prf_seed_part2_fail:
	dma_unmap_single(dev, edesc->dma_u.finish_edesc.seed_part1,
			gen_finish_rand->seed1.len, DMA_TO_DEVICE);
prf_seed_part1_fail:
	dma_unmap_single(dev, edesc->dma_u.finish_edesc.seed_part2,
			gen_finish_rand->seed2.len, DMA_TO_DEVICE);
prf_label_fail:
	dma_unmap_single(dev, edesc->dma_u.finish_edesc.label,
			gen_finish_rand->label.len, DMA_TO_DEVICE);
prf_secret_fail:
	dma_unmap_single(dev, edesc->dma_u.finish_edesc.secret,
			gen_finish_rand->master_secret.len, DMA_TO_DEVICE);
	return -EINVAL;
}


static int caam_prf_ms_edesc(struct device *dev, struct prf_req_s *req,
				struct prf_edesc *edesc)
{
	struct gen_master_secret_s *gen_ms;

	gen_ms = &req->req_u.gen_ms;
	edesc->prf_op = req->prf_op;

	edesc->dma_u.ms_edesc.secret = dma_map_single(dev,
			gen_ms->pre_master_secret.param,
			gen_ms->pre_master_secret.len, DMA_TO_DEVICE);
	if (dma_mapping_error(dev, edesc->dma_u.ms_edesc.secret)) {
		dev_err(dev, "Unable to map memory\n");
		goto prf_secret_fail;
	}
	edesc->dma_u.ms_edesc.label = dma_map_single(dev, gen_ms->label.param,
			gen_ms->label.len, DMA_TO_DEVICE);
	if (dma_mapping_error(dev, edesc->dma_u.ms_edesc.label)) {
		dev_err(dev, "Unable to map memory\n");
		goto prf_label_fail;
	}
	edesc->dma_u.ms_edesc.seed_part1 = dma_map_single(dev,
					gen_ms->client_rand.param,
					gen_ms->client_rand.len, DMA_TO_DEVICE);
	if (dma_mapping_error(dev, edesc->dma_u.ms_edesc.seed_part1)) {
		dev_err(dev, "Unable to map memory\n");
		goto prf_seed_part1_fail;
	}
	edesc->dma_u.ms_edesc.seed_part2 = dma_map_single(dev,
					gen_ms->server_rand.param,
					gen_ms->server_rand.len, DMA_TO_DEVICE);
	if (dma_mapping_error(dev, edesc->dma_u.ms_edesc.seed_part2)) {
		dev_err(dev, "Unable to map memory\n");
		goto prf_seed_part2_fail;
	}
	edesc->dma_u.ms_edesc.ms = dma_map_single(dev,
			gen_ms->out_master_secret.param,
			gen_ms->out_master_secret.len, DMA_FROM_DEVICE);
	if (dma_mapping_error(dev, edesc->dma_u.ms_edesc.ms)) {
		dev_err(dev, "Unable to map memory\n");
		goto prf_ms_fail;
	}
	return 0;

prf_ms_fail:
	dma_unmap_single(dev, edesc->dma_u.ms_edesc.ms,
			gen_ms->out_master_secret.len, DMA_FROM_DEVICE);

prf_seed_part2_fail:
	dma_unmap_single(dev, edesc->dma_u.ms_edesc.seed_part1,
			gen_ms->client_rand.len, DMA_TO_DEVICE);
prf_seed_part1_fail:
	dma_unmap_single(dev, edesc->dma_u.ms_edesc.seed_part2,
			gen_ms->server_rand.len, DMA_TO_DEVICE);
prf_label_fail:
	dma_unmap_single(dev, edesc->dma_u.ms_edesc.label,
			gen_ms->label.len, DMA_TO_DEVICE);
prf_secret_fail:
	dma_unmap_single(dev, edesc->dma_u.ms_edesc.secret,
			gen_ms->pre_master_secret.len, DMA_TO_DEVICE);
	return -EINVAL;
}

static int caam_prf_session_key_edesc(struct device *dev, struct prf_req_s *req,
				struct prf_edesc *edesc)
{
	struct gen_session_keys_s *gen_session_key;

	gen_session_key = &req->req_u.gen_session_key;
	edesc->prf_op = req->prf_op;

	edesc->dma_u.session_key_edesc.secret = dma_map_single(dev,
			gen_session_key->master_secret.param,
			gen_session_key->master_secret.len, DMA_TO_DEVICE);
	if (dma_mapping_error(dev, edesc->dma_u.session_key_edesc.secret)) {
		dev_err(dev, "Unable to map memory\n");
		goto prf_secret_fail;
	}
	edesc->dma_u.session_key_edesc.label = dma_map_single(dev,
				gen_session_key->label.param,
				gen_session_key->label.len, DMA_TO_DEVICE);
	if (dma_mapping_error(dev, edesc->dma_u.session_key_edesc.label)) {
		dev_err(dev, "Unable to map memory\n");
		goto prf_label_fail;
	}
	edesc->dma_u.session_key_edesc.seed_part2 = dma_map_single(dev,
			gen_session_key->client_rand.param,
			gen_session_key->client_rand.len, DMA_TO_DEVICE);
	if (dma_mapping_error(dev, edesc->dma_u.session_key_edesc.seed_part2)) {
		dev_err(dev, "Unable to map memory\n");
		goto prf_seed_part1_fail;
	}
	edesc->dma_u.session_key_edesc.seed_part1 = dma_map_single(dev,
			gen_session_key->server_rand.param,
			gen_session_key->server_rand.len, DMA_TO_DEVICE);
	if (dma_mapping_error(dev, edesc->dma_u.session_key_edesc.seed_part1)) {
		dev_err(dev, "Unable to map memory\n");
		goto prf_seed_part2_fail;
	}
	edesc->dma_u.session_key_edesc.client_mac_key = dma_map_single(dev,
		gen_session_key->out_client_mac_secret.param,
		gen_session_key->out_client_mac_secret.len, DMA_FROM_DEVICE);
	if (dma_mapping_error(dev,
		edesc->dma_u.session_key_edesc.client_mac_key)) {
		dev_err(dev, "Unable to map memory\n");
		goto prf_client_mac_fail;
	}
	edesc->dma_u.session_key_edesc.server_mac_key = dma_map_single(dev,
		gen_session_key->out_server_mac_secret.param,
		gen_session_key->out_server_mac_secret.len, DMA_FROM_DEVICE);
	if (dma_mapping_error(dev,
		edesc->dma_u.session_key_edesc.server_mac_key)) {
		dev_err(dev, "Unable to map memory\n");
		goto prf_server_mac_fail;
	}
	edesc->dma_u.session_key_edesc.client_crypto_key = dma_map_single(dev,
		gen_session_key->out_client_write_key.param,
		gen_session_key->out_client_write_key.len, DMA_FROM_DEVICE);
	if (dma_mapping_error(dev,
		edesc->dma_u.session_key_edesc.client_crypto_key)) {
		dev_err(dev, "Unable to map memory\n");
		goto prf_client_crypto_fail;
	}
	edesc->dma_u.session_key_edesc.server_crypto_key = dma_map_single(dev,
		gen_session_key->out_server_write_key.param,
		gen_session_key->out_server_write_key.len, DMA_FROM_DEVICE);
	if (dma_mapping_error(dev,
		edesc->dma_u.session_key_edesc.server_crypto_key)) {
		dev_err(dev, "Unable to map memory\n");
		goto prf_server_crypto_fail;
	}
	edesc->dma_u.session_key_edesc.client_iv = dma_map_single(dev,
		gen_session_key->out_client_write_iv.param,
		gen_session_key->out_client_write_iv.len, DMA_FROM_DEVICE);
	if (dma_mapping_error(dev,
		edesc->dma_u.session_key_edesc.client_iv)) {
		dev_err(dev, "Unable to map memory\n");
		goto prf_client_iv_fail;
	}
	edesc->dma_u.session_key_edesc.server_iv = dma_map_single(dev,
		gen_session_key->out_server_write_iv.param,
		gen_session_key->out_server_write_iv.len, DMA_FROM_DEVICE);
	if (dma_mapping_error(dev,
		edesc->dma_u.session_key_edesc.server_iv)) {
		dev_err(dev, "Unable to map memory\n");
		goto prf_server_iv_fail;
	}
	return 0;
prf_server_iv_fail:
	dma_unmap_single(dev, edesc->dma_u.session_key_edesc.server_iv,
		gen_session_key->out_server_write_iv.len, DMA_FROM_DEVICE);
prf_client_iv_fail:
	dma_unmap_single(dev, edesc->dma_u.session_key_edesc.client_iv,
		gen_session_key->out_client_write_iv.len, DMA_FROM_DEVICE);
prf_server_crypto_fail:
	dma_unmap_single(dev, edesc->dma_u.session_key_edesc.server_crypto_key,
		gen_session_key->out_server_write_key.len, DMA_FROM_DEVICE);
prf_client_crypto_fail:
	dma_unmap_single(dev, edesc->dma_u.session_key_edesc.client_crypto_key,
		gen_session_key->out_client_write_key.len, DMA_FROM_DEVICE);
prf_server_mac_fail:
	dma_unmap_single(dev, edesc->dma_u.session_key_edesc.server_mac_key,
		gen_session_key->out_server_mac_secret.len, DMA_FROM_DEVICE);
prf_client_mac_fail:
	dma_unmap_single(dev, edesc->dma_u.session_key_edesc.client_mac_key,
		gen_session_key->out_client_mac_secret.len, DMA_FROM_DEVICE);

prf_seed_part2_fail:
	dma_unmap_single(dev, edesc->dma_u.session_key_edesc.seed_part2,
			gen_session_key->client_rand.len, DMA_TO_DEVICE);
prf_seed_part1_fail:
	dma_unmap_single(dev, edesc->dma_u.session_key_edesc.seed_part1,
			gen_session_key->server_rand.len, DMA_TO_DEVICE);
prf_label_fail:
	dma_unmap_single(dev, edesc->dma_u.session_key_edesc.label,
			gen_session_key->label.len, DMA_TO_DEVICE);
prf_secret_fail:
	dma_unmap_single(dev, edesc->dma_u.session_key_edesc.secret,
			gen_session_key->master_secret.len, DMA_TO_DEVICE);
	return -EINVAL;
}



/* CAAM Descriptor creator for prf operations */
static void *caam_prf_desc_init(struct device *dev, struct prf_req_s *req)
{
	void *desc = NULL;
	struct prf_edesc *edesc = NULL;

	switch (req->prf_op) {
	case GEN_MASTER_SECRET:
	{
		edesc =
			kmalloc(sizeof(*edesc) +
				sizeof(struct prf_gen_ms_desc_s), GFP_DMA);

		if (!edesc) {
			dev_err(dev, "kmalloc failed\n");
			return NULL;
		}
		edesc->prf_op = req->prf_op;
		if (caam_prf_ms_edesc(dev, req, edesc)) {
			dev_err(dev, "caam_prf_ms_edesc failed !\n");
			kfree(edesc);
			return NULL;
		}

		desc = caam_prf_gen_ms_desc(req, edesc);
		break;
	}
	case GEN_SESSION_KEYS:
	{
		edesc =
			kmalloc(sizeof(*edesc) +
				sizeof(struct prf_gen_session_desc_s), GFP_DMA);

		if (!edesc) {
			dev_err(dev, "kmalloc failed\n");
			return NULL;
		}
		edesc->prf_op = req->prf_op;
		if (caam_prf_session_key_edesc(dev, req, edesc)) {
			dev_err(dev, "caam_prf_session_key_edesc failed !\n");
			kfree(edesc);
			return NULL;
		}
		desc = caam_prf_session_keys_desc(req, edesc);
		break;
	}
	case GEN_FINISH_RAND:
	{
		edesc =
			kmalloc(sizeof(*edesc) +
				sizeof(struct prf_gen_finish_desc_s), GFP_DMA);

		if (!edesc) {
			dev_err(dev, "kmalloc failed\n");
			return NULL;
		}
		edesc->prf_op = req->prf_op;
		if (caam_prf_finish_edesc(dev, req, edesc)) {
			dev_err(dev, "caam_prf_finish_edesc failed !\n");
			kfree(edesc);
			return NULL;
		}

		desc = caam_prf_gen_finish_desc(req, edesc);
		break;
	}


	default:
		pr_debug("Unknown request type\n");
		return NULL;
	}

	return desc;
}

/* prf operation Handler */
int prf_op(struct device *dev, struct prf_req_s *req)
{
	int ret = 0;
	void *desc = NULL;
	if (!prfdev) {
		dev_err(dev, "No device exist\n");
		return -ENODEV;
	}
	req->ret = 0;
	desc = caam_prf_desc_init(dev, req);
	if (!desc) {
		dev_err(dev, "Unable to allocate descriptor\n");
		return -ENOMEM;
	}
	init_completion(&req->comp);
	ret = caam_jr_enqueue(dev, desc, prf_op_done, req);
	if (!ret) {
		wait_for_completion_interruptible(&req->comp);
		ret = req->ret;
	}
	return ret;
}
EXPORT_SYMBOL(prf_op);

/* Per session prf's driver context cleanup function */
void caam_prf_ctx_del(struct device *dev)
{
	/* Nothing to cleanup in private context */
	caam_jr_free(dev);
}
EXPORT_SYMBOL(caam_prf_ctx_del);

/* Per session prf's driver context creation function */
struct device *caam_prf_ctx_create(void)
{

	struct device *dev = NULL;

	if (!prfdev) {
		dev_err(dev, "No device exist\n");
		return ERR_PTR(-ENODEV);
	}
	dev = caam_jr_alloc();
	if (IS_ERR(dev)) {
		pr_err("prf Job Ring Device allocation for transform failed\n");
		return ERR_PTR(-ENODEV);
	}
	return dev;
}
EXPORT_SYMBOL(caam_prf_ctx_create);

/* psuedo random function module initialization handler */
static int __init caam_prf_init(void)
{
	struct device_node *dev_node;
	struct platform_device *pdev;
	struct caam_drv_private *priv;
	int err = 0;

	dev_node = of_find_compatible_node(NULL, NULL, "fsl,sec-v4.0");
	if (!dev_node) {
		dev_node = of_find_compatible_node(NULL, NULL, "fsl,sec4.0");
		if (!dev_node)
			return -ENODEV;
	}

	pdev = of_find_device_by_node(dev_node);
	if (!pdev)
		return -ENODEV;

	prfdev = &pdev->dev;
	priv = dev_get_drvdata(prfdev);
	of_node_put(dev_node);

	/*
	 * If priv is NULL, it's probably because the caam driver wasn't
	 * properly initialized (e.g. RNG4 init failed). Thus, bail out here.
	 */
	if (!priv)
		return -ENODEV;

	return err;
}

static void __exit caam_prf_exit(void)
{
	struct device_node *dev_node;

	dev_node = of_find_compatible_node(NULL, NULL, "fsl,sec-v4.0");

	if (!dev_node) {
		dev_node = of_find_compatible_node(NULL, NULL, "fsl,sec4.0");
		if (!dev_node)
			return;
	}
	of_node_put(dev_node);
}

module_init(caam_prf_init);
module_exit(caam_prf_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("FSL CAAM support for PRF functions of cryptodev");
MODULE_AUTHOR("Anand Singh <anand.singh@freescale.com>");
