/*
 * \file - prf_desc.h
 * \brief - Freescale FSL CAAM support for Public Key Cryptography
 * Copyright 2015 Freescale Semiconductor, Inc.
 * There is no shared descriptor for PRF but Job descriptor must carry
 * all the desired key parameters, input and output pointers
 *
 */
#ifndef _PRF_DESC_H_
#define _PRF_DESC_H_

#include "compat.h"

#include "regs.h"
#include "intern.h"
#include "desc_constr.h"
#include "jr.h"
#include "error.h"
#include "sg_sw_sec4.h"
#include <linux/crypto.h>
#include "pdb.h"

/*
 * prf_edesc - s/w-extended for prf descriptors
 * @hw_desc: the h/w job descriptor
 */
struct gen_master_secret_edesc_s {
	dma_addr_t secret;
	dma_addr_t label;
	dma_addr_t seed_part1;
	dma_addr_t seed_part2;
	dma_addr_t ms;
};

struct gen_finish_random_edesc_s {
	dma_addr_t secret;
	dma_addr_t label;
	dma_addr_t seed_part1;
	dma_addr_t seed_part2;
	dma_addr_t verify;
};

struct gen_session_keys_edesc_s {
	dma_addr_t secret;
	dma_addr_t label;
	dma_addr_t seed_part1;
	dma_addr_t seed_part2;
	dma_addr_t client_mac_key;
	dma_addr_t server_mac_key;
	dma_addr_t client_crypto_key;
	dma_addr_t server_crypto_key;
	dma_addr_t client_iv;
	dma_addr_t server_iv;
};


struct prf_edesc {
	u32 prf_op;
	u32 tls_version;
	union {
		struct gen_master_secret_edesc_s ms_edesc;
		struct gen_session_keys_edesc_s session_key_edesc;
		struct gen_finish_random_edesc_s finish_edesc;
	} dma_u;
	u32 hw_desc[];
};


void *caam_prf_gen_ms_desc(struct prf_req_s *req, struct prf_edesc *edesc);
void *caam_prf_session_keys_desc(struct prf_req_s *req,
					struct prf_edesc *edesc);
void *caam_prf_gen_finish_desc(struct prf_req_s *req, struct prf_edesc *edesc);
#endif
