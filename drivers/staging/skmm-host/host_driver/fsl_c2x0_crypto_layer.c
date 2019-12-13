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
#include "device.h"
#include "fsl_c2x0_crypto_layer.h"
#include "fsl_c2x0_driver.h"
#include "command.h"
#include "memmgr.h"
#include "algs.h"
#include "crypto_ctx.h"
#ifdef VIRTIO_C2X0
#include "hash.h"		/* hash */
#include "fsl_c2x0_virtio.h"
#endif
#define DEFAULT_HOST_OP_BUFFER_POOL_SIZE	(1*1024)
#define DEFAULT_FIRMWARE_RESP_RING_DEPTH	(128*4)
#define FIRMWARE_IP_BUFFER_POOL_SIZE		(384*1024 + 1024*120)

#define CACHE_LINE_SIZE_SHIFT		6
#define CACHE_LINE_SIZE			(1 << CACHE_LINE_SIZE_SHIFT)
#define ALIGN_TO_CACHE_LINE(x)	\
	(((x) + (CACHE_LINE_SIZE-1)) & ~(CACHE_LINE_SIZE-1))

#define ALIGN_LEN_TO_PAGE_SIZE(x)	\
	(((x) + (PAGE_SIZE-1)) & ~(PAGE_SIZE-1))

#ifdef PRINT_DEBUG
#ifndef HIGH_PERF
static int32_t total_resp;
#endif
#endif
#ifndef HIGH_PERF
#ifdef MULTIPLE_RESP_RINGS
static void store_dev_ctx(void *, uint8_t, uint32_t);
#endif
#endif
/* For debugging purpose */
static volatile uint32_t enqueue_counter;
static volatile uint32_t dequeue_counter;

int32_t distribute_rings(fsl_crypto_dev_t *dev, crypto_dev_config_t *config)
{
	fsl_h_rsrc_ring_pair_t *rp = NULL;

	uint32_t core_no = 0;
	uint32_t isr_count = 0;
	uint32_t i = 0;

	uint32_t total_cores = 0;

	per_core_struct_t *instance = NULL;
	isr_ctx_t *isr_ctx = NULL;

	for_each_online_cpu(i)
	    ++total_cores;

	print_debug("Total cores        :%d\n", total_cores);
#define TOTAL_NUM_OF_ISRS            (((fsl_pci_dev_t *)dev->priv_dev)\
					->intr_info.intr_vectors_cnt)
	isr_ctx =
	    list_entry((&
			(((fsl_pci_dev_t *) (dev->priv_dev))->
			 intr_info.isr_ctx_list_head))->next, isr_ctx_t, list);

	INIT_LIST_HEAD(&(isr_ctx->ring_list_head));

	for_each_online_cpu(i) {
		instance = per_cpu_ptr(per_core, i);
#if 0
		INIT_LIST_HEAD(&(instance->ring_list_head));
#endif
	}

	instance = NULL;
	/* Affine the ring to CPU & ISR */
	for (i = 0; i < config->num_of_rings; i++) {
		while (!(wt_cpu_mask & (1 << core_no)))
			core_no = (core_no + 1) % total_cores;

		print_debug("Ring no:   %d Core no: %d\n", i, core_no);
		instance = per_cpu_ptr(per_core, core_no);

		rp = &(dev->ring_pairs[i]);

		rp->core_no = core_no;

		config->ring[i].msi_addr_l = isr_ctx->msi_addr_low;
		config->ring[i].msi_addr_h = isr_ctx->msi_addr_high;
		config->ring[i].msi_data = isr_ctx->msi_data;

		/* Adding the ring to the ISR */
		list_add(&(rp->isr_ctx_list_node), &(isr_ctx->ring_list_head));
		list_add(&(rp->bh_ctx_list_node), &(instance->ring_list_head));

		if ((++isr_count) % TOTAL_NUM_OF_ISRS)
			list_entry(isr_ctx->list.next, isr_ctx_t, list);
		else
			isr_ctx =
			    list_entry((&
					(((fsl_pci_dev_t *) dev->
					  priv_dev)->intr_info.
					 isr_ctx_list_head))->next, isr_ctx_t,
				       list);

		print_debug("ISR COUNT  :%d total num of isrs   :%d\n",
			    isr_count, TOTAL_NUM_OF_ISRS);

		core_no = (core_no + 1) % total_cores;
	}

	return 0;
}

static void pow2_rp_len(crypto_dev_config_t *config)
{
	uint32_t i = 0, pow2 = 0x01;
	/* Correct the ring depths to be power of 2 */
	for (i = 0; i < config->num_of_rings; i++) {
		for (pow2 = 0X01; (pow2 < config->ring[i].depth);
		    (pow2 = pow2 << 1))
			;
		config->ring[i].depth = pow2;
	}
}

static void rearrange_config(crypto_dev_config_t *config)
{
	struct ring_info temp;
	uint32_t pri_j = 0, pri_j_1 = 0, i = 0, j = 0;

	for (i = 1; i < config->num_of_rings - 1; i++) {
		for (j = 1; j < config->num_of_rings - i; j++) {
			pri_j =
			    (((config->
			       ring[j].flags) & APP_RING_PROP_PRIO_MASK) >>
			     APP_RING_PROP_PRIO_SHIFT);
			pri_j_1 =
			    (((config->
			       ring[j +
				    1].flags) & APP_RING_PROP_PRIO_MASK) >>
			     APP_RING_PROP_PRIO_SHIFT);
			if (pri_j > pri_j_1) {
				temp = config->ring[j];
				config->ring[j] = config->ring[j + 1];
				config->ring[j + 1] = temp;
			}
		}
	}

	j = 1;
	config->ring[0].ring_id = 0;
	config->ring[0].flags &= ~(APP_RING_PROP_PRIO_MASK);
	config->ring[0].flags |= (uint8_t) (j) << APP_RING_PROP_PRIO_SHIFT;

	for (i = 1; i < config->num_of_rings - 1; i++) {
		config->ring[i].ring_id = i;
		pri_j = (((config->ring[i].flags) &
			  APP_RING_PROP_PRIO_MASK) >> APP_RING_PROP_PRIO_SHIFT);
		pri_j_1 = (((config->ring[i + 1].flags) &
			    APP_RING_PROP_PRIO_MASK) >>
			   APP_RING_PROP_PRIO_SHIFT);

		config->ring[i].flags &= ~(APP_RING_PROP_PRIO_MASK);
		config->ring[i].flags |=
		    (uint8_t) (j) << APP_RING_PROP_PRIO_SHIFT;

		if (pri_j_1 != pri_j)
			j++;
	}

	config->ring[i].ring_id = i;
	config->ring[i].flags &= ~(APP_RING_PROP_PRIO_MASK);
	config->ring[i].flags |= (uint8_t) (j) << APP_RING_PROP_PRIO_SHIFT;
}

void rearrange_rings(fsl_crypto_dev_t *dev, crypto_dev_config_t *config)
{
	uint32_t i = 0;
	uint32_t pri = 0;

	pow2_rp_len(config);
	rearrange_config(config);

	for (i = 0; i < MAX_PRIORITY_LEVELS; i++)
		INIT_LIST_HEAD(&(dev->pri_queue[i].ring_list_head));

	/* Put the rings in proper prio q */
	for (i = 0; i < config->num_of_rings; i++) {
		pri =
		    (((config->ring[i].flags) & APP_RING_PROP_PRIO_MASK) >>
		     APP_RING_PROP_PRIO_SHIFT);
		dev->max_pri_level =
		    (dev->max_pri_level < pri) ? pri : dev->max_pri_level;

		pri = pri - 1;

		dev->ring_pairs[i].info = config->ring[i];

		list_add_tail(&(dev->ring_pairs[i].ring_pair_list_node),
			      &(dev->pri_queue[pri].ring_list_head));
	}
	dev->num_of_rings = config->num_of_rings;
}

static uint32_t calc_rp_mem_len(crypto_dev_config_t *config)
{
	uint32_t i = 0, pow2 = 0x01, len = 0;
	/* Correct the ring depths to be power of 2 */
	for (i = 0; i < config->num_of_rings; i++) {
		for (pow2 = 0X01; (pow2 < config->ring[i].depth);
		     (pow2 = pow2 << 1))
			 ;
		config->ring[i].depth = pow2;
		len += pow2;
	}
	return len;
}

static uint32_t calc_ob_mem_len(fsl_crypto_dev_t *dev,
				crypto_dev_config_t *config)
{
	uint32_t ob_mem_len = 0;
	uint32_t rp_len = 0;

	/* One cache line for container structure */
	dev->ob_mem.h_mem = ob_mem_len;
	ob_mem_len += DRIVER_HS_MEM_SIZE;

	/* Cache aligned memory for HS */
	dev->ob_mem.hs_mem = ob_mem_len;
	ob_mem_len += DRIVER_HS_MEM_SIZE;

	/* Correct the ring depths to power of 2 */
	ob_mem_len = ALIGN_TO_CACHE_LINE(ob_mem_len);
	dev->ob_mem.drv_resp_rings = ob_mem_len;
	rp_len = calc_rp_mem_len(config);
	ob_mem_len += (rp_len * sizeof(resp_ring_entry_t));
	dev->tot_req_mem_size += (rp_len * sizeof(req_ring_entry_t));

	/* For each rp we need a local memory for indexes */
	ob_mem_len = ALIGN_TO_CACHE_LINE(ob_mem_len);
	dev->ob_mem.l_idxs_mem = ob_mem_len;
	ob_mem_len += (config->num_of_rings + 1) * (sizeof(ring_idxs_mem_t));

	ob_mem_len = ALIGN_TO_CACHE_LINE(ob_mem_len);
	dev->ob_mem.s_c_idxs_mem = ob_mem_len;
	ob_mem_len += (config->num_of_rings + 1) * (sizeof(ring_idxs_mem_t));

	ob_mem_len = ALIGN_TO_CACHE_LINE(ob_mem_len);
	dev->ob_mem.l_r_cntrs_mem = ob_mem_len;
	ob_mem_len += (config->num_of_rings + 1) * sizeof(ring_counters_mem_t);

	ob_mem_len = ALIGN_TO_CACHE_LINE(ob_mem_len);
	dev->ob_mem.s_c_r_cntrs_mem = ob_mem_len;
	ob_mem_len += (config->num_of_rings + 1) * sizeof(ring_counters_mem_t);

	ob_mem_len = ALIGN_TO_CACHE_LINE(ob_mem_len);
	dev->ob_mem.cntrs_mem = ob_mem_len;
	ob_mem_len += sizeof(counters_mem_t);
	dev->ob_mem.s_c_cntrs_mem += sizeof(counters_mem_t);

	/* We have to make sure that we align the output buffer pool to DMA */
	ob_mem_len = ALIGN_TO_CACHE_LINE(ob_mem_len);
	dev->ob_mem.op_pool = ob_mem_len;
	ob_mem_len += DEFAULT_HOST_OP_BUFFER_POOL_SIZE;

	/* See if the mem already allocated is occupying a page */
	if ((PAGE_SIZE - (ob_mem_len % PAGE_SIZE)) <
	    (DEFAULT_FIRMWARE_RESP_RING_DEPTH * sizeof(resp_ring_entry_t)))
		ob_mem_len = ALIGN_LEN_TO_PAGE_SIZE(ob_mem_len);

	dev->ob_mem.fw_resp_ring = ob_mem_len;
	ob_mem_len +=
	    DEFAULT_FIRMWARE_RESP_RING_DEPTH * sizeof(resp_ring_entry_t);

	/* For IP Pool we need to make sure that we always
	 * get 32BYTE aligned address */
	ob_mem_len = ALIGN_TO_CACHE_LINE(ob_mem_len);
	dev->ob_mem.ip_pool = ob_mem_len;
	ob_mem_len += FIRMWARE_IP_BUFFER_POOL_SIZE;

	/* Make the total mem requirement aligned to page size */
	ob_mem_len = ALIGN_LEN_TO_PAGE_SIZE(ob_mem_len);

	return ob_mem_len;
}

int32_t alloc_ob_mem(fsl_crypto_dev_t *dev, crypto_dev_config_t *config)
{
	/* First get the total ob mem required */
	uint32_t ob_mem_len = calc_ob_mem_len(dev, config);

	print_debug("\t alloc_ob_mem entered........\n");
	print_debug("\t Total ob mem returned	:%d\n", ob_mem_len);

	dev->mem[MEM_TYPE_DRIVER].host_v_addr =
	    pci_alloc_consistent(((fsl_pci_dev_t *) dev->priv_dev)->dev,
				 ob_mem_len,
				 &(dev->mem[MEM_TYPE_DRIVER].host_dma_addr));
	dev->mem[MEM_TYPE_DRIVER].len = ob_mem_len;
	if (unlikely(NULL == dev->mem[MEM_TYPE_DRIVER].host_v_addr)) {
		print_error("\t \t Allocating ob mem failed....\n");
		goto error;
	}

	dev->mem[MEM_TYPE_DRIVER].host_p_addr =
	    __pa(dev->mem[MEM_TYPE_DRIVER].host_v_addr);
	print_debug("OB Mem address....	:%p\n",
		    dev->mem[MEM_TYPE_DRIVER].host_v_addr);
	print_debug("OB Mem dma address... :%llx\n",
		    dev->mem[MEM_TYPE_DRIVER].host_dma_addr);
	print_debug("OB Mem physical address.. :%llx\n",
		    dev->mem[MEM_TYPE_DRIVER].host_p_addr);

	dev->h_mem = dev->mem[MEM_TYPE_DRIVER].host_v_addr;

	/* Assign the diff pointers properly */
	dev->h_mem->fw_resp_ring =
	    (dev->mem[MEM_TYPE_DRIVER].host_v_addr + dev->ob_mem.fw_resp_ring);
	dev->h_mem->drv_resp_ring =
	    (dev->mem[MEM_TYPE_DRIVER].host_v_addr +
	     dev->ob_mem.drv_resp_rings);
	dev->h_mem->l_idxs_mem =
	    (dev->mem[MEM_TYPE_DRIVER].host_v_addr + dev->ob_mem.l_idxs_mem);
	dev->h_mem->s_c_idxs_mem =
	    (dev->mem[MEM_TYPE_DRIVER].host_v_addr + dev->ob_mem.s_c_idxs_mem);
	dev->h_mem->l_r_cntrs_mem =
	    (dev->mem[MEM_TYPE_DRIVER].host_v_addr + dev->ob_mem.l_r_cntrs_mem);
	dev->h_mem->s_c_r_cntrs_mem =
	    (dev->mem[MEM_TYPE_DRIVER].host_v_addr +
	     dev->ob_mem.s_c_r_cntrs_mem);
	dev->h_mem->cntrs_mem =
	    (dev->mem[MEM_TYPE_DRIVER].host_v_addr + dev->ob_mem.cntrs_mem);
	dev->h_mem->s_c_cntrs_mem =
	    (dev->mem[MEM_TYPE_DRIVER].host_v_addr + dev->ob_mem.s_c_cntrs_mem);
	dev->h_mem->op_pool =
	    (dev->mem[MEM_TYPE_DRIVER].host_v_addr + dev->ob_mem.op_pool);
	dev->h_mem->ip_pool =
	    (dev->mem[MEM_TYPE_DRIVER].host_v_addr + dev->ob_mem.ip_pool);

	print_debug("\n ====== OB MEM POINTERS =======\n");
	print_debug("\t Hmem			:%p\n", dev->h_mem);
	print_debug("\t H HS Mem		:%p\n", &(dev->h_mem->hs_mem));
	print_debug("\t Fw resp ring		:%p\n",
		    dev->h_mem->fw_resp_ring);
	print_debug("\t Drv resp ring		:%p\n",
		    dev->h_mem->drv_resp_ring);
	print_debug("\t L Idxs mem		:%p\n",
		    dev->h_mem->l_idxs_mem);
	print_debug("\t S C Idxs mem		:%p\n",
		    dev->h_mem->s_c_idxs_mem);
	print_debug("\t L R cntrs mem		:%p\n",
		    dev->h_mem->l_r_cntrs_mem);
	print_debug("\t S C R cntrs mem	:%p\n", dev->h_mem->s_c_r_cntrs_mem);
	print_debug("\t Cntrs mem		:%p\n", dev->h_mem->cntrs_mem);
	print_debug("\t S C cntrs mem		:%p\n",
		    dev->h_mem->s_c_cntrs_mem);
	print_debug("\t OP pool			:%p\n", dev->h_mem->op_pool);
	print_debug("\t IP pool			:%p\n", dev->h_mem->ip_pool);
	print_debug("\t Total req mem size	:%x\n", dev->tot_req_mem_size);

	return 0;

error:
	return -1;
}

void init_handshake(fsl_crypto_dev_t *dev)
{
	phys_addr_t ob_mem = dev->mem[MEM_TYPE_DRIVER].host_p_addr;
	phys_addr_t msi_mem = dev->mem[MEM_TYPE_MSI].host_p_addr;

	/* Write our address to the firmware -
	 * It uses this to give it details when it is up */
	uint32_t l_val = (uint32_t) (ob_mem & PHYS_ADDR_L_32_BIT_MASK);
	uint32_t h_val = (ob_mem & PHYS_ADDR_H_32_BIT_MASK) >> 32;

	dev->h_mem->hs_mem.state = DEFAULT;

	print_debug("C HS mem addr		:%p\n",
		    &(dev->c_hs_mem->h_ob_mem_l));
	print_debug("Host ob mem addr,	L	:%0x	H	:%0x\n", l_val,
		    h_val);
#ifdef P4080_BUILD
	IO_LE_WRITE32(l_val, &(dev->c_hs_mem->h_ob_mem_l));
	IO_LE_WRITE32(h_val, &(dev->c_hs_mem->h_ob_mem_h));
#else
	IO_BE_WRITE32(l_val, &(dev->c_hs_mem->h_ob_mem_l));
	IO_BE_WRITE32(h_val, &(dev->c_hs_mem->h_ob_mem_h));
#endif

	/* Write MSI info the device */
	l_val = (uint32_t) (msi_mem & PHYS_ADDR_L_32_BIT_MASK);
	h_val = (msi_mem & PHYS_ADDR_H_32_BIT_MASK) >> 32;
	print_debug("MSI mem addr,	L	:%0x	H	:%0x\n", l_val,
		    h_val);
#ifdef P4080_BUILD
	IO_LE_WRITE32(l_val, &(dev->c_hs_mem->h_msi_mem_l));
	IO_LE_WRITE32(h_val, &(dev->c_hs_mem->h_msi_mem_h));
#else
	IO_BE_WRITE32(l_val, &(dev->c_hs_mem->h_msi_mem_l));
	IO_BE_WRITE32(h_val, &(dev->c_hs_mem->h_msi_mem_h));
#endif
}

void init_fw_resp_ring(fsl_crypto_dev_t *dev)
{
	fw_resp_ring_t *fw_ring = dev->fw_resp_rings;
	int i = 0, offset = 0;

	for (i = 0; i < NUM_OF_RESP_RINGS; i++) {
		fw_ring = &dev->fw_resp_rings[i];
		fw_ring->id = i;
		fw_ring->depth = DEFAULT_FIRMWARE_RESP_RING_DEPTH;
		fw_ring->v_addr = dev->h_mem->fw_resp_ring;
		fw_ring->p_addr = __pa(fw_ring->v_addr);

		fw_ring->idxs = &(dev->h_mem->l_idxs_mem[dev->num_of_rings]);
		fw_ring->cntrs =
		    &(dev->h_mem->l_r_cntrs_mem[dev->num_of_rings]);
		fw_ring->s_c_cntrs =
		    &(dev->h_mem->s_c_r_cntrs_mem[dev->num_of_rings]);
		fw_ring->s_cntrs = NULL;

		offset += (DEFAULT_FIRMWARE_RESP_RING_DEPTH *
			   sizeof(resp_ring_entry_t));
	}
}

void make_fw_resp_ring_circ_list(fsl_crypto_dev_t *dev)
{
	int i = 0;

	for (i = 1; i < NUM_OF_RESP_RINGS; i++)
		dev->fw_resp_rings[i - 1].next = &(dev->fw_resp_rings[i]);
	dev->fw_resp_rings[i - 1].next = dev->fw_resp_rings[0].next;
}

void init_rps(fsl_crypto_dev_t *dev)
{
	fsl_h_rsrc_ring_pair_t *rp = NULL;
	uint32_t off = 0, i = 0;

	for (i = 0; i < dev->num_of_rings; i++) {
		rp = &(dev->ring_pairs[i]);

		rp->dev = dev;
		rp->depth = rp->info.depth;
		rp->num_of_sec_engines = 1;

		rp->ip_pool = dev->ip_pool.drv_map_pool.pool;
		rp->req_r = NULL;
		rp->resp_r =
		    (resp_ring_entry_t *) ((uint8_t *) dev->h_mem->
					   drv_resp_ring + off);
		off += (rp->depth * sizeof(resp_ring_entry_t));

		rp->intr_ctrl_flag = NULL;
		rp->indexes = &(dev->h_mem->l_idxs_mem[i]);
		rp->counters = &(dev->h_mem->l_r_cntrs_mem[i]);
		rp->s_c_counters = &(dev->h_mem->s_c_r_cntrs_mem[i]);
		rp->shadow_counters = NULL;

		INIT_LIST_HEAD(&(rp->ring_pair_list_node));
		INIT_LIST_HEAD(&(rp->isr_ctx_list_node));
		INIT_LIST_HEAD(&(rp->bh_ctx_list_node));

		atomic_set(&(rp->sec_eng_sel), 0);
		spin_lock_init(&(rp->ring_lock));
	}

}

static void send_hs_command(uint8_t cmd, fsl_crypto_dev_t *dev, void *data)
{
	const char *str_state = NULL;

	switch (cmd) {
	case HS_INIT_CONFIG:
		str_state = "HS_INIT_CONFIG\n";
		set_sysfs_value(dev->priv_dev, DEVICE_STATE_SYSFILE,
				(uint8_t *) str_state, strlen(str_state));
		{
			phys_addr_t drv_resp_rings =
			    dev->mem[MEM_TYPE_DRIVER].host_p_addr +
			    dev->ob_mem.drv_resp_rings;
			phys_addr_t fw_resp_ring =
			    dev->mem[MEM_TYPE_DRIVER].host_p_addr +
			    dev->ob_mem.fw_resp_ring;
			phys_addr_t s_cntrs =
			    dev->mem[MEM_TYPE_DRIVER].host_p_addr +
			    dev->ob_mem.s_c_cntrs_mem;
			phys_addr_t r_s_cntrs =
			    dev->mem[MEM_TYPE_DRIVER].host_p_addr +
			    dev->ob_mem.s_c_r_cntrs_mem;

			ASSIGN8(dev->c_hs_mem->command, HS_INIT_CONFIG);
			ASSIGN8(dev->c_hs_mem->data.config.num_of_rps,
				dev->num_of_rings);
			ASSIGN8(dev->c_hs_mem->data.config.max_pri,
				dev->max_pri_level);
			ASSIGN8(dev->c_hs_mem->data.config.num_of_fwresp_rings,
				NUM_OF_RESP_RINGS);

			ASSIGN16(dev->c_hs_mem->data.config.req_mem_size,
				 dev->tot_req_mem_size);
			ASSIGN32(dev->c_hs_mem->data.config.drv_resp_ring,
				 drv_resp_rings);
			ASSIGN32(dev->c_hs_mem->data.config.fw_resp_ring,
				 fw_resp_ring);
			ASSIGN32(dev->c_hs_mem->data.config.s_cntrs, s_cntrs);
			ASSIGN32(dev->c_hs_mem->data.config.r_s_cntrs,
				 r_s_cntrs);
			ASSIGN32(dev->c_hs_mem->data.config.fw_resp_ring_depth,
				 DEFAULT_FIRMWARE_RESP_RING_DEPTH);

			print_debug("\n	HS_INIT_CONFIG Details\n");
			print_debug
			    ("\t Num of rps			:%d\n",
			     dev->num_of_rings);
			print_debug
			    ("\t Max pri			:%d\n",
			     dev->max_pri_level);
			print_debug
			    ("\t Req mem size			:%d\n",
			     dev->tot_req_mem_size);
			print_debug
			    ("\t Drv resp ring			:%llx\n",
			     drv_resp_rings);
			print_debug
			    ("\t Fw resp ring			:%llx\n",
			     fw_resp_ring);
			print_debug
			    ("\t S C Counters			:%llx\n",
			     s_cntrs);
			print_debug
			    ("\t R S C counters			:%llx\n",
			     r_s_cntrs);
		}
		print_debug
		    ("\t Sending FW_INIT_CONFIG command at addr	:%p\n",
		     &(dev->c_hs_mem->state));
		ASSIGN8(dev->c_hs_mem->state, FW_INIT_CONFIG);
		break;

	case HS_INIT_RING_PAIR:
		str_state = "HS_INIT_RING_PAIR\n";
		set_sysfs_value(dev->priv_dev, DEVICE_STATE_SYSFILE,
				(uint8_t *) str_state, strlen(str_state));
		{
			struct ring_info *ring = data;
			phys_addr_t resp_r =
			    __pa(dev->ring_pairs[ring->ring_id].resp_r);
			phys_addr_t s_r_cntrs =
			    __pa(dev->ring_pairs[ring->ring_id].s_c_counters);

			ASSIGN8(dev->c_hs_mem->command, HS_INIT_RING_PAIR);
			ASSIGN8(dev->c_hs_mem->data.ring.rid, ring->ring_id);
			ASSIGN8(dev->c_hs_mem->data.ring.props, ring->flags);
			ASSIGN16(dev->c_hs_mem->data.ring.msi_data,
				 ring->msi_data);
			ASSIGN32(dev->c_hs_mem->data.ring.depth, ring->depth);
			ASSIGN32(dev->c_hs_mem->data.ring.resp_ring, resp_r);
			ASSIGN32(dev->c_hs_mem->data.ring.msi_addr_l,
				 ring->msi_addr_l);
			ASSIGN32(dev->c_hs_mem->data.ring.msi_addr_h,
				 ring->msi_addr_h);
			ASSIGN32(dev->c_hs_mem->data.ring.s_r_cntrs, s_r_cntrs);

			print_debug("\n	HS_INIT_RING_PAIR Details\n");
			print_debug
			    ("\t Rid				:%d\n",
			     ring->ring_id);
			print_debug
			    ("\t Depth				:%d\n",
			     ring->depth);
			print_debug
			    ("\t MSI Data			:%0x\n",
			     ring->msi_data);
			print_debug
			    ("\t MSI Addr L			:%0x\n",
			     ring->msi_addr_l);
			print_debug
			    ("\t MSI Addr H			:%0x\n",
			     ring->msi_addr_h);
			print_debug
			    ("\t MSI data			:%0x\n",
			     ring->msi_data);
			print_debug
			    ("\t Ring counters addr		:%llx\n",
			     s_r_cntrs);

		}
		ASSIGN8(dev->c_hs_mem->state, FW_INIT_RING_PAIR);
		break;
	case HS_COMPLETE:
		str_state = "HS_COMPLETE\n";
		set_sysfs_value(dev->priv_dev, DEVICE_STATE_SYSFILE,
				(uint8_t *) str_state, strlen(str_state));
		set_sysfs_value(dev->priv_dev, FIRMWARE_STATE_SYSFILE,
				(uint8_t *) str_state, strlen(str_state));

		ASSIGN8(dev->c_hs_mem->command, HS_COMPLETE);
		ASSIGN8(dev->c_hs_mem->state, FW_HS_COMPLETE);
		break;
	case WAIT_FOR_RNG:
		str_state = "WAIT_FOR_RNG\n";
		set_sysfs_value(dev->priv_dev, DEVICE_STATE_SYSFILE,
				(uint8_t *) str_state, strlen(str_state));
		set_sysfs_value(dev->priv_dev, FIRMWARE_STATE_SYSFILE,
				(uint8_t *) str_state, strlen(str_state));

		ASSIGN8(dev->c_hs_mem->command, WAIT_FOR_RNG);
		ASSIGN8(dev->c_hs_mem->state, FW_WAIT_FOR_RNG);

		break;
	case RNG_DONE:
		str_state = "RNG_DONE\n";
		set_sysfs_value(dev->priv_dev, DEVICE_STATE_SYSFILE,
				(uint8_t *) str_state, strlen(str_state));
		set_sysfs_value(dev->priv_dev, FIRMWARE_STATE_SYSFILE,
				(uint8_t *) str_state, strlen(str_state));

		ASSIGN8(dev->c_hs_mem->command, RNG_DONE);
		ASSIGN8(dev->c_hs_mem->state, FW_RNG_DONE);

		break;
	default:
		print_error("Invalid command	:%d\n", cmd);
	}

	return;
}

int32_t handshake(fsl_crypto_dev_t *dev, crypto_dev_config_t *config)
{
	const char *str_state = NULL;
	uint8_t rid = 0;
	uint32_t timeoutcntr = 0;
#define HS_RESULT_OK			1
#define CHECK_HS_RESULT(x)		if (HS_RESULT_OK != x) return -1;
#define LOOP_BREAK_TIMEOUT_MS		1000
#define LOOP_BREAK_TIMEOUT_JIFFIES	msecs_to_jiffies(LOOP_BREAK_TIMEOUT_MS)
#define HS_TIMEOUT_IN_MS		(50 * LOOP_BREAK_TIMEOUT_MS)

	ASSIGN8(dev->c_hs_mem->state, FIRMWARE_UP);
	while (true) {
		ASSIGN8(dev->h_mem->hs_mem.state, dev->h_mem->hs_mem.state);
		switch (dev->h_mem->hs_mem.state) {
		case FIRMWARE_UP:
			print_debug("\n ----------- FIRMWARE_UP -----------\n");
			str_state = "FIRMWARE_UP\n";
			set_sysfs_value(dev->priv_dev, FIRMWARE_STATE_SYSFILE,
					(uint8_t *) str_state,
					strlen(str_state));

			dev->h_mem->hs_mem.state = DEFAULT;

			ASSIGN32(dev->h_mem->hs_mem.data.device.p_ib_mem_base_l,
				 dev->h_mem->hs_mem.data.
				 device.p_ib_mem_base_l);
			ASSIGN32(dev->h_mem->hs_mem.data.device.p_ib_mem_base_h,
				 dev->h_mem->hs_mem.data.
				 device.p_ib_mem_base_h);
			ASSIGN32(dev->h_mem->hs_mem.data.device.p_ob_mem_base_l,
				 dev->h_mem->hs_mem.data.
				 device.p_ob_mem_base_l);
			ASSIGN32(dev->h_mem->hs_mem.data.device.p_ob_mem_base_h,
				 dev->h_mem->hs_mem.data.
				 device.p_ob_mem_base_h);
			ASSIGN32(dev->h_mem->hs_mem.data.device.no_secs,
				 dev->h_mem->hs_mem.data.device.no_secs);

			print_debug("\t Device Shared Details ::\n");
			print_debug
			    ("\tIb mem PhyAddr L:%0x, Ib mem PhyAddr H:%0x\n",
			     dev->h_mem->hs_mem.data.device.p_ib_mem_base_l,
			     dev->h_mem->hs_mem.data.device.p_ib_mem_base_h);

			print_debug
			    ("\tOb mem PhyAddr L:%0x, Ob mem PhyAddr H:%0x\n",
			     dev->h_mem->hs_mem.data.device.p_ob_mem_base_l,
			     dev->h_mem->hs_mem.data.device.p_ob_mem_base_h);

			dev->mem[MEM_TYPE_SRAM].dev_p_addr = (dev_p_addr_t)
			    ((dev_p_addr_t)
			     (dev->h_mem->hs_mem.data.
			      device.p_ib_mem_base_h) << 32) | (dev->h_mem->
				  hs_mem.data.device.p_ib_mem_base_l);

			dev->mem[MEM_TYPE_DRIVER].dev_p_addr = (dev_p_addr_t)
			    ((dev_p_addr_t)
			     (dev->h_mem->hs_mem.data.
			      device.p_ob_mem_base_h) << 32) | (dev->h_mem->
				  hs_mem.data.device.p_ob_mem_base_l);

			print_debug
			    ("\t Formed dev ib mem phys address  : %0llx\n",
			     dev->mem[MEM_TYPE_SRAM].dev_p_addr);
			print_debug
			    ("\t Formed dev ob mem phys address  : %0llx\n",
			     dev->mem[MEM_TYPE_DRIVER].dev_p_addr);

			send_hs_command(HS_INIT_CONFIG, dev, config);
			break;

		case FW_INIT_CONFIG_COMPLETE:
			print_debug("\n --- FW_INIT_CONFIG_COMPLETE ---\n");
			str_state = "FW_INIT_CONFIG_COMPLETE\n";
			set_sysfs_value(dev->priv_dev, FIRMWARE_STATE_SYSFILE,
					(uint8_t *) str_state,
					strlen(str_state));

			dev->h_mem->hs_mem.state = DEFAULT;

			ASSIGN32(dev->h_mem->hs_mem.data.config.s_r_cntrs,
				 dev->h_mem->hs_mem.data.config.s_r_cntrs);

			dev->s_mem.s_r_cntrs =
			    ((dev->mem[MEM_TYPE_SRAM].host_v_addr) +
			     dev->h_mem->hs_mem.data.config.s_r_cntrs);

			ASSIGN32(dev->h_mem->hs_mem.data.config.s_cntrs,
				 dev->h_mem->hs_mem.data.config.s_cntrs);

			dev->s_mem.s_cntrs =
			    ((dev->mem[MEM_TYPE_SRAM].host_v_addr) +
			     dev->h_mem->hs_mem.data.config.s_cntrs);

			ASSIGN32(dev->h_mem->hs_mem.data.config.ip_pool,
				 dev->h_mem->hs_mem.data.config.ip_pool);

			dev->ip_pool.fw_pool.dev_p_addr =
			    ((dev->mem[MEM_TYPE_SRAM].dev_p_addr) +
			     dev->h_mem->hs_mem.data.config.ip_pool);
			dev->ip_pool.fw_pool.host_map_p_addr =
			    ((dev->mem[MEM_TYPE_SRAM].host_p_addr) +
			     dev->h_mem->hs_mem.data.config.ip_pool);
			dev->ip_pool.fw_pool.host_map_v_addr =
			    ((dev->mem[MEM_TYPE_SRAM].host_v_addr) +
			     dev->h_mem->hs_mem.data.config.ip_pool);

			ASSIGN32(dev->h_mem->hs_mem.data.
				 config.resp_intr_ctrl_flag,
				 dev->h_mem->hs_mem.data.
				 config.resp_intr_ctrl_flag);

			{
				int i = 0;
				void *ptr =
				    ((dev->mem[MEM_TYPE_SRAM].host_v_addr) +
				     dev->h_mem->hs_mem.data.config.
				     resp_intr_ctrl_flag);
				for (i = 0; i < NUM_OF_RESP_RINGS; i++) {
					dev->fw_resp_rings[i].intr_ctrl_flag =
					    ptr + (i * sizeof(uint32_t *));
					dev->fw_resp_rings[i].s_cntrs =
					    &(dev->s_mem.
					      s_r_cntrs[dev->num_of_rings + i]);
					print_debug
				    ("\t FW Intrl Ctrl Flag:%p\n",
				     dev->fw_resp_rings[i].intr_ctrl_flag);
				}
			}

			print_debug
			    ("\n ----- Details from firmware  -------\n");
			print_debug
			    ("\t \t SRAM H V ADDR		:%p\n",
			     dev->mem[MEM_TYPE_SRAM].host_v_addr);
			print_debug("\t \t S R CNTRS OFFSET	:%0x\n",
				    dev->h_mem->hs_mem.data.config.s_r_cntrs);
			print_debug
			    ("\t \t S CNTRS				:%0x\n",
			     dev->h_mem->hs_mem.data.config.s_cntrs);
			print_debug("\n -----------------------------------\n");

			print_debug
			    ("\t R S Cntrs			:%p\n",
			     dev->s_mem.s_r_cntrs);
			print_debug
			    ("\t S Cntrs			:%p\n",
			     dev->s_mem.s_cntrs);
			print_debug
			    ("\t FW Pool Dev P addr		:%llx\n",
			     dev->ip_pool.fw_pool.dev_p_addr);
			print_debug("\t FW Pool host P addr	:%llx\n",
				    dev->ip_pool.fw_pool.host_map_p_addr);
			print_debug("\t FW Pool host V addr	:%p\n",
				    dev->ip_pool.fw_pool.host_map_v_addr);
			send_hs_command(HS_INIT_RING_PAIR, dev,
					&(config->ring[rid]));
			break;

		case FW_INIT_RING_PAIR_COMPLETE:
			print_debug
			    ("\n ---- FW_INIT_RING_PAIR_COMPLETE ----\n");
			str_state = "FW_INIT_RING_PAIR_COMPLETE\n";
			set_sysfs_value(dev->priv_dev, FIRMWARE_STATE_SYSFILE,
					(uint8_t *) str_state,
					strlen(str_state));
			dev->h_mem->hs_mem.state = DEFAULT;

			if(((config->ring[rid].flags & APP_RING_PROP_AFFINE_MASK)
				>> APP_RING_PROP_AFFINE_SHIFT) >
				(dev->h_mem->hs_mem.data.device.no_secs)){
				print_error("Wrong Affinity for the ring: %d "
					"No of SECs are %d\n",rid,
					dev->h_mem->hs_mem.data.device.no_secs);
				goto error;
			}
			ASSIGN32(dev->h_mem->hs_mem.data.ring.req_r,
				 dev->h_mem->hs_mem.data.ring.req_r);
			ASSIGN32(dev->h_mem->hs_mem.data.ring.intr_ctrl_flag,
				 dev->h_mem->hs_mem.data.ring.intr_ctrl_flag);

			dev->ring_pairs[rid].shadow_counters =
			    &(dev->s_mem.s_r_cntrs[rid]);
			dev->ring_pairs[rid].req_r =
			    ((dev->mem[MEM_TYPE_SRAM].host_v_addr) +
			     dev->h_mem->hs_mem.data.ring.req_r);
			dev->ring_pairs[rid].intr_ctrl_flag =
			    ((dev->mem[MEM_TYPE_SRAM].host_v_addr) +
			     dev->h_mem->hs_mem.data.ring.intr_ctrl_flag);

			print_debug
			    ("\t Ring id				:%d\n",
			     rid);
			print_debug
			    ("\t Shadow cntrs				:%p\n",
			     dev->ring_pairs[rid].shadow_counters);
			print_debug
			    ("\t Req r					:%p\n",
			     dev->ring_pairs[rid].req_r);
			if (++rid >= dev->num_of_rings) {
				send_hs_command(HS_COMPLETE, dev, NULL);
			} else
				send_hs_command(HS_INIT_RING_PAIR, dev,
						&(config->ring[rid]));
			break;
		case FW_INIT_RNG:
			send_hs_command(WAIT_FOR_RNG, dev, NULL);
			if (rng_instantiation(dev)) {
				print_error("RNG Instantiation Failed.\n");
				goto error;
			} else {
				send_hs_command(RNG_DONE, dev, NULL);
				goto exit;
			}
			break;
		case FW_RNG_COMPLETE:
			goto exit;

		case DEFAULT:
			if (!
			    (HS_TIMEOUT_IN_MS -
			     (timeoutcntr * LOOP_BREAK_TIMEOUT_MS))) {
				print_error("HS Timed out !!!!\n");
				goto error;
			}

			/* Schedule out so that loop does not hog CPU */
			++timeoutcntr;
			set_current_state(TASK_INTERRUPTIBLE);
			schedule_timeout(LOOP_BREAK_TIMEOUT_JIFFIES);

			break;

		default:
			print_error("Invalid state	:%d\n",
				    dev->h_mem->hs_mem.state);
			goto error;
		}
	}
exit:
	return 0;

error:
	return -1;

}


void init_op_pool(fsl_crypto_dev_t *dev)
{
	dev->op_pool.v_addr = dev->h_mem->op_pool;
	dev->op_pool.p_addr = __pa(dev->op_pool.v_addr);

	dev->op_pool.pool =
	    reg_mem_pool(dev->op_pool.v_addr, DEFAULT_HOST_OP_BUFFER_POOL_SIZE);
}

void init_ip_pool(fsl_crypto_dev_t *dev)
{
	dev->ip_pool.drv_map_pool.v_addr = dev->h_mem->ip_pool;
	dev->ip_pool.drv_map_pool.p_addr =
	    __pa(dev->ip_pool.drv_map_pool.v_addr);

	dev->ip_pool.drv_map_pool.pool =
	    reg_mem_pool(dev->h_mem->ip_pool, FIRMWARE_IP_BUFFER_POOL_SIZE);
	print_debug
	    ("\t \t Registered Pool Address			:%p\n",
	     dev->ip_pool.drv_map_pool.pool);
}

void init_crypto_ctx_pool(fsl_crypto_dev_t *dev)
{
	dev->ctx_pool = init_ctx_pool();
}

static int32_t ring_enqueue(fsl_crypto_dev_t *c_dev, uint32_t jr_id,
			    dev_dma_addr_t sec_desc)
{
	uint32_t wi = 0;
	uint32_t jobs_processed = 0;
#ifndef HIGH_PERF
	uint32_t app_req_cnt = 0;
#endif
	fsl_h_rsrc_ring_pair_t *rp = NULL;

#ifndef HIGH_PERF
#ifdef MULTIPLE_RESP_RINGS
	dev_dma_addr_t ctx_desc = 0;
	void *h_desc = 0;
#endif
#endif

	print_debug("Sec desc addr	: %0llx\n", sec_desc);
	print_debug("Enqueue job in ring	: %d\n", jr_id);

	rp = &(c_dev->ring_pairs[jr_id]);

	/* Acquire the lock on current ring */
	spin_lock_bh(&rp->ring_lock);

#ifdef P4080_BUILD
	jobs_processed = rp->s_c_counters->jobs_processed;
#else
	ASSIGN32(jobs_processed, rp->s_c_counters->jobs_processed);
#endif

#define RING_FULL(rp) \
	(((rp->counters->jobs_added - jobs_processed) >= rp->depth) ? 1 : 0)

	if (RING_FULL(rp)) {
		print_error("Ring	:%d is full\n", jr_id);
		spin_unlock_bh(&(rp->ring_lock));
		return -1;
	}
#ifndef HIGH_PERF
#ifdef MULTIPLE_RESP_RINGS
	if (jr_id != 0) {
		ctx_desc = sec_desc & ~((uint64_t) 0x03);
		if (ctx_desc < c_dev->mem[MEM_TYPE_DRIVER].dev_p_addr)
			h_desc = c_dev->ip_pool.fw_pool.host_map_v_addr +
			    (ctx_desc - c_dev->ip_pool.fw_pool.dev_p_addr);
		else
			h_desc = c_dev->ip_pool.fw_pool.host_map_v_addr +
			(ctx_desc - c_dev->mem[MEM_TYPE_DRIVER].dev_p_addr -
			c_dev->ip_pool.drv_map_pool.p_addr);

		if (rp->info.flags & APP_RING_PROP_ORDER_MASK >>
		    APP_RING_PROP_ORDER_SHIFT) {
			print_debug("Order bit is set : %d, Desc : %0llx\n", rp->indexes->w_index, sec_desc);
			store_dev_ctx(h_desc, jr_id, rp->indexes->w_index + 1);
		} else{
			print_debug("Order bit is not set : %d, Desc : %0llx\n", rp->indexes->w_index, sec_desc);
			store_dev_ctx(h_desc, jr_id, 0);
		}
	}
#endif
#endif
	wi = rp->indexes->w_index;

	print_debug("Enqueuing at the index : %d\n", wi);
	print_debug("Enqueuing to the req r addr	:%p\n", rp->req_r);
	print_debug("Writing at the addr		:%p\n",
		    &(rp->req_r[wi].sec_desc));

#ifndef P4080_BUILD
	ASSIGN64(rp->req_r[wi].sec_desc, sec_desc);
#else
	rp->req_r[wi].sec_desc = sec_desc;
#endif

	rp->indexes->w_index = (wi + 1) % rp->depth;
	print_debug("Update W index		: %d\n", rp->indexes->w_index);

	rp->counters->jobs_added += 1;
	print_debug("Updated jobs added	:%d\n", rp->counters->jobs_added);
#ifndef HIGH_PERF
	if (jr_id) {
		app_req_cnt =  atomic_inc_return(&c_dev->app_req_cnt);
		set_sysfs_value(c_dev->priv_dev, STATS_REQ_COUNT_SYS_FILE,
				(uint8_t *) &(app_req_cnt),
				sizeof(app_req_cnt));
	}
#endif
	print_debug("Ring	:%d	Shadow counter address	%p\n", jr_id,
		    &(rp->shadow_counters->req_jobs_added));
#ifndef P4080_BUILD
	ASSIGN32(rp->shadow_counters->req_jobs_added, rp->counters->jobs_added);
#else
	rp->shadow_counters->req_jobs_added = rp->counters->jobs_added;
#endif

	spin_unlock_bh(&(rp->ring_lock));
	return 0;
}

void prepare_crypto_cfg_info_string( crypto_dev_config_t *config, uint8_t *cryp_cfg_str )
{
	uint32_t    i = 0;
	uint8_t     ring_str[100];

	sprintf(cryp_cfg_str, "Tot rings:%d\n", config->num_of_rings);
	sprintf(ring_str, "rid,dpth,affin,prio,ord\n");
	strcat(cryp_cfg_str, ring_str);
	for (i = 0; i < config->num_of_rings; i++) {
		sprintf(ring_str, " %d,%4d,%d,%d,%d\n", i,
			config->ring[i].depth,
			((config->ring[i].flags & APP_RING_PROP_AFFINE_MASK) >>
			 APP_RING_PROP_AFFINE_SHIFT),
			((config->ring[i].flags & APP_RING_PROP_PRIO_MASK) >>
			 APP_RING_PROP_PRIO_SHIFT),
			((config->ring[i].flags & APP_RING_PROP_ORDER_MASK) >>
			 APP_RING_PROP_ORDER_SHIFT));
		strcat(cryp_cfg_str, ring_str);
	}
	return;
}


int32_t set_device_status_per_cpu(fsl_crypto_dev_t *c_dev, uint8_t set)
{
	uint32_t i = 0;
	per_dev_struct_t *dev_stat = NULL;
	for_each_online_cpu(i) {
		dev_stat = per_cpu_ptr(c_dev->dev_status, i);
		atomic_set(&(dev_stat->device_status), set);
	}
	return 0;
}

void *fsl_crypto_layer_add_device(void *dev, crypto_dev_config_t *config)
{
	uint32_t i = 0;
	uint8_t  crypto_info_str[200];	

	fsl_crypto_dev_t *c_dev = kzalloc(sizeof(fsl_crypto_dev_t), GFP_KERNEL);
	fsl_h_rsrc_ring_pair_t *rp =
	    kzalloc(sizeof(fsl_h_rsrc_ring_pair_t) * config->num_of_rings,
		    GFP_KERNEL);

	if (unlikely(NULL == c_dev) || unlikely(NULL == rp)) {
		print_error("\t Mem alloc failed !!\n");
		goto error;
	}

	c_dev->priv_dev = dev;
	c_dev->ring_pairs = rp;
	c_dev->config = config;

	/* HACK */
	((fsl_pci_dev_t *) dev)->crypto_dev = c_dev;

	/* Get the inbound memory addresses from the PCI driver */
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4, 19, 0))
	for (i = 0; i < MEM_TYPE_MAX; i++) {
		c_dev->mem[i].type = i;
		fsl_drv_get_mem(dev, &c_dev->mem[i]);
	}
#else
	for (i = 0; i < MEM_TYPE_MAX_SKMM; i++) {
		c_dev->mem[i].type = i;
		fsl_drv_get_mem(dev, &c_dev->mem[i]);
	}
#endif

	atomic_set(&(c_dev->crypto_dev_sess_cnt), 0);

	c_dev->c_hs_mem =
	    (crypto_c_hs_mem_t *) (c_dev->mem[MEM_TYPE_SRAM].host_v_addr +
				   DEV_MEM_SIZE - FSL_FIRMWARE_SIZE -
				   DEVICE_CACHE_LINE_SIZE);
	print_debug
	    ("\t IB mem addr					:%p\n",
	     c_dev->mem[MEM_TYPE_SRAM].host_v_addr);
	print_debug
	    ("\t Device hs mem addr				:%p\n",
	     c_dev->c_hs_mem);

	print_debug("\t Rearrange rings.....\n");
	/* Rearrange rings acc to their priority */
	rearrange_rings(c_dev, config);
	print_debug("\t Rearrange complete....\n");

	/* Alloc ob mem */
	if (unlikely(alloc_ob_mem(c_dev, config))) {
		print_error("\t Ob mem alloc failed....\n");
		goto error;
	}

	init_ip_pool(c_dev);
	init_op_pool(c_dev);
	init_crypto_ctx_pool(c_dev);

	print_debug("\t Init fw resp ring....\n");
	/* Initialise fw resp ring info */
	init_fw_resp_ring(c_dev);
	make_fw_resp_ring_circ_list(c_dev);
	print_debug("\t Init fw resp ring complete...\n");

	print_debug("\t Init ring  pair....\n");
	/* Init rp struct */
	init_rps(c_dev);
	print_debug("\t Init ring pair complete...\n");

	print_debug("\t Distribute ring...\n");
	/* Distribute rings to cores and BHs */
	distribute_rings(c_dev, config);
	print_debug("\t Distribute ring complete...\n");

	print_debug("\t Init Handshake....\n");
	/* Initialise hs mem */
	init_handshake(c_dev);
	print_debug("\t Init Handshake complete...\n");

	set_sysfs_value(dev, DEVICE_STATE_SYSFILE, (uint8_t *) "HS Started\n",
			strlen("HS Started\n"));

	c_dev->dev_status = alloc_percpu(per_dev_struct_t);
	set_device_status_per_cpu(c_dev, 1);
	atomic_set(&(c_dev->active_jobs), 0);

	/* Do the handshake */
	if (unlikely(handshake(c_dev, config))) {
		print_error("Handshake failed\n");
		goto error;
	}

	set_sysfs_value(dev, FIRMWARE_STATE_SYSFILE, (uint8_t *) "FW READY\n",
			strlen("FW READY\n"));

	set_sysfs_value(dev, DEVICE_STATE_SYSFILE, (uint8_t *) "DRIVER READY\n",
			strlen("DRIVER READY\n"));

	prepare_crypto_cfg_info_string(config, crypto_info_str);
	set_sysfs_value(dev, CRYPTO_INFO_SYS_FILE, (uint8_t *)crypto_info_str,
			strlen(crypto_info_str));

	printk(KERN_INFO "[FSL-CRYPTO-OFFLOAD-DRV] DevId:%d DEVICE IS UP\n",
	       c_dev->config->dev_no);

	return c_dev;
error:
	cleanup_crypto_device(c_dev);
	return NULL;
}

void cleanup_crypto_device(fsl_crypto_dev_t *dev)
{
	if (NULL == dev)
		return;
#if 0
	int i = 0;
	for (i = 0; i < dev->num_of_rings; i++) {
		/* Delete all the links */
		list_del(&(dev->ring_pairs[i].ring_pair_list_node));
		list_del(&(dev->ring_pairs[i].isr_ctx_list_node));
		list_del(&(dev->ring_pairs[i].bh_ctx_list_node));
	}
#endif

	destroy_ctx_pool(dev->ctx_pool);
	destroy_pool(dev->ip_pool.drv_map_pool.pool);
	destroy_pool(dev->op_pool.pool);

	/* Free the pci alloc consistent mem */
	if (dev->mem[MEM_TYPE_DRIVER].host_v_addr) {
		pci_free_consistent(((fsl_pci_dev_t *) (dev->priv_dev))->dev,
				    dev->mem[MEM_TYPE_DRIVER].len,
				    dev->mem[MEM_TYPE_DRIVER].host_v_addr,
				    dev->mem[MEM_TYPE_DRIVER].host_dma_addr);
	}
	kfree(dev->ring_pairs);
	kfree(dev);
}

int32_t app_ring_enqueue(fsl_crypto_dev_t *c_dev, uint32_t jr_id,
			 dev_dma_addr_t sec_desc)
{
	int32_t ret = 0;
#ifndef HIGH_PERF
	/* Check the block flag for the ring */
	if (0 != atomic_read(&(c_dev->ring_pairs[jr_id].block))) {
		print_debug("Block condition is set for the ring    :%d\n",
			    jr_id);
		return -1;
	}
#endif
	ret = ring_enqueue(c_dev, jr_id, sec_desc);

	return ret;
}

int32_t cmd_ring_enqueue(fsl_crypto_dev_t *c_dev, uint32_t jr_id,
			 dev_dma_addr_t sec_desc)
{
	print_debug("Command ring enqueue called.....\n");
	return ring_enqueue(c_dev, jr_id, sec_desc);
}

void handle_response(fsl_crypto_dev_t *dev, uint64_t desc, int32_t res)
{
	void *h_desc;
	crypto_op_ctx_t *ctx0 = NULL;
	if (desc < dev->mem[MEM_TYPE_SRAM].dev_p_addr)
		h_desc =
		dev->ip_pool.drv_map_pool.v_addr +
		(u32)(desc - dev->mem[MEM_TYPE_DRIVER].dev_p_addr -
		dev->ip_pool.drv_map_pool.p_addr);
	else
		h_desc =
	    dev->ip_pool.drv_map_pool.v_addr + (u32)(desc -
						dev->ip_pool.
						fw_pool.dev_p_addr);

#ifndef HIGH_PERF
	crypto_job_ctx_t *ctx1 = NULL;

	if (get_flag(dev->ip_pool.drv_map_pool.pool, h_desc))
#endif
		ctx0 =
		    (crypto_op_ctx_t *) get_priv_data(dev->ip_pool.
						      drv_map_pool.pool,
						      h_desc);
#ifndef HIGH_PERF
	else
		ctx1 =
		    (crypto_job_ctx_t *) get_priv_data(dev->
						       ip_pool.drv_map_pool.
						       pool, h_desc);
	print_debug("Total Resp count: %d\n", ++total_resp);
	print_debug
	    ("[DEQ] Dev sec desc :%0llx H sec desc :%p"
	     "Ctx0 address :%p Ctx1 address :%p\n", desc, h_desc, ctx0, ctx1);
#endif
	print_debug("\n");
	if (ctx0)
		ctx0->op_done(ctx0, res);
	else
		print_debug("NULL Context !!\n");

#ifndef HIGH_PERF
	if (ctx1)
		crypto_op_done(dev, ctx1, res);
#endif
	return;

}

static inline uint64_t readtb1(void)
{
	uint32_t l = 0, h = 0;

	asm volatile ("mfspr %0, 526" : "=r" (l));
	asm volatile ("mfspr %0, 527" : "=r" (h));

	return ((uint64_t) h << 32) | l;
}

#ifndef MULTIPLE_RESP_RINGS
void demux_fw_responses(fsl_crypto_dev_t *dev)
{
	uint32_t ri = 0;
	uint32_t count = 0;
	uint64_t desc = 0;
	int32_t res = 0;
	uint32_t jobs_added = 0;
	uint32_t app_resp_cnt = 0;
#define MAX_ERROR_STRING 400
	char outstr[MAX_ERROR_STRING];

	resp_ring_entry_t *resp_ring =
	    ((resp_ring_entry_t *) (dev->fw_resp_ring.v_addr));

#ifdef HOST_TYPE_P4080
	jobs_added = dev->fw_resp_ring.s_c_cntrs->jobs_added;
#else
	ASSIGN32(jobs_added, dev->fw_resp_ring.s_c_cntrs->jobs_added);
#endif

	count = jobs_added - dev->fw_resp_ring.cntrs->jobs_processed;

	if (!count)
		goto CMD_RING_RESP;

	dev->fw_resp_ring.cntrs->jobs_processed += count;
	ri = dev->fw_resp_ring.idxs->r_index;

	app_resp_cnt = atomic_read(&dev->app_resp_cnt);


	while (count) {
#if 0
		/* Enqueue it to the dest ring */
		enqueue_to_dest_ring(dev, resp_ring[ri].sec_desc,
				     resp_ring[ri].result);
#endif
#ifdef HOST_TYPE_P4080
		desc = resp_ring[ri].sec_desc;
		res = resp_ring[ri].result;
#else
		ASSIGN64(desc, resp_ring[ri].sec_desc);
		ASSIGN32(res, resp_ring[ri].result);
#endif
		sec_jr_strstatus(outstr, res);

		if (res)
			print_error("Error from SEC	:%s\n", outstr);

		ri = (ri + 1) % (dev->fw_resp_ring.depth);

		count--;

		print_debug("Read index : %d\n", ri);

		handle_response(dev, desc, res);
		print_debug("Handle response done....\n");

		atomic_inc_return(&dev->app_resp_cnt);
	}

	if(app_resp_cnt != atomic_read(&dev->app_resp_cnt))
	{
		app_resp_cnt = atomic_read(&dev->app_resp_cnt);
		set_sysfs_value(dev->priv_dev, STATS_RESP_COUNT_SYS_FILE,
			(uint8_t *) &(app_resp_cnt),
			sizeof(app_resp_cnt));
	}

#ifdef P4080_BUILD
	ASSIGN32(dev->fw_resp_ring.idxs->r_index, ri);
#else
	dev->fw_resp_ring.idxs->r_index = ri;
#endif

	ASSIGN32(dev->fw_resp_ring.s_cntrs->resp_jobs_processed,
		 dev->fw_resp_ring.cntrs->jobs_processed);

	*(dev->fw_resp_ring.intr_ctrl_flag) = 0;

CMD_RING_RESP:
/* Command ring response processing */
/*	printk(KERN_ERR "*** Jobs added.. :%d Jobs processed... :%d\n",
		dev->ring_pairs[0].s_c_counters->jobs_added ,
		dev->ring_pairs[0].counters->jobs_processed);*/

	if (dev->ring_pairs[0].s_c_counters->jobs_added -
	    dev->ring_pairs[0].counters->jobs_processed) {
		ri = dev->ring_pairs[0].indexes->r_index;

#ifdef HOST_TYPE_P4080
		desc = dev->ring_pairs[0].resp_r[ri].sec_desc;
#else
		ASSIGN64(desc, dev->ring_pairs[0].resp_r[ri].sec_desc);
#endif

		print_debug
		    ("DEQUEUE RESP AT : %u RESP DESC : %0llx  == [%p]",
		     ri, desc, &(dev->ring_pairs[0].resp_r[ri]));

		if (desc) {
#ifdef HOST_TYPE_P4080
			res = dev->ring_pairs[0].resp_r[ri].result;
#else
			ASSIGN32(res, dev->ring_pairs[0].resp_r[ri].result);
#endif
			process_cmd_response(dev, desc, res);
			ri = (ri + 1) % (dev->ring_pairs[0].depth);
#ifdef P4080_BUILD
			ASSIGN32(dev->ring_pairs[0].indexes->r_index, ri);
#else
			dev->ring_pairs[0].indexes->r_index = ri;
#endif
			dev->ring_pairs[0].counters->jobs_processed += 1;

			ASSIGN32(dev->ring_pairs[0].
				 shadow_counters->resp_jobs_processed,
				 dev->ring_pairs[0].counters->jobs_processed);
		}
	}
	return;
}

#else

int32_t process_response(fsl_crypto_dev_t *dev,
			 struct list_head *ring_list_head)
{
#define MAX_ERROR_STRING 400
	uint64_t desc = 0;
	uint32_t r_id = 0;
	uint32_t resp_cnt = 0;
	uint32_t ri = 0;
	int32_t res = 0;
	uint32_t jobs_added = 0;
	uint32_t pollcount = 0;
#ifndef HIGH_PERF
	uint32_t app_resp_cnt = 0;
#endif
	char outstr[MAX_ERROR_STRING];
	fsl_h_rsrc_ring_pair_t *ring_cursor = NULL;

	print_debug
	    (" ---------------- PROCESSING RESPONSE ------------------\n");

	list_for_each_entry(ring_cursor, ring_list_head, bh_ctx_list_node) {
		pollcount = 0;

		while (pollcount++ < napi_poll_count) {
#ifdef HOST_TYPE_P4080
			jobs_added = ring_cursor->s_c_counters->jobs_added;
#else
			ASSIGN32(jobs_added,
				 ring_cursor->s_c_counters->jobs_added);
#endif
			resp_cnt =
			    jobs_added - ring_cursor->counters->jobs_processed;

			print_debug("response count :%d\n", resp_cnt);

			if (!resp_cnt)
				continue;

			dev = (fsl_crypto_dev_t *) ring_cursor->dev;
			r_id = ring_cursor->info.ring_id;
			ri = ring_cursor->indexes->r_index;
			print_debug("RING ID : %d\n",
				    ring_cursor->info.ring_id);
			print_debug("GOT INTERRUPT FROM DEV : %d\n",
				    dev->config->dev_no);

			while (resp_cnt) {
#ifdef HOST_TYPE_P4080
				desc = ring_cursor->resp_r[ri].sec_desc;
				res = ring_cursor->resp_r[ri].result;
#else
				ASSIGN64(desc,
					 ring_cursor->resp_r[ri].sec_desc);
				ASSIGN32(res, ring_cursor->resp_r[ri].result);
#endif
				ri = (ri + 1) % (ring_cursor->depth);
				ring_cursor->indexes->r_index = ri;
#ifndef HIGH_PERF
				if (r_id == 0) {
					print_debug
					    ("COMMAND RING GOT AN INTERRUPT\n");

					if (desc)
						process_cmd_response(dev, desc,
								     res);
				} else 
#endif
				{
					print_debug
					    ("APP RING GOT AN INTERRUPT\n");

					if (desc) {
						if (res)
						{
							sec_jr_strstatus(outstr, res);
							printk(KERN_INFO "SEC Error:%s\n",
							       outstr);
						}
						handle_response(dev, desc, res);
					} else
						print_error
					    ("INVALID DESC AT RI : %u\n",
					     ri - 1);
#ifndef HIGH_PERF
					atomic_inc_return(&dev->app_resp_cnt);
#endif
				}
				ring_cursor->counters->jobs_processed += 1;
				ASSIGN32
				    (ring_cursor->shadow_counters->
				     resp_jobs_processed,
				     ring_cursor->counters->jobs_processed);

				--resp_cnt;
			}
		}
		/* Enable the intrs for this ring */
		*(ring_cursor->intr_ctrl_flag) = 0;
	}
#ifndef HIGH_PERF
	/* UPDATE SYSFS ENTRY */
	app_resp_cnt = atomic_read(&dev->app_resp_cnt);
	set_sysfs_value(dev->priv_dev, STATS_RESP_COUNT_SYS_FILE,
			(uint8_t *) &(app_resp_cnt),
			sizeof(app_resp_cnt));
#endif
	print_debug(" DONE PROCESSING RESPONSE :)\n");
	return 0;
}
#endif

/* Backward compatible functions for other algorithms */
static inline unsigned long ip_buf_d_v_addr(fsl_crypto_dev_t *dev,
					    unsigned long h_v_addr)
{
	unsigned long offset =
	    h_v_addr - (unsigned long)dev->ip_pool.drv_map_pool.v_addr;
	return (unsigned long)(dev->ip_pool.fw_pool.host_map_v_addr + offset);
}

void *cmd_get_op_buffer(void *id, uint32_t len, unsigned long flag)
{
	return alloc_buffer(id, len, flag);
}

void cmd_put_op_buffer(void *id, void *addr)
{
	free_buffer(id, addr);
}

void *get_buffer(fsl_crypto_dev_t *c_dev, void *id, uint32_t len,
		 unsigned long flag)
{
	void *addr = NULL;
/*	fsl_crypto_dev_t *c_dev = NULL;	*/

	addr = alloc_buffer(id, len, flag);
	if (NULL == addr)
		return addr;

/*	c_dev = get_crypto_dev(1);	*/
	addr = (void *)ip_buf_d_v_addr(c_dev, (unsigned long)addr);

	return addr;
}

void put_buffer(fsl_crypto_dev_t *c_dev, void *id, void *addr)
{
/*
	fsl_crypto_dev_t *dev = NULL;

	dev = get_crypto_dev(1);
*/
	addr =
	    c_dev->ip_pool.drv_map_pool.v_addr + (addr -
						  c_dev->ip_pool.
						  fw_pool.host_map_v_addr);
	free_buffer(id, addr);
}

void store_crypto_ctx(fsl_crypto_dev_t *c_dev, void *pool, void *buffer,
		      void *ctx)
{
/*	fsl_crypto_dev_t *dev = get_crypto_dev(1); */
	void *addr =
	    c_dev->ip_pool.drv_map_pool.v_addr + (buffer -
						  c_dev->ip_pool.
						  fw_pool.host_map_v_addr);
#ifndef HIGH_PERF
	set_flag(pool, addr, 0);
#endif
	store_priv_data(pool, addr, (unsigned long)ctx);
}

#ifndef HIGH_PERF
#ifdef MULTIPLE_RESP_RINGS
static void store_dev_ctx(void *buffer, uint8_t rid, uint32_t wi)
{
	dev_ctx_t *ctx = (dev_ctx_t *) (buffer - 32);
	ctx->rid = rid;
	ASSIGN32(ctx->wi, wi);
}
#endif
#endif

#ifdef VIRTIO_C2X0
/* For debug purpose */
void print_sess_list()
{
	int cntr_sess = 0;
	struct virtio_c2x0_crypto_sess_ctx *hash_sess = NULL, *next_sess = NULL;

	list_for_each_entry_safe(hash_sess, next_sess,
				 &virtio_c2x0_hash_sess_list, list_entry) {
		cntr_sess++;
		printk(KERN_INFO "sessid[%lx], guest_id[%d]\n",
		       hash_sess->sess_id, hash_sess->guest_id);
	}
	printk(KERN_INFO "=================*******************===============\n");
	printk(KERN_INFO "No of hash_sess in list = %d\n", cntr_sess);
	printk(KERN_INFO "=================*******************===============\n");
}

void cleanup_virtio_pkc_buffers(struct pkc_request *req)
{
	if (NULL == req) {
		print_error("Trying to cleanup NULL pkc request\n");
		return;
	}
	switch (req->type) {
	case RSA_PUB:
		{
			if (req->req_u.rsa_pub_req.n)
				kfree(req->req_u.rsa_pub_req.n);
			if (req->req_u.rsa_pub_req.e)
				kfree(req->req_u.rsa_pub_req.e);
			if (req->req_u.rsa_pub_req.f)
				kfree(req->req_u.rsa_pub_req.f);
			if (req->req_u.rsa_pub_req.g)
				kfree(req->req_u.rsa_pub_req.g);
		}
		break;
	case RSA_PRIV_FORM1:
		{
			if (req->req_u.rsa_priv_f1.n)
				kfree(req->req_u.rsa_priv_f1.n);
			if (req->req_u.rsa_priv_f1.d)
				kfree(req->req_u.rsa_priv_f1.d);
			if (req->req_u.rsa_priv_f1.g)
				kfree(req->req_u.rsa_priv_f1.g);
			if (req->req_u.rsa_priv_f1.f)
				kfree(req->req_u.rsa_priv_f1.f);
		}
		break;
	case RSA_PRIV_FORM2:
		{
			if (req->req_u.rsa_priv_f2.p)
				kfree(req->req_u.rsa_priv_f2.p);
			if (req->req_u.rsa_priv_f2.q)
				kfree(req->req_u.rsa_priv_f2.q);
			if (req->req_u.rsa_priv_f2.d)
				kfree(req->req_u.rsa_priv_f2.d);
			if (req->req_u.rsa_priv_f2.g)
				kfree(req->req_u.rsa_priv_f2.g);
			if (req->req_u.rsa_priv_f2.f)
				kfree(req->req_u.rsa_priv_f2.f);
		}
		break;
	case RSA_PRIV_FORM3:
		{
			if (req->req_u.rsa_priv_f3.p)
				kfree(req->req_u.rsa_priv_f3.p);
			if (req->req_u.rsa_priv_f3.q)
				kfree(req->req_u.rsa_priv_f3.q);
			if (req->req_u.rsa_priv_f3.dp)
				kfree(req->req_u.rsa_priv_f3.dp);
			if (req->req_u.rsa_priv_f3.dq)
				kfree(req->req_u.rsa_priv_f3.dq);
			if (req->req_u.rsa_priv_f3.c)
				kfree(req->req_u.rsa_priv_f3.c);
			if (req->req_u.rsa_priv_f3.g)
				kfree(req->req_u.rsa_priv_f3.g);
			if (req->req_u.rsa_priv_f3.f)
				kfree(req->req_u.rsa_priv_f3.f);
		}
		break;
	case DSA_SIGN:
	case ECDSA_SIGN:
		{
			if (req->req_u.dsa_sign.q)
				kfree(req->req_u.dsa_sign.q);
			if (req->req_u.dsa_sign.r)
				kfree(req->req_u.dsa_sign.r);
			if (req->req_u.dsa_sign.g)
				kfree(req->req_u.dsa_sign.g);
			if (req->req_u.dsa_sign.priv_key)
				kfree(req->req_u.dsa_sign.priv_key);
			if (req->req_u.dsa_sign.m)
				kfree(req->req_u.dsa_sign.m);
			if (req->req_u.dsa_sign.c)
				kfree(req->req_u.dsa_sign.c);
			if (req->req_u.dsa_sign.d)
				kfree(req->req_u.dsa_sign.d);
			if (ECDSA_SIGN == req->type)
				if (req->req_u.dsa_sign.ab)
					kfree(req->req_u.dsa_sign.ab);
		}
		break;
	case DSA_VERIFY:
	case ECDSA_VERIFY:
		{
			if (req->req_u.dsa_verify.q)
				kfree(req->req_u.dsa_verify.q);
			if (req->req_u.dsa_verify.r)
				kfree(req->req_u.dsa_verify.r);
			if (req->req_u.dsa_verify.g)
				kfree(req->req_u.dsa_verify.g);
			if (req->req_u.dsa_verify.pub_key)
				kfree(req->req_u.dsa_verify.pub_key);
			if (req->req_u.dsa_verify.m)
				kfree(req->req_u.dsa_verify.m);
			if (req->req_u.dsa_verify.c)
				kfree(req->req_u.dsa_verify.c);
			if (req->req_u.dsa_verify.d)
				kfree(req->req_u.dsa_verify.d);
			if (ECDSA_VERIFY == req->type)
				if (req->req_u.dsa_verify.ab)
					kfree(req->req_u.dsa_verify.ab);
		}
		break;
	case DH_COMPUTE_KEY:
	case ECDH_COMPUTE_KEY:
		{
			if (req->req_u.dh_req.q)
				kfree(req->req_u.dh_req.q);
			if (req->req_u.dh_req.pub_key)
				kfree(req->req_u.dh_req.pub_key);
			if (req->req_u.dh_req.s)
				kfree(req->req_u.dh_req.s);
			if (req->req_u.dh_req.z)
				kfree(req->req_u.dh_req.z);
			if (ECDH_COMPUTE_KEY == req->type)
				if (req->req_u.dh_req.ab)
					kfree(req->req_u.dh_req.ab);
		}
		break;
	default:
		print_error("Invalid pkc_request_type %d\n", req->type);
		return;
	}
}

void process_virtio_job_response(struct virtio_c2x0_job_ctx *virtio_job)
{
	int32_t ret = 0;
	switch (virtio_job->qemu_cmd.op) {
	case RSA:
		{
			struct pkc_request *req = virtio_job->ctx->req.pkc;
			struct pkc_request *q_req =
			    &virtio_job->qemu_cmd.u.pkc.pkc_req;

			switch (q_req->type) {
			case RSA_PUB:
				print_debug("RSA_PUB completion\n");

				ret =
				    copy_to_user((void __user *)q_req->
						 req_u.rsa_pub_req.g,
						 (void *)req->req_u.rsa_pub_req.
						 g,
						 req->req_u.rsa_pub_req.g_len);
				if (ret != 0)
					print_debug
					    ("return value for RSA PUB of"
						"ouput copy_to_user = %d\n",
						ret);

				cleanup_virtio_pkc_buffers(req);
				break;

			case RSA_PRIV_FORM1:
				print_debug
				("RSA_FORM1 completion : "
				"Output f_len = %d\n",
				req->req_u.rsa_priv_f1.f_len);

				ret =
				    copy_to_user((void __user *)q_req->req_u.
						 rsa_priv_f1.f,
						 (void *)req->req_u.
						 rsa_priv_f1.f,
						 req->req_u.rsa_priv_f1.f_len);

				if (ret != 0)
					print_debug("return value for RSA"
					"FORM 1 of ouput copy_to_user = %d\n",
					ret);

				cleanup_virtio_pkc_buffers(req);

				break;

			case RSA_PRIV_FORM2:
				print_debug
				("RSA_FORM2 completion : "
				"Output f_len = %d\n",
				req->req_u.rsa_priv_f2.f_len);

				ret =
				    copy_to_user((void __user *)q_req->req_u.
						 rsa_priv_f2.f,
						 (void *)req->req_u.
						 rsa_priv_f2.f,
						 req->req_u.rsa_priv_f2.f_len);

				if (ret != 0)
					print_debug
					("return value for RSA FORM 2 of ouput"
						"copy_to_user = %d\n", ret);

				cleanup_virtio_pkc_buffers(req);

				break;

			case RSA_PRIV_FORM3:
				print_debug
				("RSA_FORM3 completion : "
				"Output f_len = %d\n",
				req->req_u.rsa_priv_f3.f_len);

				ret =
				    copy_to_user((void __user *)q_req->req_u.
						 rsa_priv_f3.f,
						 (void *)req->req_u.
						 rsa_priv_f3.f,
						 req->req_u.rsa_priv_f3.f_len);

				if (ret != 0)
					print_debug
					("return value for RSA FORM 3 of ouput"
					"copy_to_user = %d\n", ret);

				cleanup_virtio_pkc_buffers(req);

				break;

			default:
				print_error("OP NOT handled\n");
				break;
			}

			if (req)
				kfree(req);
			break;
		}
	case DSA:{
			struct pkc_request *req = virtio_job->ctx->req.pkc;
			struct pkc_request *q_req =
			    &virtio_job->qemu_cmd.u.pkc.pkc_req;

			switch (q_req->type) {
			case DSA_SIGN:
			case ECDSA_SIGN:{
					print_debug
					    ("DSA/ECDSA_SIGN completion\n");

					ret = copy_to_user((void __user *)
							   q_req->
							   req_u.dsa_sign.c,
							   (void *)req->req_u.
							   dsa_sign.c,
							   req->req_u.dsa_sign.
							   d_len);

					if (ret != 0)
						print_debug
						("ret val DSASIGN c of ouput"
						"copy_to_user = %d\n", ret);

					ret = copy_to_user((void __user *)
							   q_req->req_u.
							   dsa_sign.d,
							   (void *)req->req_u.
							   dsa_sign.d,
							   req->req_u.dsa_sign.
							   d_len);

					if (ret != 0)
						print_debug("return value DSA"
						"SIGN 'd' of ouput"
						"copy_to_user = %d\n", ret);

					cleanup_virtio_pkc_buffers(req);
				}
				break;
			case DSA_VERIFY:
			case ECDSA_VERIFY:
				{
					print_debug
					    ("DSA/ECDSA_VERIFY completion\n");
					cleanup_virtio_pkc_buffers(req);
				}
				break;
			default:
				{
					print_error("OP NOT handled\n");
					break;
				}
			}
			if (req)
				kfree(req);
			break;
		}
	case DH:{
			struct pkc_request *req = virtio_job->ctx->req.pkc;
			struct pkc_request *q_req =
			    &virtio_job->qemu_cmd.u.pkc.pkc_req;

			switch (q_req->type) {
			case DH_COMPUTE_KEY:
			case ECDH_COMPUTE_KEY:
				{
					print_debug
					    ("DH/ECDH_COMPUTE completion\n");
					ret = copy_to_user((void __user *)
							   q_req->req_u.
							   dh_req.z,
							   (void *)req->req_u.
							   dh_req.z,
							   req->req_u.dh_req.
							   z_len);

					if (ret != 0)
						print_debug("return value DH/"
						"ECDH z ouput"
						"copy_to_user = %d\n", ret);

					cleanup_virtio_pkc_buffers(req);
				}
				break;
			default:
				{
					print_error("OP NOT handled\n");
					break;
				}
			}
			if (req)
				kfree(req);
			break;
		}
#ifdef HASH_OFFLOAD
	case AHASH_DIGEST:
		{
			struct scatterlist *sg = NULL;
			uint8_t *buf = NULL;
			int i = 0;

			print_debug("AHASH_DIGEST completion\n");
			ret = copy_to_user((void __user *)
					   virtio_job->qemu_cmd.u.
					   hash.digest_req.result, (void *)
					   (virtio_job->ctx->req.ahash->result),
					   virtio_job->qemu_cmd.u.
					   hash.digest_req.digestsize);
			if (ret != 0)
				print_debug
					("return val AHASH_DIGEST "
					"ouput copy_to_user = %d\n",
					ret);

			sg = virtio_job->ctx->req.ahash->src;
			for (i = 0;
			     i <
			     virtio_job->qemu_cmd.u.hash.digest_req.
			     sg_info.sg_count; i++) {
				buf = sg_virt(sg);
				kfree(buf);

				sg = sg_next(sg);
				buf = NULL;
			}
			kfree(virtio_job->ctx->req.ahash->src);
			kfree(virtio_job->ctx->req.ahash->result);
			kfree(virtio_job->ctx->req.ahash);

			break;
		}
	case AHASH_UPDATE_CTX:
	case AHASH_UPDATE_NO_CTX:
	case AHASH_UPDATE_FIRST:
		{
			struct hash_state *state = NULL;
			struct scatterlist *sg = NULL;
			uint8_t *buf = NULL;
			int i = 0;

			print_debug
			    ("AHASH_UPDATE [%d] completion\n",
			     virtio_job->qemu_cmd.op);

			state = ahash_request_ctx(virtio_job->ctx->req.ahash);
			ret = copy_to_user((void __user *)
					   virtio_job->qemu_cmd.u.
					   hash.update_req.ctx, (uint8_t *)
					   (state->ctx),
					   virtio_job->qemu_cmd.u.
					   hash.update_req.ctxlen);
			if (ret != 0)
				print_debug
				("return value AHASH_UPDATE "
				"ouput copy_to_user = %d\n",
				ret);
			sg = virtio_job->ctx->req.ahash->src;
			for (i = 0;
			     i <
			     virtio_job->qemu_cmd.u.hash.update_req.
			     sg_info.sg_count; i++) {
				buf = sg_virt(sg);
				kfree(buf);

				sg = sg_next(sg);
				buf = NULL;
			}
			kfree(virtio_job->ctx->req.ahash->src);
			kfree(virtio_job->ctx->req.ahash);
			break;
		}
	case AHASH_FINAL_CTX:
	case AHASH_FINAL_NO_CTX:
		{
			print_debug
			    ("AHASH_FINAL[%d] completion\n",
			     virtio_job->qemu_cmd.op);

			ret = copy_to_user((void __user *)
					   virtio_job->qemu_cmd.u.
					   hash.final_req.result, (void *)
					   (virtio_job->ctx->req.ahash->result),
					   virtio_job->qemu_cmd.u.
					   hash.final_req.digestsize);
			if (ret != 0)
				print_debug
				("return value AHASH_FINAL "
				"ouput copy_to_user = %d\n",
				ret);

			kfree(virtio_job->ctx->req.ahash->result);
			kfree(virtio_job->ctx->req.ahash);
			break;
		}
	case AHASH_FINUP_CTX:
	case AHASH_FINUP_NO_CTX:
		{
			struct scatterlist *sg = NULL;
			uint8_t *buf = NULL;
			int i = 0;

			print_debug
			    ("AHASH_FINUP[%d] completion\n",
			     virtio_job->qemu_cmd.op);
			ret = copy_to_user((void __user *)
					   virtio_job->qemu_cmd.u.
					   hash.finup_req.result, (void *)
					   (virtio_job->ctx->req.ahash->result),
					   virtio_job->qemu_cmd.u.
					   hash.finup_req.digestsize);
			if (ret != 0)
				print_debug
				("return value AHASH_FINUP "
				"ouput copy_to_user = %d\n",
				ret);

			sg = virtio_job->ctx->req.ahash->src;
			for (i = 0;
			     i <
			     virtio_job->qemu_cmd.u.hash.finup_req.
			     sg_info.sg_count; i++) {
				buf = sg_virt(sg);
				kfree(buf);

				sg = sg_next(sg);
				buf = NULL;
			}
			kfree(virtio_job->ctx->req.ahash->src);
			kfree(virtio_job->ctx->req.ahash->result);
			kfree(virtio_job->ctx->req.ahash);

			break;
		}
#endif
#ifdef SYMMETRIC_OFFLOAD
	case ABLK_ENCRYPT:
	case ABLK_DECRYPT:
		{
			struct scatterlist *sg = NULL;
			uint8_t *buf = NULL;
			int i = 0;

			print_debug
			    ("ABLK [%d] completion\n", virtio_job->qemu_cmd.op);

			sg = virtio_job->ctx->req.ablk->dst;
			for (i = 0;
			     i <
			     virtio_job->qemu_cmd.u.symm.cmd_req.
			     dst_sg_info.sg_count; i++) {
				buf = sg_virt(sg);
				ret = copy_to_user((void __user *)
						   virtio_job->qemu_cmd.u.
						   symm.cmd_req.dst[i], (void *)
						   buf,
						   virtio_job->qemu_cmd.u.
						   symm.cmd_req.dst_len[i]);
				if (ret != 0)
					print_debug
					("return value ABLK[%d] "
					"ouput copy_to_user = %d\n",
					virtio_job->qemu_cmd.op, ret);

				sg = sg_next(sg);
				kfree(buf);
				buf = NULL;
			}

			sg = virtio_job->ctx->req.ablk->src;
			for (i = 0;
			     i <
			     virtio_job->qemu_cmd.u.symm.cmd_req.
			     src_sg_info.sg_count; i++) {
				buf = sg_virt(sg);
				kfree(buf);

				sg = sg_next(sg);
				buf = NULL;
			}

			kfree(virtio_job->qemu_cmd.u.symm.cmd_req.dst);
			kfree(virtio_job->qemu_cmd.u.symm.cmd_req.dst_len);
			kfree(virtio_job->qemu_cmd.u.symm.cmd_req.src);
			kfree(virtio_job->qemu_cmd.u.symm.cmd_req.src_len);
			kfree(virtio_job->ctx->req.ablk->src);
			kfree(virtio_job->ctx->req.ablk->dst);
			kfree(virtio_job->ctx->req.ablk->info);
			kfree(virtio_job->ctx->req.ablk);

			print_debug
			    ("ABLK [%d] completion Success\n",
			     virtio_job->qemu_cmd.op);

			break;
		}
#endif

	default:
		{
			print_error("Unknow OP\n");
			break;
		}

	}
}


/*******************************************************************************
* Function     : process_virtio_dh_job
*
* Arguments    : virtio_job - virtio job structure
*
* Return Value : int32_t
*
* Description  : Copying dh job request data from user space to kernel space and
*                processes the dh job for virtio
*
*******************************************************************************/

int32_t process_virtio_dh_job(struct virtio_c2x0_job_ctx *virtio_job)
{
	struct pkc_request *req = NULL;
	int32_t ret = 0;
	struct virtio_c2x0_qemu_cmd *qemu_cmd = &virtio_job->qemu_cmd;

	req =
	    (struct pkc_request *)kzalloc(sizeof(struct pkc_request),
					  GFP_KERNEL);
	if (!req) {
		print_error("Alloc failed req:%p, qemu_cmd:%p\n", req,
			    qemu_cmd);
		return -1;
	}

	req->type = qemu_cmd->u.pkc.pkc_req.type;
	req->curve_type = qemu_cmd->u.pkc.pkc_req.curve_type;
	print_debug("req->tye = %d\n", req->type);

	switch (req->type) {
	case DH_COMPUTE_KEY:
	case ECDH_COMPUTE_KEY:
		print_debug("DH COMPUTE_KEY\n");

		req->req_u.dh_req.q_len =
		    qemu_cmd->u.pkc.pkc_req.req_u.dh_req.q_len;
		req->req_u.dh_req.q =
		    kzalloc(req->req_u.dh_req.q_len, GFP_KERNEL);
		if (NULL == req->req_u.dh_req.q) {
			print_error("kzlloc failed\n");
			goto error;
		}
		ret =
		    copy_from_user(req->req_u.dh_req.q,
				   qemu_cmd->u.pkc.pkc_req.req_u.dh_req.q,
				   req->req_u.dh_req.q_len);
		if (ret != 0) {
			print_error("Copy from user failed  = %d\n", ret);
			goto error;
		}

		req->req_u.dh_req.pub_key_len =
		    qemu_cmd->u.pkc.pkc_req.req_u.dh_req.pub_key_len;
		req->req_u.dh_req.pub_key =
		    kzalloc(req->req_u.dh_req.pub_key_len, GFP_KERNEL);
		if (NULL == req->req_u.dh_req.pub_key) {
			print_error("kzlloc failed\n");
			goto error;
		}
		ret =
		    copy_from_user(req->req_u.dh_req.pub_key,
				   qemu_cmd->u.pkc.pkc_req.req_u.dh_req.pub_key,
				   req->req_u.dh_req.pub_key_len);
		if (ret != 0) {
			print_error("Copy from user failed  = %d\n", ret);
			goto error;
		}

		req->req_u.dh_req.s_len =
		    qemu_cmd->u.pkc.pkc_req.req_u.dh_req.s_len;
		req->req_u.dh_req.s =
		    kzalloc(req->req_u.dh_req.s_len, GFP_KERNEL);
		if (NULL == req->req_u.dh_req.s) {
			print_error("kzlloc failed\n");
			goto error;
		}
		ret =
		    copy_from_user(req->req_u.dh_req.s,
				   qemu_cmd->u.pkc.pkc_req.req_u.dh_req.s,
				   req->req_u.dh_req.s_len);
		if (ret != 0) {
			print_error("Copy from user failed  = %d\n", ret);
			goto error;
		}

		if (ECDH_COMPUTE_KEY == req->type) {
			req->req_u.dh_req.ab_len =
			    qemu_cmd->u.pkc.pkc_req.req_u.dh_req.ab_len;
			req->req_u.dh_req.ab =
			    kzalloc(req->req_u.dh_req.ab_len, GFP_KERNEL);
			if (NULL == req->req_u.dh_req.ab) {
				print_error("kzlloc failed\n");
				goto error;
			}
			ret =
			    copy_from_user(req->req_u.dh_req.ab,
					   qemu_cmd->u.pkc.pkc_req.req_u.dh_req.
					   ab, req->req_u.dh_req.ab_len);
			if (ret != 0) {
				print_error("Copy from user failed  = %d\n",
					    ret);
				goto error;
			}
		}

		req->req_u.dh_req.z_len =
		    qemu_cmd->u.pkc.pkc_req.req_u.dh_req.z_len;
		req->req_u.dh_req.z =
		    kzalloc(req->req_u.dh_req.z_len, GFP_KERNEL);
		if (NULL == req->req_u.dh_req.z) {
			print_error("kzlloc failed\n");
			goto error;
		}

		break;

	default:
		print_error
		    ("OP[%d];subop[%d:%d];"
			 "cmd_index[%d];guest_id[%d]"
			 "NOT handled\n",
		     qemu_cmd->op, qemu_cmd->u.pkc.pkc_req.type,
			 req->type,
		     qemu_cmd->cmd_index, qemu_cmd->guest_id);
		goto error_op;
	}

	ret = dh_op(req, virtio_job);
	if (-1 == ret) {
		print_error("failed to send DH[%d] job with %d ret\n",
			    req->type, ret);
		goto error;
	}

	return 0;

error:
	cleanup_virtio_pkc_buffers(req);
error_op:
	kfree(req);
	return -1;
}

/*******************************************************************************
* Function     : process_virtio_dsa_job
*
* Arguments    : virtio_job - virtio job structure
*
* Return Value : int32_t
*
* Description  : Coping dsa job request data from user space to kernel space and
*                processes the dsa job for virtio
*
*******************************************************************************/
int32_t process_virtio_dsa_job(struct virtio_c2x0_job_ctx *virtio_job)
{
	struct pkc_request *req = NULL;
	int32_t ret = 0;
	struct virtio_c2x0_qemu_cmd *qemu_cmd = &virtio_job->qemu_cmd;

	req =
	    (struct pkc_request *)kzalloc(sizeof(struct pkc_request),
					  GFP_KERNEL);
	if (!req) {
		print_error("Alloc failed req:%p, qemu_cmd:%p\n", req,
			    qemu_cmd);
		return -1;
	}

	req->type = qemu_cmd->u.pkc.pkc_req.type;
	req->curve_type = qemu_cmd->u.pkc.pkc_req.curve_type;
	print_debug("req->tye = %d\n", req->type);

	switch (req->type) {
	case DSA_SIGN:
	case ECDSA_SIGN:
		print_debug("DSA/ECDSA_SIGN\n");

		req->req_u.dsa_sign.q_len =
		    qemu_cmd->u.pkc.pkc_req.req_u.dsa_sign.q_len;
		req->req_u.dsa_sign.q =
		    kzalloc(req->req_u.dsa_sign.q_len, GFP_KERNEL);
		if (NULL == req->req_u.dsa_sign.q) {
			print_error("kzlloc failed\n");
			goto error;
		}
		ret =
		    copy_from_user(req->req_u.dsa_sign.q,
				   qemu_cmd->u.pkc.pkc_req.req_u.dsa_sign.q,
				   req->req_u.dsa_sign.q_len);
		if (ret != 0) {
			print_error("Copy from user failed  = %d\n", ret);
			goto error;
		}

		req->req_u.dsa_sign.r_len =
		    qemu_cmd->u.pkc.pkc_req.req_u.dsa_sign.r_len;
		req->req_u.dsa_sign.r =
		    kzalloc(req->req_u.dsa_sign.r_len, GFP_KERNEL);
		if (NULL == req->req_u.dsa_sign.r) {
			print_error("kzlloc failed\n");
			goto error;
		}
		ret =
		    copy_from_user(req->req_u.dsa_sign.r,
				   qemu_cmd->u.pkc.pkc_req.req_u.dsa_sign.r,
				   req->req_u.dsa_sign.r_len);
		if (ret != 0) {
			print_error("Copy from user failed  = %d\n", ret);
			goto error;
		}

		req->req_u.dsa_sign.g_len =
		    qemu_cmd->u.pkc.pkc_req.req_u.dsa_sign.g_len;
		req->req_u.dsa_sign.g =
		    kzalloc(req->req_u.dsa_sign.g_len, GFP_KERNEL);
		if (NULL == req->req_u.dsa_sign.g) {
			print_error("kzlloc failed\n");
			goto error;
		}
		ret =
		    copy_from_user(req->req_u.dsa_sign.g,
				   qemu_cmd->u.pkc.pkc_req.req_u.dsa_sign.g,
				   req->req_u.dsa_sign.g_len);
		if (ret != 0) {
			print_error("Copy from user failed  = %d\n", ret);
			goto error;
		}

		req->req_u.dsa_sign.priv_key_len =
		    qemu_cmd->u.pkc.pkc_req.req_u.dsa_sign.priv_key_len;
		req->req_u.dsa_sign.priv_key =
		    kzalloc(req->req_u.dsa_sign.priv_key_len, GFP_KERNEL);
		if (NULL == req->req_u.dsa_sign.priv_key) {
			print_error("kzlloc failed\n");
			goto error;
		}
		ret =
		    copy_from_user(req->req_u.dsa_sign.priv_key,
				   qemu_cmd->u.pkc.pkc_req.req_u.dsa_sign.
				   priv_key, req->req_u.dsa_sign.priv_key_len);
		if (ret != 0) {
			print_error("Copy from user failed  = %d\n", ret);
			goto error;
		}

		req->req_u.dsa_sign.m_len =
		    qemu_cmd->u.pkc.pkc_req.req_u.dsa_sign.m_len;
		req->req_u.dsa_sign.m =
		    kzalloc(req->req_u.dsa_sign.m_len, GFP_KERNEL);
		if (NULL == req->req_u.dsa_sign.m) {
			print_error("kzlloc failed\n");
			goto error;
		}
		ret =
		    copy_from_user(req->req_u.dsa_sign.m,
				   qemu_cmd->u.pkc.pkc_req.req_u.dsa_sign.m,
				   req->req_u.dsa_sign.m_len);
		if (ret != 0) {
			print_error("Copy from user failed  = %d\n", ret);
			goto error;
		}

		if (ECDSA_SIGN == req->type) {
			req->req_u.dsa_sign.ab_len =
			    qemu_cmd->u.pkc.pkc_req.req_u.dsa_sign.ab_len;
			req->req_u.dsa_sign.ab =
			    kzalloc(req->req_u.dsa_sign.ab_len, GFP_KERNEL);
			if (NULL == req->req_u.dsa_sign.ab) {
				print_error("kzlloc failed\n");
				goto error;
			}
			ret =
			    copy_from_user(req->req_u.dsa_sign.ab,
					   qemu_cmd->u.pkc.pkc_req.req_u.
					   dsa_sign.ab,
					   req->req_u.dsa_sign.ab_len);
			if (ret != 0) {
				print_error("Copy from user failed  = %d\n",
					    ret);
				goto error;
			}
		}

		/*  Allocating memory for o/p buffer  */
		req->req_u.dsa_sign.d_len =
		    qemu_cmd->u.pkc.pkc_req.req_u.dsa_sign.d_len;
		req->req_u.dsa_sign.c =
		    kzalloc(req->req_u.dsa_sign.d_len, GFP_KERNEL);
		if (NULL == req->req_u.dsa_sign.c) {
			print_error("kzlloc failed\n");
			goto error;
		}
		req->req_u.dsa_sign.d =
		    kzalloc(req->req_u.dsa_sign.d_len, GFP_KERNEL);
		if (NULL == req->req_u.dsa_sign.d) {
			print_error("kzlloc failed\n");
			goto error;
		}

		break;

	case DSA_VERIFY:
	case ECDSA_VERIFY:
		print_debug("DSA/ECDSA_VERIFY\n");

		req->req_u.dsa_verify.q_len =
		    qemu_cmd->u.pkc.pkc_req.req_u.dsa_verify.q_len;
		req->req_u.dsa_verify.q =
		    kzalloc(req->req_u.dsa_verify.q_len, GFP_KERNEL);
		if (NULL == req->req_u.dsa_verify.q) {
			print_error("kzlloc failed\n");
			goto error;
		}
		ret =
		    copy_from_user(req->req_u.dsa_verify.q,
				   qemu_cmd->u.pkc.pkc_req.req_u.dsa_verify.q,
				   req->req_u.dsa_verify.q_len);
		if (ret != 0) {
			print_error("Copy from user failed  = %d\n", ret);
			goto error;
		}

		req->req_u.dsa_verify.r_len =
		    qemu_cmd->u.pkc.pkc_req.req_u.dsa_verify.r_len;
		req->req_u.dsa_verify.r =
		    kzalloc(req->req_u.dsa_verify.r_len, GFP_KERNEL);
		if (NULL == req->req_u.dsa_verify.r) {
			print_error("kzlloc failed\n");
			goto error;
		}
		ret =
		    copy_from_user(req->req_u.dsa_verify.r,
				   qemu_cmd->u.pkc.pkc_req.req_u.dsa_verify.r,
				   req->req_u.dsa_verify.r_len);
		if (ret != 0) {
			print_error("Copy from user failed  = %d\n", ret);
			goto error;
		}

		req->req_u.dsa_verify.g_len =
		    qemu_cmd->u.pkc.pkc_req.req_u.dsa_verify.g_len;
		req->req_u.dsa_verify.g =
		    kzalloc(req->req_u.dsa_verify.g_len, GFP_KERNEL);
		if (NULL == req->req_u.dsa_verify.g) {
			print_error("kzlloc failed\n");
			goto error;
		}
		ret =
		    copy_from_user(req->req_u.dsa_verify.g,
				   qemu_cmd->u.pkc.pkc_req.req_u.dsa_verify.g,
				   req->req_u.dsa_verify.g_len);
		if (ret != 0) {
			print_error("Copy from user failed  = %d\n", ret);
			goto error;
		}

		req->req_u.dsa_verify.pub_key_len =
		    qemu_cmd->u.pkc.pkc_req.req_u.dsa_verify.pub_key_len;
		req->req_u.dsa_verify.pub_key =
		    kzalloc(req->req_u.dsa_verify.pub_key_len, GFP_KERNEL);
		if (NULL == req->req_u.dsa_verify.pub_key) {
			print_error("kzlloc failed\n");
			goto error;
		}
		ret =
		    copy_from_user(req->req_u.dsa_verify.pub_key,
				   qemu_cmd->u.pkc.pkc_req.req_u.dsa_verify.
				   pub_key, req->req_u.dsa_verify.pub_key_len);
		if (ret != 0) {
			print_error("Copy from user failed  = %d\n", ret);
			goto error;
		}

		req->req_u.dsa_verify.m_len =
		    qemu_cmd->u.pkc.pkc_req.req_u.dsa_verify.m_len;
		req->req_u.dsa_verify.m =
		    kzalloc(req->req_u.dsa_verify.m_len, GFP_KERNEL);
		if (NULL == req->req_u.dsa_verify.m) {
			print_error("kzlloc failed\n");
			goto error;
		}
		ret =
		    copy_from_user(req->req_u.dsa_verify.m,
				   qemu_cmd->u.pkc.pkc_req.req_u.dsa_verify.m,
				   req->req_u.dsa_verify.m_len);
		if (ret != 0) {
			print_error("Copy from user failed  = %d\n", ret);
			goto error;
		}

		if (ECDSA_VERIFY == req->type) {
			req->req_u.dsa_verify.ab_len =
			    qemu_cmd->u.pkc.pkc_req.req_u.dsa_verify.ab_len;
			req->req_u.dsa_verify.ab =
			    kzalloc(req->req_u.dsa_verify.ab_len, GFP_KERNEL);
			if (NULL == req->req_u.dsa_verify.ab) {
				print_error("kzlloc failed\n");
				goto error;
			}
			ret =
			    copy_from_user(req->req_u.dsa_verify.ab,
					   qemu_cmd->u.pkc.pkc_req.req_u.
					   dsa_verify.ab,
					   req->req_u.dsa_verify.ab_len);
			if (ret != 0) {
				print_error("Copy from user failed  = %d\n",
					    ret);
				goto error;
			}
		}

		req->req_u.dsa_verify.c =
		    kzalloc(req->req_u.dsa_verify.q_len, GFP_KERNEL);
		if (NULL == req->req_u.dsa_verify.c) {
			print_error("kzlloc failed\n");
			goto error;
		}
		ret =
		    copy_from_user(req->req_u.dsa_verify.c,
				   qemu_cmd->u.pkc.pkc_req.req_u.dsa_verify.c,
				   req->req_u.dsa_verify.q_len);
		if (ret != 0) {
			print_error("Copy from user failed  = %d\n", ret);
			goto error;
		}

		req->req_u.dsa_verify.d_len =
		    qemu_cmd->u.pkc.pkc_req.req_u.dsa_verify.d_len;
		req->req_u.dsa_verify.d =
		    kzalloc(req->req_u.dsa_verify.d_len, GFP_KERNEL);
		if (NULL == req->req_u.dsa_verify.d) {
			print_error("kzlloc failed\n");
			goto error;
		}
		ret =
		    copy_from_user(req->req_u.dsa_verify.d,
				   qemu_cmd->u.pkc.pkc_req.req_u.dsa_verify.d,
				   req->req_u.dsa_verify.d_len);
		if (ret != 0) {
			print_error("Copy from user failed  = %d\n", ret);
			goto error;
		}

		break;
	default:
		{
			print_error
			    ("OP[%d];subop[%d:%d];"
				 "cmd_index[%d];guest_id[%d] NOT handled\n",
			     qemu_cmd->op, qemu_cmd->u.pkc.pkc_req.type,
			     req->type, qemu_cmd->cmd_index,
			     qemu_cmd->guest_id);
			goto error_op;
		}
	}

	ret = dsa_op(req, virtio_job);
	if (-1 == ret) {
		print_error("failed to send DSA[%d] job with %d ret\n",
			    req->type, ret);
		goto error;
	}

	return 0;

error:
	cleanup_virtio_pkc_buffers(req);
error_op:
	kfree(req);
	return -1;
}

/*******************************************************************************
* Function     : process_virtio_rsa_job
*
* Arguments    : virtio_job - virtio job structure
*
* Return Value : int32_t
*
* Description  : Coping rsa job request data from user space to kernel space and
*                processes the rsa job for virtio
*
*******************************************************************************/
int32_t process_virtio_rsa_job(struct virtio_c2x0_job_ctx *virtio_job)
{
	struct pkc_request *req = NULL;
	int32_t ret = 0;
	struct virtio_c2x0_qemu_cmd *qemu_cmd = &virtio_job->qemu_cmd;

	req =
	    (struct pkc_request *)kzalloc(sizeof(struct pkc_request),
					  GFP_KERNEL);
	if (!req) {
		print_error("Alloc failed req:%p, qemu_cmd:%p\n", req,
			    qemu_cmd);
		return -1;
	}

	req->type = qemu_cmd->u.pkc.pkc_req.type;
	req->curve_type = qemu_cmd->u.pkc.pkc_req.curve_type;
	print_debug("req->tye = %d\n", req->type);

	switch (req->type) {
	case RSA_PUB:
		print_debug("RSA_PUB\n");

		req->req_u.rsa_pub_req.n_len =
		    qemu_cmd->u.pkc.pkc_req.req_u.rsa_pub_req.n_len;
		req->req_u.rsa_pub_req.n =
		    kzalloc(req->req_u.rsa_pub_req.n_len, GFP_KERNEL);
		if (NULL == req->req_u.rsa_pub_req.n) {
			print_error("kzlloc failed\n");
			goto error;
		}
		ret =
		    copy_from_user(req->req_u.rsa_pub_req.n,
				   qemu_cmd->u.pkc.pkc_req.req_u.rsa_pub_req.n,
				   req->req_u.rsa_pub_req.n_len);
		if (ret != 0) {
			print_error("Copy from user failed  = %d\n", ret);
			goto error;
		}

		req->req_u.rsa_pub_req.e_len =
		    qemu_cmd->u.pkc.pkc_req.req_u.rsa_pub_req.e_len;
		req->req_u.rsa_pub_req.e =
		    kzalloc(req->req_u.rsa_pub_req.e_len, GFP_KERNEL);
		if (NULL == req->req_u.rsa_pub_req.e) {
			print_error("kzlloc failed\n");
			goto error;
		}
		ret =
		    copy_from_user(req->req_u.rsa_pub_req.e,
				   qemu_cmd->u.pkc.pkc_req.req_u.rsa_pub_req.e,
				   req->req_u.rsa_pub_req.e_len);
		if (ret != 0) {
			print_error("Copy from user failed  = %d\n", ret);
			goto error;
		}

		req->req_u.rsa_pub_req.f_len =
		    qemu_cmd->u.pkc.pkc_req.req_u.rsa_pub_req.f_len;
		req->req_u.rsa_pub_req.f =
		    kzalloc(req->req_u.rsa_pub_req.f_len, GFP_KERNEL);
		if (NULL == req->req_u.rsa_pub_req.f) {
			print_error("kzlloc failed\n");
			goto error;
		}
		ret =
		    copy_from_user(req->req_u.rsa_pub_req.f,
				   qemu_cmd->u.pkc.pkc_req.req_u.rsa_pub_req.f,
				   req->req_u.rsa_pub_req.f_len);
		if (ret != 0) {
			print_error("Copy from user failed  = %d\n", ret);
			goto error;
		}

		/*  Allocating memory for o/p buffer  */
		req->req_u.rsa_pub_req.g_len =
		    qemu_cmd->u.pkc.pkc_req.req_u.rsa_pub_req.n_len;
		req->req_u.rsa_pub_req.g =
		    kzalloc(req->req_u.rsa_pub_req.g_len, GFP_KERNEL);
		if (NULL == req->req_u.rsa_pub_req.g) {
			print_error("kzlloc failed\n");
			goto error;
		}

		break;
	case RSA_PRIV_FORM1:

		print_debug("RSA_PRIV_FORM1\n");

		req->req_u.rsa_priv_f1.n_len =
		    qemu_cmd->u.pkc.pkc_req.req_u.rsa_priv_f1.n_len;
		req->req_u.rsa_priv_f1.n =
		    kzalloc(req->req_u.rsa_priv_f1.n_len, GFP_KERNEL);
		if (NULL == req->req_u.rsa_priv_f1.n) {
			print_error("kzlloc failed\n");
			goto error;
		}
		ret =
		    copy_from_user(req->req_u.rsa_priv_f1.n,
				   qemu_cmd->u.pkc.pkc_req.req_u.rsa_priv_f1.n,
				   req->req_u.rsa_priv_f1.n_len);
		if (ret != 0) {
			print_error("Copy from user failed  = %d\n", ret);
			goto error;
		}

		req->req_u.rsa_priv_f1.d_len =
		    qemu_cmd->u.pkc.pkc_req.req_u.rsa_priv_f1.d_len;
		req->req_u.rsa_priv_f1.d =
		    kzalloc(req->req_u.rsa_priv_f1.d_len, GFP_KERNEL);
		if (NULL == req->req_u.rsa_priv_f1.d) {
			print_error("kzlloc failed\n");
			goto error;
		}
		ret =
		    copy_from_user(req->req_u.rsa_priv_f1.d,
				   qemu_cmd->u.pkc.pkc_req.req_u.rsa_priv_f1.d,
				   req->req_u.rsa_priv_f1.d_len);
		if (ret != 0) {
			print_error("Copy from user failed  = %d\n", ret);
			goto error;
		}

		/*  Allocating memory for o/p buffer  */
		req->req_u.rsa_priv_f1.f_len =
		    qemu_cmd->u.pkc.pkc_req.req_u.rsa_priv_f1.n_len;
		req->req_u.rsa_priv_f1.f =
		    kzalloc(req->req_u.rsa_priv_f1.f_len, GFP_KERNEL);
		if (NULL == req->req_u.rsa_priv_f1.f) {
			print_error("kzlloc failed\n");
			goto error;
		}

		req->req_u.rsa_priv_f1.g_len =
		    qemu_cmd->u.pkc.pkc_req.req_u.rsa_priv_f1.g_len;
		req->req_u.rsa_priv_f1.g =
		    kzalloc(req->req_u.rsa_priv_f1.g_len, GFP_KERNEL);
		if (NULL == req->req_u.rsa_priv_f1.g) {
			print_error("kzlloc failed\n");
			goto error;
		}
		ret =
		    copy_from_user(req->req_u.rsa_priv_f1.g,
				   qemu_cmd->u.pkc.pkc_req.req_u.rsa_priv_f1.g,
				   req->req_u.rsa_priv_f1.g_len);
		if (ret != 0) {
			print_error("Copy from user failed  = %d\n", ret);
			goto error;
		}

		break;

	case RSA_PRIV_FORM2:
		print_debug("RSA_PRIV_FORM2\n");

		req->req_u.rsa_priv_f2.p_len =
		    qemu_cmd->u.pkc.pkc_req.req_u.rsa_priv_f2.p_len;
		req->req_u.rsa_priv_f2.p =
		    kzalloc(req->req_u.rsa_priv_f2.p_len, GFP_KERNEL);
		if (NULL == req->req_u.rsa_priv_f2.p) {
			print_error("kzlloc failed\n");
			goto error;
		}
		ret =
		    copy_from_user(req->req_u.rsa_priv_f2.p,
				   qemu_cmd->u.pkc.pkc_req.req_u.rsa_priv_f2.p,
				   req->req_u.rsa_priv_f2.p_len);
		if (ret != 0) {
			print_error("Copy from user failed  = %d\n", ret);
			goto error;
		}

		req->req_u.rsa_priv_f2.q_len =
		    qemu_cmd->u.pkc.pkc_req.req_u.rsa_priv_f2.q_len;
		req->req_u.rsa_priv_f2.q =
		    kzalloc(req->req_u.rsa_priv_f2.q_len, GFP_KERNEL);
		if (NULL == req->req_u.rsa_priv_f2.q) {
			print_error("kzlloc failed\n");
			goto error;
		}
		ret =
		    copy_from_user(req->req_u.rsa_priv_f2.q,
				   qemu_cmd->u.pkc.pkc_req.req_u.rsa_priv_f2.q,
				   req->req_u.rsa_priv_f2.q_len);
		if (ret != 0) {
			print_error("Copy from user failed  = %d\n", ret);
			goto error;
		}

		req->req_u.rsa_priv_f2.d_len =
		    qemu_cmd->u.pkc.pkc_req.req_u.rsa_priv_f2.d_len;
		req->req_u.rsa_priv_f2.d =
		    kzalloc(req->req_u.rsa_priv_f2.d_len, GFP_KERNEL);
		if (NULL == req->req_u.rsa_priv_f2.d) {
			print_error("kzlloc failed\n");
			goto error;
		}
		ret =
		    copy_from_user(req->req_u.rsa_priv_f2.d,
				   qemu_cmd->u.pkc.pkc_req.req_u.rsa_priv_f2.d,
				   req->req_u.rsa_priv_f2.d_len);
		if (ret != 0) {
			print_error("Copy from user failed  = %d\n", ret);
			goto error;
		}

		req->req_u.rsa_priv_f2.g_len =
		    qemu_cmd->u.pkc.pkc_req.req_u.rsa_priv_f2.g_len;
		req->req_u.rsa_priv_f2.g =
		    kzalloc(req->req_u.rsa_priv_f2.g_len, GFP_KERNEL);
		if (NULL == req->req_u.rsa_priv_f2.g) {
			print_error("kzlloc failed\n");
			goto error;
		}
		ret =
		    copy_from_user(req->req_u.rsa_priv_f2.g,
				   qemu_cmd->u.pkc.pkc_req.req_u.rsa_priv_f2.g,
				   req->req_u.rsa_priv_f2.g_len);
		if (ret != 0) {
			print_error("Copy from user failed  = %d\n", ret);
			goto error;
		}

		/*  Allocating memory for o/p buffer  */
		req->req_u.rsa_priv_f2.f_len =
		    qemu_cmd->u.pkc.pkc_req.req_u.rsa_priv_f2.n_len;
		req->req_u.rsa_priv_f2.f =
		    kzalloc(req->req_u.rsa_priv_f2.f_len, GFP_KERNEL);
		if (NULL == req->req_u.rsa_priv_f2.f) {
			print_error("kzlloc failed\n");
			goto error;
		}

		req->req_u.rsa_priv_f2.n_len =
		    qemu_cmd->u.pkc.pkc_req.req_u.rsa_priv_f2.n_len;

		break;

	case RSA_PRIV_FORM3:
		print_debug("RSA_PRIV_FORM3\n");

		req->req_u.rsa_priv_f3.p_len =
		    qemu_cmd->u.pkc.pkc_req.req_u.rsa_priv_f3.p_len;
		req->req_u.rsa_priv_f3.p =
		    kzalloc(req->req_u.rsa_priv_f3.p_len, GFP_KERNEL);
		if (NULL == req->req_u.rsa_priv_f3.p) {
			print_error("kzlloc failed\n");
			goto error;
		}
		ret =
		    copy_from_user(req->req_u.rsa_priv_f3.p,
				   qemu_cmd->u.pkc.pkc_req.req_u.rsa_priv_f3.p,
				   req->req_u.rsa_priv_f3.p_len);
		if (ret != 0) {
			print_error("Copy from user failed  = %d\n", ret);
			goto error;
		}

		req->req_u.rsa_priv_f3.q_len =
		    qemu_cmd->u.pkc.pkc_req.req_u.rsa_priv_f3.q_len;
		req->req_u.rsa_priv_f3.q =
		    kzalloc(req->req_u.rsa_priv_f3.q_len, GFP_KERNEL);
		if (NULL == req->req_u.rsa_priv_f3.q) {
			print_error("kzlloc failed\n");
			goto error;
		}
		ret =
		    copy_from_user(req->req_u.rsa_priv_f3.q,
				   qemu_cmd->u.pkc.pkc_req.req_u.rsa_priv_f3.q,
				   req->req_u.rsa_priv_f3.q_len);
		if (ret != 0) {
			print_error("Copy from user failed  = %d\n", ret);
			goto error;
		}

		req->req_u.rsa_priv_f3.dp_len =
		    qemu_cmd->u.pkc.pkc_req.req_u.rsa_priv_f3.dp_len;
		req->req_u.rsa_priv_f3.dp =
		    kzalloc(req->req_u.rsa_priv_f3.dp_len, GFP_KERNEL);
		if (NULL == req->req_u.rsa_priv_f3.dp) {
			print_error("kzlloc failed\n");
			goto error;
		}
		ret =
		    copy_from_user(req->req_u.rsa_priv_f3.dp,
				   qemu_cmd->u.pkc.pkc_req.req_u.rsa_priv_f3.dp,
				   req->req_u.rsa_priv_f3.dp_len);
		if (ret != 0) {
			print_error("Copy from user failed  = %d\n", ret);
			goto error;
		}

		req->req_u.rsa_priv_f3.dq_len =
		    qemu_cmd->u.pkc.pkc_req.req_u.rsa_priv_f3.dq_len;
		req->req_u.rsa_priv_f3.dq =
		    kzalloc(req->req_u.rsa_priv_f3.dq_len, GFP_KERNEL);
		if (NULL == req->req_u.rsa_priv_f3.dq) {
			print_error("kzlloc failed\n");
			goto error;
		}
		ret =
		    copy_from_user(req->req_u.rsa_priv_f3.dq,
				   qemu_cmd->u.pkc.pkc_req.req_u.rsa_priv_f3.dq,
				   req->req_u.rsa_priv_f3.dq_len);
		if (ret != 0) {
			print_error("Copy from user failed  = %d\n", ret);
			goto error;
		}

		req->req_u.rsa_priv_f3.c_len =
		    qemu_cmd->u.pkc.pkc_req.req_u.rsa_priv_f3.c_len;
		req->req_u.rsa_priv_f3.c =
		    kzalloc(req->req_u.rsa_priv_f3.c_len, GFP_KERNEL);
		if (NULL == req->req_u.rsa_priv_f3.c) {
			print_error("kzlloc failed\n");
			goto error;
		}
		ret =
		    copy_from_user(req->req_u.rsa_priv_f3.c,
				   qemu_cmd->u.pkc.pkc_req.req_u.rsa_priv_f3.c,
				   req->req_u.rsa_priv_f3.c_len);
		if (ret != 0) {
			print_error("Copy from user failed  = %d\n", ret);
			goto error;
		}

		req->req_u.rsa_priv_f3.g_len =
		    qemu_cmd->u.pkc.pkc_req.req_u.rsa_priv_f3.g_len;
		req->req_u.rsa_priv_f3.g =
		    kzalloc(req->req_u.rsa_priv_f3.g_len, GFP_KERNEL);
		if (NULL == req->req_u.rsa_priv_f3.g) {
			print_error("kzlloc failed\n");
			goto error;
		}
		ret =
		    copy_from_user(req->req_u.rsa_priv_f3.g,
				   qemu_cmd->u.pkc.pkc_req.req_u.rsa_priv_f3.g,
				   req->req_u.rsa_priv_f3.g_len);
		if (ret != 0) {
			print_error("Copy from user failed  = %d\n", ret);
			goto error;
		}

		/*  Allocating memory for o/p buffer  */
		req->req_u.rsa_priv_f3.f_len =
		    qemu_cmd->u.pkc.pkc_req.req_u.rsa_priv_f3.f_len;
		req->req_u.rsa_priv_f3.f =
		    kzalloc(req->req_u.rsa_priv_f3.f_len, GFP_KERNEL);
		if (NULL == req->req_u.rsa_priv_f3.f) {
			print_error("kzlloc failed\n");
			goto error;
		}

		break;
	default:
		print_error
		    ("OP[%d];subop[%d:%d];cmd_index[%d];"
			 "guest_id[%d] NOT handled\n",
		     qemu_cmd->op, qemu_cmd->u.pkc.pkc_req.type, req->type,
		     qemu_cmd->cmd_index, qemu_cmd->guest_id);
		goto error_op;
	}

	ret = rsa_op(req, virtio_job);
	if (-1 == ret) {
		print_error("failed to send RSA[%d] job with %d ret\n",
			    req->type, ret);
		goto error;
	}

	return 0;

error:
	cleanup_virtio_pkc_buffers(req);
error_op:
	kfree(req);
	return -1;
}

#ifdef HASH_OFFLOAD
int32_t process_virtio_hash_split_key_job(struct virtio_c2x0_job_ctx *
					  virtio_job)
{
	int32_t status = 0;
	int32_t ret = 0;
	uint8_t *key = NULL, *key_bkp = NULL;
	struct virtio_c2x0_qemu_cmd *qemu_cmd = &virtio_job->qemu_cmd;

	key =
	    (uint8_t *) kzalloc((qemu_cmd->u.hash).setkey_req.keylen,
				GFP_KERNEL);
	if (!key) {
		print_error("Alloc failed setkey_req:%p, qemu_cmd:%p\n",
			    key, qemu_cmd);
		return -1;
	}

	ret = copy_from_user(key, &(qemu_cmd->u.hash).setkey_req.key,
			     (qemu_cmd->u.hash).setkey_req.keylen);
	if (ret != 0) {
		print_error("Copy from user failed  = %d\n", ret);
		kfree(key);
		return -1;
	}
	key_bkp = key;

	status = ahash_setkey(key, qemu_cmd);
	/*
	 * TODO :  ???
	 * How to send the status back
	 * Whether to send 0/-1 or to send whatever status returned by card
	 *
	 * Problem because returnj values other than 0/-1 NOT reflected in Host
	 * Soln -> Copy return value in qemu_cmd->host_status
	 * and send 0/-1 as ioctl return
	 */
	ret =
	    copy_to_user((uint8_t *) qemu_cmd->host_status, (uint8_t *) status,
			 sizeof(int32_t));
	if (ret > 0)
		print_error("Copy to user for status failed\n");

	kfree(key_bkp);
	if (status < 0)
		ret = -1;
	else
		ret = 0;
	return ret;
}

int32_t process_virtio_ahash_digest_job(struct virtio_c2x0_job_ctx *virtio_job)
{
	int32_t ret = 0;
	struct virtio_c2x0_qemu_cmd *qemu_cmd = &virtio_job->qemu_cmd;
	struct ahash_request *req = NULL;
	struct scatterlist *sg = NULL;
	uint8_t *buf = NULL;
	uint32_t buflen;
	uint8_t **src = NULL;
	uint32_t *src_len = NULL;
	int i = 0, max_filled_sgs = 0;

	if (0 == qemu_cmd->u.hash.digest_req.sg_info.sg_count) {
		printk(KERN_INFO "%s:Entered; sg_count = %d;nbytes = %d;\n",
				 __func__,
		       qemu_cmd->u.hash.digest_req.sg_info.sg_count,
		       qemu_cmd->u.hash.digest_req.sg_info.nbytes);
	}

	/*
	 * Allocating memory for scatterlist in ahash_request
	 */
	sg = kzalloc(sizeof(struct scatterlist) *
		     qemu_cmd->u.hash.digest_req.sg_info.sg_count, GFP_KERNEL);
#if 0
	if (!sg) {
		print_error("scatter gather memory allocation failed\n");
		return -1;
	}
#else
	if (unlikely(ZERO_OR_NULL_PTR(sg))) {
		print_error("sg[%p] is ZERO_SIZE_PTR\n", sg);
		kfree(sg);
		return -1;
	}
#endif

	/* VM's virtual addresses of each sg entry */
	src = (uint8_t **) kzalloc(sizeof(uint8_t *) *
				   qemu_cmd->u.hash.digest_req.sg_info.sg_count,
				   GFP_KERNEL);
	if (!src) {
		print_error("src alloc failed\n");
		goto failed_src;
	}
	ret = copy_from_user(src, qemu_cmd->u.hash.digest_req.src,
			     sizeof(uint8_t *) *
			     qemu_cmd->u.hash.digest_req.sg_info.sg_count);
	if (ret != 0) {
		print_error("src Copy from user failed  = %d\n", ret);
		goto failed_copy_src;
	}

	src_len = (uint32_t *) kzalloc(sizeof(uint32_t *) *
				       qemu_cmd->u.hash.digest_req.sg_info.
				       sg_count, GFP_KERNEL);
	if (!src_len) {
		print_error("srclen alloc failed\n");
		goto failed_srclen;
	}
	ret = copy_from_user(src_len, qemu_cmd->u.hash.digest_req.src_len,
			     sizeof(uint32_t *) *
			     qemu_cmd->u.hash.digest_req.sg_info.sg_count);
	if (ret != 0) {
		print_error("srclen Copy from user failed  = %d\n", ret);
		goto failed_copy_srclen;
	}

	/*
	 * Copy input data from VM and
	 * Fill the ahash_request->scatterlist entries from the
	 * VM's sg address received through Qemu
	 */
	for (i = 0; i < qemu_cmd->u.hash.digest_req.sg_info.sg_count; i++) {
		buflen = src_len[i];
		buf = kzalloc(buflen, GFP_KERNEL);
		if (!buf) {
			print_error("buf alloc failed\n");
			goto failed_buf;
		}
		max_filled_sgs++;
		ret = copy_from_user(buf, src[i], buflen);
		if (ret != 0) {
			print_error("Copy from user failed  = %d\n", ret);
			goto failed_buf;
		}
		sg_set_buf(&sg[i], (void *)buf, buflen);
	}

	/*
	 * Creating ahahs_request
	 */
	req =
	    (struct ahash_request *)kzalloc(sizeof(struct ahash_request),
					    GFP_KERNEL);
	if (!req) {
		print_error("Alloc failed req:%p,\n", req);
		goto failed_req;
	}

	req->nbytes = qemu_cmd->u.hash.digest_req.sg_info.nbytes;
	req->src = sg;

	req->result =
	    kzalloc(qemu_cmd->u.hash.digest_req.digestsize, GFP_KERNEL);
	if (!req->result) {
		print_error("result memory allocation failed\n");
		goto failed_result;
	}

	ret = ahash_digest(req, virtio_job);
	kfree(src_len);
	kfree(src);
	src = NULL;
	src_len = NULL;

	if (-1 != ret) {
		print_debug
		    ("AHASH_DIGEST[%d] job succesfully given to card : %d\n",
		     qemu_cmd->op, ret);
		return 0;
	}

	print_error("AHASH_DIGEST[%d] returns : %d\n", qemu_cmd->op, ret);

	kfree(req->result);
failed_result:
	kfree(req);
failed_req:
failed_buf:
	{
		uint8_t *buf = NULL;

		int i = 0;
		for (i = 0; i < max_filled_sgs; i++) {
			buf = sg_virt(&sg[i]);
			kfree(buf);
		}
	}
failed_copy_srclen:
	if (src_len)
		kfree(src_len);
failed_srclen:
failed_copy_src:
	if (src)
		kfree(src);
failed_src:
	kfree(sg);
	return -1;

}

int32_t process_virtio_ahash_update_job(struct virtio_c2x0_job_ctx *virtio_job)
{
	int32_t ret = 0;
	struct virtio_c2x0_qemu_cmd *qemu_cmd = &virtio_job->qemu_cmd;
	struct ahash_request *req = NULL;
	struct scatterlist *sg = NULL;
	struct hash_state *state = NULL;
	uint8_t *buf = NULL;
	uint32_t buflen;
	uint8_t **src = NULL;
	uint32_t *src_len = NULL;
	int i = 0, max_filled_sgs = 0;

	if (0 == qemu_cmd->u.hash.update_req.sg_info.sg_count) {
		printk(KERN_INFO "%s:Entered; sg_count = %d;nbytes = %d;\n",
				__func__,
			qemu_cmd->u.hash.update_req.sg_info.sg_count,
			qemu_cmd->u.hash.update_req.sg_info.nbytes);
	}

	/*
	 * Allocating memory for scatterlist in ahash_request
	 */
	sg = kzalloc(sizeof(struct scatterlist) *
		     qemu_cmd->u.hash.update_req.sg_info.sg_count, GFP_KERNEL);
#if 0
	if (!sg) {
		print_error("scatter gather memory allocation failed\n");
		return -1;
	}
#else
	if (unlikely(ZERO_OR_NULL_PTR(sg))) {
		print_error("sg[%p] is ZERO_SIZE_PTR\n", sg);
		kfree(sg);
		return -1;
	}
#endif

	/* VM's virtual addresses of each sg entry */
	src = (uint8_t **) kzalloc(sizeof(uint8_t *) *
				   qemu_cmd->u.hash.update_req.sg_info.sg_count,
				   GFP_KERNEL);
	if (!src) {
		print_error("src alloc failed\n");
		goto failed_src;
	}
	ret = copy_from_user(src, qemu_cmd->u.hash.update_req.src,
			     sizeof(uint8_t *) *
			     qemu_cmd->u.hash.update_req.sg_info.sg_count);
	if (ret != 0) {
		print_error("Copy from user failed  = %d\n", ret);
		goto failed_copy_src;
	}

	src_len = (uint32_t *) kzalloc(sizeof(uint32_t *) *
				       qemu_cmd->u.hash.update_req.sg_info.
				       sg_count, GFP_KERNEL);
	if (!src_len) {
		print_error("src_len alloc failed\n");
		goto failed_srclen;
	}
	ret = copy_from_user(src_len, qemu_cmd->u.hash.update_req.src_len,
			     sizeof(uint32_t *) *
			     qemu_cmd->u.hash.update_req.sg_info.sg_count);
	if (ret != 0) {
		print_error("Copy from user failed  = %d\n", ret);
		goto failed_copy_srclen;
	}

	/*
	 * Copy input data from VM and
	 * Fill the ahash_request->scatterlist entries from the
	 * VM's sg address received through Qemu
	 */
	for (i = 0; i < qemu_cmd->u.hash.update_req.sg_info.sg_count; i++) {
		buflen = src_len[i];
		print_debug("sg[%d] len = %u; %u; %d\n", i, src_len[i], buflen,
			    buflen);
		buf = kzalloc(buflen, GFP_KERNEL);
		if (!buf) {
			print_error("buf alloc failed\n");
			goto failed_buf;
		}
		max_filled_sgs++;
		ret = copy_from_user(buf, src[i], buflen);
		if (ret != 0) {
			print_error("Copy from user failed  = %d\n", ret);
			goto failed_copy_buf;
		}

		sg_set_buf(&sg[i], (void *)buf, buflen);
		buf = NULL;
	}
	sg_mark_end(&sg[i - 1]);	/* TODO : Is it necessary ?? */

	/*
	 * Creating ahash_request
	 */
	req =
	    (struct ahash_request *)kzalloc(sizeof(struct ahash_request) +
					    sizeof(struct hash_state),
					    GFP_KERNEL);
	if (!req) {
		print_error("Alloc failed req:%p,\n", req);
		goto failed_req;
	}
	state = ahash_request_ctx(req);

	req->nbytes = qemu_cmd->u.hash.update_req.sg_info.nbytes;
	req->src = sg;
	ret = copy_from_user(state, qemu_cmd->u.hash.update_req.state,
			     sizeof(struct hash_state));
	if (ret != 0) {
		print_error("Copy from user failed  = %d\n", ret);
		goto failed_copy_state;
		return -1;
	}

	/*
	 * Need to free up this locally state later
	 * Later, this state's ctx is copied as output to userspace
	 */
	if (AHASH_UPDATE_CTX == qemu_cmd->op)
		ret = ahash_update_ctx(req, virtio_job);
	else if (AHASH_UPDATE_NO_CTX == qemu_cmd->op)
		ret = ahash_update_no_ctx(req, virtio_job);
	else if (AHASH_UPDATE_FIRST == qemu_cmd->op)
		ret = ahash_update_first(req, virtio_job);

	kfree(src_len);
	kfree(src);
	src = NULL;
	src_len = NULL;

	if (-1 != ret) {
		print_debug
		    ("AHASH_UPDATE[%d] job succesfully given to card : %d\n",
		     qemu_cmd->op, ret);
		return 0;
	}
	print_error("AHASH_UPDATE[%d] returns : %d\n", qemu_cmd->op, ret);

failed_copy_state:
	kfree(req);
failed_req:
failed_copy_buf:
failed_buf:
	{
		uint8_t *buf = NULL;

		int i = 0;
		for (i = 0; i < max_filled_sgs; i++) {
			buf = sg_virt(&sg[i]);
			kfree(buf);
		}
	}
failed_copy_srclen:
	if (src_len)
		kfree(src_len);
failed_srclen:
failed_copy_src:
	if (src)
		kfree(src);
failed_src:
	kfree(sg);
	return -1;
}

int32_t process_virtio_ahash_final_job(struct virtio_c2x0_job_ctx *virtio_job)
{
	int32_t ret = 0;
	struct virtio_c2x0_qemu_cmd *qemu_cmd = &virtio_job->qemu_cmd;
	struct ahash_request *req = NULL;
	struct hash_state *state = NULL;

	/*
	 * Creating ahash_request
	 */
	req =
	    (struct ahash_request *)kzalloc(sizeof(struct ahash_request) +
					    sizeof(struct hash_state),
					    GFP_KERNEL);
	if (!req) {
		print_error("Alloc failed req:%p,\n", req);
		return -1;
	}

	state = ahash_request_ctx(req);
	ret = copy_from_user(state, qemu_cmd->u.hash.final_req.state,
			     sizeof(struct hash_state));
	if (ret != 0) {
		print_error("Copy from user failed  = %d\n", ret);
		goto failed_copy_state;
	}

	req->result =
	    kzalloc(qemu_cmd->u.hash.final_req.digestsize, GFP_KERNEL);
	if (!req->result) {
		print_error("result memory allocation failed\n");
		goto failed_copy_state;
	}

	if (AHASH_FINAL_CTX == qemu_cmd->op)
		ret = ahash_final_ctx(req, virtio_job);
	else if (AHASH_FINAL_NO_CTX == qemu_cmd->op)
		ret = ahash_final_no_ctx(req, virtio_job);

	if (-1 != ret) {
		print_debug
		    ("AHASH_FINAL[%d] job succesfully given to card : %d\n",
		     qemu_cmd->op, ret);
		return 0;
	}
	print_error("AHASH_FINAL[%d] returns : %d\n", qemu_cmd->op, ret);

	kfree(req->result);
failed_copy_state:
	kfree(req);
	return -1;
}

int32_t process_virtio_ahash_finup_job(struct virtio_c2x0_job_ctx *virtio_job)
{
	int32_t ret = 0;
	struct virtio_c2x0_qemu_cmd *qemu_cmd = &virtio_job->qemu_cmd;
	struct ahash_request *req = NULL;
	struct hash_state *state = NULL;
	struct scatterlist *sg = NULL;
	uint8_t *buf = NULL;
	uint32_t buflen;
	uint8_t **src = NULL;
	uint32_t *src_len = NULL;
	int i = 0, max_filled_sgs = 0;

	if (0 == qemu_cmd->u.hash.finup_req.sg_info.sg_count) {
		printk(KERN_INFO "%s:Entered; sg_count = %d;nbytes = %d;\n",
				__func__,
		       qemu_cmd->u.hash.finup_req.sg_info.sg_count,
		       qemu_cmd->u.hash.finup_req.sg_info.nbytes);
	}

	/*
	 * Allocating memory for scatterlist in ahash_request
	 */
	sg = kzalloc(sizeof(struct scatterlist) *
		     qemu_cmd->u.hash.finup_req.sg_info.sg_count, GFP_KERNEL);
#if 0
	if (!sg) {
		print_error("scatter gather memory allocation failed\n");
		return -1;
	}
#else
	if (unlikely(ZERO_OR_NULL_PTR(sg))) {
		print_error("sg[%p] is ZERO_SIZE_PTR\n", sg);
		kfree(sg);
		return -1;
	}
#endif

	/* VM's virtual addresses of each sg entry */
	src = (uint8_t **) kzalloc(sizeof(uint8_t *) *
				   qemu_cmd->u.hash.finup_req.sg_info.sg_count,
				   GFP_KERNEL);
	if (!src) {
		print_error("src alloc failed\n");
		goto failed_src;
	}
	ret = copy_from_user(src, qemu_cmd->u.hash.finup_req.src,
			     sizeof(uint8_t *) *
			     qemu_cmd->u.hash.finup_req.sg_info.sg_count);
	if (ret != 0) {
		print_error("src Copy from user failed  = %d\n", ret);
		goto failed_copy_src;
	}

	src_len = (uint32_t *) kzalloc(sizeof(uint32_t *) *
				       qemu_cmd->u.hash.finup_req.sg_info.
				       sg_count, GFP_KERNEL);
	if (!src_len) {
		print_error("srclen alloc failed\n");
		goto failed_srclen;
	}
	ret = copy_from_user(src_len, qemu_cmd->u.hash.finup_req.src_len,
			     sizeof(uint32_t *) *
			     qemu_cmd->u.hash.finup_req.sg_info.sg_count);
	if (ret != 0) {
		print_error("srclen Copy from user failed  = %d\n", ret);
		goto failed_copy_srclen;
	}

	/*
	 * Copy input data from VM and
	 * Fill the ahash_request->scatterlist entries from the
	 * VM's sg address received through Qemu
	 */
	for (i = 0; i < qemu_cmd->u.hash.finup_req.sg_info.sg_count; i++) {
		buflen = src_len[i];
		buf = kzalloc(buflen, GFP_KERNEL);
		if (!buf) {
			print_error("buf alloc failed\n");
			goto failed_buf;
		}
		max_filled_sgs++;
		ret = copy_from_user(buf, src[i], buflen);
		if (ret != 0) {
			print_error("Copy from user failed  = %d\n", ret);
			goto failed_buf;
		}
		sg_set_buf(&sg[i], (void *)buf, buflen);
	}

	/*
	 * Creating ahahs_request
	 */
	req =
	    (struct ahash_request *)kzalloc(sizeof(struct ahash_request) +
					    sizeof(struct hash_state),
					    GFP_KERNEL);
	if (!req) {
		print_error("Alloc failed req:%p,\n", req);
		goto failed_req;
	}
	req->result =
	    kzalloc(qemu_cmd->u.hash.finup_req.digestsize, GFP_KERNEL);
	if (!req->result) {
		print_error("result memory allocation failed\n");
		goto failed_result;
	}
	state = ahash_request_ctx(req);
	ret = copy_from_user(state, qemu_cmd->u.hash.update_req.state,
			     sizeof(struct hash_state));
	if (ret != 0) {
		print_error("Copy from user failed  = %d\n", ret);
		goto failed_copy_state;
		return -1;
	}

	req->nbytes = qemu_cmd->u.hash.finup_req.sg_info.nbytes;
	req->src = sg;

	kfree(src_len);
	kfree(src);
	src = NULL;
	src_len = NULL;

	if (AHASH_FINUP_CTX == qemu_cmd->op)
		ret = ahash_finup_ctx(req, virtio_job);
	else if (AHASH_FINUP_NO_CTX == qemu_cmd->op)
		ret = ahash_finup_no_ctx(req, virtio_job);

	if (-1 != ret) {
		print_debug
		    ("AHASH_FINUP[%d] job succesfully given to card : %d\n",
		     qemu_cmd->op, ret);
		return 0;
	}
	print_error("AHASH_FINUP[%d] returns : %d\n", qemu_cmd->op, ret);

failed_copy_state:
	kfree(req->result);
failed_result:
	kfree(req);
failed_req:
failed_buf:
	{
		uint8_t *buf = NULL;

		int i = 0;
		for (i = 0; i < max_filled_sgs; i++) {
			buf = sg_virt(&sg[i]);
			kfree(buf);
		}
	}
failed_copy_srclen:
	if (src_len)
		kfree(src_len);
failed_srclen:
failed_copy_src:
	if (src)
		kfree(src);
failed_src:
	kfree(sg);
	return -1;
}

/***********************************************************************
 * Function     : virtio_c2x0_hash_cra_init
 *
 * Arguments    : tfm
 *
 * Return Value : Error code
 *
 * Description  : cra_init for crypto_alg to setup the context.
 *
 ***********************************************************************/
int virtio_c2x0_hash_cra_init(struct virtio_c2x0_job_ctx *virtio_job)
{
	return hash_cra_init(virtio_job);
}

/***********************************************************************
 * Function     : virtio_c2x0_hash_cra_exit
 *
 * Arguments    : tfm
 *
 * Return Value : void
 *
 * Description  : cra_exit for crypto_alg.
 *
 ***********************************************************************/
int virtio_c2x0_hash_cra_exit(struct virtio_c2x0_qemu_cmd *qemu_cmd)
{
	crypto_dev_sess_t *c_sess = NULL;
	struct hash_ctx *ctx = NULL;

	struct virtio_c2x0_crypto_sess_ctx *hash_sess = NULL, *next_sess = NULL;
	int flag = 0;

	spin_lock(&hash_sess_list_lock);
	list_for_each_entry_safe(hash_sess, next_sess,
				 &virtio_c2x0_hash_sess_list, list_entry) {
		if (hash_sess->sess_id == qemu_cmd->u.hash.exit.sess_id
		    && hash_sess->guest_id == qemu_cmd->guest_id) {
			c_sess = &(hash_sess->c_sess);
			ctx = &c_sess->u.hash;
			flag = 1;
			print_debug("Hash session FOUND; sess_id = %x\n",
				    hash_sess->sess_id);
			break;
		}
	}
	if (0 == flag) {
		print_error("Hash session[%lx] for guest [%d] NOT found\n",
			    qemu_cmd->u.hash.exit.sess_id, qemu_cmd->guest_id);
		/* print_sess_list(); */

		spin_unlock(&hash_sess_list_lock);
		return -1;
	}
	/*
	 * Delete the session id entry from hash Session list
	 */
	list_del(&hash_sess->list_entry);
	spin_unlock(&hash_sess_list_lock);

	hash_cra_exit(c_sess);

	kfree(hash_sess);

	return 0;
}
#endif

#ifdef SYMMETRIC_OFFLOAD
/***********************************************************************
* Function     : virtio_c2x0_symm_cra_init
*
* Arguments    : virtio_job - virtio job structure
*
* Return Value : int32_t
*
* Description  : Context initialization for Ciphers
*
************************************************************************/
int virtio_c2x0_symm_cra_init(struct virtio_c2x0_job_ctx *virtio_job)
{
	return sym_cra_init(virtio_job);
}

/************************************************************************
* Function     : virtio_c2x0_symm_cra_exit
*
* Arguments    : virtio_job - virtio job structure
*
* Return Value : int32_t
*
* Description  : Context Removal for Ciphers
*
*************************************************************************/
int virtio_c2x0_symm_cra_exit(struct virtio_c2x0_qemu_cmd *qemu_cmd)
{
	struct virtio_c2x0_crypto_sess_ctx *vc_sess = NULL, *next_sess = NULL;
	crypto_dev_sess_t *ctx = NULL;
	int flag = 0;

	print_debug("VIRTIO SYM_CRA_EXIT\n");

	spin_lock(&symm_sess_list_lock);
	list_for_each_entry_safe(vc_sess, next_sess,
				 &virtio_c2x0_symm_sess_list, list_entry) {
		if (vc_sess->sess_id == qemu_cmd->u.symm.exit.sess_id
		    && vc_sess->guest_id == qemu_cmd->guest_id) {
			ctx = &(vc_sess->c_sess);
			flag = 1;
			print_debug("Symm session FOUND; sess_id = %x\n",
				    vc_sess->sess_id);
			break;
		}
	}
	if (0 == flag) {
		print_error("Symm session[%lx] for guest [%d] NOT found\n",
			    qemu_cmd->u.symm.exit.sess_id, qemu_cmd->guest_id);
		spin_unlock(&symm_sess_list_lock);
		return -1;
	}
	/* Remove the symm session from list */
	list_del(&vc_sess->list_entry);
	spin_unlock(&symm_sess_list_lock);

	sym_cra_exit(ctx);

	kfree(vc_sess);

	print_debug("EXIT FROM VIRTIO SYM_CRA_EXIT\n");
	return 0;
}

int32_t process_virtio_ablkcipher_job(struct virtio_c2x0_job_ctx *virtio_job)
{
	int32_t ret = 0;
	struct virtio_c2x0_qemu_cmd *qemu_cmd = &virtio_job->qemu_cmd;
	struct ablkcipher_request *req = NULL;
	struct scatterlist *sg_src = NULL;
	struct scatterlist *sg_dst = NULL;
	uint8_t *buf = NULL;
	uint32_t buflen;
	uint8_t **src = NULL;
	uint32_t *src_len = NULL;
	uint8_t **dst = NULL;
	uint32_t *dst_len = NULL;
	int i = 0, max_filled_src_sgs = 0, max_filled_dst_sgs = 0;

	if (0 == qemu_cmd->u.symm.cmd_req.src_sg_info.sg_count) {
		printk(KERN_INFO "%s:Entered; src_sg_count = %d;nbytes = %d;\n",
		       __func__,
		       qemu_cmd->u.symm.cmd_req.src_sg_info.sg_count,
		       qemu_cmd->u.symm.cmd_req.src_sg_info.nbytes);
	}
	if (0 == qemu_cmd->u.symm.cmd_req.dst_sg_info.sg_count) {
		printk(KERN_INFO "%s:Entered; dst_sg_count = %d;nbytes = %d;\n",
		       __func__,
		       qemu_cmd->u.symm.cmd_req.dst_sg_info.sg_count,
		       qemu_cmd->u.symm.cmd_req.dst_sg_info.nbytes);
	}

	/*
	 * Allocating memory for scatterlist in ablkcipher_request->src
	 */
	sg_src = kzalloc(sizeof(struct scatterlist) *
			 qemu_cmd->u.symm.cmd_req.src_sg_info.sg_count,
			 GFP_KERNEL);
#if 0
	if (!sg_src) {
		print_error("scatter gather memory allocation failed\n");
		return -1;
	}
#else
	if (unlikely(ZERO_OR_NULL_PTR(sg_src))) {
		print_error("sg_src[%p] is ZERO_SIZE_PTR\n", sg_src);
		kfree(sg_src);
		return -1;
	}
#endif

	/* VM's virtual addresses of each sg entry */
	src = (uint8_t **) kzalloc(sizeof(uint8_t *) *
				   qemu_cmd->u.symm.cmd_req.src_sg_info.
				   sg_count, GFP_KERNEL);
	if (!src) {
		print_error("src alloc failed\n");
		goto failed_src;
	}
	ret = copy_from_user(src, qemu_cmd->u.symm.cmd_req.src,
			     sizeof(uint8_t *) *
			     qemu_cmd->u.symm.cmd_req.src_sg_info.sg_count);
	if (ret != 0) {
		print_error("src Copy from user failed  = %d\n", ret);
		goto failed_copy_src;
	}

	src_len = (uint32_t *) kzalloc(sizeof(uint32_t *) *
				       qemu_cmd->u.symm.cmd_req.src_sg_info.
				       sg_count, GFP_KERNEL);
	if (!src_len) {
		print_error("srclen alloc failed\n");
		goto failed_srclen;
	}
	ret = copy_from_user(src_len, qemu_cmd->u.symm.cmd_req.src_len,
			     sizeof(uint32_t *) *
			     qemu_cmd->u.symm.cmd_req.src_sg_info.sg_count);
	if (ret != 0) {
		print_error("srclen Copy from user failed  = %d\n", ret);
		goto failed_copy_srclen;
	}

	/*
	 * Copy input data from VM and
	 * Fill the ahash_request->scatterlist entries from the
	 * VM's sg address received through Qemu
	 */
	for (i = 0; i < qemu_cmd->u.symm.cmd_req.src_sg_info.sg_count; i++) {
		buflen = src_len[i];
		buf = (uint8_t *) kzalloc(buflen, GFP_KERNEL);
		if (!buf) {
			print_error("Copy from user failed  = %d\n", ret);
			goto failed_buf_src;
		}
		max_filled_src_sgs++;
		ret = copy_from_user(buf, src[i], buflen);
		if (ret != 0) {
			print_error("Copy from user failed  = %d\n", ret);
			goto failed_buf_src;
		}
		sg_set_buf(&sg_src[i], (void *)buf, buflen);
		buf = NULL;
	}

	/*
	 * Allocating memory for scatterlist in ablkcipher_request->dst
	 */
	sg_dst = kzalloc(sizeof(struct scatterlist) *
			 qemu_cmd->u.symm.cmd_req.dst_sg_info.sg_count,
			 GFP_KERNEL);
	if (!sg_dst) {
		print_error("scatter gather memory allocation failed\n");
		goto failed_sg_dst;
		return -1;
	}

	/* VM's virtual addresses of each sg entry */
	dst = (uint8_t **) kzalloc(sizeof(uint8_t *) *
				   qemu_cmd->u.symm.cmd_req.dst_sg_info.
				   sg_count, GFP_KERNEL);
	if (!dst) {
		print_error("src alloc failed\n");
		goto failed_dst;
	}
	ret = copy_from_user(dst, qemu_cmd->u.symm.cmd_req.dst,
			     sizeof(uint8_t *) *
			     qemu_cmd->u.symm.cmd_req.dst_sg_info.sg_count);
	if (ret != 0) {
		print_error("src Copy from user failed  = %d\n", ret);
		goto failed_copy_dst;
	}

	dst_len = (uint32_t *) kzalloc(sizeof(uint32_t *) *
				       qemu_cmd->u.symm.cmd_req.dst_sg_info.
				       sg_count, GFP_KERNEL);
	if (!dst_len) {
		print_error("srclen alloc failed\n");
		goto failed_dstlen;
	}
	ret = copy_from_user(dst_len, qemu_cmd->u.symm.cmd_req.dst_len,
			     sizeof(uint32_t *) *
			     qemu_cmd->u.symm.cmd_req.dst_sg_info.sg_count);
	if (ret != 0) {
		print_error("dstlen Copy from user failed  = %d\n", ret);
		goto failed_copy_dstlen;
	}

	/*
	 * Copy input data from VM and
	 * Fill the ahash_request->scatterlist entries from the
	 * VM's sg address received through Qemu
	 */
	for (i = 0; i < qemu_cmd->u.symm.cmd_req.dst_sg_info.sg_count; i++) {
		buflen = dst_len[i];
		buf = (uint8_t *) kzalloc(buflen, GFP_KERNEL);
		if (!buf) {
			print_error("Copy from user failed  = %d\n", ret);
			goto failed_buf_dst;
		}
		max_filled_dst_sgs++;
		ret = copy_from_user(buf, dst[i], buflen);
		if (ret != 0) {
			print_error("Copy from user failed  = %d\n", ret);
			goto failed_buf_dst;
		}
		sg_set_buf(&sg_dst[i], (void *)buf, buflen);
		buf = NULL;
	}

	/*
	 * In driver's qemu_cmd, Overwrite the actual userspace
	 * qemu double pointer
	 * (holding adresses of userspace pointers)
	 * with local double pointer
	 * (holding copy of userspace pointers)
	 * This does NOT alter the qemu's copy of qemu_cmd
	 * This is done to preserve userspace pointers to
	 * copy output in response path
	 */
	qemu_cmd->u.symm.cmd_req.src = src;
	qemu_cmd->u.symm.cmd_req.src_len = src_len;
	qemu_cmd->u.symm.cmd_req.dst = dst;
	qemu_cmd->u.symm.cmd_req.dst_len = dst_len;

	/*
	 * Creating ablkcipher_request
	 */
	req =
	    (struct ablkcipher_request *)
	    kzalloc(sizeof(struct ablkcipher_request), GFP_KERNEL);
	if (!req) {
		print_error("Alloc failed req:%p,\n", req);
		goto failed_req;
	}

	req->nbytes = qemu_cmd->u.symm.cmd_req.src_sg_info.nbytes;
	req->src = sg_src;
	req->dst = sg_dst;

	req->info = kzalloc(qemu_cmd->u.symm.cmd_req.ivsize, GFP_KERNEL);
	if (!req->info) {
		print_error("result memory allocation failed\n");
		goto failed_info;
	}

	ret = copy_from_user(req->info, qemu_cmd->u.symm.cmd_req.info,
			     qemu_cmd->u.symm.cmd_req.ivsize);
	if (0 != ret) {
		print_error("copy_from_user failed\n");
		goto failed_copy_info;
	}

	if (ABLK_ENCRYPT == qemu_cmd->op)
		ret = fsl_ablkcipher(req, true, virtio_job);
	else if (ABLK_DECRYPT == qemu_cmd->op)
		ret = fsl_ablkcipher(req, false, virtio_job);

	if (-1 != ret) {
		print_debug("ABLK job succesfully given to card : %d\n", ret);
		return 0;
	}
	print_error("fsl_ablkcipher_desc_alloc returns : %d\n", ret);

failed_copy_info:
	kfree(req->info);
failed_info:
	kfree(req);
failed_req:
failed_buf_dst:
	{
		uint8_t *buf = NULL;

		int i = 0;
		for (i = 0; i < max_filled_dst_sgs; i++) {
			buf = sg_virt(&sg_dst[i]);
			kfree(buf);
		}
	}
failed_copy_dstlen:
	kfree(dst_len);
failed_dstlen:
failed_copy_dst:
	kfree(dst);
failed_dst:
	kfree(sg_dst);
failed_sg_dst:
failed_buf_src:
	{
		uint8_t *buf = NULL;

		int i = 0;
		for (i = 0; i < max_filled_src_sgs; i++) {
			buf = sg_virt(&sg_src[i]);
			kfree(buf);
		}
	}
failed_copy_srclen:
	kfree(src_len);
failed_srclen:
failed_copy_src:
	kfree(src);
failed_src:
	kfree(sg_src);
	return -1;

}
#endif

/********************************************************************
* Function     : process_virtio_app_req
*
* Arguments    : virtio_job - virtio job structure
*
* Return Value : int32_t
*
* Description  : processes the job  for virtio
*
**********************************************************************/

int32_t process_virtio_app_req(struct virtio_c2x0_job_ctx *virtio_job)
{
	int32_t ret = 0;
	struct virtio_c2x0_qemu_cmd *qemu_cmd = &virtio_job->qemu_cmd;

	print_debug("Virtio job request with operation : %d\n", qemu_cmd->op);
	switch (qemu_cmd->op) {
	case RSA:
		print_debug(" RSA Operation\n");
		ret = process_virtio_rsa_job(virtio_job);
		break;

	case DSA:
		print_debug(" DSA Operation\n");
		ret = process_virtio_dsa_job(virtio_job);
		break;
	case DH:
		print_debug(" DH Operation\n");
		ret = process_virtio_dh_job(virtio_job);
		break;
#ifdef HASH_OFFLOAD
	case HASH_SPLIT_KEY:
		print_debug("HASH_SPLIT_KEY operation\n");
		ret = process_virtio_hash_split_key_job(virtio_job);
		break;
	case AHASH_DIGEST:
		print_debug("AHASH_DIGEST operation\n");
		ret = process_virtio_ahash_digest_job(virtio_job);
		break;
	case AHASH_UPDATE_CTX:
		print_debug("AHASH_UPDATE_CTX operation\n");
		ret = process_virtio_ahash_update_job(virtio_job);
		break;
	case AHASH_UPDATE_NO_CTX:
		print_debug("AHASH_UPDATE_NO_CTX operation\n");
		ret = process_virtio_ahash_update_job(virtio_job);
		break;
	case AHASH_UPDATE_FIRST:
		print_debug("AHASH_UPDATE_FIRST operation\n");
		ret = process_virtio_ahash_update_job(virtio_job);
		break;
	case AHASH_FINAL_CTX:
		print_debug("AHASH_FINAL_CTX operation\n");
		ret = process_virtio_ahash_final_job(virtio_job);
		break;
	case AHASH_FINAL_NO_CTX:
		print_debug("AHASH_FINAL_NO_CTX operation\n");
		ret = process_virtio_ahash_final_job(virtio_job);
		break;
	case AHASH_FINUP_CTX:
		print_debug("AHASH_FINUP_CTX operation\n");
		ret = process_virtio_ahash_finup_job(virtio_job);
		break;
	case AHASH_FINUP_NO_CTX:
		print_debug("AHASH_FINUP_NO_CTX operation\n");
		ret = process_virtio_ahash_finup_job(virtio_job);
		break;
#endif
#ifdef SYMMETRIC_OFFLOAD
	case ABLK_ENCRYPT:
		print_debug("ABLK_ENCRYPT operation\n");
		ret = process_virtio_ablkcipher_job(virtio_job);
		break;
	case ABLK_DECRYPT:
		print_debug("ABLK_DECRYPT operation\n");
		ret = process_virtio_ablkcipher_job(virtio_job);
		break;
	case VIRTIO_C2X0_ABLK_SETKEY:
		{
			uint8_t *key = NULL;

			print_debug("VIRTIO_C2X0_ABLK_SETKEY operation\n");
			key =
			    (uint8_t *) kzalloc(virtio_job->qemu_cmd.u.symm.
						setkey_req.keylen, GFP_KERNEL);
			if (!key) {
				print_error("Key alloc failed\n");
				return -1;
			}

			ret =
			    copy_from_user(key,
					   virtio_job->qemu_cmd.u.symm.
					   setkey_req.key,
					   virtio_job->qemu_cmd.u.symm.
					   setkey_req.keylen);
			if (0 != ret) {
				print_error("copy from user failed with %d\n",
					    ret);
				kfree(key);
				return -1;
			}

			ret = fsl_ablkcipher_setkey(qemu_cmd,
						    key,
						    virtio_job->qemu_cmd.u.symm.
						    setkey_req.keylen);

			kfree(key);
			if (ret >= 0)
				return 0;

			break;
		}
#endif
#ifdef RNG_OFFLOAD
	case RNG:
		print_debug("RNG Operation\n");
		ret = process_virtio_rng_job(virtio_job);
		break;
#endif
	default:
		print_error(" Invalid Operation ");
		ret = -1;
		break;
	}
	return ret;
}
#endif /* VIRTIO_C2X0 : handling virtio_operations */
