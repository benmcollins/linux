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
#include "desc_cnstr.h"
#include "pkc_desc.h"
#include "memmgr.h"
#include "abs_req.h"

#undef OP_BUFFER_IN_DEV_MEM
/* #define RETRY_FOR_BUFFERS */

uint8_t *alloc_mem(void *pool, uint32_t len)
{
	uint32_t aligned_len = ALIGN_LEN_TO_DMA(len);
	print_debug("Allocating len.... :%d\n", aligned_len);
	return alloc_buffer(pool, aligned_len, 1);
}

static void dealloc_mem(void *pool, void *buffer)
{
	free_buffer(pool, buffer);
}

static void distribute_buffers(crypto_mem_info_t *mem_info, uint8_t *mem)
{
	uint32_t offset = 0;
#if 0
	uint32_t i = 0;
	for (i = 0; i < mem_info->count; i++) {
		switch (mem_info->buffers[i].bt) {
		case BT_DESC:
			mem_info->buffers[i].v_mem = (mem + offset);
			offset += ALIGN_LEN_TO_DMA(mem_info->buffers[i].len);
			break;
		case BT_IP:
			if (!mem_info->split_ip) {
				mem_info->buffers[i].v_mem = (mem + offset);
				offset +=
				    ALIGN_LEN_TO_DMA(mem_info->buffers[i].len);
			}
			break;
		case BT_OP:
#ifdef OP_BUFFER_IN_DEV_MEM
			mem_info->buffers[i].v_mem = (mem + offset);
			offset += ALIGN_LEN_TO_DMA(mem_info->buffers[i].len);
#endif
			break;
		}
	}
#endif
	if (!mem_info->split_ip)
		mem_info->abs_req = mem + offset;

	return;
}

static void dealloc_crypto_spit_mem(crypto_mem_info_t *mem_info,  uint32_t j)
{
	uint32_t i;

	/* The structure will have all the memory requirements */
	for (i = 0; i <= j; i++) {
		if (BT_IP == mem_info->buffers[i].bt) {
			if (NULL != mem_info->buffers[i].v_mem)
				dealloc_mem(mem_info->pool,
					    mem_info->buffers[i].v_mem);
		}
	}
}

/******************************************************************************
Description :	Allocates device memory as specified in the given structure
				crypto_mem_info_t.    
Fields      :   
			mem_info	:	Contains all the information needed to allocate 
							the memory (like, how much memory needed, how
							many buffers need memory etc).   
Returns		:	SUCCESS/FAILURE
******************************************************************************/

int32_t alloc_crypto_mem(crypto_mem_info_t *mem_info)
{
	uint32_t i = 0;
	uint32_t tot_mem = 0;
	uint8_t *mem = NULL;
#ifdef PRINT_DEBUG
#ifndef SPLIT_BUFFERS
#ifdef RETRY_FOR_BUFFERS
	uint32_t retry_cnt = 0;
#endif
#endif
#endif
#if 0
	/* The structure will have all the memory requirements */
	for (i = 0; i < mem_info->count; i++) {
		switch (mem_info->buffers[i].bt) {
		case BT_DESC:
			tot_mem += ALIGN_LEN_TO_DMA(mem_info->buffers[i].len);
			break;
		case BT_IP:
			if (!mem_info->split_ip)
				tot_mem +=
				    ALIGN_LEN_TO_DMA(mem_info->buffers[i].len);
			break;
		case BT_OP:
#ifdef OP_BUFFER_IN_DEV_MEM
			tot_mem += ALIGN_LEN_TO_DMA(mem_info->buffers[i].len);
#endif
			break;
		}
	}
#endif
	/* Add abstract request memory */
	if (!mem_info->split_ip)
		tot_mem += ALIGN_LEN_TO_DMA(sizeof(struct abs_req));
	else {
		mem_info->abs_req = alloc_mem(mem_info->pool,
						sizeof(struct abs_req));
		if (unlikely(!mem_info->abs_req)) {
			print_error("Alloc memory errror!\n");
			goto error;
		}
	}

	if (tot_mem)
		mem_info->sg_cnt++;


	if (!mem_info->split_ip) {
#ifdef RETRY_FOR_BUFFERS
RETRY1:
#endif
		mem = alloc_mem(mem_info->pool, tot_mem);
		if (NULL == mem) {
#ifdef RETRY_FOR_BUFFERS
			set_current_state(TASK_INTERRUPTIBLE);
			schedule_timeout(msecs_to_jiffies(100));
			print_debug("No mem... retrying... :%d\n", ++retry_cnt);
			goto RETRY1;
#else
			return -ENOMEM;
#endif

		}
	}

	mem_info->src_buff = mem;
	mem_info->alloc_len = tot_mem;
	distribute_buffers(mem_info, mem);

	return 0;

error:

	/* Deallocate the prev allocated buffers */
	if (!mem_info->split_ip)
		dealloc_mem(mem_info->pool, mem);
	else
		dealloc_crypto_spit_mem(mem_info, i);

	return -ENOMEM;
}

/******************************************************************************
Description :	Deallocates the device memory from the structure
				crypto_mem_info_t.   
Fields      :
			mem_info	:	Contains all the information needed to deallocate 
							the memory (like, how much memory needed, how
							many buffers need memory etc).   
Returns     :	SUCCESS/FAILURE
******************************************************************************/

int32_t dealloc_crypto_mem(crypto_mem_info_t *mem_info)
{
	fsl_crypto_dev_t *c_dev = mem_info->dev;
	fsl_pci_dev_t *pci_dev = c_dev->priv_dev;
	uint32_t i = 0;

	if (NULL != mem_info->src_buff)
		dealloc_mem(mem_info->pool, mem_info->src_buff);

	/* The structure will have all the memory requirements */
	if (mem_info->split_ip) {
		for (i = 0; i < mem_info->count; i++) {
			if (BT_IP == mem_info->buffers[i].bt) {
				if (NULL != mem_info->buffers[i].v_mem)
					dealloc_mem(mem_info->pool,
						    mem_info->buffers[i].v_mem);
			}
		}
	}
#if 0
#ifdef OP_BUFFER_IN_DEV_MEM
	for (i = 0; i < mem_info->count; i++) {
		if (BT_OP == mem_info->buffers[i].bt)
			dealloc_mem(mem_info->pool, mem_info->buffers[i].v_mem);
	}
#endif
#endif

	for (i = 0; i < mem_info->count; i++) {
		switch (mem_info->buffers[i].bt) {
		case BT_DESC:
		case BT_IP:
			break;
		case BT_OP:
			if (0 != mem_info->buffers[i].dev_buffer.h_dma_addr)
				pci_unmap_single(pci_dev->dev,
						 mem_info->
						 buffers[i].dev_buffer.
						 h_dma_addr,
						 mem_info->buffers[i].len,
						 PCI_DMA_BIDIRECTIONAL);
			break;
		}
	}

	return 0;
}

static inline dev_dma_addr_t desc_d_p_addr(fsl_crypto_dev_t *dev,
					   unsigned long h_v_addr)
{
	phys_addr_t ob = dev->mem[MEM_TYPE_DRIVER].dev_p_addr;
	return __pa(h_v_addr) + ob;

}

static inline unsigned long desc_d_v_addr(fsl_crypto_dev_t *dev,
					  unsigned long h_v_addr)
{
	unsigned long offset =
	    h_v_addr - (unsigned long)dev->ip_pool.drv_map_pool.v_addr;
	return (unsigned long)(dev->ip_pool.fw_pool.host_map_v_addr + offset);
}

static inline dev_dma_addr_t ip_buf_d_p_addr(fsl_crypto_dev_t *dev,
					     unsigned long h_v_addr)
{
	unsigned long offset =
	    h_v_addr - (unsigned long)dev->ip_pool.drv_map_pool.v_addr;
	return (dev_dma_addr_t) (dev->ip_pool.fw_pool.dev_p_addr + offset);
}

static inline unsigned long ip_buf_d_v_addr(fsl_crypto_dev_t *dev,
					    unsigned long h_v_addr)
{
	unsigned long offset =
	    h_v_addr - (unsigned long)dev->ip_pool.drv_map_pool.v_addr;
	return (unsigned long)(dev->ip_pool.fw_pool.host_map_v_addr + offset);
}

static inline dma_addr_t op_buf_h_dma_addr(fsl_crypto_dev_t *dev,
					   unsigned long h_v_addr, uint32_t len)
{
	fsl_pci_dev_t *pci_dev = dev->priv_dev;
	return pci_map_single
	    (pci_dev->dev, (void *)h_v_addr, len, PCI_DMA_BIDIRECTIONAL);
}

static inline dev_dma_addr_t op_buf_d_dma_addr(fsl_crypto_dev_t *dev,
					       dma_addr_t h_dma_addr)
{
	dev_dma_addr_t d_dma = (dev_dma_addr_t) h_dma_addr;
	return d_dma + dev->mem[MEM_TYPE_DRIVER].dev_p_addr;
}

static phys_addr_t h_map_p_addr(fsl_crypto_dev_t *dev, unsigned long h_v_addr)
{
	unsigned long offset =
	    h_v_addr - (unsigned long)dev->ip_pool.drv_map_pool.v_addr;
	return (phys_addr_t) (dev->ip_pool.fw_pool.host_map_p_addr + offset);
}

/******************************************************************************
Description :	Calculate all the related addresses from the device memory
				allocated.   
Fields      :   
			mem_info	:	The data structure which contains all the
							information related to the device memory allocated
							for any particular job.
Returns     :	SUCCESS/ FAILURE
******************************************************************************/

int32_t host_to_dev(crypto_mem_info_t *mem_info)
{
	uint32_t i = 0;

	for (i = 0; i < mem_info->count; i++) {
		switch (mem_info->buffers[i].bt) {
		case BT_DESC:
			mem_info->buffers[i].dev_buffer.h_v_addr =
			    (unsigned long)mem_info->buffers[i].v_mem;
			mem_info->buffers[i].dev_buffer.h_p_addr =
			    __pa(mem_info->buffers[i].dev_buffer.h_v_addr);
			mem_info->buffers[i].dev_buffer.h_dma_addr =
			    mem_info->buffers[i].dev_buffer.h_p_addr;
			mem_info->buffers[i].dev_buffer.h_map_p_addr =
			    h_map_p_addr(mem_info->dev,
					 (unsigned long)mem_info->
					 buffers[i].v_mem);

			mem_info->buffers[i].dev_buffer.d_v_addr =
			    desc_d_v_addr(mem_info->dev,
					  (unsigned long)mem_info->
					  buffers[i].v_mem);
			mem_info->buffers[i].dev_buffer.d_p_addr =
			    desc_d_p_addr(mem_info->dev,
					  (unsigned long)mem_info->
					  buffers[i].v_mem);
			break;

		case BT_IP:
			mem_info->buffers[i].dev_buffer.h_v_addr =
			    (unsigned long)mem_info->buffers[i].v_mem;
			mem_info->buffers[i].dev_buffer.h_p_addr =
			    __pa(mem_info->buffers[i].dev_buffer.h_v_addr);
			mem_info->buffers[i].dev_buffer.h_dma_addr =
			    mem_info->buffers[i].dev_buffer.h_p_addr;
			mem_info->buffers[i].dev_buffer.h_map_p_addr =
			    h_map_p_addr(mem_info->dev,
					 (unsigned long)mem_info->
					 buffers[i].v_mem);

			mem_info->buffers[i].dev_buffer.d_v_addr =
			    desc_d_v_addr(mem_info->dev,
					  (unsigned long)mem_info->
					  buffers[i].v_mem);
			mem_info->buffers[i].dev_buffer.d_p_addr =
			    desc_d_p_addr(mem_info->dev,
					  (unsigned long)mem_info->
					  buffers[i].v_mem);
			break;

		case BT_OP:
#ifndef OP_BUFFER_IN_DEV_MEM
			mem_info->buffers[i].dev_buffer.h_v_addr =
			    (unsigned long)mem_info->buffers[i].v_mem;
			mem_info->buffers[i].dev_buffer.h_p_addr =
			    __pa(mem_info->buffers[i].dev_buffer.h_v_addr);

			mem_info->buffers[i].dev_buffer.h_dma_addr =
			    op_buf_h_dma_addr(mem_info->dev,
					      (unsigned long)
					      mem_info->buffers[i].v_mem,
					      mem_info->buffers[i].len);
			mem_info->buffers[i].dev_buffer.d_p_addr =
			    op_buf_d_dma_addr(mem_info->dev,
					      mem_info->buffers[i].
					      dev_buffer.h_dma_addr);
#else
			mem_info->buffers[i].dev_buffer.h_v_addr =
			    (unsigned long)mem_info->buffers[i].v_mem;
			mem_info->buffers[i].dev_buffer.h_p_addr =
			    __pa(mem_info->buffers[i].dev_buffer.h_v_addr);
			mem_info->buffers[i].dev_buffer.h_dma_addr =
			    mem_info->buffers[i].dev_buffer.h_p_addr;

			mem_info->buffers[i].dev_buffer.d_v_addr =
			    desc_d_v_addr(mem_info->dev,
					  (unsigned long)mem_info->
					  buffers[i].v_mem);
			mem_info->buffers[i].dev_buffer.d_p_addr =
			    desc_d_p_addr(mem_info->dev,
					  (unsigned long)mem_info->
					  buffers[i].v_mem);
#endif
			break;

		}
	}

	if (mem_info->abs_req)
		mem_info->abs_p_h_map_addr = h_map_p_addr(mem_info->dev,
					(unsigned long)mem_info->abs_req);

	return 0;
}

/******************************************************************************
Description : Copy the data from host memory to device memory.   
Fields      :   
			mem	:	The data structure which contains all the
					information related to the device memory allocated
					for any particular job.	
Returns     :	SUCCESS/ FAILURE
******************************************************************************/

int32_t memcpy_to_dev(crypto_mem_info_t *mem)
{
	uint32_t i = 0;
	buffer_info_t *src = NULL;
	dev_buffer_t *dst = NULL;

	/* This function will take care of endian conversions across pcie */
	for (i = 0; i < (mem->count); i++) {
		src = &(mem->buffers[i]);
		dst = &(mem->buffers[i].dev_buffer);
		switch (src->bt) {
		case BT_DESC:
			memcpy((void *)dst->d_v_addr, src->v_mem, src->len);
			break;
		case BT_IP:
			memcpy((void *)dst->d_v_addr, src->req_ptr, src->len);
		case BT_OP:
			break;
		}
	}

	return 0;
}

#if 0
unsigned long ib_dev_v_addr(fsl_crypto_dev_t *dev, unsigned long h_mem_addr)
{
	unsigned long dev_v_addr =
	    h_mem_addr - dev->mem[MEM_TYPE_SRAM].host_v_addr;
	return dev_v_addr + dev->mem[MEM_TYPE_SRAM].dev_v_addr;
}

dev_dma_addr_t ib_dev_p_addr(fsl_crypto_dev_t *dev, phys_addr_t h_p_addr)
{
	phys_addr_t dev_p_addr = h_p_addr - dev->mem[MEM_TYPE_SRAM].host_p_addr;
	return dev_p_addr + dev->mem[MEM_TYPE_SRAM].dev_p_addr;
}

unsigned long ib_h_map_v_addr(fsl_crypto_dev_t *dev, unsigned long d_v_addr)
{
	unsigned long h_v_addr = d_v_addr - dev->mem[MEM_TYPE_SRAM].dev_v_addr;
	return h_v_addr + dev->mem[MEM_TYPE_SRAM].host_v_addr;
}

phys_addr_t ib_h_map_p_addr(fsl_crypto_dev_t *dev, unsigned long h_v_addr)
{
	return __pa(h_v_addr);
}

dma_addr_t h_dma_map_op_buffer(fsl_crypto_dev_t *dev, unsigned long h_v_addr,
			       uint32_t len)
{
	return pci_map_single
	    (dev->priv_dev->pci_dev, h_v_addr, len, PCI_DMA_BIDIRECTIONAL);
}

dev_dma_addr_t ob_dev_dma_addr(fsl_crypto_dev_t *dev, phys_addr_t h_p_addr)
{
	dev_dma_addr_t dev_p_addr =
	    h_p_addr - dev->mem[MEM_TYPE_DRIVER].host_p_addr;
	return dev_p_addr + dev->mem[MEM_TYPE_DRIVER].dev_p_addr;
}
#endif
