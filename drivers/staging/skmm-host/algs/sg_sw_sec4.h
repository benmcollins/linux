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

#ifndef __SG_SW_SEC4_H__
#define __SG_SW_SEC4_H__

#include"common.h"
#include "memmgr.h"
#include "fsl_c2x0_crypto_layer.h"
#include "fsl_c2x0_driver.h"
#ifdef VIRTIO_C2X0
#include <crypto/scatterwalk.h>
#endif
struct sec4_sg_entry;

static inline void sg_map_copy(u8 *dest, struct scatterlist *sg,
			       int len, int offset)
{
	u8 *mapped_addr;

	/*
	 * Page here can be user-space pinned using get_user_pages
	 * Same must be kmapped before use and kunmapped subsequently
	 */
	mapped_addr = kmap(sg_page(sg));
	memcpy(dest, mapped_addr + offset, len);
	kunmap(sg_page(sg));
}

/*
 * convert single dma address to h/w link table format
 */
static inline int sg_to_sec4_sg_one(struct sec4_sg_entry *sec4_sg_ptr,
				    struct scatterlist *sg, u32 offset,
				    void *mempool, fsl_crypto_dev_t *c_dev,
				    u8 **dev_sg, u32 *dev_sg_count,
				    int sg_count)
{
	u8 *buff_addr;
	u32 len = 0;
	dev_dma_addr_t dev_ptr;
	dev_sg[*dev_sg_count] = get_buffer(c_dev, mempool, sg->length, 0);
	buff_addr = dev_sg[*dev_sg_count];

	if (!buff_addr)
		return -1;

	(*dev_sg_count)++;
	sg_map_copy(buff_addr, sg, sg->length, sg->offset);
	len = sg->length;
	if (1 == sg_count)
		len |= SEC4_SG_LEN_FIN;

	dev_ptr =
	    (phys_addr_t) ((unsigned long)buff_addr -
			   (unsigned long)c_dev->
			   mem[MEM_TYPE_SRAM].host_v_addr);
	dev_ptr =
	    (dev_dma_addr_t) c_dev->mem[MEM_TYPE_SRAM].dev_p_addr + dev_ptr;
	ASSIGN64(sec4_sg_ptr->ptr, dev_ptr);
	ASSIGN32(sec4_sg_ptr->len, len);
	ASSIGN8(sec4_sg_ptr->reserved, 0);
	ASSIGN8(sec4_sg_ptr->buf_pool_id, 0);
	ASSIGN16(sec4_sg_ptr->offset, offset);

	return 0;
}

static inline int ptr_to_sec4_sg_one(struct sec4_sg_entry *sec4_sg_ptr,
				     u8 *ptr, u32 length, u32 offset,
				     void *mempool, fsl_crypto_dev_t *c_dev,
				     u8 **dev_sg, u32 *dev_sg_count,
				     int sg_count)
{
	u8 *buff_addr;
	u32 len = 0;
	dev_dma_addr_t dev_ptr;
	dev_sg[*dev_sg_count] = get_buffer(c_dev, mempool, length, 0);
	buff_addr = dev_sg[*dev_sg_count];
	if (!buff_addr)
		return -1;

	(*dev_sg_count)++;
	memcpy(buff_addr, ptr, length);
	len = length;
	if (1 == sg_count)
		len |= SEC4_SG_LEN_FIN;

	dev_ptr =
	    (phys_addr_t) ((unsigned long)buff_addr -
			   (unsigned long)c_dev->
			   mem[MEM_TYPE_SRAM].host_v_addr);
	dev_ptr =
	    (dev_dma_addr_t) c_dev->mem[MEM_TYPE_SRAM].dev_p_addr + dev_ptr;
	ASSIGN64(sec4_sg_ptr->ptr, dev_ptr);
	ASSIGN32(sec4_sg_ptr->len, len);
	ASSIGN8(sec4_sg_ptr->reserved, 0);
	ASSIGN8(sec4_sg_ptr->buf_pool_id, 0);
	ASSIGN16(sec4_sg_ptr->offset, offset);

	return 0;
}

/*
 * convert scatterlist to h/w link table format
 * but does not have final bit; instead, returns last entry
 */
static inline int sg_to_sec4_sg(struct scatterlist *sg, int sg_count,
				struct sec4_sg_entry *sec4_sg_ptr, u32 offset,
				void *mempool, fsl_crypto_dev_t *c_dev,
				u8 **dev_sg, u32 *dev_sg_count)
{
	int ret = 0;
	while (sg_count) {
		ret =
		    sg_to_sec4_sg_one(sec4_sg_ptr, sg, offset, mempool, c_dev,
				      dev_sg, dev_sg_count, sg_count);
		if (ret == -1)
			return ret;
		sec4_sg_ptr++;
		sg = sg_next(sg);
		sg_count--;
	}
	return ret;
}

/*
 * convert scatterlist to h/w link table format
 * scatterlist must have been previously dma mapped
 */

static inline int sg_to_sec4_sg_last(struct scatterlist *sg, int sg_count,
				     struct sec4_sg_entry *sec4_sg_ptr,
				     u32 offset, void *mempool,
				     fsl_crypto_dev_t *c_dev, u8 **dev_sg,
				     u32 *dev_sg_count)
{
	return sg_to_sec4_sg(sg, sg_count, sec4_sg_ptr, offset, mempool, c_dev,
			     dev_sg, dev_sg_count);

}

static inline void dma_to_sec4_sg_one(struct sec4_sg_entry *sec4_sg_ptr,
				      dma_addr_t dma, u32 len, u32 offset,
				      int sg_count, fsl_crypto_dev_t *c_dev)
{
	dev_dma_addr_t dev_ptr;
	if (1 == sg_count)
		len |= SEC4_SG_LEN_FIN;

	dev_ptr = (dev_dma_addr_t) dma;
	dev_ptr = c_dev->mem[MEM_TYPE_DRIVER].dev_p_addr + dev_ptr;

	ASSIGN64(sec4_sg_ptr->ptr, dev_ptr);
	ASSIGN32(sec4_sg_ptr->len, len);
	ASSIGN8(sec4_sg_ptr->reserved, 0);
	ASSIGN8(sec4_sg_ptr->buf_pool_id, 0);
	ASSIGN16(sec4_sg_ptr->offset, offset);
}

static inline void pci_sg_to_sec4_sg(struct scatterlist *sg, int sg_count,
				     struct sec4_sg_entry *sec4_sg_ptr,
				     u32 offset, fsl_crypto_dev_t *c_dev)
{
	while (sg_count) {
		dma_to_sec4_sg_one(sec4_sg_ptr, sg_dma_address(sg),
				   sg_dma_len(sg), offset, sg_count, c_dev);
		sec4_sg_ptr++;
		sg = sg_next(sg);
		sg_count--;
	}
}

/*
 * convert single dma address to h/w link table format
 */
static inline void dev_dma_to_sec4_sg_one(struct sec4_sg_entry *sec4_sg_ptr,
					  dev_dma_addr_t dma, u32 len,
					  u32 offset)
{
	ASSIGN64(sec4_sg_ptr->ptr, dma);
	ASSIGN32(sec4_sg_ptr->len, len);
	ASSIGN8(sec4_sg_ptr->reserved, 0);
	ASSIGN8(sec4_sg_ptr->buf_pool_id, 0);
	ASSIGN16(sec4_sg_ptr->offset, offset);
}

/*
 * convert scatterlist to h/w link table format
 * but does not have final bit; instead, returns last entry
 */
static inline struct sec4_sg_entry *dev_sg_to_sec4_sg(struct scatterlist *sg,
						      int sg_count,
						      struct sec4_sg_entry
						      *sec4_sg_ptr, u32 offset,
						      fsl_crypto_dev_t *c_dev,
						      int32_t *len)
{
	while (sg_count) {
		*len = sg_dma_len(sg);
		dev_dma_to_sec4_sg_one(sec4_sg_ptr,
				       (dev_dma_addr_t) sg_dma_address(sg) +
				       c_dev->mem[MEM_TYPE_DRIVER].dev_p_addr,
				       sg_dma_len(sg), offset);
		sec4_sg_ptr++;
		sg = sg_next(sg);
		sg_count--;
	}
	return sec4_sg_ptr - 1;
}

/*
 * convert scatterlist to h/w link table format
 * scatterlist must have been previously dma mapped
 */
static inline void dev_sg_to_sec4_sg_last(struct scatterlist *sg, int sg_count,
					  struct sec4_sg_entry *sec4_sg_ptr,
					  u32 offset, fsl_crypto_dev_t *c_dev)
{
	int32_t len = 0;
	sec4_sg_ptr =
	    dev_sg_to_sec4_sg(sg, sg_count, sec4_sg_ptr, offset, c_dev, &len);
	ASSIGN32(sec4_sg_ptr->len, len | SEC4_SG_LEN_FIN);
}

/* count number of elements in scatterlist */
static inline int __sg_count(struct scatterlist *sg_list, int nbytes,
			     bool *chained)
{
	struct scatterlist *sg = sg_list;
	int sg_nents = 0;

	while (nbytes > 0) {
		sg_nents++;
		nbytes -= sg->length;
		if (!sg_is_last(sg) && (sg + 1)->length == 0)
			*chained = true;
		sg = sg_next(sg);
	}

	return sg_nents;
}

/* derive number of elements in scatterlist, but return 0 for 1 */
static inline int sg_count(struct scatterlist *sg_list, int nbytes,
			   bool *chained)
{
	int sg_nents = __sg_count(sg_list, nbytes, chained);

	if (likely(sg_nents == 1))
		return 0;

	return sg_nents;
}

static inline int pci_map_sg_chained(struct pci_dev *dev,
				     struct scatterlist *sg, unsigned int nents,
				     int dir, bool chained)
{
	int ret = 0;
	if (unlikely(chained)) {
		int i;
		for (i = 0; i < nents; i++) {
			ret = pci_map_sg(dev, sg, 1, dir);
			if (0 == ret)
				return 0;
			sg = sg_next(sg);
		}
	} else {
		ret = pci_map_sg(dev, sg, nents, dir);
		if (0 == ret)
			return 0;

	}
	return nents;
}

static inline int pci_unmap_sg_chained(struct pci_dev *dev,
				       struct scatterlist *sg,
				       unsigned int nents, int dir,
				       bool chained)
{
	int i;
	if (unlikely(chained)) {
		for (i = 0; i < nents; i++) {
			if (sg_dma_address(sg) != 0)
				pci_unmap_sg(dev, sg, 1, dir);
			sg = sg_next(sg);
		}
	} else {
#if 0
		pci_unmap_sg(dev, sg, nents, dir);
#endif
#if 1
		for (i = 0; i < nents; i++) {
			if (sg_dma_address(sg) != 0)
				pci_unmap_sg(dev, sg, 1, dir);
			sg = sg_next(sg);
		}
#endif
	}
	return nents;
}

static inline int dma_map_sg_chained(struct device *dev, struct scatterlist *sg,
				     unsigned int nents,
				     enum dma_data_direction dir, bool chained)
{
	if (unlikely(chained)) {
		int i;
		for (i = 0; i < nents; i++) {
			dma_map_sg(dev, sg, 1, dir);
			sg = sg_next(sg);
		}
	} else {
		dma_map_sg(dev, sg, nents, dir);
	}
	return nents;
}

static inline int dma_unmap_sg_chained(struct device *dev,
				       struct scatterlist *sg,
				       unsigned int nents,
				       enum dma_data_direction dir,
				       bool chained)
{
	if (unlikely(chained)) {
		int i;
		for (i = 0; i < nents; i++) {
			dma_unmap_sg(dev, sg, 1, dir);
			sg = sg_next(sg);
		}
	} else {
		dma_unmap_sg(dev, sg, nents, dir);
	}
	return nents;
}

#if 0
static inline void sg_map_copy(u8 *dest, struct scatterlist *sg,
			       int len, int offset)
{
	u8 *mapped_addr;

	/*
	 * Page here can be user-space pinned using get_user_pages
	 * Same must be kmapped before use and kunmapped subsequently
	 */
	mapped_addr = kmap(sg_page(sg));
	memcpy(dest, mapped_addr + offset, len);
	kunmap(sg_page(sg));
}
#endif
#endif
