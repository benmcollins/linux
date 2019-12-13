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

#ifndef __MEMMGR_H__
#define __MEMMGR_H__

#if (__WORDSIZE == 64)
/* Making sure that metadata is min 32 bytes -
 * so that actual buf mem will be aligned to 32 bytes
 * for better performance.
 */
struct buffer_header {
	struct buffer_header *prev_link;
	struct buffer_header *next_link;

	uint32_t len;
	uint8_t in_use;
	uint8_t flag;
	uint8_t pad[2];

	unsigned long priv;
} __packed;
#endif

#if (__WORDSIZE == 32)
struct buffer_header {
	struct buffer_header *prev_link;
	struct buffer_header *next_link;

	uint32_t len;
	uint8_t in_use;
	uint8_t flag;
	uint8_t pad1[2];

	unsigned long priv;
	uint32_t pad[3];
} __packed;
#endif

typedef struct buffer_header bh;

typedef struct buffer_pool {
	uint32_t tot_free_mem;
	bh *free_list;

	void *buff;
	uint32_t len;
	spinlock_t mem_lock;
} bp;

void *reg_mem_pool(void *mem, uint32_t size);
void destroy_pool(void *pool);
void *get_buffer(fsl_crypto_dev_t *c_dev, void *pool, uint32_t size,
		 unsigned long flags);
void put_buffer(fsl_crypto_dev_t *c_dev, void *pool, void *buffer);
void *alloc_buffer(void *pool, uint32_t size, unsigned long flags);
void free_buffer(void *pool, void *buffer);
void reset_pool(void *pool);

unsigned long get_priv_data(void *pool, void *buffer);
unsigned long get_flag(void *id, void *buffer);
void set_flag(void *id, void *buffer, unsigned long flag);
void store_priv_data(void *pool, void *buffer, unsigned long priv);

#endif
