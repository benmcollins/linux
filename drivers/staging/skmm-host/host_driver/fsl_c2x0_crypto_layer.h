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

#ifndef __CRYPTO_LAYER_H__
#define __CRYPTO_LAYER_H__

extern int napi_poll_count;

/* 64 bytes of handshake memory */
#define DRIVER_HS_MEM_SIZE		64

/* Identifies different states of the device */
typedef enum handshake_state {
	DEFAULT,
	FIRMWARE_UP = 10,
	FW_INIT_CONFIG_COMPLETE,
	FW_GET_SEC_INFO_COMPLETE,
	FW_INIT_RING_PAIR_COMPLETE,
	FW_INIT_MSI_INFO_COMPLETE,
	FW_INIT_IDX_MEM_COMPLETE,
	FW_INIT_COUNTERS_MEM_COMPLETE,
	FW_INIT_RNG,
	FW_RNG_COMPLETE
} handshake_state_t;

/* Identifies different commands to be sent to the firmware */
typedef enum h_handshake_commands {
	HS_GET_SEC_INFO,
	HS_INIT_CONFIG,
	HS_INIT_RING_PAIR,
	HS_INIT_MSI_INFO,
	HS_INIT_IDX_MEM,
	HS_INIT_COUNTERS_MEM,
	HS_COMPLETE,
	WAIT_FOR_RNG,
	RNG_DONE
} h_handshake_commands_t;

/* Identifies different commands to be sent to the firmware */
typedef enum fw_handshake_commands {
	FW_GET_SEC_INFO,
	FW_INIT_CONFIG,
	FW_INIT_RING_PAIR,
	FW_INIT_MSI_INFO,
	FW_INIT_IDX_MEM,
	FW_INIT_COUNTERS_MEM,
	FW_HS_COMPLETE,
	FW_WAIT_FOR_RNG,
	FW_RNG_DONE
} fw_handshake_commands_t;

/* Identifies the different devices */
typedef enum crypto_dev_type {
	CRYPTO_DEV_P4080,
	CRYPTO_DEV_C270,
	CRYPTO_DEV_C280,
	CRYPTO_DEV_C290
} crypto_dev_type_t;

#define JR_SIZE_SHIFT   0
#define JR_SIZE_MASK    0x0000ffff
#define JR_NO_SHIFT     16
#define JR_NO_MASK      0x00ff0000
#define SEC_NO_SHIFT    24
#define SEC_NO_MASK     0xff000000

/*** HANDSHAKE RELATED DATA STRUCTURES ***/

/***********************************************************************
Description : Defines the handshake memory on the host
Fields      :
***********************************************************************/
typedef struct fsl_h_mem_handshake {
	uint8_t state;
	uint8_t result;

	uint32_t dev_avail_mem;

	union resp_data {
		struct fw_up_data {
			uint32_t p_ib_mem_base_l;
			uint32_t p_ib_mem_base_h;
			uint32_t p_ob_mem_base_l;
			uint32_t p_ob_mem_base_h;
			uint32_t no_secs;
		} device;
		struct config_data {
			uint32_t s_r_cntrs;
			uint32_t s_cntrs;
			uint32_t ip_pool;
			uint32_t resp_intr_ctrl_flag;
		} config;
		struct ring_data {
			uint32_t req_r;
			uint32_t intr_ctrl_flag;
		} ring;
	} data;
} fsl_h_mem_handshake_t;

/*******************************************************************************
Description : Defines the handshake memory on the device
Fields      :
*******************************************************************************/
typedef struct crypto_c_hs_mem {
	uint32_t h_ob_mem_l;
	uint32_t h_ob_mem_h;

	uint32_t h_msi_mem_l;
	uint32_t h_msi_mem_h;

	uint8_t state;
	uint8_t command;
	uint8_t data_len;
	uint8_t pad;

	union cmd_data {
		struct c_config_data {
			uint8_t num_of_rps;
			uint8_t max_pri;
			uint8_t num_of_fwresp_rings;
			uint16_t req_mem_size;
			uint32_t drv_resp_ring;
			uint32_t fw_resp_ring;
			uint32_t s_cntrs;
			uint32_t r_s_cntrs;
			uint32_t fw_resp_ring_depth;
		} config;
		struct c_ring_data {
			uint8_t rid;
			uint8_t props;
			uint16_t msi_data;
			uint32_t depth;
			uint32_t resp_ring;
			uint32_t msi_addr_l;
			uint32_t msi_addr_h;
			uint32_t s_r_cntrs;
		} ring;
	} data;
} crypto_c_hs_mem_t;

/********************************************/

#define MULTIPLE_RESP_RINGS

#ifdef MULTIPLE_RESP_RINGS
struct dev_ctx {
	volatile uint8_t rid;
	volatile uint32_t wi;
} __packed;
typedef struct dev_ctx dev_ctx_t;
#endif

/*******************************************************************************
Description :	Defines the input buffer pool
Fields      :	pool		: Pool pointer returned by the pool manager
		drv_pool_addr	: Address in ib mem for driver's internal use
		dev_pool_base	: Holds the address of pool inside the device,
					will be required inside the SEC desc
*******************************************************************************/
typedef struct fsl_h_rsrc_pool {
	void *pool;

	void *drv_pool_addr;
	uint32_t dev_pool_base;
	uint32_t len;
} fsl_h_rsrc_pool_t;

/*******************************************************************************
Description :	Defines the ring indexes
Fields      :	w_index		: Request ring write index
		r_index		: Response ring read index
*******************************************************************************/
typedef struct ring_idxs_mem {
	uint32_t w_index;
	uint32_t r_index;
} ring_idxs_mem_t;

/*******************************************************************************
Description :	Defines the shadow ring indexes
Fields      :	w_index	: Pointer to the req w index in the device mem
		r_index	: Pointer to the resp r index in the device mem
*******************************************************************************/
typedef ring_idxs_mem_t ring_shadow_idxs_mem_t;

/*******************************************************************************
Description :	Contains the counters per job ring. There will two copies one
		for local usage and one shadowed for firmware
Fields      :	Local memory
		jobs_added	: Count of number of req jobs added
		jobs_processed	: Count of number of resp jobs processed
					Shadow copy memory
		jobs_added	: Count of number of resp jobs added by fw
		jobs_processed	: Count of number of req jobs
					processed by fw
*******************************************************************************/
typedef struct ring_counters_mem {
	uint32_t jobs_added;
	uint32_t jobs_processed;
} ring_counters_mem_t;

/*******************************************************************************
Description :	Contains the total counters. There will two copies one
		for local usage and one shadowed for firmware
Fields      :	Local memory
		tot_jobs_added	: Total count of req jobs added by driver
		tot_jobs_processed: Total count of resp jobs processed
					Shadow copy memory
		tot_jobs_added	: Total count of resp jobs added by fw
		tot_jobs_processed: Total count of req jobs processed by fw
*******************************************************************************/
typedef struct counters_mem {
	uint32_t tot_jobs_added;
	uint32_t tot_jobs_processed;
} counters_mem_t;

/*******************************************************************************
Description :	Contains the counters per job ring. This mem exist on device.
Fields      :	req_jobs_added	: Count of Jobs added by driver to the fw.
		resp_jobs_processed: Count of resp jobs processed by driver.
*******************************************************************************/
typedef struct ring_shadow_counters_mem {
	uint32_t req_jobs_added;
	uint32_t resp_jobs_processed;
} ring_shadow_counters_mem_t;

/*******************************************************************************
Description :	Contains the overall counters. This mem exist on device.
Fields      :	req_tot_jobs_added	: Total no of reqs added by driver to fw
		resp_tot_jobs_processed	: Total no of reqs processed by driver
*******************************************************************************/
typedef counters_mem_t shadow_counters_mem_t;

/*******************************************************************************
Description :	Contains the identity information of the crypto device.
Fields      :	dev_type	: P4080/c270/c280/c290 – String version
					of the device type
		sec_version	: version of the SEC engine
		num_sec_engines	: Number of sec engines in the product
		CHA_v_id	: CHA version id.
		PKHA_v_id	: PKHA version id.
		supported_ops	: OR of supported operations by this device
*******************************************************************************/
typedef struct crypto_dev_info {
	crypto_dev_type_t dev_type;
	uint8_t sec_version;
	uint8_t num_sec_engines;	/* Can get from SVR register */
	uint8_t CHA_v_id;
	uint8_t PKHA_v_id;
	uint8_t supported_ops;
} crypto_dev_info_t;

/**** RING PAIR RELATED DATA STRUCTURES ****/

/*******************************************************************************
Description : Identifies the request ring entry
Fields      : sec_desc        : DMA address of the sec addr valid in dev domain
*******************************************************************************/
typedef struct req_ring_entry {
	dev_dma_addr_t sec_desc;
} req_ring_entry_t;

/*******************************************************************************
Description :	Identifies the response ring entry
Fields      :	sec_desc: DMA address of the sec addr valid in dev domain
		result	: Result word from sec engine
*******************************************************************************/
struct resp_ring_entry {
	dev_dma_addr_t sec_desc;
	volatile int32_t result;
} __packed;

typedef struct resp_ring_entry resp_ring_entry_t;

/*******************************************************************************
Description :	Identifies the priority queue which has linked list of rings
		with same priority level
Fields      :	ring_list_head	: Head of the equal priority ring pairs.
*******************************************************************************/
typedef struct fsl_priority_queue {
	/*fsl_h_rsrc_ring_pair_t *ring_pair; */
	uint32_t ring_count;
	 LINKED_LIST_HEAD(ring_list_head);
} fsl_priority_queue_t;

/*******************************************************************************
Description :	Contains the information about each ring pair
Fields      :	depth: Depth of the ring
		props: Valid only for application ring as :
			4bits : Priority level
			3bits :	Affinity level
			1bit  : Ordered/Un-ordered
		intr_ctrl_flag	: Address of intr ctrl flag on device. This will
				be used in data processing to enable/disable
				interrupt per ring.
		req_ring_addr	: Address of the request ring in ib window
		resp_ring_addr	: Response ring address in ob window
		pool		: Input buffer pool information
*******************************************************************************/
typedef struct fsl_h_rsrc_ring_pair {
	struct fsl_crypto_dev *dev;
	struct ring_info info;

	struct list_head ring_pair_list_node;
	struct list_head isr_ctx_list_node;
	struct list_head bh_ctx_list_node;

	uint32_t *intr_ctrl_flag;
	void *ip_pool;
	req_ring_entry_t *req_r;
	resp_ring_entry_t *resp_r;
	ring_idxs_mem_t *indexes;
	ring_counters_mem_t *counters;
	ring_counters_mem_t *s_c_counters;
	ring_shadow_counters_mem_t *shadow_counters;

	uint32_t depth;
	uint32_t core_no;
	uint32_t num_of_sec_engines;

	atomic_t sec_eng_sel;
	spinlock_t ring_lock;

	/* Will be used to notify the running contexts to block the ring -
	 * used during reset operations */
	atomic_t block;

} fsl_h_rsrc_ring_pair_t;

/* Structure defining the input pool */
typedef struct ip_pool_info {
	/* Information about the pool in firmware */
	struct fw_pool_t {
		dev_dma_addr_t dev_p_addr;
		phys_addr_t host_map_p_addr;
		void *host_map_v_addr;
	} fw_pool;
	/* Information about the shadow pool in driver */
	struct drv_map_pool_t {
		phys_addr_t p_addr;
		void *v_addr;
		void *pool;
	} drv_map_pool;
} ip_pool_info_t;

/* Structure defining the output pool */
typedef struct op_pool_info {
	phys_addr_t p_addr;
	void *v_addr;
	void *pool;
} op_pool_info_t;

typedef struct shadow_memory {
	/* Pointer to the shadow indexes memory */

	/* Pointer to the shadow ring counters memory */
	ring_shadow_counters_mem_t *s_r_cntrs;

	/* Pointer to the shadow total counters memory */
	shadow_counters_mem_t *s_cntrs;
} shadow_memory_t;

/* This structure defines the resp ring interfacing with the firmware */
typedef struct fw_resp_ring {
	phys_addr_t p_addr;
	void *v_addr;
	uint32_t depth;

	uint8_t id;

	uint32_t *intr_ctrl_flag;
	ring_idxs_mem_t *idxs;
	ring_counters_mem_t *cntrs;
	ring_counters_mem_t *s_c_cntrs;
	ring_shadow_counters_mem_t *s_cntrs;

	struct fw_resp_ring *next;
} fw_resp_ring_t;

/*******************************************************************************
Description :	Contains the structured layout of the driver mem - outbound mem
Fields      :	hs_mem	: Handshake memory - 64bytes
		request_rings_mem: Sequence of bytes for rings holding req ring
				mem and input buffer pool. Exact binding is
				updated in different data structure.
		idxs	: Memory of the ring pair indexes
		shadow_idxs: Memory of the shadow ring pair indexes
		counters: Memory of the counters per ring
		shadow_counters: Memory of the shadow counters per ring
*******************************************************************************/
typedef struct crypto_h_mem_layout {
	fsl_h_mem_handshake_t hs_mem;

	resp_ring_entry_t *fw_resp_ring;
	resp_ring_entry_t *drv_resp_ring;
	ring_idxs_mem_t *l_idxs_mem;
	ring_idxs_mem_t *s_c_idxs_mem;
	ring_counters_mem_t *l_r_cntrs_mem;
	ring_counters_mem_t *s_c_r_cntrs_mem;
	counters_mem_t *cntrs_mem;
	counters_mem_t *s_c_cntrs_mem;
	void *op_pool;
	void *ip_pool;

} crypto_h_mem_layout_t;

typedef struct driver_ob_mem {
	uint32_t h_mem;
	uint32_t hs_mem;
	uint32_t drv_resp_rings;
	uint32_t fw_resp_ring;
	uint32_t ip_pool;
	uint32_t op_pool;
	uint32_t l_idxs_mem;
	uint32_t l_r_cntrs_mem;
	uint32_t s_c_idxs_mem;
	uint32_t s_c_r_cntrs_mem;
	uint32_t s_c_cntrs_mem;
	uint32_t cntrs_mem;
} driver_ob_mem_t;

/* Per dev status structure */
typedef struct per_dev_struct {
	atomic_t device_status;
} per_dev_struct_t;

/*******************************************************************************
Description :	Contains all the information of the crypto device.
Fields      :	priv_dev	: Low level private data structure of the device
		dev_info	: Info of the EP crypto device
		config		: configuration of the device.
		mem		: All the memories between the device and driver
		h_mem		: Layout of the driver memory.
		pci_id		: Device ID structure of the device.
		bars		: Holds the information of the PCIe BARs.
		intr_info	: Holds the interrupt information
		list		: To make multiple instances of this structure
					as linked list.
*******************************************************************************/

typedef struct fsl_crypto_dev {
	void *priv_dev;

	crypto_dev_info_t dev_info;

	crypto_dev_config_t *config;
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4, 19, 0))
	crypto_dev_mem_info_t mem[MEM_TYPE_MAX + 1];
#else
	crypto_dev_mem_info_t mem[MEM_TYPE_MAX_SKMM + 1];
#endif

	driver_ob_mem_t ob_mem;

	uint32_t tot_req_mem_size;

	/* Pointer to the memory on the host side, structures the plain bytes.
	 * Represents the memory layout on the driver.
	 * This points to the base of the outbound memory.
	 */
	crypto_h_mem_layout_t *h_mem;

	/* Pointer to the device's handshake memory, this will be
	 * pointing to the inbound memory.
	 * This data structure helps in structured access of raw bytes
	 * in the device memory during the handshake.
	 */
	crypto_c_hs_mem_t *c_hs_mem;

	/* Structure defining the shadow memories on the device which
	 * needs to be updated by driver */
	shadow_memory_t s_mem;

	/* Structure defining the input pool */
	ip_pool_info_t ip_pool;

	/* Output pool - Currently used by command ring to avoid
	 * dynamic mem allocations */
	op_pool_info_t op_pool;

	/* Ctx pool - Will be used during data path to allocate one
	 * of the available static contexts */
	void *ctx_pool;

	/* Firmware resp ring information */
#define NUM_OF_RESP_RINGS 1
	fw_resp_ring_t fw_resp_rings[NUM_OF_RESP_RINGS];

#define MAX_PRIORITY_LEVELS		16
	uint32_t max_pri_level;
	fsl_priority_queue_t pri_queue[MAX_PRIORITY_LEVELS];

	uint32_t num_of_rings;
	fsl_h_rsrc_ring_pair_t *ring_pairs;

	/* Holds the count of number of crypto dev sessions */
	atomic_t crypto_dev_sess_cnt;

	/* FLAG TO INDICATE DEVICE'S LIVELENESS STATUS */
	per_dev_struct_t __percpu *dev_status;
	atomic_t active_jobs;

	atomic_t app_req_cnt;
	atomic_t app_resp_cnt;
} fsl_crypto_dev_t;

/*extern void *per_core;*/
/*extern per_core_struct_t __percpu *per_core;*/
int32_t app_ring_enqueue(fsl_crypto_dev_t *c_dev, uint32_t jr_id,
			 dev_dma_addr_t sec_desc);
int32_t cmd_ring_enqueue(fsl_crypto_dev_t *c_dev, uint32_t jr_id,
			 dev_dma_addr_t sec_desc);

void *fsl_crypto_layer_add_device(void *dev, crypto_dev_config_t *config);
void demux_fw_responses(fsl_crypto_dev_t *dev);
void cleanup_crypto_device(fsl_crypto_dev_t *dev);
void store_crypto_ctx(fsl_crypto_dev_t *c_dev, void *pool, void *buffer,
		      void *ctx);
int32_t handshake(fsl_crypto_dev_t *dev, crypto_dev_config_t *config);
void rearrange_rings(fsl_crypto_dev_t *dev, crypto_dev_config_t *config);
int32_t distribute_rings(fsl_crypto_dev_t *dev, crypto_dev_config_t *config);
int32_t alloc_ob_mem(fsl_crypto_dev_t *dev, crypto_dev_config_t *config);
void init_ip_pool(fsl_crypto_dev_t *dev);
void init_op_pool(fsl_crypto_dev_t *dev);
void init_crypto_ctx_pool(fsl_crypto_dev_t *dev);
void init_handshake(fsl_crypto_dev_t *dev);
void init_fw_resp_ring(fsl_crypto_dev_t *dev);
void init_rps(fsl_crypto_dev_t *dev);
crypto_dev_config_t *get_config(uint32_t dev_no);

void *cmd_get_op_buffer(void *id, uint32_t len, unsigned long flag);
void cmd_put_op_buffer(void *id, void *addr);
int32_t set_device_status_per_cpu(fsl_crypto_dev_t *c_dev, uint8_t set);

#ifdef MULTIPLE_RESP_RINGS
int32_t process_response(fsl_crypto_dev_t *, struct list_head *);
#endif

extern int32_t rng_instantiation(fsl_crypto_dev_t *c_dev);

#endif
