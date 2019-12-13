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
#include "command.h"
#include "sysfs.h"
#include "memmgr.h"

/* Functions used in case of reset commands for smooth exit */
static int32_t wait_for_cmd_response(cmd_op_t *cmd_op);
static cmd_op_t *get_cmd_op_ctx(fsl_crypto_dev_t *c_dev,
				cmd_ring_entry_desc_t *pci_cmd_desc);
static void block_app_rings(fsl_crypto_dev_t *dev);
static void unblock_app_rings(fsl_crypto_dev_t *dev);
static void flush_app_resp_rings(fsl_crypto_dev_t *dev);
static void flush_app_req_rings(fsl_crypto_dev_t *c_dev);
static int32_t flush_app_jobs(fsl_crypto_dev_t *dev);

/*******************************************************************************
* Function     : process_cmd_response
*
* Arguments    : c_dev - crypto device          desc - command descriptor
*
* Return Value : -
*
* Description  : processes the commands for device
*
*******************************************************************************/
void process_cmd_response(fsl_crypto_dev_t *c_dev, dev_dma_addr_t desc,
			  int32_t result)
{
	cmd_op_t *op_mem = NULL;
	dma_addr_t *h_desc =
	    (dma_addr_t *) (c_dev->ip_pool.fw_pool.host_map_v_addr +
			    (desc - c_dev->ip_pool.fw_pool.dev_p_addr));
	dev_dma_addr_t op_buf_addr = 0;

	cmd_ring_entry_desc_t *cmd_desc = NULL;

	print_debug("h_desc %p\n", h_desc);
	print_debug("Desc : %0llx, Result : %0x\n", desc, result);

	cmd_desc = (cmd_ring_entry_desc_t *) h_desc;
	print_debug("cmd_desc : %p\n", cmd_desc);

	print_debug("cmd_desc->cmd_op                      :%0llx\n",
		    cmd_desc->cmd_op);

#ifndef P4080_BUILD
	IO_BE_READ64(op_buf_addr, &(cmd_desc->cmd_op));
#else
	IO_LE_READ64(op_buf_addr, &(cmd_desc->cmd_op));
#endif
	print_debug("Dev domain output buffer address       :%0llx\n",
		    op_buf_addr);

	if (0 == op_buf_addr) {
		print_debug("No output buffer address for the command.....\n");
		return;
	}

	print_debug("DEV_P_ADDR:%0llx   HOST_V_ADDR:%p\n",
		    c_dev->mem[MEM_TYPE_DRIVER].dev_p_addr,
		    c_dev->mem[MEM_TYPE_DRIVER].host_v_addr);

	op_buf_addr =
	    (dev_dma_addr_t) (op_buf_addr -
			      c_dev->mem[MEM_TYPE_DRIVER].dev_p_addr);
	print_debug("Offset in device domain            :%0llx\n", op_buf_addr);

	op_buf_addr = (op_buf_addr - c_dev->mem[MEM_TYPE_DRIVER].host_p_addr);
	print_debug("Offset in host domain              :%0llx\n", op_buf_addr);

	op_mem =
	    (cmd_op_t *) (c_dev->mem[MEM_TYPE_DRIVER].host_v_addr +
			  (unsigned long)op_buf_addr);
	print_debug("Buffer virtual address               :%p\n", op_mem);

	op_mem =
	    (cmd_op_t *) ((unsigned long)op_mem - sizeof(cmd_trace_ctx_t *));
	print_debug("response for command type          :%d\n",
		    op_mem->cmd_ctx->cmd_type);

	print_debug
	    ("JOB COMPLETED, op_mem: %p, cmd_ctx :%p, cmd_compltn: %p\n",
	     op_mem, op_mem->cmd_ctx, &(op_mem->cmd_ctx->cmd_completion));
	if (op_mem->cmd_ctx) {
		op_mem->cmd_ctx->result = result;
		complete(&(op_mem->cmd_ctx->cmd_completion));
	}
}

/*******************************************************************************
* Function     : set_device
*
* Arguments    : fname
*				 device - device no
*				 size	- length device
*				 flag
*
* Return Value : -
*
* Description  : callback for fw trigger sysfs entry of fw_trigger
*				 it sets the device again
*				 which was reset previously
*
*******************************************************************************/
void set_device(int8_t *fname, int8_t *device, int32_t size, char flag)
{
	int32_t cpu = 0;
	per_dev_struct_t *dev_stat = NULL;
	fsl_pci_dev_t *fsl_pci_dev = NULL;
	fsl_crypto_dev_t *c_dev = NULL;
	crypto_dev_config_t *config = NULL;
	unsigned long dev_no;

	print_debug("INSIDE DEVICE SET FUNCTION\n");
	if (kstrtol(device, 0, &dev_no)) {
		print_error("INVALID DEVICE VALUE\n");
		return;
	}

	print_debug("GOT THE VALUE : %lu\n", dev_no);
	print_debug("GOING FOR DEVICE SET\n");

	/* GET THE DEVICE */
	c_dev = get_crypto_dev(dev_no);
	if (NULL == c_dev) {
		print_error("DEVICE NOT FOUND\n");
		return;
	}

	/* CHECK DEVICE HAS BEEN RESET */
	cpu = get_cpu();
	dev_stat = per_cpu_ptr(c_dev->dev_status, cpu);
	put_cpu();
	if (atomic_read(&(dev_stat->device_status))) {
		print_error("DEVICE IS ALIVE\n");
		return;
	}

	/* CLEAN DEVICE */
	fsl_pci_dev = (fsl_pci_dev_t *) c_dev->priv_dev;
	cleanup_crypto_device(c_dev);

	/* PUT DEVICE IN SET MODE */
#define PIC_PIR 0x041090
	FSL_DEVICE_WRITE32_BAR0_REG(fsl_pci_dev->bars[PCI_BAR_NUM_0].v_addr,
				    PIC_PIR, 0x0);

	/* GET THE OLD DEVICE CONFIG */
	config = get_dev_config(fsl_pci_dev);
	fsl_pci_dev->crypto_dev =
	    fsl_crypto_layer_add_device(fsl_pci_dev, config);
	if (unlikely(NULL == fsl_pci_dev->crypto_dev)) {
		print_error("ADDING DEVICE FAILED\n");
		return;
	}
}

/*******************************************************************************
 * Function     : rehandshake
 *
 * Arguments    : crypto_config_t usr_config  - usr configuration
 *
 * Return Value : int32_t
 *
 * Description  : performs the handshake with giver configuration
 *
 ******************************************************************************/
int32_t rehandshake(int8_t *config_file, fsl_crypto_dev_t *dev)
{
	crypto_dev_config_t *curr_config =
	    get_dev_config(dev->priv_dev);
	fsl_crypto_dev_t *crypto_dev = NULL; 
	crypto_dev_config_t *new_config = NULL;

	uint32_t i = 0;
	int32_t new_dev_no = 1;
	int32_t tot_dev_count = 0;

	print_debug("\n --- REHANDSHAKE ---\n");

	if (NULL == curr_config) {
		print_error("Could not get the config for device.....\n");
		return -1;
	}
    
    crypto_dev = get_crypto_dev(curr_config->dev_no);

	/* SEARCH FOR MAX DEVICES */
	for (; new_dev_no <= dev_count; ++new_dev_no) {
		if (NULL == get_config(new_dev_no))
			break;
	}

	/* PARSE THE CONFIGURATION FILE & ADD TO CONFIG LIST */
	if (-1 == parse_config_file(config_file)) {
		print_error("FILE PARSING FAILED ... TAKING PREVIOUS CONFIGURATION\n");
		goto dconfig;
	}

	/* GET THE NEW PARSE CONFIG FILE */
	new_config = get_config(new_dev_no);
	if (NULL == new_config) {
		print_error
		    ("COULD NOT FIND THE NEW CONFIGURATION ... EXITING\n");
		return -1;
	}

	/* Get the config node for the device and edit it */
	print_debug("\n User given configuration\n");
	curr_config->num_of_rings = new_config->num_of_rings;

	for (i = 0; i < curr_config->num_of_rings; ++i) {
		curr_config->ring[i].ring_id = i;
		curr_config->ring[i].depth = new_config->ring[i].depth;
		curr_config->ring[i].flags = new_config->ring[i].flags;
	}

	/* DELETE THE NEW CONFIGURATION(s) */
	tot_dev_count = dev_count;
	for (i = new_dev_no; i <= tot_dev_count; ++i) {
		new_config = get_config(i);
		list_del(&(new_config->list));
		dev_count--;
	}

dconfig:
	for (i = 0; i < crypto_dev->num_of_rings; i++) {
		/*crypto_dev->ring_pairs[i].req_job_count = 0; */
		/* Deregister the pool */
		atomic_set(&(crypto_dev->ring_pairs[i].sec_eng_sel), 0);

		/* Delete all the links */
		list_del(&(crypto_dev->ring_pairs[i].ring_pair_list_node));
		list_del(&(crypto_dev->ring_pairs[i].isr_ctx_list_node));
		list_del(&(crypto_dev->ring_pairs[i].bh_ctx_list_node));
	}

	/* FREE THE CURRENT RINGS */
	kfree(crypto_dev->ring_pairs);
	/* REALLOCATE OB MEMORY */
	pci_free_consistent(((fsl_pci_dev_t *) crypto_dev->priv_dev)->dev,
			    crypto_dev->mem[MEM_TYPE_DRIVER].len,
			    crypto_dev->mem[MEM_TYPE_DRIVER].host_v_addr,
			    crypto_dev->mem[MEM_TYPE_DRIVER].host_dma_addr);

	atomic_set(&(crypto_dev->crypto_dev_sess_cnt), 0);

	/* ALLOCATE MEMORY FOR RINGS */
	crypto_dev->ring_pairs =
	    kzalloc(sizeof(fsl_h_rsrc_ring_pair_t) * curr_config->num_of_rings,
		    GFP_KERNEL);

    if( NULL == crypto_dev->ring_pairs )
    {
        print_error("\t Mem alloc failed for ring pares....\n");
        return -1;
    }
	/* atomic_set(&(crypto_dev->crypto_dev_sess_cnt), 0);   */

	/* Rearrange rings acc to their priority */
	rearrange_rings(crypto_dev, curr_config);

	/* Alloc ob mem */
	if (unlikely(alloc_ob_mem(crypto_dev, curr_config))) {
		print_error("\t Ob mem alloc failed....\n");
		kfree(crypto_dev->ring_pairs);
		return -1;
	}

	init_ip_pool(crypto_dev);
	init_op_pool(crypto_dev);
	init_crypto_ctx_pool(crypto_dev);

	/* Initialise fw resp ring info */
	init_fw_resp_ring(crypto_dev);

	/* Init rp struct */
	init_rps(crypto_dev);

	/* Distribute rings to cores and BHs */
	distribute_rings(crypto_dev, curr_config);

	/* Initialise hs mem */
	init_handshake(crypto_dev);

	/* atomic_set(&(crypto_dev->active_jobs), 0);   */

	/* SEND READY FLAG FOR REHANDSHAKE TO DEVICE */
#define READY 212
	dev->c_hs_mem->state = READY;

	/* Do the handshake */
	return handshake(crypto_dev, curr_config);

}

/*******************************************************************************
* Function     : validate_cmd_args
*
* Arguments    : config - device configuration , cmd - usr command type
*
* Return Value : int32_t
*
* Description  : validates the arguments before sending it to firmaware
*
*******************************************************************************/
int32_t validate_cmd_args(fsl_crypto_dev_t *c_dev, user_command_args_t *cmd)
{
	crypto_dev_config_t *config = NULL;

	switch (cmd->cmd_type) {
	case RINGSTAT:
		config = get_dev_config(c_dev->priv_dev);

		if (!config || (config->num_of_rings < (cmd->rsrc.ring_id + 1)))
			return -1;
		break;
	case RESETSEC:
#ifdef C293_EP
		if (2 < cmd->rsrc.sec_id)
			return -1;
#else
		if (0 < cmd->rsrc.sec_id)
			return -1;
#endif
		break;
	case REHANDSHAKE:
		{
			struct file *file = NULL;
			mm_segment_t old_fs;
			char *config_file = cmd->rsrc.config;
			old_fs = get_fs();
			if (unlikely(NULL == config_file)) {
				print_error("Empty configuration file. Configuring default\n");
				return -1;
			}

			set_fs(KERNEL_DS);
			file = filp_open(config_file, O_RDWR, 0);

			if (IS_ERR(file)) {
				print_error("No file at path [%s]\n", config_file);
				set_fs(old_fs);
				return -1;
			}
			filp_close(file, 0);
		}
		break;
	case DEBUG:
	case DEVSTAT:
	case PINGDEV:
	case RESETDEV:
	case SECSTAT:
	case BLOCK_APP_JOBS:
	default:
		break;
	}
	return 0;

}

void wait_active_jobs_to_finish(fsl_crypto_dev_t *c_dev)
{
	uint32_t count = 0;
	while (atomic_read(&(c_dev->active_jobs))) {
		if (++count > 1000000)
			print_error("WAITING ACTIVE JOBS TO FINISH : %d\n",
				    atomic_read(&(c_dev->active_jobs)));
	}
	return;
}

/*******************************************************************************
* Function     : process_cmd_req
*
* Arguments    : c_dev - device structure , usr_cmd_desc - usr cmd descriptor
*
* Return Value : int32_t
*
* Description  : processes the commands for device
*
*******************************************************************************/
int32_t process_cmd_req(fsl_crypto_dev_t *c_dev,
			user_command_args_t *usr_cmd_desc)
{
	int32_t result = 0;
	int32_t cpu = 0;
/*    crypto_config_t     rehandshake_config = { };	*/

	per_dev_struct_t *dev_stat = NULL;

	print_debug("cmd ring processing\n");

	cpu = get_cpu();

	dev_stat = per_cpu_ptr(c_dev->dev_status, cpu);
	if (NULL == dev_stat) {
		print_error("per_cpu_ptr failed process_cmd_req\n");
		return -1;
	}
	if (0 == atomic_read(&(dev_stat->device_status))) {
		print_error("DEVICE IS DEAD CPU %d\n", cpu);
		result = -1;
        if( copy_to_user((void __user *)usr_cmd_desc->result, &(result),
                    sizeof(result)))
        {
            print_error("Copy to user failed ....\n");
            return -1;
        }
		return 0;
	}
	print_debug("After check device status is ALIVE\n");

	if (-1 == validate_cmd_args(c_dev, usr_cmd_desc)) {
		print_debug("Command validation failed...\n");
		return -1;
	}

	switch (usr_cmd_desc->cmd_type) {
	case DEVSTAT:
	case SECSTAT:
	case RINGSTAT:
	case PINGDEV:
		result =
		    send_command_to_fw(c_dev, usr_cmd_desc->cmd_type,
				       usr_cmd_desc);
		if (result == -1)
			print_error("Sending command failed....\n");
		break;

	case RESETDEV:
	case RESETSEC:

		set_device_status_per_cpu(c_dev, 0);
		wait_active_jobs_to_finish(c_dev);
		/* Flush the rings properly */
		flush_app_jobs(c_dev);

		result =
		    send_command_to_fw(c_dev, usr_cmd_desc->cmd_type,
				       usr_cmd_desc);
		if (result == -1) {
			print_error("Sending command failed....\n");
			goto out;
		}

		if (RESETDEV != usr_cmd_desc->cmd_type) {
			print_debug("Unblocking app rings..........\n");
			/* Unblock the app rings */
			unblock_app_rings(c_dev);
			set_device_status_per_cpu(c_dev, 1);
		}
#if 0
		else {
			print_debug("SETTING DEVICE IN DEAD STATE\n");
			atomic_set(&(c_dev->device_staus), 0);
		}
#endif
		break;
	case REHANDSHAKE:
		set_device_status_per_cpu(c_dev, 0);
		wait_active_jobs_to_finish(c_dev);
		flush_app_jobs(c_dev);

		result =
		    send_command_to_fw(c_dev, usr_cmd_desc->cmd_type,
				       usr_cmd_desc);
		if (result == -1) {
			print_error("Sending command failed....\n");
			goto out;
		}

		if (-1 == rehandshake(usr_cmd_desc->rsrc.config, c_dev)) {
			result = -1;
			goto out;
		}

		print_debug("Unblocking app rings..........\n");
		/* Unblock the app rings */
		unblock_app_rings(c_dev);
		set_device_status_per_cpu(c_dev, 1);
		break;

	case DEBUG:
		print_debug(" DEBUGGGING ...\n");
		print_debug(" GOT DEBUG COMMAND :%d\n",
			    usr_cmd_desc->rsrc.dgb.cmd_id);
		print_debug(" GOT ADDRESS : %u\n",
			    usr_cmd_desc->rsrc.dgb.address);
		print_debug(" GOT VALUE   : %u\n", usr_cmd_desc->rsrc.dgb.val);
		result =
		    send_command_to_fw(c_dev, usr_cmd_desc->cmd_type,
				       usr_cmd_desc);
		if (result == -1) {
			print_error("Sending command failed....\n");
			goto out;
		}

		break;

	default:
		print_error("Invalid command........\n");
		result = -1;
		break;
	}
out:
	if (copy_to_user
	    ((void __user *)usr_cmd_desc->result, &(result), sizeof(result))) {
		print_error("Copy to user failed ....\n");
		return -1; 
	}

	return 0;
}

static int32_t wait_for_cmd_response(cmd_op_t *cmd_op)
{
	int32_t ret = -1;
	int32_t wait_counter = 60;

	if (NULL != cmd_op) {
		print_debug("Waiting for command completion.....\n");

		while (wait_counter-- > 0) {
			set_current_state(TASK_INTERRUPTIBLE);
			schedule_timeout(msecs_to_jiffies(1000));

			if (1 ==
			    try_wait_for_completion(&
						    (cmd_op->cmd_ctx->
						     cmd_completion))) {
				ret = cmd_op->cmd_ctx->result;
				break;
			}
		}
		print_debug("Result from fw     :%d\n", ret);
	}

	return ret;
}

static cmd_op_t *get_cmd_op_ctx(fsl_crypto_dev_t *c_dev,
				cmd_ring_entry_desc_t *pci_cmd_desc)
{
	cmd_op_t *cmd_op = NULL;
	dev_dma_addr_t op_dev_addr = 0;

	print_debug("c_dev->op_pool.pool : %p, %p\n", c_dev->op_pool.pool,
		    c_dev->op_pool.pool);
	cmd_op =
	    (cmd_op_t *) cmd_get_op_buffer(c_dev->op_pool.pool,
					   sizeof(cmd_op_t), 0);
	if (NULL == cmd_op) {
		print_error("Op buffer alloc failed !!!!\n");
		goto error;
	}

	print_debug("get_cmd_op_ctx: cmd_op adr : %p, %p\n", cmd_op,
		    cmd_op);
	cmd_op->cmd_ctx = kzalloc(sizeof(cmd_trace_ctx_t), GFP_KERNEL);
	if (NULL == cmd_op->cmd_ctx) {
		print_error("Ctx buffer alloc failed !!!!\n");
		goto error;
	}
	print_debug("CMD CTX:%p\n", cmd_op->cmd_ctx);

	init_completion(&(cmd_op->cmd_ctx->cmd_completion));

	print_debug("host_p_addr: %0llx, %0llx\n",
		    c_dev->mem[MEM_TYPE_DRIVER].host_p_addr,
		    c_dev->mem[MEM_TYPE_DRIVER].host_p_addr);
	print_debug("host_v_addr: %p, %p\n",
		    c_dev->mem[MEM_TYPE_DRIVER].host_v_addr,
		    c_dev->mem[MEM_TYPE_DRIVER].host_v_addr);
	print_debug("get_cmd_op_ctx: cmd_op adr : %p, %p\n", cmd_op,
		    cmd_op);
	print_debug("cmd_trace_ctx_t size : %lu\n", sizeof(cmd_trace_ctx_t *));

	op_dev_addr = (dev_dma_addr_t)
	    (c_dev->mem[MEM_TYPE_DRIVER].host_p_addr) +
	    (((unsigned long)cmd_op + sizeof(cmd_trace_ctx_t *)) -
	     ((unsigned long)c_dev->mem[MEM_TYPE_DRIVER].host_v_addr));

	op_dev_addr =
	    (dev_dma_addr_t) (c_dev->mem[MEM_TYPE_DRIVER].dev_p_addr +
			      op_dev_addr);

	ASSIGN64(pci_cmd_desc->cmd_op, op_dev_addr);

	return cmd_op;
error:
	if (NULL != cmd_op) {
		if (NULL != cmd_op->cmd_ctx)
			kfree(cmd_op->cmd_ctx);

		put_buffer(c_dev, c_dev->op_pool.pool, cmd_op);
	}

	return NULL;
}

int32_t send_command_to_fw(fsl_crypto_dev_t *c_dev, commands_t command,
			   user_command_args_t *usr_cmd)
{
	cmd_ring_entry_desc_t *pci_cmd_desc = NULL;
	cmd_op_t *cmd_op = NULL;
	void *user_op_buff = NULL;

	dev_dma_addr_t desc_dev_addr = 0;

	int32_t ret = 0;
	print_debug("Sending command  :%d to firmware\n", command);

	pci_cmd_desc =
	    (cmd_ring_entry_desc_t *) get_buffer(c_dev,
						 c_dev->ring_pairs[0].ip_pool,
						 sizeof(cmd_ring_entry_desc_t),
						 0);
	if (NULL == pci_cmd_desc) {
		print_error("Cmd desc alloc failed !!!!\n");
		ret = -1;
		goto exit;
	}

	ASSIGN64(pci_cmd_desc->cmd_op, (uint64_t) 0X0);

	cmd_op = get_cmd_op_ctx(c_dev, pci_cmd_desc);
	if (NULL == cmd_op) {
		print_error("Op alloc failed !!!\n");
		ret = -1;
		goto exit;
	}
	cmd_op->cmd_ctx->cmd_type = command;
	ASSIGN32(pci_cmd_desc->cmd_type, command);

	if (NULL != usr_cmd) {
		if (SECSTAT == usr_cmd->cmd_type) {
			ASSIGN32(pci_cmd_desc->ip_info.sec_id,
				 usr_cmd->rsrc.sec_id);
			user_op_buff = usr_cmd->op_buffer;
		}
		if (DEBUG == usr_cmd->cmd_type) {
			ASSIGN32(pci_cmd_desc->ip_info.dgb.cmd_id,
				 usr_cmd->rsrc.dgb.cmd_id);
			ASSIGN32(pci_cmd_desc->ip_info.dgb.address,
				 usr_cmd->rsrc.dgb.address);
			ASSIGN32(pci_cmd_desc->ip_info.dgb.val,
				 usr_cmd->rsrc.dgb.val);
			user_op_buff = usr_cmd->op_buffer;
		}
		if (RESETSEC == usr_cmd->cmd_type)
			ASSIGN32(pci_cmd_desc->ip_info.sec_id,
				 usr_cmd->rsrc.sec_id);
		if (DEVSTAT == usr_cmd->cmd_type)
			user_op_buff = usr_cmd->op_buffer;
		if (RINGSTAT == usr_cmd->cmd_type) {
			ASSIGN32(pci_cmd_desc->ip_info.ring_id,
				 usr_cmd->rsrc.ring_id);
			user_op_buff = usr_cmd->op_buffer;
		}
		if (PINGDEV == usr_cmd->cmd_type) {
			ASSIGN32(pci_cmd_desc->ip_info.count, 555);
			user_op_buff = usr_cmd->op_buffer;
		}
	}

	print_debug("pci_cmd_desc :  %0lx, %0lx\n", (unsigned long)pci_cmd_desc,
		    (unsigned long)pci_cmd_desc);
	print_debug("host_v_addr :  %lx, %lx\n",
		    (unsigned long)c_dev->mem[MEM_TYPE_SRAM].host_v_addr,
		    (unsigned long)c_dev->mem[MEM_TYPE_SRAM].host_v_addr);

	desc_dev_addr =
	    (dev_dma_addr_t) ((unsigned long)pci_cmd_desc -
			      (unsigned long)c_dev->mem[MEM_TYPE_SRAM].
			      host_v_addr);

	print_debug("desc_dev_addr : %0llx, %0llx\n", desc_dev_addr,
		    desc_dev_addr);
	print_debug("dev_p_addr : %0llx, %0llx\n",
		    c_dev->mem[MEM_TYPE_SRAM].dev_p_addr,
		    c_dev->mem[MEM_TYPE_SRAM].dev_p_addr);

	desc_dev_addr =
	    (dev_dma_addr_t) (c_dev->mem[MEM_TYPE_SRAM].dev_p_addr +
			      desc_dev_addr);

	print_debug("Enqueueing CMD DESC ADDR   :%0llx\n", desc_dev_addr);

	if (-1 == cmd_ring_enqueue(c_dev, 0, desc_dev_addr)) {
		print_error("Command ring enqueue failed.....\n");
		ret = -1;
		goto exit;
	} else
		print_debug("Command ring enqueue succeed.....\n");

	if (RESETDEV == command) {
		/* No need to do anything if device has been reset */
		set_sysfs_value(c_dev->priv_dev, FIRMWARE_STATE_SYSFILE,
				(uint8_t *) "NO FIRMWARE\n",
				strlen("NO FIRMWARE\n"));

		set_sysfs_value(c_dev->priv_dev, DEVICE_STATE_SYSFILE,
				(uint8_t *) "READY FOR HS\n",
				strlen("READY FOR HS\n"));

		return 0;
	}

	print_debug
	    ("Going to wait for response for command.. %d, cmd_op : %p\n",
	     command, cmd_op);
	if (-1 == wait_for_cmd_response(cmd_op)) {
		print_debug
		    ("Wait finished but no response from firmware.....\n");
		ret = -1;
		goto exit;
	}

	if (NULL != user_op_buff) {
		if (copy_to_user
		    ((void __user *)user_op_buff, &(cmd_op->buffer),
		     sizeof(op_buffer_t))) {
			print_error("Error while copying to userspace......\n");
			ret = -1;
		}
	}

exit:

	if (NULL != pci_cmd_desc)
		put_buffer(c_dev, c_dev->ring_pairs[0].ip_pool, pci_cmd_desc);

	if (NULL != cmd_op) {
		kfree(cmd_op->cmd_ctx);
		cmd_put_op_buffer(c_dev->op_pool.pool, cmd_op);
	}

	return ret;
}

static void block_app_rings(fsl_crypto_dev_t *dev)
{
	int32_t i = 0;

	for (i = 1; i < dev->num_of_rings; i++) {
		/* Set blocking variable for all the rings */
		atomic_set(&(dev->ring_pairs[i].block), 1);
	}
}

static void unblock_app_rings(fsl_crypto_dev_t *dev)
{
	int32_t i = 0;

	for (i = 1; i < dev->num_of_rings; i++) {
		/* Set blocking variable for all the rings */
		atomic_set(&(dev->ring_pairs[i].block), 0);
	}
}

static void flush_app_resp_rings(fsl_crypto_dev_t *dev)
{
	int32_t i = 0;

	for (i = 1; i < dev->num_of_rings; ++i) {
		dev->ring_pairs[i].counters->jobs_processed = 0;
		dev->ring_pairs[i].s_c_counters->jobs_added = 0;
		dev->ring_pairs[i].indexes->r_index = 0;
	}
	for (i = 0; i < NUM_OF_RESP_RINGS; i++) {
		dev->fw_resp_rings[i].cntrs->jobs_processed = 0;
		dev->fw_resp_rings[i].s_c_cntrs->jobs_added = 0;
		dev->fw_resp_rings[i].idxs->r_index = 0;
		print_debug
		    ("dev->fw_resp_ring.cntrs->jobs_processed : %d\n",
		     dev->fw_resp_rings[i].cntrs->jobs_processed);
	}
}

static void flush_app_req_rings(fsl_crypto_dev_t *c_dev)
{
	int32_t i = 0;

	atomic_set(&(c_dev->crypto_dev_sess_cnt), 0);
	for (i = 1; i < c_dev->num_of_rings; ++i) {
		atomic_set(&(c_dev->ring_pairs[i].sec_eng_sel), 0);

		c_dev->ring_pairs[i].indexes->w_index = 0;

		c_dev->ring_pairs[i].counters->jobs_added = 0;
		c_dev->ring_pairs[i].s_c_counters->jobs_processed = 0;
	}
}

static int32_t flush_app_jobs(fsl_crypto_dev_t *dev)
{
	/* Block the ongoing flow of jobs */
	int32_t i = 0;
	int32_t j = 0;
	uint32_t jobs_added = 0;

	print_debug("# # # # # Flushing app jobs # # # # #\n");

	block_app_rings(dev);

	print_debug("App ring blocked\n");
	/* Give some time for the jobs to get stopped */
	set_current_state(TASK_INTERRUPTIBLE);
	schedule_timeout(msecs_to_jiffies(1000));

	print_debug("Sending STOP_PROCESSING_APP_JOBS command to firmware\n");

	/* print_debug("Resetting the pool ..........\n"); */

	/*reset_pool(dev->common_ip_pool); */

	/* Now send the command to firmware to stop processing
	 * any more app commands */
	if (-1 == send_command_to_fw(dev, BLOCK_APP_JOBS, NULL)) {
		print_debug("Sending STOP_PROCESSING_APP_JOBS Failed\n");
		return -1;
	}

	/* Wait if there are pending resps to be handled */
	while (j < 5) {
		for (i = 1; i < dev->num_of_rings; i++) {
#ifdef HOST_TYPE_P4080
			jobs_added =
			    dev->ring_pairs[i].s_c_counters->jobs_added;
#else
			ASSIGN32(jobs_added,
				 dev->ring_pairs[i].s_c_counters->jobs_added);
#endif
			while (0 != (jobs_added -
				     dev->ring_pairs[i].
				     counters->jobs_processed)) {
				print_debug
				    ("%d, jobs pending resps on ring :%d\n",
				     (jobs_added -
				      dev->ring_pairs[i].
				      counters->jobs_processed), i);

				/* Give some time for the jobs to get stopped */
				set_current_state(TASK_INTERRUPTIBLE);
				schedule_timeout(msecs_to_jiffies(1000));
			}
		}

		set_current_state(TASK_INTERRUPTIBLE);
		schedule_timeout(msecs_to_jiffies(1000));

		j++;
	}

	print_debug("# # # # # Flushing app resp rings # # # # #\n");
	/* Flush the resp ring */
	flush_app_resp_rings(dev);

	/* For all the pending requests unhandled by fw return -1 to cbs */
	/*invalidate_pending_reqs(c_dev); */

	print_debug("# # # # # Flushing app req rings # # # # #\n");
	/* Flush the req ring */
	flush_app_req_rings(dev);

	return 0;
}
