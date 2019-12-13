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

#ifndef __COMMAND_H
#define __COMMAND_H

/* OUTPUT STRUCTURES FOR STAT */
/* DEVICES STAT */
typedef enum commands {
	DEBUG,
	DEVSTAT,
	REHANDSHAKE,
	PINGDEV,
	RESETDEV,
	RESETSEC,
	RINGSTAT,
	SECSTAT,
	BLOCK_APP_JOBS,
	UNBLOCK_APP_JOBS,
} commands_t;

typedef enum debug_commands {
	MD,
	MW,
	PRINT1_DEBUG,
	PRINT1_ERROR,
} dgb_cmd_type_t;

#if 0
typedef struct crypto_config {
	int32_t dev_no;
	int32_t no_of_rings;
	struct usr_ring_info {
		int32_t depth;
		int32_t affinity;
		int32_t priority;
		int32_t order;
	} ring[FSL_CRYPTO_MAX_RING_PAIRS];

} crypto_config_t;
#endif

#define MAX_SEC_NO 3
/* SEC STAT */
typedef struct fsl_sec_stat {
	uint32_t sec_ver;
	uint32_t cha_ver;
	uint32_t no_of_sec_engines;
	uint32_t no_of_sec_jr;
	uint32_t jr_size;
	struct sec_ctrs_t {
		uint32_t sec_tot_req_jobs;
		uint32_t sec_tot_resp_jobs;
	} sec[MAX_SEC_NO];
} fsl_sec_stat_t;

typedef struct fsl_dev_stat_op {
	uint32_t fwvversion;
	uint32_t totalmem;
	uint32_t codemem;
	uint32_t heapmem;
	uint32_t freemem;
	uint32_t num_of_sec_engine;
	uint32_t no_of_app_rings;
	uint32_t total_jobs_rx;
	uint32_t total_jobs_pending;
} fsl_dev_stat_op_t;

/* RESOURCE STAT */
struct fsl_ring_stat_op {
	uint32_t depth;
	uint32_t tot_size;
	uint32_t priority;	/* PRIORITY OF RING  */
	uint32_t affinity;	/* AFFINITY OF RING  */
	uint32_t order;		/* ORDER OF RING    */
	uint32_t free_count;	/* DEPTH - CURRENT JOBS */
	uint32_t jobs_processed;
	uint32_t jobs_pending;
	uint32_t budget;
} __packed;

typedef struct fsl_ring_stat_op fsl_ring_stat_op_t;

/* DEBUG */
typedef struct debug_op {
	uint32_t total_ticks;
	uint32_t pcie_data_consume_ticks;	/*WRITE HOST TO CARD+CARD TO HOST */
	uint32_t job_wait_ticks;	/* WAIT TIME IN JOB QUEUE */
	uint32_t job_process_ticks;	/* PROCESS TIME */
	uint32_t sec_job_ticks;	/* TICKS FOR SEC TO COMPLETE JOB */
} debug_op_t;

typedef struct ping_op {
	int32_t resp;
} ping_op_t;

typedef union op_buffer {
	ping_op_t ping_op;
	/* debug_op_t          debug_op; */
	uint32_t debug_op[64];
	fsl_ring_stat_op_t ring_stat_op;
	fsl_dev_stat_op_t dev_stat_op;
	fsl_sec_stat_t sec_op;
} op_buffer_t;

typedef struct debug_ip {
	dgb_cmd_type_t cmd_id;
	uint32_t address;
	uint32_t val;
} debug_ip_t;

/*******************************************************************************
Description : Identifies the user command arguments
Fields      :   cmd_type      : type of command
		rsrc          : resource on which command will operate
		result        : result fail/success
		op_buffer     : output buffer
*******************************************************************************/
typedef struct user_command_args {
	commands_t cmd_type;
	uint32_t dev_id;

	union rsrc_t {
		int sec_id;
		int ring_id;
		debug_ip_t dgb;
		char config[200];
	} rsrc;

	int32_t *result;
	op_buffer_t *op_buffer;
} user_command_args_t;

/*******************************************************************************
Description :   command context
Fields      :   cmd_type          : type of command
		cmd_completion    : command completion variable
*******************************************************************************/
typedef struct cmd_trace_ctx {
	commands_t cmd_type;
	int32_t result;
	struct completion cmd_completion;
} cmd_trace_ctx_t;

/*******************************************************************************
Description	:	output from the device in repsonse of command
Fields		:	cmd_ctx	: context of command
			buffer	: output buffer
*******************************************************************************/
typedef struct cmd_op {
	cmd_trace_ctx_t *cmd_ctx;
	op_buffer_t buffer;
} cmd_op_t;

/*******************************************************************************
Description:	prepares the command descriptor for command ring
Fields:		cmd_type:	type of command
		ip_info:	input to the command
		cmd_op:		output buffer
*******************************************************************************/
struct cmd_ring_entry_desc {
	commands_t cmd_type;
	union __ip_info {
		uint32_t ring_id;	/* RING ID */
		uint32_t sec_id;	/* SEC ENGINE ID */
		uint32_t count;	/* COUNT VAR TO CKECK LIVELENESS */
		debug_ip_t dgb;
	} ip_info;
	dev_dma_addr_t cmd_op;	/*OP OF THE COMMAND POINTING TO cmd_op_t */
} __packed;

typedef struct cmd_ring_entry_desc cmd_ring_entry_desc_t;

#define PENDING     0xfafa
#define COMPLETE    0xfbfb
int32_t process_cmd_req(fsl_crypto_dev_t *c_dev,
			user_command_args_t *usr_cmd_desc);
int32_t send_command_to_fw(fsl_crypto_dev_t *c_dev, commands_t command,
			   user_command_args_t *);
void process_cmd_response(fsl_crypto_dev_t *c_dev, dev_dma_addr_t desc,
			  int32_t result);
int32_t validate_cmd_args(fsl_crypto_dev_t *, user_command_args_t *);
extern uint32_t dev_count;
#endif
