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

#define VAR

#include "common.h"
#include "device.h"
#include "fsl_c2x0_driver.h"
#include "fsl_c2x0_crypto_layer.h"
#include "sysfs.h"
#include "command.h"
#include "ioctl.h"
#ifdef VIRTIO_C2X0
#include "crypto_ctx.h"
#include "fsl_c2x0_virtio.h"
#endif
#include "algs.h"

/* #ifdef KCAPI_INTEG_BUILD */
#include "algs_reg.h"
/* #endif */

#include "test.h"
#include "dma.h"

static void create_default_config(crypto_dev_config_t *, int32_t, int32_t);
/*********************************************************
 *                  MACRO DEFINITIONS                    *
 *********************************************************/
#define DEV_PRINT_DEBUG(...) dev_print_dbg(fsl_pci_dev, ##__VA_ARGS__)
#define DEV_PRINT_ERROR(...) dev_print_err(fsl_pci_dev, ##__VA_ARGS__)

/*********************************************************
 *         INTERNAL FUNCTION PROTOTYPES                  *
 *********************************************************/
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 19))
static void response_ring_handler(struct work_struct *work);
#else
static void response_ring_handler(void *data);
#endif

static long fsl_cryptodev_ioctl(struct file *filp, unsigned int cmd,
				unsigned long arg);
static irqreturn_t fsl_crypto_isr(int irq, void *dev);

static int32_t fsl_crypto_pci_probe(struct pci_dev *dev,
				    const struct pci_device_id *id);
static void fsl_crypto_pci_remove(struct pci_dev *dev);

/*********************************************************
 *        GLOBAL VARIABLES                               *
 *********************************************************/
static char *dev_config_file = "/etc/skmm/skmm_crypto.cfg";
int napi_poll_count = -1;

static uint8_t pci_driver_registered;

#ifdef VIRTIO_C2X0
struct list_head virtio_c2x0_cmd_list;
struct list_head virtio_c2x0_hash_sess_list;
struct list_head virtio_c2x0_symm_sess_list;
spinlock_t cmd_list_lock;
spinlock_t hash_sess_list_lock;
spinlock_t symm_sess_list_lock;

uint64_t virtio_enq_cnt;
uint64_t virtio_deq_cnt;
#endif

static uint32_t dev_no;
int32_t dma_channel_count = 1;
int32_t dma_channel_cpu_mask[NR_CPUS];
int32_t cpu_mask_count;

/* Module Load time parameter */
/* This parameter specifies the file system path of the configuration file .*/
module_param(dev_config_file, charp, S_IRUGO);
MODULE_PARM_DESC(dev_config_file, "Configuration file for the device");

module_param(napi_poll_count, int, S_IRUGO);
MODULE_PARM_DESC(napi_poll_count, "Poll count for NAPI thread");

module_param(wt_cpu_mask, int, S_IRUGO);
MODULE_PARM_DESC(wt_cpu_mask, "CPU mask for napi worker threads");

module_param(dma_channel_count, int, S_IRUGO);
MODULE_PARM_DESC(dma_channel_count, "No of dma chnls to use");

module_param_array(dma_channel_cpu_mask, int, &cpu_mask_count, 0000);
MODULE_PARM_DESC(dma_channel_cpu_mask, "CPU mask for dma chnl alloc");

static struct pci_device_id fsl_crypto_pci_dev_ids[] = {
#ifdef P4080_EP 
	{PCI_DEVICE(FSL_CRYPTO_PCI_VENDOR_ID, FSL_CRYPTO_PCI_DEVICE_ID)},
#elif C293_EP
	{PCI_DEVICE(FSL_CRYPTO_PCI_VENDOR_ID, FSL_CRYPTO_C290_PCI_DEVICE_ID)},
	{PCI_DEVICE(FSL_CRYPTO_PCI_VENDOR_ID, FSL_CRYPTO_C280_PCI_DEVICE_ID)},
	{PCI_DEVICE(FSL_CRYPTO_PCI_VENDOR_ID, FSL_CRYPTO_C270_PCI_DEVICE_ID)},
	{PCI_DEVICE(FSL_CRYPTO_PCI_VENDOR_ID, FSL_CRYPTO_C291_PCI_DEVICE_ID)},
	{PCI_DEVICE(FSL_CRYPTO_PCI_VENDOR_ID, FSL_CRYPTO_C281_PCI_DEVICE_ID)},
	{PCI_DEVICE(FSL_CRYPTO_PCI_VENDOR_ID, FSL_CRYPTO_C271_PCI_DEVICE_ID)},
	{PCI_DEVICE(FSL_CRYPTO_PCI_VENDOR_ID, FSL_CRYPTO_TBD1_PCI_DEVICE_ID)},
	{PCI_DEVICE(FSL_CRYPTO_PCI_VENDOR_ID, FSL_CRYPTO_TBD2_PCI_DEVICE_ID)},
	{PCI_DEVICE(FSL_CRYPTO_PCI_VENDOR_ID, FSL_CRYPTO_TBD3_PCI_DEVICE_ID)},
	{PCI_DEVICE(FSL_CRYPTO_PCI_VENDOR_ID, FSL_CRYPTO_TBD4_PCI_DEVICE_ID)},
	{PCI_DEVICE(FSL_CRYPTO_PCI_VENDOR_ID, FSL_CRYPTO_TBD5_PCI_DEVICE_ID)},
	{PCI_DEVICE(FSL_CRYPTO_PCI_VENDOR_ID, FSL_CRYPTO_TBD6_PCI_DEVICE_ID)},
#endif
	{0,},
};

fsl_pci_dev_t *g_fsl_pci_dev;

/*********************************************************
 *        FILE OPERATION STRUCTURE                       *
 *********************************************************/
static const struct file_operations fsl_cryptodev_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = fsl_cryptodev_ioctl,
};

static struct miscdevice fsl_cryptodev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "fsl_cryptodev",
	.fops = &fsl_cryptodev_fops,
	.mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH,
};

static struct pci_driver fsl_cypto_driver = {
	.name = "FSL-Crypto-Driver",
	.id_table = fsl_crypto_pci_dev_ids,
	.probe = fsl_crypto_pci_probe,
	.remove = fsl_crypto_pci_remove
};

/* Head of the PCI devices linked list */
LIST_HEAD(pci_dev_list);

/* Head of the list of configuration data structure instances */
LIST_HEAD(crypto_dev_config_list);

/* Head of the list of per core cpu data structures */
LIST_HEAD(per_core_list_head);

/* Head of all the sysfs entries */
void *fsl_sysfs_entries;
void *wt_loop_cnt_sysfs_file;

/* Pointer to the base of per cpu memory */
per_core_struct_t __percpu *per_core;

void sysfs_napi_loop_count_set(int8_t *fname, int8_t *count, int len,
			       char flag)
{
	uint32_t no = *((uint32_t *) (count));
	printk(KERN_ERR "Count to set... :%d\n", no);
	napi_poll_count = no;
}

/*******************************************************************************
 * Function     : fsl_cryptodev_register
 *
 * Arguments    : None
 *
 * Return Value : int32_t
 *
 * Description  : Registers the fsl_crypto device
 *
 ******************************************************************************/
static int32_t __init fsl_cryptodev_register(void)
{
	int rc;
	rc = misc_register(&fsl_cryptodev);
	if (0 != rc) {
		print_error("registration of /dev/fsl_crypto failed\n");
		return rc;
	}
	return 0;
}

/*******************************************************************************
 * Function     : fsl_cryptodev_deregister
 *
 * Arguments    : None
 *
 * Return Value : None
 *
 * Description  : Unregisters the fsl_crypto device
 *
 ******************************************************************************/
static void __exit fsl_cryptodev_deregister(void)
{
	misc_deregister(&fsl_cryptodev);
}

uint32_t get_no_of_devices(void)
{
	return dev_no;
}

/*******************************************************************************
 * Function     : get_crypto_dev
 *
 * Arguments    : no : Device number
 *
 * Return Value : fsl_crypto_dev_t - Crypto dev instance
 *
 * Description  : Searches the device corresponding to the input argument number
 *                and returns the corresponding crypto dev instance.
 *
 ******************************************************************************/
fsl_crypto_dev_t *get_crypto_dev(uint32_t no)
{
	fsl_pci_dev_t *dev_n_cursor = NULL;
	fsl_pci_dev_t *dev_cursor = NULL;

	list_for_each_entry_safe(dev_cursor,
		dev_n_cursor, &pci_dev_list, list) {
		print_debug("Input number [%d] Dev cursor dev no [%d]\n", no,
			    dev_cursor->dev_no);

		if (no == dev_cursor->dev_no) {

			print_debug("Found the device\n");
			return dev_cursor->crypto_dev;
		}
	}
	return NULL;
}

/*******************************************************************************
 * Function     : fsl_cryptodev_ioctl
 *
 * Arguments    :
 *
 * Return Value :
 *
 * Description  : ioctl command handler
 *
 ******************************************************************************/
static long fsl_cryptodev_ioctl(struct file *filp, unsigned int cmd,
				unsigned long arg)
{
	print_debug("fsl_cryptodev_ioctl\n");
	print_debug("COMMAND :%u\nCMDOPERATION:%lu\n", cmd, CMDOPERATION);
	switch (cmd) {
	case CMDOPERATION:
		{
#ifdef HIGH_PERF
			return EACCES;
#else
			fsl_crypto_dev_t *c_dev = NULL;
			user_command_args_t usr_cmd_desc = { };

			if (copy_from_user
			    ((void *)&usr_cmd_desc, (void *)arg,
			     sizeof(usr_cmd_desc))) {
				print_error("Copy from user failed....\n");
				return -1;
			}

			c_dev = get_crypto_dev(usr_cmd_desc.dev_id);
			if (NULL == c_dev) {
				print_debug
				    ("Invalid device number		:%d\n",
				     (usr_cmd_desc.dev_id));
				return -1;
			}
			return process_cmd_req(c_dev, &usr_cmd_desc);
#endif
		}
	case CHECKCMD:
		{
#ifdef HIGH_PERF
			return EACCES;
#else
			fsl_crypto_dev_t *c_dev = NULL;
			user_command_args_t usr_cmd_desc = { };
			if (copy_from_user
					((void *)&usr_cmd_desc, (void *)arg,
					sizeof(usr_cmd_desc))) {
				print_error("Copy from user failed....\n");
				return -1;
			}
			c_dev = get_crypto_dev(usr_cmd_desc.dev_id);
			if (NULL == c_dev) {
				print_debug
					("Invalid device number     :%d\n",
					(usr_cmd_desc.dev_id));
				return -1;
			}
			return validate_cmd_args(c_dev, &usr_cmd_desc); 
#endif
		}
#ifdef VIRTIO_C2X0
	case VIRTIOOPERATION:
		{
			struct virtio_c2x0_qemu_cmd *qemu_cmd = NULL;
			struct virtio_c2x0_job_ctx *virtio_job = NULL;
			int ret = 0;

			virtio_job = (struct virtio_c2x0_job_ctx *)
			    kzalloc(sizeof(struct virtio_c2x0_job_ctx),
				    GFP_KERNEL);
			if (!virtio_job) {
				print_error
				    ("Alloc failed for virtio_job: %p\n",
				     virtio_job);
				return -1;
			}

			qemu_cmd = &(virtio_job->qemu_cmd);

			print_debug
			    ("Allocation succeed %p,\
				 coping data from user space\n",
			     qemu_cmd);
			ret =
			    copy_from_user(qemu_cmd,
					   (struct virtio_c2x0_qemu_cmd *)arg,
					   sizeof(struct virtio_c2x0_qemu_cmd));
			if (ret != 0) {
				print_error("Copy from user failed\n");
				return -1;
			}

			ret = process_virtio_app_req(virtio_job);
			if (ret < 0) {
				print_error
				    ("Virtio Job,op[%d],cmd_index[%d],\
					 guest_id[%d] failed with ret %d\n",
				     qemu_cmd->op, qemu_cmd->cmd_index,
				     qemu_cmd->guest_id, ret);
				if (virtio_job->ctx)
					free_crypto_ctx(virtio_job->ctx->
							ctx_pool,
							virtio_job->ctx);
				kfree(virtio_job);
				return ret;
			}
			if (NONBLOCKING == qemu_cmd->block_type) {
				/*  Adding job to pending job list  */
				print_debug
			    ("Adding index %u to pending list\n",
				     qemu_cmd->cmd_index);
				spin_lock(&cmd_list_lock);
				list_add_tail(&virtio_job->list_entry,
					      &virtio_c2x0_cmd_list);
				spin_unlock(&cmd_list_lock);
			} else if (BLOCKING == qemu_cmd->block_type) {
				/*
				 * Blocking Command finished
				 * Free up virtio job
				 */
				if (virtio_job->ctx)
					free_crypto_ctx(virtio_job->ctx->
							ctx_pool,
							virtio_job->ctx);
				kfree(virtio_job);
			}

			print_debug
			("VIRTIOIOERATION returninig with ret %d\n",
			ret);

			return ret;
		}
		break;
	case VIRTIOOPSTATUS:
		{
			struct virtio_c2x0_job_ctx *virtio_job = NULL;
			struct virtio_c2x0_job_ctx *next_job = NULL;
			int ret = -1;

			list_for_each_entry_safe(virtio_job, next_job,
						 &virtio_c2x0_cmd_list,
						 list_entry) {

				if (virtio_job->ctx->card_status != -1) {
					switch (virtio_job->qemu_cmd.op) {
					case RSA:{
							switch (virtio_job->
								qemu_cmd.u.pkc.
								pkc_req.type) {
							case RSA_PUB:
								print_debug
							    ("RSA_PUB completion\n");
								ret =
								    copy_to_user
								    ((void
								      __user *)
									virtio_job->
								    qemu_cmd.u.
								    pkc.
								    pkc_req.
								    req_u.
								    rsa_pub_req.
								    g,
								    (void *)
								    virtio_job->
								    ctx->req.
								    pkc->req_u.
								    rsa_pub_req.
								    g,
								    virtio_job->
								    ctx->req.
								    pkc->req_u.
								    rsa_pub_req.
								    g_len);
								print_debug
							    ("return value for RSA\
								 PUB of ouput copy_to_user = %d\n",
								 ret);
								break;
							case RSA_PRIV_FORM1:
							case RSA_PRIV_FORM2:
							case RSA_PRIV_FORM3:
								{
									int i =
									    0;

									print_debug
								    ("RSA_FORM3 completion :\
									  Output f_len = %d\n",
								     virtio_job->
								     ctx->
								     req.
								     pkc->
								     req_u.
								     rsa_priv_f3.
								     f_len);

									for (i =
									     0;
									     i <
									     virtio_job->
									     ctx->
									     req.
									     pkc->
									     req_u.
									     rsa_priv_f3.
									     f_len;
									     i++) {
										print_debug
										    ("0x%x ",
										     virtio_job->
										     ctx->
										     req.
										     pkc->
										     req_u.
										     rsa_priv_f3.
										     f
										     [i]);
									}

									ret =
									    copy_to_user
									    ((void __user *)
										virtio_job->
										qemu_cmd.u.pkc.pkc_req.
										req_u.rsa_priv_f3.f,
										(void *)virtio_job->ctx->
										req.pkc->req_u.rsa_priv_f3.f,
										virtio_job->ctx->req.pkc->
										req_u.rsa_priv_f3.f_len);

									print_debug
								    ("return value for RSA\
									 FORM 3 of ouput copy_to_user = %d\n",
									 ret);
									break;
								}
							default:
								break;
							}
							break;
						}
					case DSA:{
							switch (virtio_job->
								qemu_cmd.u.pkc.
								pkc_req.type) {
							case DSA_SIGN:
								{
									ret =
									    copy_to_user
									    ((void __user *)
										virtio_job->qemu_cmd.u.pkc.
										pkc_req.req_u.dsa_sign.c,
										(void *)virtio_job->ctx->req.
										pkc->req_u.dsa_sign.c,
										virtio_job->ctx->req.pkc->
										req_u.dsa_sign.d_len);

									print_debug
								    ("return value DSA\
									SIGN 'c' of ouput copy_to_user = %d\n",
									ret);
									ret =
									    copy_to_user
									    ((void __user *)
										virtio_job->qemu_cmd.u.pkc.
										pkc_req.req_u.dsa_sign.d,
										(void *)virtio_job->ctx->req.
										pkc->req_u.dsa_sign.d,
										virtio_job->ctx->req.pkc->
										req_u.dsa_sign.d_len);
									print_debug
								    ("return value DSA\
									 SIGN 'd' of ouput copy_to_user = %d\n",
									 ret);
								}
								break;
							default:
								break;
							}
							break;
						}
					default:
						{
							print_error
							    ("OP NOT handled\n");
							break;
						}
					}
					print_debug
					    ("Status from Device : 0x%08x\n",
					     virtio_job->ctx->card_status);
					ret =
					    copy_to_user((void __user *)
							 virtio_job->qemu_cmd.
							 host_status,
							 (void *)&virtio_job->
							 ctx->card_status,
							 sizeof(virtio_job->
								ctx->
								card_status));
					print_debug
					    ("return value of status copy_to_user = %d\n",
					     ret);
					/* count++; */
					ret = 0;
					print_debug
					    ("Job finished : ret =  %d\n", ret);
					print_debug
					    ("VIRTIOOPSTATUS returninig succesfuly\n");

					/* Clean up */
					kfree(virtio_job->ctx);
					list_del(&virtio_job->list_entry);
					kfree(virtio_job);
		    /********************/
				}
			}
			return ret;
		}
		break;
	case VIRTIOSINGLECMDSTATUS:
		{
			struct virtio_c2x0_job_ctx *virtio_job = NULL;
			struct virtio_c2x0_job_ctx *next_job = NULL;
			struct virtio_c2x0_cmd_status *resp = NULL;
			int ret = 0;

			resp = (struct virtio_c2x0_cmd_status *)
			    kzalloc(sizeof(struct virtio_c2x0_cmd_status),
				    GFP_KERNEL);
			if (!resp) {
				print_error("Alloc failed for resp: %p\n",
					    resp);
				return -1;
			}

			ret =
			    copy_from_user(resp,
					   (struct virtio_c2x0_cmd_status *)arg,
					   sizeof(struct
						  virtio_c2x0_cmd_status));
			if (ret != 0) {
				print_error("Copy from user failed\n");
				kfree(resp);
				return -1;
			}

			spin_lock(&cmd_list_lock);
			list_for_each_entry_safe(virtio_job, next_job,
						 &virtio_c2x0_cmd_list,
						 list_entry) {
				if ((virtio_job->qemu_cmd.cmd_index ==
				     resp->cmd_index)
				    && (virtio_job->qemu_cmd.guest_id ==
					resp->guest_id)) {

					if (NULL == virtio_job->ctx) {
						print_error
						    ("NULL ctx in virtio_job for %d OP, cmd_index %d, %d guest_id",
						     virtio_job->qemu_cmd.op,
						     virtio_job->qemu_cmd.
						     cmd_index,
						     virtio_job->qemu_cmd.
						     guest_id);
						/* No completion to check; Free up the buffers and return success */
						list_del(&virtio_job->
							 list_entry);
						kfree(virtio_job);
						spin_unlock(&cmd_list_lock);
						kfree(resp);
						return 0;
					}
					if (-1 == virtio_job->ctx->card_status) {
						/*
						 * If command is still under process, return immediately
						 */
						spin_unlock(&cmd_list_lock);
						kfree(resp);
						return -1;
					}

					print_debug
					    ("Status from Device : 0x%08x\n",
					     virtio_job->ctx->card_status);
					resp->status =
					    virtio_job->ctx->card_status;

					ret =
					    copy_to_user((void __user *)arg,
							 (void *)resp,
							 sizeof(struct
								virtio_c2x0_cmd_status));
					if (ret != 0) {
						print_error
						    ("Status copytouser=%d for Cmd index[%d],qemuid[%d]\n",
						     ret, resp->cmd_index,
						     resp->guest_id);
						spin_unlock(&cmd_list_lock);
						kfree(resp);
						return -1;
					}

                    /*
                     * Send response of the virtio job
                     * by copying ouputs to VM buffers
                     */
					process_virtio_job_response(virtio_job);

					/* Clean up */
					free_crypto_ctx(virtio_job->ctx->
							ctx_pool,
							virtio_job->ctx);

					list_del(&virtio_job->list_entry);
					kfree(virtio_job);
		    /********************/
					spin_unlock(&cmd_list_lock);
					kfree(resp);
					return ret;
				}
			}

			spin_unlock(&cmd_list_lock);

			print_error
			    ("Cmd with index[%d],qemuid[%d] NOT found in list\n",
			     resp->cmd_index, resp->guest_id);
			/* No completion to check; Free up the buffers and return success */
			kfree(resp);
			return 0;
		}
		break;
#ifdef HASH_OFFLOAD
	case VIRTIO_HASHCRAINIT:
		{
			struct virtio_c2x0_qemu_cmd *qemu_cmd = NULL;
			struct virtio_c2x0_job_ctx *virtio_job = NULL;
			int ret = 0;

			print_debug("VIRTIO_HASHCRAINIT:\n");
			virtio_job = (struct virtio_c2x0_job_ctx *)
			    kzalloc(sizeof(struct virtio_c2x0_job_ctx),
				    GFP_KERNEL);
			if (!virtio_job) {
				print_error
				    ("Alloc failed for virtio_job: %p\n",
				     virtio_job);
				return -1;
			}

			qemu_cmd = &(virtio_job->qemu_cmd);

			print_debug
			    ("Allocation succeed %p, coping data from user space %p\n",
			     qemu_cmd, (struct virtio_c2x0_qemu_cmd *)arg);
			ret =
			    copy_from_user(qemu_cmd,
					   (struct virtio_c2x0_qemu_cmd *)arg,
					   sizeof(struct virtio_c2x0_qemu_cmd));
			if (ret != 0) {
				print_error("Copy from user failed\n");
				kfree(virtio_job);
				return -1;
			}

			ret = virtio_c2x0_hash_cra_init(virtio_job);
			print_debug
			    ("%s: VIRTIO_HASHCRAINIT returning with %d return vallue for id [%8x]\n",
			     __func__, ret, qemu_cmd->u.hash.init.sess_id);

			kfree(virtio_job);

			if (ret < 0)
				return -1;

			break;
		}

	case VIRTIO_HASHCRAEXIT:
		{
			/* unsigned long sess_id = (unsigned long) arg; */
			struct virtio_c2x0_qemu_cmd *qemu_cmd = NULL;
			int ret = 0;
			/* struct virtio_c2x0_crypto_sess_ctx *hash_sess = NULL,
				*next_sess = NULL; */

			print_debug("VIRTIO_HASHCRAEXIT:\n");
			qemu_cmd = (struct virtio_c2x0_qemu_cmd *)
			    kzalloc(sizeof(struct virtio_c2x0_qemu_cmd),
				    GFP_KERNEL);
			if (!qemu_cmd) {
				print_error("Alloc failed for qemu_cmd: %p\n",
					    qemu_cmd);
				return -1;
			}
			ret =
			    copy_from_user(qemu_cmd,
					   (struct virtio_c2x0_qemu_cmd *)arg,
					   sizeof(struct virtio_c2x0_qemu_cmd));
			if (ret != 0) {
				print_error("Copy from user failed\n");
				kfree(qemu_cmd);
				return -1;
			}

			ret = virtio_c2x0_hash_cra_exit(qemu_cmd);
			print_debug
			    ("%s: VIRTIO_HASHCRAEXIT returning with %d return vallue for id[%8X]\n",
			     __func__, ret, qemu_cmd->u.hash.exit.sess_id);
#if 0
			/*
			 * Verify if sess_id is still present in list
			 * even after deletion of an entry
			 */
			list_for_each_entry_safe(hash_sess, next_sess,
						 &virtio_c2x0_hash_sess_list,
						 list_entry) {
				if (hash_sess->sess_id ==
				    qemu_cmd->u.hash.exit.sess_id
				    && hash_sess->guest_id ==
				    qemu_cmd->guest_id) {
					print_error
					    ("hash sess_id[%x],guest[%d] still in list\n",
					     qemu_cmd->u.hash.exit.sess_id,
					     qemu_cmd->guest_id);
				}
			}
#endif

			kfree(qemu_cmd);

			if (ret < 0)
				return -1;

			break;
		}
#endif
#ifdef SYMMETRIC_OFFLOAD
	case VIRTIO_SYMMCRAINIT:
		{
			struct virtio_c2x0_qemu_cmd *qemu_cmd = NULL;
			struct virtio_c2x0_job_ctx *virtio_job = NULL;
			int ret = 0;

			print_debug("VIRTIO_SYMMCRAINIT:\n");
			virtio_job = (struct virtio_c2x0_job_ctx *)
			    kzalloc(sizeof(struct virtio_c2x0_job_ctx),
				    GFP_KERNEL);
			if (!virtio_job) {
				print_error
				    ("Alloc failed for virtio_job: %p\n",
				     virtio_job);
				return -1;
			}

			qemu_cmd = &(virtio_job->qemu_cmd);

			print_debug
			    ("Allocation succeed %p, coping data from user space %p\n",
			     qemu_cmd, (struct virtio_c2x0_qemu_cmd *)arg);
			ret =
			    copy_from_user(qemu_cmd,
					   (struct virtio_c2x0_qemu_cmd *)arg,
					   sizeof(struct virtio_c2x0_qemu_cmd));
			if (ret != 0) {
				print_error("Copy from user failed\n");
				kfree(virtio_job);
				return -1;
			}

			ret = virtio_c2x0_symm_cra_init(virtio_job);
			print_debug
			    ("%s: VIRTIO_SYMMCRAINIT returninig with %d return vallue for id [%8x]\n",
			     __func__, ret, qemu_cmd->u.symm.init.sess_id);

			kfree(virtio_job);

			if (ret < 0)
				return -1;

			break;
		}
	case VIRTIO_SYMMCRAEXIT:
		{
			int ret = 0;

			struct virtio_c2x0_qemu_cmd *qemu_cmd = NULL;

			print_debug("VIRTIO_SYMMCRAEXIT:\n");
			qemu_cmd = (struct virtio_c2x0_qemu_cmd *)
			    kzalloc(sizeof(struct virtio_c2x0_qemu_cmd),
				    GFP_KERNEL);
			if (!qemu_cmd) {
				print_error("Alloc failed for qemu_cmd: %p\n",
					    qemu_cmd);
				return -1;
			}
			ret =
			    copy_from_user(qemu_cmd,
					   (struct virtio_c2x0_qemu_cmd *)arg,
					   sizeof(struct virtio_c2x0_qemu_cmd));
			if (ret != 0) {
				print_error("Copy from user failed\n");
				kfree(qemu_cmd);
				return -1;
			}

			ret = virtio_c2x0_symm_cra_exit(qemu_cmd);
			print_debug
			    ("%s: VIRTIO_SYMMCRAEXIT returninig with %d return vallue for id [%8x]\n",
			     __func__, ret, qemu_cmd->u.symm.exit.sess_id);
			kfree(qemu_cmd);
			if (ret < 0)
				return -1;
			break;
		}
#endif

#endif /* VIRTIO_C2X0 : Virtio ioctl operations */

		print_error("DEFAULT IOCTL CALLED\n");
		break;
	}
	return 0;
}

/*******************************************************************************
 * Function     : response_ring_handler
 *
 * Arguments    : work - Kernel work posted to this handler
 *
 * Return Value : none
 *
 * Description  : Bottom half implementation to handle the responses.
 *
 ******************************************************************************/
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 19))
static void response_ring_handler(struct work_struct *work)
{
#else
static void response_ring_handler(void *data)
{
    struct work_struct *work = (struct work_struct *)data; 
#endif
	bh_handler_t *bh = container_of(work, bh_handler_t, work);
	per_core_struct_t *instance = NULL;
	fsl_crypto_dev_t *c_dev = NULL;

	if (unlikely(NULL == bh)) {
		print_error("No bottom half handler found for the work\n");
		return;
	}

	c_dev = (fsl_crypto_dev_t *) bh->c_dev;	/* get_crypto_dev(1); */
	print_debug("GOT INTERRUPT FROM DEV : %d\n", c_dev->config->dev_no);
#ifdef MULTIPLE_RESP_RINGS
	print_debug("Worker thread invoked on cpu [%d]\n", bh->core_no);
	instance = per_cpu_ptr(per_core, bh->core_no);
	process_response(c_dev, &(instance->ring_list_head));
#else
	demux_fw_responses(c_dev);
#endif
	return;
}

/*******************************************************************************
 * Function     : get_dev_config
 *
 * Arguments    : dev : PCI device instance
 *
 * Return Value : config - Config struct corresponding to the device
 *
 * Description  : Returns the configuration corresponding to the device
 *
 ******************************************************************************/

crypto_dev_config_t *get_config(uint32_t dev_no)
{
	crypto_dev_config_t *config = NULL;

	/* Loop for each config to get to the correct config.
	 */
	list_for_each_entry(config, &crypto_dev_config_list, list) {
		print_debug("Config Dev no:%d Arg Dev no: %d\n",
			    config->dev_no, dev_no);

		if (config->dev_no == dev_no)
			return config;

	}

	return NULL;
}

/*******************************************************************************
 * Function     : get_dev_config
 *
 * Arguments    : dev : PCI device instance
 *
 * Return Value : config - Config struct corresponding to the device
 *
 * Description  : Returns the configuration corresponding to the device
 *
 ******************************************************************************/

crypto_dev_config_t *get_dev_config(fsl_pci_dev_t *fsl_pci_dev)
{
	crypto_dev_config_t *config = NULL;

	/* Loop for each config to get to the correct config.
	 */
	list_for_each_entry(config, &crypto_dev_config_list, list) {
		print_debug("Config Dev no:%d Arg Dev no: %d\n",
			    config->dev_no, fsl_pci_dev->dev_no);

		if (config->dev_no == fsl_pci_dev->dev_no)
			return config;

	}

	return NULL;
}

/*******************************************************************************
 * Function     : fsl_drv_get_mem
 *
 * Arguments    : dev : PCI device structure instance.
 *                mem : Structure identifying the mem info
 *
 * Return Value : none
 *
 * Description  : API to get the addresses of the device (ib memory)
 *
 ******************************************************************************/
void fsl_drv_get_mem(fsl_pci_dev_t *dev, crypto_dev_mem_info_t *mem)
{
	mem->host_v_addr = dev->bars[mem->type].v_addr;
	mem->host_p_addr = dev->bars[mem->type].phy_addr;
}

#if 0
static uint64_t readtb(void)
{
	uint32_t tbl = 0, tbh = 0;
	uint64_t tb = 0;

	asm volatile ("mfspr %0, 526" : "=r" (tbl));
	asm volatile ("mfspr %0, 527" : "=r" (tbh));

	tb = ((uint64_t) tbh << 32) | tbl;

	return tb;
}
#endif

/*******************************************************************************
 * Function     : fsl_crypto_isr
 *
 * Arguments    : irq : Vector number
 *                dev : Instance of the device which raised this interrupt
 *
 * Return Value : irqreturn_t
 *
 * Description  : ISR implementation
 *
 ******************************************************************************/
static irqreturn_t fsl_crypto_isr(int irq, void *data)
{
	isr_ctx_t *isr_ctx = (isr_ctx_t *) data;
	per_core_struct_t *instance = NULL;
	fsl_h_rsrc_ring_pair_t *rp = NULL;

	if (unlikely(!isr_ctx)) {
		print_error("[ISR] Null Params.....\n");
		return IRQ_NONE;
	}
#if 1
/*	queue_work_on(0, instance->bh_handler.workq,
		      &(instance->bh_handler.work)); */

	list_for_each_entry((rp), &(isr_ctx->ring_list_head), isr_ctx_list_node) {
		print_debug("Ring is assoc with this intr on core [%d]\n",
			    rp->core_no);
		print_debug("SHEDULING THE WORK ON CORE : %d\n", rp->core_no);
		/* From the core number get the per core info instance */
		instance = per_cpu_ptr(per_core, rp->core_no);
		instance->bh_handler.c_dev = isr_ctx->dev->crypto_dev;
		/* Queue work for the bh handler which is working on
		 * a specific cpu */
		queue_work_on(rp->core_no, instance->bh_handler.workq,
			      &(instance->bh_handler.work));
	}
#else
	/* Tasklet has cpu hog issues if it runs continuously */
	tasklet_hi_schedule(&(isr_ctx->tasklet));
#endif

	return IRQ_HANDLED;
}

static void resp_process_tasklet(unsigned long data)
{
#ifndef MULTIPLE_RESP_RINGS
	isr_ctx_t *isr_ctx = (isr_ctx_t *) data;
	demux_fw_responses(isr_ctx->dev->crypto_dev);
#endif
}

/*******************************************************************************
 * Function     : fsl_crypto_pci_probe
 *
 * Arguments    : dev : PCI device structure instance.
 *				  id  : Id of the PCI device.
 *
 * Return Value : int32_t
 *
 * Description  : Handles the PCI probe of the device.
 *
 ******************************************************************************/
static int32_t fsl_crypto_pci_probe(struct pci_dev *dev,
				    const struct pci_device_id *id)
{
	int32_t ret = 0;
	int32_t i = 0;

#ifndef P4080_BUILD
	int32_t rsrc_bar_addr = 0;
	int32_t config_bar_addr = 0;
#endif

	uint8_t is_msix_cap = 0;
	uint8_t is_msi_cap = 0;
	uint8_t is_intr_cap = 0;

	uint32_t num_of_vectors = 0;

	int8_t pci_info[60];
	int8_t sys_pci_info[100];

	fsl_pci_dev_t *fsl_pci_dev = NULL;
	crypto_dev_config_t *config = NULL;
	isr_ctx_t *isr_context = NULL;

	print_debug("\n\n ========== PROBE FUNCTION ==========\n");

	if (!dev) {
		print_error
		    ("PCI device with VendorId:%0x DeviceId:%0x is not found\n",
		     id->device, id->vendor);
		return -ENODEV;
	}

	/* Allocate memory for the new PCI device data structure */
	fsl_pci_dev = kzalloc(sizeof(fsl_pci_dev_t), GFP_KERNEL);
	if (unlikely((NULL == fsl_pci_dev))) {
		print_error("Memory allocation failed\n");
		ret = -ENOMEM;
		goto error;
	}

	/* Set this device instance as private data inside the pci dev struct */
	dev_set_drvdata(&(dev->dev), fsl_pci_dev);

	fsl_pci_dev->dev = dev;

	fsl_pci_dev->id = id;

	/* Starts from 1 */
	fsl_pci_dev->dev_no = ++dev_no;

	snprintf(fsl_pci_dev->dev_name, FSL_PCI_DEV_NAME_MAX_LEN, "%s",
		 FSL_PCI_DEV_NAME);
	snprintf(((fsl_pci_dev->dev_name) + (FSL_PCI_DEV_NAME_MAX_LEN - 2)),
		 FSL_PCI_DEV_NAME_MAX_LEN, "%d", dev_no);

	DEV_PRINT_DEBUG("Found PCI Device: ");

	/* Add this node to the pci device's linked list */
	list_add(&(fsl_pci_dev->list), &pci_dev_list);

	/* TODO :- We may need to remove the following code */
	/* The following code is generally not required -
	 * But it is seen that u-boot of the
	 * firmware is over-riding the PCI bar addresses.
	 * Hence we need this code to correct them
	 * 1) This will not be issue, as we will not have
	 * u-boot in the final code.
	 * 2) For the first release even if the u-boot is present,
	 * we can modify the u-boot code.
	 * Currently leaving this code as such. We can figure out
	 * later whether do we need this.
	 */

#ifndef P4080_BUILD
	pci_read_config_dword(dev, PCI_BAR0_REGISTER, &config_bar_addr);
	rsrc_bar_addr = pci_resource_start(dev, PCI_BAR_NUM_0);

	if ((rsrc_bar_addr & 0xfffffe00) != (config_bar_addr & 0xfffffe00))
		dev_pci_cfg_write_word32(dev, PCI_BAR0_REGISTER, rsrc_bar_addr);

	pci_read_config_dword(dev, PCI_BAR1_REGISTER, &config_bar_addr);
	rsrc_bar_addr = pci_resource_start(dev, PCI_BAR_NUM_1);

	if ((rsrc_bar_addr & 0xfffffe00) != (config_bar_addr & 0xfffffe00))
		dev_pci_cfg_write_word32(dev, PCI_BAR1_REGISTER, rsrc_bar_addr);

#endif

	/* Set the DMA mask for the device. This helps the PCI subsystem
	 * for proper dma mappings */
#ifdef SEC_ENGINE_DMA_36BIT
	pci_set_dma_mask(dev, DMA_36BIT_MASK);
#else
	pci_set_dma_mask(dev, DMA_32BIT_MASK);
#endif

	/* Read the different capabilities of the device */

	/* Check whether the device has PCIE cap */
	if (unlikely(!pci_find_capability(dev, PCI_CAP_ID_EXP))) {
		DEV_PRINT_ERROR("Does not have PCIE cap\n");
		ret = -ENODEV;
		goto error;
	}

	DEV_PRINT_DEBUG("Is PCIe Capable\n");

	/* Check whether the device has MSIx cap */
	if (likely(pci_find_capability(dev, PCI_CAP_ID_MSIX))) {
		DEV_PRINT_DEBUG("MSIx Support\n");
		is_msix_cap = true;
	} else if (likely(pci_find_capability(dev, PCI_CAP_ID_MSI))) {
		DEV_PRINT_DEBUG("MSI Support\n");
		is_msi_cap = true;
	} else {
		DEV_PRINT_DEBUG("INTR Support\n");
		is_intr_cap = true;
	}

	/* Wake up the device if it is in suspended state */
	if (unlikely(pci_enable_device(dev))) {
		DEV_PRINT_ERROR("Enable Device failed\n");
		ret = -ENODEV;
		goto error;
	}

	fsl_pci_dev->enabled = true;

	/* Set bus master */
	pci_set_master(dev);

	/* Get the BAR resources and remap them into the driver memory */
	for (i = 0; i < PCI_IB_BAR_MAX; i++) {
		/* Read the hardware address */
		fsl_pci_dev->bars[i].phy_addr = pci_resource_start(dev, i);
		if (unlikely(0 == fsl_pci_dev->bars[i].phy_addr)) {
			DEV_PRINT_ERROR
			    ("Failed to get hardware address of BAR:%d\n", i);
			ret = -ENOMEM;
			goto error;
		}

		DEV_PRINT_DEBUG("Physical address of BAR : %d is %llx\n", i,
				fsl_pci_dev->bars[i].phy_addr);

		fsl_pci_dev->bars[i].len = pci_resource_len(dev, i);

		/* Request resource region */
		if (unlikely
		    (!request_mem_region
		     (fsl_pci_dev->bars[i].phy_addr, fsl_pci_dev->bars[i].len,
		      "FSL-CRYPTO"))) {
			DEV_PRINT_ERROR("Bar:%d Request mem region failed\n",
					i);
			ret = -ENOMEM;
			goto error;
		}

		/* Map the MEM to the kernel address space */
		fsl_pci_dev->bars[i].v_addr =
		    ioremap(fsl_pci_dev->bars[i].phy_addr,
			    fsl_pci_dev->bars[i].len);
		if (unlikely(NULL == fsl_pci_dev->bars[i].v_addr)) {
			DEV_PRINT_ERROR
			    ("Bar:%d Mapping to kernel address failed\n", i);
			ret = -ENOMEM;
			goto error;
		}
		DEV_PRINT_DEBUG("Bar:%d virtual address [%p] Length [%0lx]\n",
				i, fsl_pci_dev->bars[i].v_addr,
				fsl_pci_dev->bars[i].len);
		/* We will not be using DMA from RC or DMA from EP.
		 * Hence this memory need not be mapped to DMA. */
		fsl_pci_dev->bars[i].dma_addr = 0;
	}

	/* RESET THE PIC_PIR */
#define PIC_PIR 0x041090
	FSL_DEVICE_WRITE32_BAR0_REG(fsl_pci_dev->bars[PCI_BAR_NUM_0].v_addr,
				    PIC_PIR, 0x0);

	/* Call to the following function gets the number of
	 * application rings to be created for the device.
	 * The actual number of ring pairs created can be different
	 * and can only be known during the handshake.
	 * This number is the max limit. Number of iv's
	 * to ask = number of application rings.*/

	config = get_dev_config(fsl_pci_dev);
	if (unlikely(NULL == config)) {
		/* FIX: IF NO CONFIGURATION IS SPECIFIED THEN
		 * TAKE THE DEFAULT CONFIGURATION */
		print_debug
		    ("NO CONFIG FOUND, CREATING DEFAULT CONFIGURATION\n");
		config = kzalloc(sizeof(crypto_dev_config_t), GFP_KERNEL);
		if (unlikely(NULL == config)) {
			print_error("Mem allocation failed\n");
			ret = -ENODEV;
			goto error;
		}

		list_add(&(config->list), &(crypto_dev_config_list));
		print_debug
		    ("\t\t\t===== DEFAULT CONFIGURATION DETAILS ======\n");
		config->dev_no = fsl_pci_dev->dev_no;
		strcpy(config->fw_file_path, FIRMWARE_FILE_DEFAULT_PATH);
		print_debug("Firmware Path : %s\n", config->fw_file_path);
		create_default_config(config, 0, 2);
	}

	/*** Following code setup the interrupt ***/

	/* If MSIx is supported - Then number of vectors to be asked
	 * should be equal to the number of application
	 * rings + command ring.
	 *
	 * [MAK] TODO: Discuss how this would scale in case if there are
	 * number of cores less than application rings.
	 * What is the important - Parallel processing or
	 * data path separation ??
	 * For now, with virtualization in mind,
	 * data path separation is considered.
	 */
	if (is_msix_cap) {
		/* The count here is total count - cmd + no of app rings */
		num_of_vectors = config->num_of_rings;

		fsl_pci_dev->intr_info.msix_entries =
		    kzalloc((num_of_vectors * sizeof(struct msix_entry)),
			    GFP_KERNEL);
		if (unlikely(NULL == fsl_pci_dev->intr_info.msix_entries)) {
			DEV_PRINT_ERROR("MSIx entries mem alloc failed\n");
			ret = -ENODEV;
			goto error;
		}

		for (i = 0; i < num_of_vectors; i++) {
			/* In case of MSIx - The driver needs to fill
			 * this value inside the MSIx entry. For this
			 * entry number, kernel will fill the vector number.
			 */
			fsl_pci_dev->intr_info.msix_entries[i].entry = i;
		}

		/* Though we may need vectors we want,
		 * the Kernel/APIC may not entertain it.
		 * This loop determines the actual number of
		 * vectors allocated by the APIC
		 * for this device. We have to live with it.
		 * The actual distribution of rings
		 * to the iv's will be done in later stage.
		 */
		while (ret > 0) {
			ret =
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0))
			    pci_enable_msix(dev,
					    fsl_pci_dev->intr_info.msix_entries,
					    num_of_vectors);
#else
			    pci_enable_msix_exact(dev,
					    fsl_pci_dev->intr_info.msix_entries,
					    num_of_vectors);
#endif
			if (ret > 0)
				num_of_vectors = ret;
		}
		if (ret < 0) {
			DEV_PRINT_ERROR("MSIx enable failed !!\n");
			ret = -ENODEV;
			goto error;
		}
	} else if (is_msi_cap) {
		num_of_vectors = 1;
#ifdef MULTIPLE_MSI_SUPPORT
		/* Check whether the device supports multiple MSI interrupts */
		uint16_t msi_ctrl_word = 0x0;
		uint32_t mmc_count = 0x0;
		uint32_t mme_count = 0x0;
		dev_pci_cfg_read_word16(dev, PCI_MSI_CTRL_REGISTER,
					&msi_ctrl_word);

		/* Check the MMC field to see how many MSIs are supported */
		mmc_count =
		    (msi_ctrl_word & MSI_CTRL_WORD_MMC_MASK) >>
		    MSI_CTRL_WORD_MMC_SHIFT;
		mmc_count = ((0x01) << mmc_count);

		/* Check the MME field to see howo many are actually
		 * enabled by PCI subsystem */
		mme_count =
		    (msi_ctrl_word & MSI_CTRL_WORD_MME_MASK) >>
		    MSI_CTRL_WORD_MME_SHIFT;
		mme_count = ((0x01) << mmc_count);

		DEV_PRINT_DEBUG("MMC count [%d] MME count [%d]\n", mmc_count,
				mme_count);

		/* As for number of vectors equal to number of rings */
		num_of_vectors = config->num_of_rings;
		while (ret > 0) {
			ret = pci_enable_msi_block(dev, num_of_vectors);
			if (ret > 0)
				num_of_vectors = ret;
		}
		if (ret < 0) {
			DEV_PRINT_ERROR("MSI enable failed !!\n");
			ret = -ENODEV;
			goto error;
		}

		DEV_PRINT_DEBUG("Number of MSI vectors actually enabled %d\n",
				num_of_vectors);
#else
		ret = pci_enable_msi(dev);
		if (unlikely(ret)) {
			DEV_PRINT_ERROR("MSI enable failed !!\n");
			ret = -ENODEV;
			goto error;
		}
#endif
	} else
		num_of_vectors = 1;

	fsl_pci_dev->intr_info.intr_vectors_cnt = num_of_vectors;

	/* Init the intr list head */
	INIT_LIST_HEAD(&(fsl_pci_dev->intr_info.isr_ctx_list_head));

	/* Number of vectors required are determined in the above logic,
	 * now allocate memory for the isr contexts */
	for (i = 0; i < num_of_vectors; i++) {
		isr_context = kzalloc(sizeof(isr_ctx_t), GFP_KERNEL);

		if (unlikely(NULL == isr_context)) {
			DEV_PRINT_ERROR("Mem alloc failed\n");
			ret = -ENOMEM;
			goto error;
		}

		isr_context->dev = fsl_pci_dev;

		tasklet_init(&(isr_context->tasklet), resp_process_tasklet,
			     (unsigned long)isr_context);

		INIT_LIST_HEAD(&(isr_context->ring_list_head));

		/* Add this to the list of ISR contexts */
		list_add(&(isr_context->list),
			 &(fsl_pci_dev->intr_info.isr_ctx_list_head));

		/* Register the ISR with kernel for each vector */
		if (is_msix_cap) {
			ret =
			    request_irq(fsl_pci_dev->intr_info.
					msix_entries[i].vector,
					(irq_handler_t) fsl_crypto_isr, 0,
					fsl_pci_dev->dev_name, isr_context);

		} else {
#ifdef MULTIPLE_MSI_SUPPORT
			ret =
			    request_irq((dev->irq + i),
					(irq_handler_t) fsl_crypto_isr, 0,
					fsl_pci_dev->dev_name, isr_context);
#else
			ret =
			    request_irq((dev->irq),
					(irq_handler_t) fsl_crypto_isr, 0,
					fsl_pci_dev->dev_name, isr_context);
#endif
		}

		if (likely(ret)) {
			DEV_PRINT_ERROR("Request IRQ failed for vector : %d\n",
					i);
			ret = -ENODEV;
			goto error;
		}

		if (is_msix_cap) {
			/* [MAK] TODO: For MSIx support, Device will expose an
			 * another BAR which will have table of MSI
			 * address and data. To get the MSI address and data a
			 * look up has to be done with the entry
			 * number. The exact implementation will depend on the
			 * MSIx implementation in the device.*/
		} else if (is_msi_cap) {
			/* Get the MSI address and MSI data from the
			 * configuration space */
			dev_pci_cfg_read_word32(dev, PCI_MSI_ADDR_LOW,
						&(isr_context->msi_addr_low));
			dev_pci_cfg_read_word32(dev, PCI_MSI_ADDR_HIGH,
						&(isr_context->msi_addr_high));
			dev_pci_cfg_read_word16(dev, PCI_MSI_ADDR_DATA,
						&(isr_context->msi_data));

			DEV_PRINT_DEBUG
			    ("MSI addr low [%0X] MSI addr high [%0X] "
			     "MSI data [%0X]\n",
			     isr_context->msi_addr_low,
			     isr_context->msi_addr_high, isr_context->msi_data);

			if (sizeof(phys_addr_t) == HOST_64_BIT_ADDR_SIZE) {
				fsl_pci_dev->bars[PCI_BAR_NUM_3].phy_addr =
				    ((((u64) isr_context->msi_addr_high) << 32)
				     | isr_context->msi_addr_low);
			} else {
				fsl_pci_dev->bars[PCI_BAR_NUM_3].phy_addr =
				    isr_context->msi_addr_low;
			}

			fsl_pci_dev->bars[PCI_BAR_NUM_3].v_addr =
			    (void *)
			    phys_to_virt(fsl_pci_dev->bars[PCI_BAR_NUM_3].
					 phy_addr);
		}
	}

	/* [MAK] TODO: Loop through each IRQ and distribute them
	 * to the available cores.  Worst distribution is when
	 * number of IRQs are more than the number of CPUs, this
	 * can happen when number of rings are more than the cores.
	 */
	isr_context = NULL;
	list_for_each_entry(isr_context,
			    &(fsl_pci_dev->intr_info.isr_ctx_list_head), list) {
	}

	/* [MAK] TODO: Create the device node with next minor number */

	/** Now create all the SYSFS entries required for this device **/
	ret = init_sysfs(fsl_pci_dev);
	if (unlikely(-1 == ret)) {
		print_error("Sysfs init failed !!\n");
		goto error;
	}

	/* Add the PCI device to the crypto layer --
	 * This layer adds the device as crypto device.
	 * To have kernel dependencies separate, all the
	 * crypto device related handling will be done
	 * by the crypto layer.
	 */
	fsl_pci_dev->crypto_dev =
	    fsl_crypto_layer_add_device(fsl_pci_dev, config);
	if (unlikely(NULL == fsl_pci_dev->crypto_dev)) {
		DEV_PRINT_ERROR("Adding device as crypto dev failed\n");
		ret = -1;
		goto error;
	}

	/* Updating the information to sysfs entries */
	print_debug("Updating sys info\n");
	snprintf(pci_info, 60, "VendorId:%0x DeviceId:%0x BusNo:%0x\nCAP:PCIe\n",
		 id->device, id->vendor, fsl_pci_dev->dev->bus->number);
	strcpy(sys_pci_info, pci_info);
	if (true == is_msi_cap)
		strcat(sys_pci_info, "MSI CAP\n");
	else if (true == is_msix_cap)
		strcat(sys_pci_info, "MSIx CAP\n");
	else
		strcat(sys_pci_info, "INTR CAP\n");

	set_sysfs_value(fsl_pci_dev, PCI_INFO_SYS_FILE,
			(uint8_t *) sys_pci_info, strlen(sys_pci_info));
	set_sysfs_value(fsl_pci_dev, FIRMWARE_PATH_SYSFILE,
			config->fw_file_path, strlen(config->fw_file_path));
	set_sysfs_value(fsl_pci_dev, FIRMWARE_VERSION_SYSFILE,
			(uint8_t *) "FSL-FW-1.1.0\n", strlen("FSL-FW-1.1.0\n"));

	g_fsl_pci_dev = fsl_pci_dev;

error:
	if (unlikely(-1 == ret))
	{
		fsl_pci_dev->dev_status = -1;
		DEV_PRINT_ERROR("Probe of device [%d] failed with status : [%d]\n",
		 fsl_pci_dev->dev_no, fsl_pci_dev->dev_status);
	}
	return ret;
}

/*******************************************************************************
 * Function     : create_per_core_info
 *
 * Arguments    : None
 *
 * Return Value : None
 *
 * Description  : Creates per core data structures
 *
 ******************************************************************************/
int32_t create_per_core_info(void)
{
	uint32_t i = 0;

	uint8_t wq_name[10];

	per_core_struct_t *instance = NULL;

	per_core = alloc_percpu(per_core_struct_t);

	if (unlikely(per_core == NULL)) {
		print_error("Mem allocation failed\n");
		return -1;
	}
	for_each_online_cpu(i) {
		if (!(wt_cpu_mask & (1 << i)))
			continue;
		instance = per_cpu_ptr(per_core, i);
		INIT_WORK(&(instance->bh_handler.work), response_ring_handler);

		snprintf(wq_name, 9, "WQ_%d", i);
		instance->bh_handler.workq = create_workqueue(wq_name);

		instance->core_no = i;
		instance->context = NULL;
		instance->cb = NULL;

		instance->bh_handler.core_no = i;

		INIT_LIST_HEAD(&(instance->ring_list_head));

		/*list_add(&(instance->list),&per_core_list_head); */
	}
	return 0;
}

/*******************************************************************************
 * Function     : str_to_int
 *
 * Arguments    : p - String
 *
 * Return Value : None
 *
 * Description  : Converts the string to an integer
 *
 ******************************************************************************/
static uint32_t str_to_int(int8_t *p)
{
	int value = 0;

	while (*p != '\0') {
		value = (value * 10) + (*p - '0');
		p++;
	}
	return value;
}

/*******************************************************************************
 * Function     : get_line
 *
 * Arguments    : file - Configuration file
 *				  pos  - Current read position inside the file
 *				  line - Output buffer to read the line
 *
 * Return Value : int32_t
 *
 * Description  : To get the line from the passed configuration file.
 *
 ******************************************************************************/
static int32_t get_line(struct file *file, loff_t *pos, uint8_t *line,
			int32_t line_size)
{
	char ch = 0;
	uint8_t count = 0;

	line[0] = '\0';
	while (ch != '\n') {
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4, 15, 0))
		if (vfs_read(file, &ch, 1, pos) <= 0)
			return -1;
#else
		if (kernel_read(file, &ch, 1, pos) <= 0)
			return -1;
#endif
		if (ch != '\n') {
			line[count++] = ch;
			if (count == line_size)
				return 0;
		}
	}

	line[count] = '\0';
	return 0;
}

/*******************************************************************************
 * Function     : get_label
 *
 * Arguments    : line - Line read from configuration file
 *
 * Return Value : int8_t*
 *
 * Description  : Parses the line to get label
 *
 ******************************************************************************/
int8_t *get_label(int8_t *line)
{
	int8_t *p = line;

	while (*line != '\n' && *line != '\0') {
		if (*line == '<')
			return line;
		else if (*line == ':' && (*line = '\0'))
			return p;
		else
			line++;
	}

	while (*p == ' ')
		p++;

	return p;
}

/*******************************************************************************
 * Function     :	create_default_config
 *
 * Arguments    :	config - current device config structure
 *			from_ring - from which ring to take default values
 *			max_ring  - maximum number of rings to be created
 *
 * Return Value :	void
 *
 * Description  :	Creates the default device configuration
 *						default values
 *			DEPTH - 16	AFFINITY - 0
 *			PRIORITY - 1	ORDER - 0
 *
 ******************************************************************************/
static void create_default_config(crypto_dev_config_t *config,
				  int32_t from_ring, int32_t max_ring)
{
	print_debug("Total no of Rings : %d\n", max_ring);
	for (; from_ring < max_ring; ++from_ring) {
		config->ring[from_ring].ring_id = from_ring;
		if (0 == from_ring)
			config->ring[from_ring].depth = 16;
		else
			config->ring[from_ring].depth = 1024;
		/* DEFAULT AFFINITY 0 */
		config->ring[from_ring].flags |=
		    (uint8_t) (0) << APP_RING_PROP_AFFINE_SHIFT;
		/* DEFAULT PRIORITY 1 */
		config->ring[from_ring].flags |=
		    (uint8_t) (1) << APP_RING_PROP_PRIO_SHIFT;
		/* DEFAULT ORDER 0 */
		config->ring[from_ring].flags |=
		    (uint8_t) (0) << APP_RING_PROP_ORDER_SHIFT;
		print_debug("Ring [%d] default Depth : %d\n", from_ring,
			    config->ring[from_ring].depth);
		print_debug("Ring [%d] default Affinity : 0\n", from_ring);
		print_debug("Ring [%d] default Priority : 1\n", from_ring);
		print_debug("Ring [%d] default Order : 0\n", from_ring);

	}
	config->num_of_rings = max_ring;
}

/*******************************************************************************
 * Function     : process_label
 *
 * Arguments    : label - Token to identify the value
 *		  value - Actual value
 *
 * Return Value : int32_t
 *
 * Description  : Understands and initialize the config data structure based on
 *		  the passed label and value
 *
 ******************************************************************************/
uint32_t dev_count;
int32_t process_label(int8_t *label, int8_t *value)
{
	int32_t conv_value = 0;
	static crypto_dev_config_t *config;
	static uint32_t rings_spec;
	static uint32_t ring_count;
	static uint32_t ring_start;
	static uint32_t dev_start;

	if (!strcmp(label, "<device>")) {
		/* New device node - allocate memory for new config structure */
		config = kzalloc(sizeof(crypto_dev_config_t), GFP_KERNEL);

		if (unlikely(NULL == config)) {
			print_error("Mem allocation failed\n");
			return -1;
		}

		/* Add this to the existing list */
		list_add(&(config->list), &(crypto_dev_config_list));
		config->dev_no = ++dev_count;

		dev_start = true;
	} else if (!strcmp(label, "firmware")) {
		strcpy(config->fw_file_path, value);
	} else if (!strcmp(label, "rings")) {
		conv_value = str_to_int(value);
		if (FSL_CRYPTO_MAX_RING_PAIRS < conv_value || 0 > conv_value)
			conv_value = FSL_CRYPTO_MAX_RING_PAIRS;
		config->num_of_rings = conv_value;
		rings_spec = true;
		/* Default values for all the rings */
		/*create_default_config(config,0,config->num_of_rings); */
	} else if (!strcmp(label, "<ring>") && (dev_start == true)) {
		/* New ring information is starting here */
		ring_start = true;
		if (false == rings_spec) {
			/* Default values for all the rings */
			create_default_config(config, 0, 2);
			return 0;
		}
		config->ring[ring_count].ring_id = ring_count;
	} else if (!strcmp(label, "depth") && (ring_start == true)) {
		config->ring[ring_count].depth = str_to_int(value);
	} else if (!strcmp(label, "affinity") && (ring_start == true)) {
		config->ring[ring_count].flags |=
		    (uint8_t) (str_to_int(value)) << APP_RING_PROP_AFFINE_SHIFT;
	} else if (!strcmp(label, "priority") && (ring_start == true)) {
		conv_value = str_to_int(value);
		if (16 < conv_value)
			conv_value = 16;
		if (0 >= conv_value)
			conv_value = 1;
		config->ring[ring_count].flags |=
		    (uint8_t) (conv_value) << APP_RING_PROP_PRIO_SHIFT;
	} else if (!strcmp(label, "order") && (ring_start == true)) {
		conv_value = str_to_int(value);
		if ( conv_value > 1 || conv_value < 0)
			conv_value = 0;
		config->ring[ring_count].flags |=
		    (uint8_t) (conv_value) << APP_RING_PROP_ORDER_SHIFT;
	} else if (!strcmp(label, "<end>")) {
		if (ring_start == true) {
			ring_start = false;
			if (config->ring[ring_count].depth < 16) {
				if (ring_count == 0)
					config->ring[ring_count].depth = 16;
				else
					config->ring[ring_count].depth = 128;
			}
			ring_count++;
		} else if (dev_start == true) {
			/* FIX: IF GIVEN CONFIGURATION FAILS THEN MAKE DEFAULT
			 * CONFIGURATION ENABLED */
			if (1 >= config->num_of_rings)
				create_default_config(config, 0, 2);
			else if (ring_count < config->num_of_rings)
				create_default_config(config, ring_count,
						      config->num_of_rings);
			else if (ring_count > config->num_of_rings)
				return -1;

			rings_spec = false;
			dev_start = false;
			ring_count = 0;
			/*dev_count++; */
		}
	} else
		return -1;

	return 0;
}

/*******************************************************************************
 * Function     : parse_config_file
 *
 * Arguments    : config_file - Path of the configuration file
 *
 * Return Value : int32_t
 *
 * Description  : Parses the configuration file and reads the configuration
 *
 ******************************************************************************/
int32_t parse_config_file(int8_t *config_file)
{
	int32_t ret = 0;
	uint8_t line[100];	/* Local buffer to hold the strings in file */

	int8_t *label = NULL;
	int8_t *value = NULL;
	struct file *file = NULL;
	struct inode *inode = NULL;

	loff_t pos = 0;

	mm_segment_t old_fs;

	old_fs = get_fs();

	print_info("Using configuration file: %s\n", dev_config_file);

	set_fs(KERNEL_DS);

	file = filp_open(config_file, O_RDWR, 0);

	if (IS_ERR(file)) {
		print_error("No file at path [%s]\n", config_file);

		set_fs(old_fs);
		return -1;
	}

	inode = file->f_path.dentry->d_inode;

	if (0 > i_size_read(inode->i_mapping->host)) {
		print_error("ERROR:Empty file\n");
		ret = -1;
		goto out;
	}

	while (true) {
		/* This could fail even on the EOF */
		/*if(unlikely(get_line(file,&pos,line))) { */
		if (unlikely(get_line(file, &pos, line, sizeof(line)))) {
			print_debug("Error/End of file reached\n");
			/* Need to know how to distinguish
			 * between EOF and error */
			goto out;
		}

		print_debug("Line read from file [%s]\n", line);

		if (strlen(line)) {
			label = get_label(line);

			value = line + strlen(label) + 1;
			print_debug("Label [%s], value : [%d]\n", label,
				    str_to_int(value));

			if (unlikely(process_label(label, value) == -1)) {
				print_error("Processing label [%s] failed\n",
					    label);
				ret = -1;
				goto out;
			}
		}
	}

out:
	if (file)
		filp_close(file, 0);

	set_fs(old_fs);

	return ret;
}

/*******************************************************************************
 * Function     : cleanup_pci_device
 *
 * Arguments    : void
 *
 * Return Value : None
 *
 * Description  : Does the PCI related cleanup of a device
 *
 ******************************************************************************/
static void cleanup_pci_device(fsl_pci_dev_t *dev)
{
	isr_ctx_t *isr_cursor = NULL;
	isr_ctx_t *isr_n_cursor = NULL;

	uint32_t i = 0;

	if (NULL == dev)
		return;

	sysfs_cleanup(dev);

	/* Free the BAR related resources */
	for (i = 0; i < PCI_IB_BAR_MAX; i++) {
		if (NULL != dev->bars[i].v_addr) {
			dev_print_dbg(dev, "IOunmap\n");
			/* io unmap */
			iounmap(dev->bars[i].v_addr);
		}

		if (0 != dev->bars[i].phy_addr) {
			dev_print_dbg(dev, "Releasing region\n");
			/* Free the resource */
			/* Free the mem region */
			pci_release_region(dev->dev, i);
		}
	}

	if (0 == dev->intr_info.intr_vectors_cnt) {
		dev_print_dbg(dev, "Zero interrupt count");
		goto disable_dev;
	}

	list_for_each_entry_safe(isr_cursor, isr_n_cursor,
				 &(dev->intr_info.isr_ctx_list_head), list) {
		dev_print_dbg(dev, "Freeing Irq\n");
		free_irq(dev->dev->irq, isr_cursor);
		list_del(&(isr_cursor->list));
		list_del(&(isr_cursor->ring_list_head));
		kfree(isr_cursor);
	}

	/* If the device was MSIx capable -
	 * free the MSIx related resources */
	if (pci_find_capability(dev->dev, PCI_CAP_ID_MSIX)) {
		if (NULL != dev->intr_info.msix_entries) {
			pci_disable_msix(dev->dev);
			kfree(dev->intr_info.msix_entries);
		}
	}

	if (pci_find_capability(dev->dev, PCI_CAP_ID_MSI)
	    && (0 != dev->intr_info.intr_vectors_cnt)) {
		dev_print_dbg(dev, "Disabling MSI\n");
		pci_disable_msi(dev->dev);
	}

disable_dev:
	if (dev->enabled)
		pci_disable_device(dev->dev);
}

/*******************************************************************************
 * Function     : cleanup_per_pci_devices
 *
 * Arguments    : pci device
 *
 * Return Value : None
 *
 * Description  : Does the cleanup of one pci devices
 *
 ******************************************************************************/
static void cleanup_per_pci_devices(fsl_pci_dev_t *dev_cursor)
{
		/* To do crypto layer related cleanup
		 * corresponding to this device */
		cleanup_crypto_device(dev_cursor->crypto_dev);
		/* Cleanup the PCI related resources */
		cleanup_pci_device(dev_cursor);
		/* Delete the device from list */
		list_del(&(dev_cursor->list));
		kfree(dev_cursor);
}


/*******************************************************************************
 * Function     : cleanup_pci_devices
 *
 * Arguments    : void
 *
 * Return Value : None
 *
 * Description  : Does the cleanup of all the pci devices
 *
 ******************************************************************************/
static void cleanup_pci_devices(void)
{
	fsl_pci_dev_t *dev_cursor = NULL;
	fsl_pci_dev_t *dev_n_cursor = NULL;

	list_for_each_entry_safe(dev_cursor, dev_n_cursor, &pci_dev_list, list) {
		/* To do crypto layer related cleanup
		 * corresponding to this device */
		cleanup_crypto_device(dev_cursor->crypto_dev);
		/* Cleanup the PCI related resources */
		cleanup_pci_device(dev_cursor);
		/* Delete the device from list */
		list_del(&(dev_cursor->list));
		kfree(dev_cursor);
	}

}

/*******************************************************************************
 * Function     : cleanup_percore_list
 *
 * Arguments    : void
 *
 * Return Value : None
 *
 * Description  : Destroys the per core information
 *
 ******************************************************************************/
static void cleanup_percore_list(void)
{
	uint32_t i = 0;
	per_core_struct_t *cursor = NULL;

	if (per_core == NULL)
		return;

	for_each_online_cpu(i)
	{
		if (!(wt_cpu_mask & (1 << i)))
			continue;

		cursor = per_cpu_ptr(per_core, i);
		if (NULL == cursor)
			return;
		if (NULL != cursor->bh_handler.workq) {
			flush_workqueue(cursor->bh_handler.workq);
			destroy_workqueue(cursor->bh_handler.workq);
		}
		list_del(&(cursor->ring_list_head));
	}

	free_percpu(per_core);
}

/*******************************************************************************
 * Function     : cleanup_config_list
 *
 * Arguments    : void
 *
 * Return Value : None
 *
 * Description  : Destroys the configuration list
 *
 ******************************************************************************/
static void cleanup_config_list(void)
{
	crypto_dev_config_t *config = NULL;
	crypto_dev_config_t *next_config = NULL;

	list_for_each_entry_safe(config, next_config, &crypto_dev_config_list,
				 list) {
		list_del(&(config->list));
		kfree(config);
	}
}

/*******************************************************************************
 * Function     : fsl_drv_init
 *
 * Arguments    : void
 *
 * Return Value : None
 *
 * Description  : Module initialization function. Init all the resources.
 *
 ******************************************************************************/
static int32_t __init fsl_crypto_drv_init(void)
{
	int32_t ret = 0;
	int32_t devno = 1;
    fsl_pci_dev_t *dev_cursor = NULL;
	fsl_pci_dev_t *dev_n_cursor = NULL;
	
	if (-1 == wt_cpu_mask) {
		print_info("CPU mask for NAPI threads "
                "is not specified, using one thread per cpu\n");
        for_each_online_cpu(ret)
            wt_cpu_mask |= ((1 << ret));
    }
    else
		print_info("CPU mask for NAPI threads "
                "is specified, configured value : 0x%x\n", wt_cpu_mask);

    if ( -1 == napi_poll_count ) {
        napi_poll_count = 1;
        print_info("NAPI poll count "
                "is not specified, using default value : %d\n", napi_poll_count);
    }
    else{
        print_info("NAPI poll count "
                "is specified, configured value : %d\n", napi_poll_count);
    }

	ret = 0;

	/* Read the configuration file - Path will be passed as module param */
	if (likely(parse_config_file(dev_config_file) < 0)) {
		print_error("Invalid path/configuration file\n");
		return -1;
	}

    if(init_common_sysfs( ) ) {
        print_error("Sysfs creation failed\n");
        return -1;
    }

	/* Create the per core data structures */
	if (unlikely(create_per_core_info())) {
		print_error("Per cpu alloc failed\n");
		ret = -1;
		goto cleanup;
	}

	/* Register the PCIe driver for the device,
	 * The register function will return success if the
	 * device is not present, hence an additional check
	 * to see whether device list is initialized
	 * or not.
	 */
	ret = pci_register_driver(&fsl_cypto_driver);
	if (ret < 0) {
		print_error
		    ("[FSL CRYPTO DRV:%s:%d] pci_register_driver( ) failed ",
		     __func__, __LINE__);
		goto cleanup;
	}
	
	pci_driver_registered = true;

	/* If there is no device detected -- goto error */
	if (!dev_no) {
		print_error("\n NO DEVICE FOUND...\n");
		goto cleanup;
	}
	
	ret = -1;
	list_for_each_entry_safe(dev_cursor, dev_n_cursor, &pci_dev_list,
			list) {
		if (-1 == dev_cursor->dev_status) {
			print_error("\n Dev no [%d] failed\n", dev_cursor->dev_no);
			print_debug("**** RESETTING THE DEVICE ****\n");
			print_debug("BAR0 V ADDR    :%p\n",
					dev_cursor->bars[PCI_BAR_NUM_0].v_addr);

			FSL_DEVICE_WRITE32_BAR0_REG(dev_cursor->bars[PCI_BAR_NUM_0].
					v_addr, PIC_PIR, 0x1);
			smp_wmb();
			cleanup_per_pci_devices(dev_cursor);
			--dev_no;
		}
		else
			/* Atleast one device is up */
			ret = 0;
	}
	if( -1 == ret ){
		print_error("\n All devices failed....\n");
		goto cleanup;
	}
	/* Assigning new device no for all active device */
	list_for_each_entry_safe(dev_cursor, dev_n_cursor, &pci_dev_list,
                        list) {
		dev_cursor->dev_no = devno++;
	} 
#ifdef USE_HOST_DMA
	/* For P4080 RC DMA channels will be used for transfer */
	if (-1 == init_rc_dma()) {
		print_error("\n Init DMA failed...\n");
		goto cleanup;
	}
#endif
	if (0 != fsl_cryptodev_register()) {
		print_error("ERROR:fsl_cryptodev_register\n");
		goto cleanup;
	}

/* #ifdef KCAPI_INTEG_BUILD */
#ifndef VIRTIO_C2X0
	fsl_algapi_init();
#endif
#ifdef RNG_OFFLOAD
	rng_init();
#endif

#ifndef VIRTIO_C2X0
	init_all_test();
#endif
/* #endif */
#ifdef VIRTIO_C2X0
	/* rng_init(); */
	INIT_LIST_HEAD(&virtio_c2x0_cmd_list);
	INIT_LIST_HEAD(&virtio_c2x0_hash_sess_list);
	INIT_LIST_HEAD(&virtio_c2x0_symm_sess_list);
	spin_lock_init(&cmd_list_lock);
	spin_lock_init(&hash_sess_list_lock);
	spin_lock_init(&symm_sess_list_lock);
#endif

	return 0;

cleanup:
	/* Clean up all the devices and the resources */
    if (true == pci_driver_registered) {
		fsl_pci_dev_t *dev_cursor = NULL;
		list_for_each_entry(dev_cursor, &pci_dev_list, list) {
			FSL_DEVICE_WRITE32_BAR0_REG(dev_cursor->
						bars[PCI_BAR_NUM_0].v_addr, PIC_PIR,
						0x1);
			smp_wmb();
		}
                /* Unregister the PCI driver */
	        pci_unregister_driver(&fsl_cypto_driver);
	}
	/* Cleanup the configuration file linked list */
	cleanup_config_list();
	/* Cleanup the per core linked list */
	cleanup_percore_list();
	/* Cleanup the devices */
	cleanup_pci_devices();
	/* Cleanup the sysfs entry */
	clean_common_sysfs();

	return -1;

}

/*******************************************************************************
 * Function     : fsl_crypto_pci_remove
 *
 * Arguments    : dev : PCI device structure instance.
 *                id  : Id of the PCI device.
 *
 * Return Value : int32_t
 *
 * Description  : Handles the PCI probe of the device.
 *
 ******************************************************************************/
static void fsl_crypto_pci_remove(struct pci_dev *dev)
{

	fsl_pci_dev_t *fsl_pci_dev = dev_get_drvdata(&(dev->dev));

	if (unlikely(NULL == fsl_pci_dev)) {
		DEV_PRINT_ERROR("No such device\n");
		return;
	}

	/* To do crypto layer related cleanup corresponding to this device */
	cleanup_crypto_device(fsl_pci_dev->crypto_dev);
	/* Cleanup the PCI related resources */
	cleanup_pci_device(fsl_pci_dev);
	/* Delete the device from list */
	list_del(&(fsl_pci_dev->list));

	kfree(fsl_pci_dev);

}

/*******************************************************************************
 * Function     : fsl_drv_exit
 *
 * Arguments    : void
 *
 * Return Value : None
 *
 * Description  : Cleanup function. Destroys all the resources.
 *
 ******************************************************************************/
static void __exit fsl_crypto_drv_exit(void)
{
	fsl_pci_dev_t *dev_cursor = NULL;

#ifdef RNG_OFFLOAD 
	rng_exit();
#endif
#ifndef VIRTIO_C2X0
	fsl_algapi_exit();
#endif

	list_for_each_entry(dev_cursor, &pci_dev_list, list) {
		print_debug("**** RESETTING THE DEVICE ****\n");
		print_debug("BAR0 V ADDR	:%p\n",
			    dev_cursor->bars[PCI_BAR_NUM_0].v_addr);
		/* FSL_DEVICE_WRITE32_BAR0_REG(dev_cursor->bars[PCI_BAR_NUM_0].
		   v_addr, 0x0e00b0, 0x2); */
		/*FSL_DEVICE_WRITE32_BAR0_REG(dev_cursor->
					    bars[PCI_BAR_NUM_0].v_addr, PIC_PIR,
					    0x1);
		*/
		smp_wmb();
	}
#ifdef USE_HOST_DMA
	cleanup_rc_dma();
#endif
	/* Unregister the fsl_crypto device node */
	fsl_cryptodev_deregister();

	/* Clean up all the devices and the resources */
	if (true == pci_driver_registered)
		/* Unregister the PCI driver */
		pci_unregister_driver(&fsl_cypto_driver);

    clean_common_sysfs();

	/* Cleanup the configuration file linked list */
	cleanup_config_list();

	/* Cleanup the per core linked list */
	cleanup_percore_list();

#ifndef VIRTIO_C2X0
	clean_all_test();
#endif

	return;
}

/* Registering Init/Exit function of driver with kernel */
module_init(fsl_crypto_drv_init);
module_exit(fsl_crypto_drv_exit);

MODULE_AUTHOR("FSL");
MODULE_DESCRIPTION("FSL c2x0 Device driver ");
MODULE_VERSION("Version 1.0.1");
MODULE_LICENSE("Dual BSD/GPL");
