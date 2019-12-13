/*
 * Driver for /dev/crypto device (aka CryptoDev)
 *
 * Copyright (c) 2004 Michal Ludvig <mludvig@logix.net.nz>, SuSE Labs
 * Copyright (c) 2009,2010,2011 Nikos Mavrogiannopoulos <nmav@gnutls.org>
 * Copyright (c) 2010 Phil Sutter
 * Copyright 2012-2014 Freescale Semiconductor, Inc.
 *
 * This file is part of linux cryptodev.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

/*
 * Device /dev/crypto provides an interface for
 * accessing kernel CryptoAPI algorithms (ciphers,
 * hashes) from userspace programs.
 *
 * /dev/crypto interface was originally introduced in
 * OpenBSD and this module attempts to keep the API.
 *
 */

#include <crypto/hash.h>
#include <linux/crypto.h>
#include <linux/mm.h>
#include <linux/highmem.h>
#include <linux/ioctl.h>
#include <linux/random.h>
#include <linux/syscalls.h>
#include <linux/pagemap.h>
#include <linux/poll.h>
#include <linux/uaccess.h>
#include <crypto/cryptodev.h>
#include <linux/scatterlist.h>
#include <linux/rtnetlink.h>
#include <crypto/authenc.h>

#include <linux/sysctl.h>

#include "cryptodev_int.h"
#include "zc.h"
#include "version.h"
#include "cipherapi.h"

MODULE_AUTHOR("Nikos Mavrogiannopoulos <nmav@gnutls.org>");
MODULE_DESCRIPTION("CryptoDev driver");
MODULE_LICENSE("GPL");

/* ====== Compile-time config ====== */

/* Default (pre-allocated) and maximum size of the job queue.
 * These are free, pending and done items all together. */
#define DEF_COP_RINGSIZE 16
#define MAX_COP_RINGSIZE 64

/* ====== Module parameters ====== */

int cryptodev_verbosity;
module_param(cryptodev_verbosity, int, 0644);
MODULE_PARM_DESC(cryptodev_verbosity, "0: normal, 1: verbose, 2: debug");

#define GFP_DMA_BUFFER		1024

/* ====== CryptoAPI ====== */
struct todo_list_item {
	struct list_head __hook;
	struct kernel_crypt_op kcop;
	int result;
};

struct locked_list {
	struct list_head list;
	struct mutex lock;
};

struct crypt_priv {
	struct fcrypt fcrypt;
	struct locked_list free, todo, done;
	int itemcount;
	struct work_struct cryptask;
	wait_queue_head_t user_waiter;
	/* List of pending cryptodev_pkc asym requests */
	struct list_head asym_completed_list;
	/* For addition/removal of entry in pending list of asymmetric request*/
	spinlock_t completion_lock;
};

/* Asymmetric request Completion handler */
void cryptodev_complete_asym(struct crypto_async_request *req, int err)
{
	struct cryptodev_pkc *pkc = req->data;
	struct cryptodev_result *res = &pkc->result;

	crypto_free_pkc(pkc->s);
	pkc->s = NULL;
	res->err = err;
	if (pkc->type == SYNCHRONOUS) {
		complete(&res->completion);
	} else {
		struct crypt_priv *pcr = pkc->priv;
		spin_lock_bh(&pcr->completion_lock);
		list_add_tail(&pkc->list, &pcr->asym_completed_list);
		spin_unlock_bh(&pcr->completion_lock);
		/* wake for POLLIN */
		wake_up_interruptible(&pcr->user_waiter);
	}

	kfree(req);
}

#define FILL_SG(sg, ptr, len)					\
	do {							\
		(sg)->page = virt_to_page(ptr);			\
		(sg)->offset = offset_in_page(ptr);		\
		(sg)->length = len;				\
		(sg)->dma_address = 0;				\
	} while (0)

/* cryptodev's own workqueue, keeps crypto tasks from disturbing the force */
static struct workqueue_struct *cryptodev_wq;

/* Prepare session for future use. */
static int
crypto_create_session(struct fcrypt *fcr, struct session_op *sop)
{
	struct csession	*ses_new = NULL, *ses_ptr;
	int ret = 0;
	const char *alg_name = NULL;
	const char *hash_name = NULL;
	int hmac_mode = 1, stream = 0, aead = 0;

	/* Does the request make sense? */
	if (unlikely(!sop->cipher && !sop->mac)) {
		ddebug(1, "Both 'cipher' and 'mac' unset.");
		return -EINVAL;
	}

	switch (sop->cipher) {
	case 0:
		break;
	case CRYPTO_DES_CBC:
		alg_name = "cbc(des)";
		break;
	case CRYPTO_3DES_CBC:
		alg_name = "cbc(des3_ede)";
		break;
	case CRYPTO_BLF_CBC:
		alg_name = "cbc(blowfish)";
		break;
	case CRYPTO_AES_CBC:
		alg_name = "cbc(aes)";
		break;
	case CRYPTO_AES_ECB:
		alg_name = "ecb(aes)";
		break;
	case CRYPTO_AES_XTS:
		alg_name = "xts(aes)";
		break;
	case CRYPTO_CAMELLIA_CBC:
		alg_name = "cbc(camellia)";
		break;
	case CRYPTO_AES_CTR:
		alg_name = "ctr(aes)";
		stream = 1;
		break;
	case CRYPTO_AES_GCM:
		alg_name = "gcm(aes)";
		stream = 1;
		aead = 1;
		break;
	case CRYPTO_TLS10_3DES_CBC_HMAC_SHA1:
		alg_name = "tls10(hmac(sha1),cbc(des3_ede))";
		stream = 0;
		aead = 1;
		break;
	case CRYPTO_TLS10_AES_CBC_HMAC_SHA1:
		alg_name = "tls10(hmac(sha1),cbc(aes))";
		stream = 0;
		aead = 1;
		break;
	case CRYPTO_TLS11_3DES_CBC_HMAC_SHA1:
		alg_name = "tls11(hmac(sha1),cbc(des3_ede))";
		stream = 0;
		aead = 1;
		break;
	case CRYPTO_TLS11_AES_CBC_HMAC_SHA1:
		alg_name = "tls11(hmac(sha1),cbc(aes))";
		stream = 0;
		aead = 1;
		break;
	case CRYPTO_TLS12_3DES_CBC_HMAC_SHA1:
		alg_name = "tls12(hmac(sha1),cbc(des3_ede))";
		stream = 0;
		aead = 1;
		break;
	case CRYPTO_TLS12_AES_CBC_HMAC_SHA1:
		alg_name = "tls12(hmac(sha1),cbc(aes))";
		stream = 0;
		aead = 1;
		break;
	case CRYPTO_TLS12_AES_CBC_HMAC_SHA256:
		alg_name = "tls12(hmac(sha256),cbc(aes))";
		stream = 0;
		aead = 1;
		break;
	case CRYPTO_AUTHENC_HMAC_SHA1_CBC_AES:
		alg_name = "authenc(hmac(sha1),cbc(aes))";
		stream = 0;
		aead = 1;
		break;
	case CRYPTO_NULL:
		alg_name = "ecb(cipher_null)";
		stream = 1;
		break;
	default:
		ddebug(1, "bad cipher: %d", sop->cipher);
		return -EINVAL;
	}

	switch (sop->mac) {
	case 0:
		break;
	case CRYPTO_MD5_HMAC:
		hash_name = "hmac(md5)";
		break;
	case CRYPTO_RIPEMD160_HMAC:
		hash_name = "hmac(rmd160)";
		break;
	case CRYPTO_SHA1_HMAC:
		hash_name = "hmac(sha1)";
		break;
	case CRYPTO_SHA2_224_HMAC:
		hash_name = "hmac(sha224)";
		break;

	case CRYPTO_SHA2_256_HMAC:
		hash_name = "hmac(sha256)";
		break;
	case CRYPTO_SHA2_384_HMAC:
		hash_name = "hmac(sha384)";
		break;
	case CRYPTO_SHA2_512_HMAC:
		hash_name = "hmac(sha512)";
		break;

	/* non-hmac cases */
	case CRYPTO_MD5:
		hash_name = "md5";
		hmac_mode = 0;
		break;
	case CRYPTO_RIPEMD160:
		hash_name = "rmd160";
		hmac_mode = 0;
		break;
	case CRYPTO_SHA1:
		hash_name = "sha1";
		hmac_mode = 0;
		break;
	case CRYPTO_SHA2_224:
		hash_name = "sha224";
		hmac_mode = 0;
		break;
	case CRYPTO_SHA2_256:
		hash_name = "sha256";
		hmac_mode = 0;
		break;
	case CRYPTO_SHA2_384:
		hash_name = "sha384";
		hmac_mode = 0;
		break;
	case CRYPTO_SHA2_512:
		hash_name = "sha512";
		hmac_mode = 0;
		break;
	case CRYPTO_CRC32C:
		hash_name = "crc32c";
		hmac_mode = 0;
		break;
	default:
		ddebug(1, "bad mac: %d", sop->mac);
		return -EINVAL;
	}

	/* Create a session and put it to the list. Zeroing the structure helps
	 * also with a single exit point in case of errors */
	ses_new = kzalloc(sizeof(*ses_new), GFP_KERNEL);
	if (!ses_new)
		return -ENOMEM;

	/* Set-up crypto transform. */
	if (alg_name) {
		unsigned int keylen;
		uint8_t *ckey;

		ret = cryptodev_get_cipher_keylen(&keylen, sop, aead);
		if (unlikely(ret < 0)) {
			ddebug(1, "Setting key failed for %s-%zu.",
				alg_name, (size_t)sop->keylen*8);
			goto session_error;
		}

		ckey = kmalloc(CRYPTO_CIPHER_MAX_KEY_LEN + CRYPTO_HMAC_MAX_KEY_LEN +
			       RTA_SPACE(sizeof(struct crypto_authenc_key_param)), GFP_DMA);
		if (unlikely(!ckey)) {
			ret = -ENOMEM;
			goto session_error;
                }

		ret = cryptodev_get_cipher_key(ckey, sop, aead);
		if (unlikely(ret < 0)) {
			kfree(ckey);
			goto session_error;
		}

		ret = cryptodev_cipher_init(&ses_new->cdata, alg_name, ckey,
						keylen, stream, aead);
		kfree(ckey);
		if (ret < 0) {
			ddebug(1, "Failed to load cipher for %s", alg_name);
			ret = -EINVAL;
			goto session_error;
		}
	}

	if (hash_name && aead == 0) {
		uint8_t *mkey = kmalloc(CRYPTO_HMAC_MAX_KEY_LEN, GFP_DMA);

		if (unlikely(!mkey)) {
			ret = -ENOMEM;
			goto session_error;
		}

		if (unlikely(sop->mackeylen > CRYPTO_HMAC_MAX_KEY_LEN)) {
			ddebug(1, "Setting key failed for %s-%zu.",
				hash_name, (size_t)sop->mackeylen*8);
			kfree(mkey);
			ret = -EINVAL;
			goto session_error;
		}

		if (sop->mackey && unlikely(copy_from_user(mkey, sop->mackey,
					    sop->mackeylen))) {
			kfree(mkey);
			ret = -EFAULT;
			goto session_error;
		}

		ret = cryptodev_hash_init(&ses_new->hdata, hash_name, hmac_mode,
					  mkey, sop->mackeylen);
		kfree(mkey);
		if (ret != 0) {
			ddebug(1, "Failed to load hash for %s", hash_name);
			ret = -EINVAL;
			goto session_error;
		}

		ret = cryptodev_hash_reset(&ses_new->hdata);
		if (ret != 0) {
			goto session_error;
		}
	}

	ses_new->alignmask = max(ses_new->cdata.alignmask,
	                                          ses_new->hdata.alignmask);
	ddebug(2, "got alignmask %d", ses_new->alignmask);

	ses_new->array_size = DEFAULT_PREALLOC_PAGES;
	ddebug(2, "preallocating for %d user pages", ses_new->array_size);
	ses_new->pages = kzalloc(ses_new->array_size *
			sizeof(struct page *), GFP_KERNEL);
	ses_new->sg = kzalloc(ses_new->array_size *
			sizeof(struct scatterlist), GFP_KERNEL);
	if (ses_new->sg == NULL || ses_new->pages == NULL) {
		ddebug(0, "Memory error");
		ret = -ENOMEM;
		goto session_error;
	}

	/* put the new session to the list */
	get_random_bytes(&ses_new->sid, sizeof(ses_new->sid));
	mutex_init(&ses_new->sem);

	mutex_lock(&fcr->sem);
restart:
	list_for_each_entry(ses_ptr, &fcr->list, entry) {
		/* Check for duplicate SID */
		if (unlikely(ses_new->sid == ses_ptr->sid)) {
			get_random_bytes(&ses_new->sid, sizeof(ses_new->sid));
			/* Unless we have a broken RNG this
			   shouldn't loop forever... ;-) */
			goto restart;
		}
	}

	list_add(&ses_new->entry, &fcr->list);
	mutex_unlock(&fcr->sem);

	/* Fill in some values for the user. */
	sop->ses = ses_new->sid;
	return 0;

	/* We count on ses_new to be initialized with zeroes
	 * Since hdata and cdata are embedded within ses_new, it follows that
	 * hdata->init and cdata->init are either zero or one as they have been
	 * initialized or not */
session_error:
	cryptodev_hash_deinit(&ses_new->hdata);
	cryptodev_cipher_deinit(&ses_new->cdata);
	kfree(ses_new->sg);
	kfree(ses_new->pages);
	kfree(ses_new);
	return ret;
}

static inline void hash_destroy_session(struct csession *ses_ptr)
{
	cryptodev_hash_deinit(&ses_ptr->hdata);
	kfree(ses_ptr->pages);
	kfree(ses_ptr->sg);
	kfree(ses_ptr);
}

static int hash_create_session(struct hash_op_data *hash_op)
{
	struct csession	*ses;
	int ret = 0;
	const char *hash_name;
	int hmac_mode = 1;
	uint8_t *mkey = kmalloc(CRYPTO_HMAC_MAX_KEY_LEN, GFP_DMA);

	if (unlikely(!mkey))
		return -ENOMEM;

	switch (hash_op->mac_op) {
	case CRYPTO_MD5_HMAC:
		hash_name = "hmac(md5)";
		break;
	case CRYPTO_RIPEMD160_HMAC:
		hash_name = "hmac(rmd160)";
		break;
	case CRYPTO_SHA1_HMAC:
		hash_name = "hmac(sha1)";
		break;
	case CRYPTO_SHA2_224_HMAC:
		hash_name = "hmac(sha224)";
		break;
	case CRYPTO_SHA2_256_HMAC:
		hash_name = "hmac(sha256)";
		break;
	case CRYPTO_SHA2_384_HMAC:
		hash_name = "hmac(sha384)";
		break;
	case CRYPTO_SHA2_512_HMAC:
		hash_name = "hmac(sha512)";
		break;
	/* non-hmac cases */
	case CRYPTO_MD5:
		hash_name = "md5";
		hmac_mode = 0;
		break;
	case CRYPTO_RIPEMD160:
		hash_name = "rmd160";
		hmac_mode = 0;
		break;
	case CRYPTO_SHA1:
		hash_name = "sha1";
		hmac_mode = 0;
		break;
	case CRYPTO_SHA2_224:
		hash_name = "sha224";
		hmac_mode = 0;
		break;
	case CRYPTO_SHA2_256:
		hash_name = "sha256";
		hmac_mode = 0;
		break;
	case CRYPTO_SHA2_384:
		hash_name = "sha384";
		hmac_mode = 0;
		break;
	case CRYPTO_SHA2_512:
		hash_name = "sha512";
		hmac_mode = 0;
		break;
	default:
		ddebug(1, "bad mac: %d", hash_op->mac_op);
		kfree(mkey);
		return -EINVAL;
	}

	ses = kzalloc(sizeof(*ses), GFP_KERNEL);
	if (!ses) {
		kfree(mkey);
		return -ENOMEM;
	}

	if (unlikely(hash_op->mackeylen > CRYPTO_HMAC_MAX_KEY_LEN)) {
		ddebug(1, "Setting key failed for %s-%zu.", hash_name,
		       (size_t)hash_op->mackeylen * 8);
		ret = -EINVAL;
		goto error_hash;
	}

	if (hash_op->mackey &&
	    unlikely(copy_from_user(mkey, hash_op->mackey, hash_op->mackeylen))) {
		ret = -EFAULT;
		goto error_hash;
	}

	ret = cryptodev_hash_init(&ses->hdata, hash_name, hmac_mode,
			mkey, hash_op->mackeylen);
	if (ret != 0) {
		ddebug(1, "Failed to load hash for %s", hash_name);
		ret = -EINVAL;
		goto error_hash;
	}

	ses->alignmask = ses->hdata.alignmask;
	ddebug(2, "got alignmask %d", ses->alignmask);

	ses->array_size = DEFAULT_PREALLOC_PAGES;
	ddebug(2, "preallocating for %d user pages", ses->array_size);

	ses->pages = kzalloc(ses->array_size * sizeof(struct page *), GFP_KERNEL);
	ses->sg = kzalloc(ses->array_size * sizeof(struct scatterlist), GFP_KERNEL);
	if (ses->sg == NULL || ses->pages == NULL) {
		ddebug(0, "Memory error");
		ret = -ENOMEM;
		goto error_hash;
	}

	hash_op->ses = ses;
	return 0;

error_hash:
	kfree(mkey);
	hash_destroy_session(ses);
	return ret;
}

/* Everything that needs to be done when removing a session. */
static inline void
crypto_destroy_session(struct csession *ses_ptr)
{
	if (!mutex_trylock(&ses_ptr->sem)) {
		ddebug(2, "Waiting for semaphore of sid=0x%08X", ses_ptr->sid);
		mutex_lock(&ses_ptr->sem);
	}
	ddebug(2, "Removed session 0x%08X", ses_ptr->sid);
	cryptodev_cipher_deinit(&ses_ptr->cdata);
	cryptodev_hash_deinit(&ses_ptr->hdata);
	ddebug(2, "freeing space for %d user pages", ses_ptr->array_size);
	kfree(ses_ptr->pages);
	kfree(ses_ptr->sg);
	mutex_unlock(&ses_ptr->sem);
	mutex_destroy(&ses_ptr->sem);
	kfree(ses_ptr);
}

/* Look up a session by ID and remove. */
static int
crypto_finish_session(struct fcrypt *fcr, uint32_t sid)
{
	struct csession *tmp, *ses_ptr;
	struct list_head *head;
	int ret = 0;

	mutex_lock(&fcr->sem);
	head = &fcr->list;
	list_for_each_entry_safe(ses_ptr, tmp, head, entry) {
		if (ses_ptr->sid == sid) {
			list_del(&ses_ptr->entry);
			crypto_destroy_session(ses_ptr);
			break;
		}
	}

	if (unlikely(!ses_ptr)) {
		derr(1, "Session with sid=0x%08X not found!", sid);
		ret = -ENOENT;
	}
	mutex_unlock(&fcr->sem);

	return ret;
}

/* Remove all sessions when closing the file */
static int
crypto_finish_all_sessions(struct fcrypt *fcr)
{
	struct csession *tmp, *ses_ptr;
	struct list_head *head;

	mutex_lock(&fcr->sem);

	head = &fcr->list;
	list_for_each_entry_safe(ses_ptr, tmp, head, entry) {
		list_del(&ses_ptr->entry);
		crypto_destroy_session(ses_ptr);
	}
	mutex_unlock(&fcr->sem);

	return 0;
}

/* Look up session by session ID. The returned session is locked. */
struct csession *
crypto_get_session_by_sid(struct fcrypt *fcr, uint32_t sid)
{
	struct csession *ses_ptr, *retval = NULL;

	if (unlikely(fcr == NULL))
		return NULL;

	mutex_lock(&fcr->sem);
	list_for_each_entry(ses_ptr, &fcr->list, entry) {
		if (ses_ptr->sid == sid) {
			mutex_lock(&ses_ptr->sem);
			retval = ses_ptr;
			break;
		}
	}
	mutex_unlock(&fcr->sem);

	return retval;
}

#ifdef CIOCCPHASH
/* Copy the hash state from one session to another */
static int
crypto_copy_hash_state(struct fcrypt *fcr, uint32_t dst_sid, uint32_t src_sid)
{
	struct csession *src_ses, *dst_ses;
	int ret;

	src_ses = crypto_get_session_by_sid(fcr, src_sid);
	if (unlikely(src_ses == NULL)) {
		derr(1, "Session with sid=0x%08X not found!", src_sid);
		return -ENOENT;
	}

	dst_ses = crypto_get_session_by_sid(fcr, dst_sid);
	if (unlikely(dst_ses == NULL)) {
		derr(1, "Session with sid=0x%08X not found!", dst_sid);
		crypto_put_session(src_ses);
		return -ENOENT;
	}

	ret = cryptodev_hash_copy(&dst_ses->hdata, &src_ses->hdata);
	crypto_put_session(src_ses);
	crypto_put_session(dst_ses);
	return ret;
}
#endif /* CIOCCPHASH */

static void cryptask_routine(struct work_struct *work)
{
	struct crypt_priv *pcr = container_of(work, struct crypt_priv, cryptask);
	struct todo_list_item *item;
	LIST_HEAD(tmp);

	/* fetch all pending jobs into the temporary list */
	mutex_lock(&pcr->todo.lock);
	list_cut_position(&tmp, &pcr->todo.list, pcr->todo.list.prev);
	mutex_unlock(&pcr->todo.lock);

	/* handle each job locklessly */
	list_for_each_entry(item, &tmp, __hook) {
		item->result = crypto_run(&pcr->fcrypt, &item->kcop);
		if (unlikely(item->result))
			derr(0, "crypto_run() failed: %d", item->result);
	}

	/* push all handled jobs to the done list at once */
	mutex_lock(&pcr->done.lock);
	list_splice_tail(&tmp, &pcr->done.list);
	mutex_unlock(&pcr->done.lock);

	/* wake for POLLIN */
	wake_up_interruptible(&pcr->user_waiter);
}

/* ====== /dev/crypto ====== */

static int
cryptodev_open(struct inode *inode, struct file *filp)
{
	struct todo_list_item *tmp, *tmp_next;
	struct crypt_priv *pcr;
	int i;

	pcr = kzalloc(sizeof(*pcr), GFP_KERNEL);
	if (!pcr)
		return -ENOMEM;
	filp->private_data = pcr;

	mutex_init(&pcr->fcrypt.sem);
	mutex_init(&pcr->free.lock);
	mutex_init(&pcr->todo.lock);
	mutex_init(&pcr->done.lock);

	INIT_LIST_HEAD(&pcr->fcrypt.list);
	INIT_LIST_HEAD(&pcr->free.list);
	INIT_LIST_HEAD(&pcr->todo.list);
	INIT_LIST_HEAD(&pcr->done.list);
	INIT_LIST_HEAD(&pcr->asym_completed_list);
	spin_lock_init(&pcr->completion_lock);

	INIT_WORK(&pcr->cryptask, cryptask_routine);

	init_waitqueue_head(&pcr->user_waiter);

	for (i = 0; i < DEF_COP_RINGSIZE; i++) {
		tmp = kzalloc(sizeof(struct todo_list_item), GFP_KERNEL);
		if (!tmp)
			goto err_ringalloc;
		pcr->itemcount++;
		ddebug(2, "allocated new item at %p", tmp);
		list_add(&tmp->__hook, &pcr->free.list);
	}

	ddebug(2, "Cryptodev handle initialised, %d elements in queue",
			DEF_COP_RINGSIZE);
	return 0;

/* In case of errors, free any memory allocated so far */
err_ringalloc:
	list_for_each_entry_safe(tmp, tmp_next, &pcr->free.list, __hook) {
		list_del(&tmp->__hook);
		kfree(tmp);
	}
	mutex_destroy(&pcr->done.lock);
	mutex_destroy(&pcr->todo.lock);
	mutex_destroy(&pcr->free.lock);
	mutex_destroy(&pcr->fcrypt.sem);
	kfree(pcr);
	filp->private_data = NULL;
	return -ENOMEM;
}

static int
cryptodev_release(struct inode *inode, struct file *filp)
{
	struct crypt_priv *pcr = filp->private_data;
	struct todo_list_item *item, *item_safe;
	int items_freed = 0;

	if (!pcr)
		return 0;

	cancel_work_sync(&pcr->cryptask);

	list_splice_tail(&pcr->todo.list, &pcr->free.list);
	list_splice_tail(&pcr->done.list, &pcr->free.list);

	list_for_each_entry_safe(item, item_safe, &pcr->free.list, __hook) {
		ddebug(2, "freeing item at %p", item);
		list_del(&item->__hook);
		kfree(item);
		items_freed++;
	}

	if (items_freed != pcr->itemcount) {
		derr(0, "freed %d items, but %d should exist!",
				items_freed, pcr->itemcount);
	}

	crypto_finish_all_sessions(&pcr->fcrypt);

	mutex_destroy(&pcr->done.lock);
	mutex_destroy(&pcr->todo.lock);
	mutex_destroy(&pcr->free.lock);
	mutex_destroy(&pcr->fcrypt.sem);

	kfree(pcr);
	filp->private_data = NULL;

	ddebug(2, "Cryptodev handle deinitialised, %d elements freed",
			items_freed);
	return 0;
}

static int
clonefd(struct file *filp)
{
	int ret;
	ret = get_unused_fd_flags(0);
	if (ret >= 0) {
			get_file(filp);
			fd_install(ret, filp);
	}

	return ret;
}

#ifdef ENABLE_ASYNC
/* enqueue a job for asynchronous completion
 *
 * returns:
 * -EBUSY when there are no free queue slots left
 *        (and the number of slots has reached it MAX_COP_RINGSIZE)
 * -EFAULT when there was a memory allocation error
 * 0 on success */
static int crypto_async_run(struct crypt_priv *pcr, struct kernel_crypt_op *kcop)
{
	struct todo_list_item *item = NULL;

	if (unlikely(kcop->cop.flags & COP_FLAG_NO_ZC))
		return -EINVAL;

	mutex_lock(&pcr->free.lock);
	if (likely(!list_empty(&pcr->free.list))) {
		item = list_first_entry(&pcr->free.list,
				struct todo_list_item, __hook);
		list_del(&item->__hook);
	} else if (pcr->itemcount < MAX_COP_RINGSIZE) {
		pcr->itemcount++;
	} else {
		mutex_unlock(&pcr->free.lock);
		return -EBUSY;
	}
	mutex_unlock(&pcr->free.lock);

	if (unlikely(!item)) {
		item = kzalloc(sizeof(struct todo_list_item), GFP_KERNEL);
		if (unlikely(!item))
			return -EFAULT;
		dinfo(1, "increased item count to %d", pcr->itemcount);
	}

	memcpy(&item->kcop, kcop, sizeof(struct kernel_crypt_op));

	mutex_lock(&pcr->todo.lock);
	list_add_tail(&item->__hook, &pcr->todo.list);
	mutex_unlock(&pcr->todo.lock);

	queue_work(cryptodev_wq, &pcr->cryptask);
	return 0;
}

/* get the first completed job from the "done" queue
 *
 * returns:
 * -EBUSY if no completed jobs are ready (yet)
 * the return value of crypto_run() otherwise */
static int crypto_async_fetch(struct crypt_priv *pcr,
		struct kernel_crypt_op *kcop)
{
	struct todo_list_item *item;
	int retval;

	mutex_lock(&pcr->done.lock);
	if (list_empty(&pcr->done.list)) {
		mutex_unlock(&pcr->done.lock);
		return -EBUSY;
	}
	item = list_first_entry(&pcr->done.list, struct todo_list_item, __hook);
	list_del(&item->__hook);
	mutex_unlock(&pcr->done.lock);

	memcpy(kcop, &item->kcop, sizeof(struct kernel_crypt_op));
	retval = item->result;

	mutex_lock(&pcr->free.lock);
	list_add_tail(&item->__hook, &pcr->free.list);
	mutex_unlock(&pcr->free.lock);

	/* wake for POLLOUT */
	wake_up_interruptible(&pcr->user_waiter);

	return retval;
}
#endif

/* get the first asym cipher completed job from the "done" queue
 *
 * returns:
 * -EBUSY if no completed jobs are ready (yet)
 * the return value otherwise */
static int crypto_async_fetch_asym(struct cryptodev_pkc *pkc)
{
	int ret = 0;
	struct kernel_crypt_kop *kop = &pkc->kop;
	struct crypt_kop *ckop = &kop->kop;

	switch (ckop->crk_op) {
	case CRK_MOD_EXP:
	{
		struct rsa_pub_req_s *rsa_req = &pkc->req->req_u.rsa_pub_req;
		ret = copy_to_user(ckop->crk_param[3].crp_p, rsa_req->g, rsa_req->g_len);
	}
	break;
	case CRK_MOD_EXP_CRT:
	{
		struct rsa_priv_frm3_req_s *rsa_req = &pkc->req->req_u.rsa_priv_f3;
		ret = copy_to_user(ckop->crk_param[6].crp_p, rsa_req->f, rsa_req->f_len);
	}
	break;
	case CRK_DSA_SIGN:
	{
		struct dsa_sign_req_s *dsa_req = &pkc->req->req_u.dsa_sign;

		if (pkc->req->type == ECDSA_SIGN) {
			ret = copy_to_user(ckop->crk_param[6].crp_p, dsa_req->c, dsa_req->d_len) ||
			      copy_to_user(ckop->crk_param[7].crp_p, dsa_req->d, dsa_req->d_len);
		} else {
			ret = copy_to_user(ckop->crk_param[5].crp_p, dsa_req->c, dsa_req->d_len) ||
			      copy_to_user(ckop->crk_param[6].crp_p, dsa_req->d, dsa_req->d_len);
		}
	}
	break;
	case CRK_DSA_VERIFY:
		break;
	case CRK_DH_COMPUTE_KEY:
	{
		struct dh_key_req_s *dh_req = &pkc->req->req_u.dh_req;
		if (pkc->req->type == ECDH_COMPUTE_KEY)
			ret = copy_to_user(ckop->crk_param[4].crp_p, dh_req->z, dh_req->z_len);
		else
			ret = copy_to_user(ckop->crk_param[3].crp_p, dh_req->z, dh_req->z_len);
	}
	break;
	case CRK_DSA_GENERATE_KEY:
	case CRK_DH_GENERATE_KEY:
	{
		struct keygen_req_s *key_req = &pkc->req->req_u.keygen;

		if (pkc->req->type == ECC_KEYGEN) {
			ret = copy_to_user(ckop->crk_param[4].crp_p, key_req->pub_key,
					key_req->pub_key_len) ||
			      copy_to_user(ckop->crk_param[5].crp_p, key_req->priv_key,
					key_req->priv_key_len);
		} else {
			ret = copy_to_user(ckop->crk_param[3].crp_p, key_req->pub_key,
					key_req->pub_key_len) ||
			      copy_to_user(ckop->crk_param[4].crp_p, key_req->priv_key,
					key_req->priv_key_len);
		}
	break;
	}
	default:
		ret = -EINVAL;
	}
	kfree(pkc->cookie);
	return ret;
}

/* this function has to be called from process context */
static int fill_kop_from_cop(struct kernel_crypt_kop *kop)
{
	kop->task = current;
	kop->mm = current->mm;
	return 0;
}

/* this function has to be called from process context */
static int fill_kcop_from_cop(struct kernel_crypt_op *kcop, struct fcrypt *fcr)
{
	struct crypt_op *cop = &kcop->cop;
	struct csession *ses_ptr;
	int rc;

	/* this also enters ses_ptr->sem */
	ses_ptr = crypto_get_session_by_sid(fcr, cop->ses);
	if (unlikely(!ses_ptr)) {
		derr(1, "invalid session ID=0x%08X", cop->ses);
		return -EINVAL;
	}
	kcop->ivlen = cop->iv ? ses_ptr->cdata.ivsize : 0;
	kcop->digestsize = 0; /* will be updated during operation */

	crypto_put_session(ses_ptr);

	kcop->task = current;
	kcop->mm = current->mm;

	if (cop->iv) {
		rc = copy_from_user(kcop->iv, cop->iv, kcop->ivlen);
		if (unlikely(rc)) {
			derr(1, "error copying IV (%d bytes), copy_from_user returned %d for address %p",
					kcop->ivlen, rc, cop->iv);
			return -EFAULT;
		}
	}

	return 0;
}

/* this function has to be called from process context */
static int fill_cop_from_kcop(struct kernel_crypt_op *kcop, struct fcrypt *fcr)
{
	int ret;

	if (kcop->digestsize) {
		ret = copy_to_user(kcop->cop.mac,
				kcop->hash_output, kcop->digestsize);
		if (unlikely(ret))
			return -EFAULT;
	}
	if (kcop->ivlen && kcop->cop.flags & COP_FLAG_WRITE_IV) {
		ret = copy_to_user(kcop->cop.iv,
				kcop->iv, kcop->ivlen);
		if (unlikely(ret))
			return -EFAULT;
	}
	return 0;
}

static int kop_from_user(struct kernel_crypt_kop *kop,
			void __user *arg)
{
	if (unlikely(copy_from_user(&kop->kop, arg, sizeof(kop->kop))))
		return -EFAULT;

	return fill_kop_from_cop(kop);
}

static int kcop_from_user(struct kernel_crypt_op *kcop,
			struct fcrypt *fcr, void __user *arg)
{
	if (unlikely(copy_from_user(&kcop->cop, arg, sizeof(kcop->cop))))
		return -EFAULT;

	return fill_kcop_from_cop(kcop, fcr);
}

static int kcop_to_user(struct kernel_crypt_op *kcop,
			struct fcrypt *fcr, void __user *arg)
{
	int ret;

	ret = fill_cop_from_kcop(kcop, fcr);
	if (unlikely(ret)) {
		derr(1, "Error in fill_cop_from_kcop");
		return ret;
	}

	if (unlikely(copy_to_user(arg, &kcop->cop, sizeof(kcop->cop)))) {
		derr(1, "Cannot copy to userspace");
		return -EFAULT;
	}
	return 0;
}

static inline void tfm_info_to_alg_info(struct alg_info *dst, struct crypto_tfm *tfm)
{
	snprintf(dst->cra_name, CRYPTODEV_MAX_ALG_NAME,
			"%s", crypto_tfm_alg_name(tfm));
	snprintf(dst->cra_driver_name, CRYPTODEV_MAX_ALG_NAME,
			"%s", crypto_tfm_alg_driver_name(tfm));
}

#ifndef CRYPTO_ALG_KERN_DRIVER_ONLY
static unsigned int is_known_accelerated(struct crypto_tfm *tfm)
{
	const char *name = crypto_tfm_alg_driver_name(tfm);

	if (name == NULL)
		return 1; /* assume accelerated */

	/* look for known crypto engine names */
	if (strstr(name, "-talitos")	||
	    !strncmp(name, "mv-", 3)	||
	    !strncmp(name, "atmel-", 6)	||
	    strstr(name, "geode")	||
	    strstr(name, "hifn")	||
	    strstr(name, "-ixp4xx")	||
	    strstr(name, "-omap")	||
	    strstr(name, "-picoxcell")	||
	    strstr(name, "-s5p")	||
	    strstr(name, "-ppc4xx")	||
	    strstr(name, "-caam")	||
	    strstr(name, "-n2"))
		return 1;

	return 0;
}
#endif

static int get_session_info(struct fcrypt *fcr, struct session_info_op *siop)
{
	struct csession *ses_ptr;
	struct crypto_tfm *tfm;

	/* this also enters ses_ptr->sem */
	ses_ptr = crypto_get_session_by_sid(fcr, siop->ses);
	if (unlikely(!ses_ptr)) {
		derr(1, "invalid session ID=0x%08X", siop->ses);
		return -EINVAL;
	}

	siop->flags = 0;

	if (ses_ptr->cdata.init) {
		if (ses_ptr->cdata.aead == 0)
			tfm = cryptodev_crypto_blkcipher_tfm(ses_ptr->cdata.async.s);
		else
			tfm = crypto_aead_tfm(ses_ptr->cdata.async.as);
		tfm_info_to_alg_info(&siop->cipher_info, tfm);
#ifdef CRYPTO_ALG_KERN_DRIVER_ONLY
		if (tfm->__crt_alg->cra_flags & CRYPTO_ALG_KERN_DRIVER_ONLY)
			siop->flags |= SIOP_FLAG_KERNEL_DRIVER_ONLY;
#else
		if (is_known_accelerated(tfm))
			siop->flags |= SIOP_FLAG_KERNEL_DRIVER_ONLY;
#endif
	}
	if (ses_ptr->hdata.init) {
		tfm = crypto_ahash_tfm(ses_ptr->hdata.async.s);
		tfm_info_to_alg_info(&siop->hash_info, tfm);
#ifdef CRYPTO_ALG_KERN_DRIVER_ONLY
		if (tfm->__crt_alg->cra_flags & CRYPTO_ALG_KERN_DRIVER_ONLY)
			siop->flags |= SIOP_FLAG_KERNEL_DRIVER_ONLY;
#else
		if (is_known_accelerated(tfm))
			siop->flags |= SIOP_FLAG_KERNEL_DRIVER_ONLY;
#endif
	}

	siop->alignmask = ses_ptr->alignmask;

	crypto_put_session(ses_ptr);
	return 0;
}

static void prf_req_free(struct prf_req_s **__req)
{
	struct prf_req_s *req = *__req;

	if (req == NULL)
		return;

	switch (req->prf_op) {
	case GEN_MASTER_SECRET:
	case GEN_SESSION_KEYS:
	case GEN_FINISH_RAND:
		kfree(req->dma_buf);
		break;
	default:
		pr_err(PFX"cryptodev memory leak !!!");
		break;
	}

	kzfree(req);
	*__req = NULL;

	return;
}

int get_gen_session_key_param(struct prf_req_s *req, struct prf_param *prfiop)
{
	struct gen_session_keys *in = &prfiop->req_u.gen_session_key;
	struct gen_session_keys_s *gen_ses_key = &req->req_u.gen_session_key;

	req->dma_len = (in->label.len + in->master_secret.len
			+ in->server_rand.len
			+ in->client_rand.len + in->out_client_mac_secret.len
			+ in->out_server_mac_secret.len
			+ in->out_client_write_key.len
			+ in->out_server_write_key.len
			+ in->out_client_write_iv.len
			+ in->out_server_write_iv.len + GFP_DMA_BUFFER);

	if (!in->out_client_mac_secret.black_key)
		req->dma_len += (2 * PRF_ENC_HMAC_SECRET_LEN);

	req->dma_buf = kzalloc(req->dma_len, GFP_DMA);
	if (!req->dma_buf)
		return -ENOMEM;

	gen_ses_key->cipher = in->cipher;
	gen_ses_key->label.len = in->label.len;
	gen_ses_key->master_secret.len = in->master_secret.len;
	gen_ses_key->server_rand.len = in->server_rand.len;
	gen_ses_key->client_rand.len = in->client_rand.len;
	gen_ses_key->out_client_mac_secret.len = in->out_client_mac_secret.len;
	gen_ses_key->out_server_mac_secret.len = in->out_server_mac_secret.len;
	if (!in->out_client_mac_secret.black_key)  {
		gen_ses_key->out_client_mac_secret.len =
			gen_ses_key->out_client_mac_secret.len +
			(PRF_ENC_HMAC_SECRET_LEN -
			gen_ses_key->out_client_mac_secret.len);
		gen_ses_key->out_server_mac_secret.len =
			gen_ses_key->out_server_mac_secret.len +
			(PRF_ENC_HMAC_SECRET_LEN -
			gen_ses_key->out_server_mac_secret.len);
	}
	gen_ses_key->out_client_write_key.len = in->out_client_write_key.len;
	gen_ses_key->out_server_write_key.len = in->out_server_write_key.len;
	gen_ses_key->out_client_write_iv.len = in->out_client_write_iv.len;
	gen_ses_key->out_server_write_iv.len = in->out_server_write_iv.len;

	gen_ses_key->label.param = req->dma_buf;
	gen_ses_key->client_rand.param = gen_ses_key->label.param
					+ gen_ses_key->label.len;
	gen_ses_key->server_rand.param = gen_ses_key->client_rand.param
					+ gen_ses_key->client_rand.len;
	gen_ses_key->master_secret.param = gen_ses_key->server_rand.param
					+ gen_ses_key->server_rand.len;
	gen_ses_key->out_client_write_key.param =
					gen_ses_key->master_secret.param
					+ gen_ses_key->master_secret.len;
	gen_ses_key->out_server_write_key.param =
					gen_ses_key->out_client_write_key.param
				+ gen_ses_key->out_client_write_key.len;
	gen_ses_key->out_client_write_iv.param =
					gen_ses_key->out_server_write_key.param
					+ gen_ses_key->out_server_write_key.len;
	gen_ses_key->out_server_write_iv.param =
					gen_ses_key->out_client_write_iv.param
					+ gen_ses_key->out_client_write_iv.len;
	gen_ses_key->out_client_mac_secret.param =
					gen_ses_key->out_server_write_iv.param
					+ gen_ses_key->out_server_write_iv.len;
	gen_ses_key->out_server_mac_secret.param =
					gen_ses_key->out_client_mac_secret.param
				+ gen_ses_key->out_client_mac_secret.len;


	if (unlikely(copy_from_user(gen_ses_key->label.param, in->label.param,
					gen_ses_key->label.len))) {
		pr_err(PFX"copy from user failed");
		return -EFAULT;
	}
	if (unlikely(copy_from_user(gen_ses_key->master_secret.param,
		in->master_secret.param, gen_ses_key->master_secret.len))) {
		pr_err(PFX"copy from user failed");
		return -EFAULT;
	}

	if (unlikely(copy_from_user(gen_ses_key->server_rand.param,
		in->server_rand.param, gen_ses_key->server_rand.len))) {
		pr_err(PFX"copy from user failed");
		return -EFAULT;
	}
	if (unlikely(copy_from_user(gen_ses_key->client_rand.param,
		in->client_rand.param, gen_ses_key->client_rand.len))) {
		pr_err(PFX"copy from user failed");
		return -EFAULT;
	}


	gen_ses_key->master_secret.black_key = in->master_secret.black_key;
	gen_ses_key->out_client_mac_secret.black_key =
				in->out_client_mac_secret.black_key;
	gen_ses_key->out_server_mac_secret.black_key =
				in->out_server_mac_secret.black_key;
	gen_ses_key->out_client_write_key.black_key =
				in->out_client_write_key.black_key;
	gen_ses_key->out_server_write_key.black_key =
				in->out_server_write_key.black_key;
	return 0;
}

static int copy_session_req_to_ms_req(struct prf_req_s *ms_req,
					struct prf_req_s *req)
{
	struct gen_session_keys_s *in = &req->req_u.gen_session_key;
	struct gen_master_secret_s *out = &ms_req->req_u.gen_ms;

	ms_req->prf_op = GEN_MASTER_SECRET;
	ms_req->tls_version = req->tls_version;
	req->dma_len = (in->label.len + in->master_secret.len + in->server_rand.len
			+ in->client_rand.len + in->out_client_mac_secret.len
			+ 128);
	req->dma_buf = kzalloc(req->dma_len, GFP_KERNEL);
	if (!req->dma_buf)
		return -ENOMEM;

	out->pre_master_secret.len = in->master_secret.len;
	out->label.len = in->label.len;
	out->server_rand.len = in->server_rand.len;
	out->client_rand.len = in->client_rand.len;
	out->out_master_secret.len = 128;

	out->label.param = req->dma_buf;
	out->pre_master_secret.param = out->label.param + out->label.len;
	out->server_rand.param = out->pre_master_secret.param +
						out->pre_master_secret.len;
	out->client_rand.param = out->server_rand.param + out->server_rand.len;
	out->out_master_secret.param = out->client_rand.param +
						out->client_rand.len;
	memcpy(out->label.param, in->label.param, out->label.len);
	out->pre_master_secret.black_key = in->master_secret.black_key;
	memcpy(out->pre_master_secret.param,
		in->master_secret.param, out->pre_master_secret.len);
	memcpy(out->server_rand.param, in->client_rand.param,
			out->server_rand.len);
	memcpy(out->client_rand.param,
		in->server_rand.param, out->client_rand.len);
	out->out_master_secret.black_key = 0;
	return 0;
}

void prepare_session_req(struct prf_req_s *req, struct prf_req_s *ms_req)
{
	struct gen_session_keys_s *out = &req->req_u.gen_session_key;
	struct gen_master_secret_s *in = &ms_req->req_u.gen_ms;

	out->out_client_mac_secret.len -= 28;
	out->out_server_mac_secret.len -= 28;
	memcpy(out->out_client_mac_secret.param,
		in->out_master_secret.param, out->out_client_mac_secret.len);
	memcpy(out->out_server_mac_secret.param,
		(in->out_master_secret.param +
			out->out_client_mac_secret.len),
		out->out_server_mac_secret.len);
	memcpy(out->out_client_write_key.param,
		(in->out_master_secret.param +
		out->out_client_mac_secret.len +
		out->out_server_mac_secret.len),
		out->out_client_write_key.len);
	memcpy(out->out_server_write_key.param,
		(in->out_master_secret.param +
		out->out_client_mac_secret.len +
		out->out_server_mac_secret.len +
		out->out_client_write_key.len),
		out->out_server_write_key.len);
}

int get_gen_ms_param(struct prf_req_s *req, struct prf_param *prfiop)
{
	struct gen_master_secret *in_ms_param = &prfiop->req_u.gen_ms;
	struct gen_master_secret_s *gen_ms = &req->req_u.gen_ms;

	if ((in_ms_param->pre_master_secret.len > PRF_PMS_MAX) ||
		(in_ms_param->label.len > PRF_LABEL_MAX))
		return -EINVAL;

	req->dma_len = (in_ms_param->label.len + in_ms_param->pre_master_secret.len
			+ gen_ms->server_rand.len +
			gen_ms->client_rand.len +
			gen_ms->out_master_secret.len + GFP_DMA_BUFFER);

	req->dma_buf = kzalloc(req->dma_len, GFP_DMA);
	if (!req->dma_buf)
		return -ENOMEM;

	gen_ms->pre_master_secret.len = in_ms_param->pre_master_secret.len;
	gen_ms->label.len = in_ms_param->label.len;
	gen_ms->server_rand.len = in_ms_param->server_rand.len;
	gen_ms->client_rand.len = in_ms_param->client_rand.len;
	gen_ms->out_master_secret.len = in_ms_param->out_master_secret.len;

	gen_ms->label.param = req->dma_buf;
	gen_ms->pre_master_secret.param = gen_ms->label.param +
						gen_ms->label.len;
	gen_ms->server_rand.param = gen_ms->pre_master_secret.param +
						gen_ms->pre_master_secret.len;
	gen_ms->client_rand.param = gen_ms->server_rand.param +
						gen_ms->server_rand.len;
	gen_ms->out_master_secret.param = gen_ms->client_rand.param +
						gen_ms->client_rand.len;

	if (unlikely(copy_from_user(gen_ms->label.param,
		in_ms_param->label.param,
		gen_ms->label.len))) {
		pr_err(PFX"copy from user failed");
		return -EFAULT;
	}

	gen_ms->pre_master_secret.black_key =
		in_ms_param->pre_master_secret.black_key;
	if (unlikely(copy_from_user(gen_ms->pre_master_secret.param,
		in_ms_param->pre_master_secret.param,
		gen_ms->pre_master_secret.len))) {
		pr_err(PFX"copy from user failed");
		return -EFAULT;
	}

	if (unlikely(copy_from_user(gen_ms->server_rand.param,
		in_ms_param->server_rand.param,
		gen_ms->server_rand.len))) {
		pr_err(PFX"copy from user failed");
		return -EFAULT;
	}

	if (unlikely(copy_from_user(gen_ms->client_rand.param,
		in_ms_param->client_rand.param,
		gen_ms->client_rand.len))) {
		pr_err(PFX"copy from user failed");
		return -EFAULT;
	}

	gen_ms->out_master_secret.black_key =
			in_ms_param->out_master_secret.black_key;
	return 0;
}

int get_gen_finish_param(struct prf_req_s *req, struct prf_param *prfiop)
{
	struct gen_finish_random *in_finish = &prfiop->req_u.gen_finish_rand;
	struct gen_finish_random_s *gen_finish = &req->req_u.gen_finish_rand;

	if ((in_finish->master_secret.len > PRF_MS_LEN) ||
		(in_finish->label.len > PRF_LABEL_MAX))
		return -EINVAL;

	req->dma_len = (in_finish->label.len + in_finish->master_secret.len
			+ gen_finish->seed1.len +
			gen_finish->seed2.len +
			gen_finish->out_data.len + GFP_DMA_BUFFER);
	req->dma_buf = kzalloc(req->dma_len, GFP_DMA);
	if (!req->dma_buf)
		return -ENOMEM;

	gen_finish->master_secret.len = in_finish->master_secret.len;
	gen_finish->label.len = in_finish->label.len;
	gen_finish->seed1.len = in_finish->seed1.len;
	gen_finish->seed2.len = in_finish->seed2.len;
	gen_finish->out_data.len = in_finish->out_data.len;

	gen_finish->label.param = req->dma_buf;
	gen_finish->master_secret.param = gen_finish->label.param +
						gen_finish->label.len;
	gen_finish->seed1.param = gen_finish->master_secret.param +
						gen_finish->master_secret.len;
	gen_finish->seed2.param = gen_finish->seed1.param +
						gen_finish->seed1.len;
	gen_finish->out_data.param = gen_finish->seed2.param +
						gen_finish->seed2.len;

	if (unlikely(copy_from_user(gen_finish->label.param,
		in_finish->label.param,
		gen_finish->label.len))) {
		pr_err(PFX"copy from user failed");
		return -EFAULT;
	}
	gen_finish->master_secret.black_key =
		in_finish->master_secret.black_key;
	if (unlikely(copy_from_user(gen_finish->master_secret.param,
		in_finish->master_secret.param,
		gen_finish->master_secret.len))) {
		pr_err(PFX"copy from user failed");
		return -EFAULT;
	}
	if (unlikely(copy_from_user(gen_finish->seed1.param,
		in_finish->seed1.param,
		gen_finish->seed1.len))) {
		pr_err(PFX"copy from user failed");
		return -EFAULT;
	}
	if (unlikely(copy_from_user(gen_finish->seed2.param,
		in_finish->seed2.param,
		gen_finish->seed2.len))) {
		pr_err(PFX"copy from user failed");
		return -EFAULT;
	}
	return 0;
}

static struct prf_req_s *get_and_validate_prf_param(struct prf_param *prfiop)
{
	struct prf_req_s *req = kzalloc(sizeof(struct prf_req_s), GFP_KERNEL);

	if (!req)
		return NULL;

	req->prf_op = prfiop->prf_op;
	req->tls_version = prfiop->tls_version;

	switch (req->prf_op) {
	case GEN_MASTER_SECRET:
		if (get_gen_ms_param(req, prfiop)) {
			prf_req_free(&req);
			pr_err(PFX"get_gen_ms_param failed!");
			return NULL;
		}
		break;
	case GEN_SESSION_KEYS:
		if (get_gen_session_key_param(req, prfiop)) {
			prf_req_free(&req);
			pr_err(PFX"get_gen_session_key_param failed!");
			return NULL;
		}
		break;
	case GEN_FINISH_RAND:
		if (get_gen_finish_param(req, prfiop)) {
			kfree(req);
			pr_err(PFX"get_gen_finish_param failed!");
			return NULL;
		}
		break;
	default:
		kfree(req);
		req = NULL;
	}

	return req;
}

static int prf_cop_to_user(struct prf_param *prfiop, struct prf_req_s *req)
{
	int ret = 0;
	int i;

#define DUMP(s, i, buf, sz)  { ddebug(1, s);                   \
	for (i = 0; i < (sz); i++)    \
		ddebug(1, "%02x ", buf[i]); \
	ddebug(1, "\n"); }
	switch (req->prf_op) {
	case GEN_MASTER_SECRET:
		DUMP("master secret", i,
		((unsigned char *)req->req_u.gen_ms.out_master_secret.param),
				req->req_u.gen_ms.out_master_secret.len);
		ret = copy_to_user(prfiop->req_u.gen_ms.out_master_secret.param,
				req->req_u.gen_ms.out_master_secret.param,
				req->req_u.gen_ms.out_master_secret.len);
		break;
	case GEN_SESSION_KEYS:
	{
		struct gen_session_keys *out = &prfiop->req_u.gen_session_key;
		struct gen_session_keys_s *in =	&req->req_u.gen_session_key;
		ret = copy_to_user(out->out_client_mac_secret.param,
				in->out_client_mac_secret.param,
				out->out_client_mac_secret.len);
		if (unlikely(ret)) {
			pr_err(PFX "copy to user failed");
			ret = -EFAULT;
		}
		ret = copy_to_user(out->out_server_mac_secret.param,
				in->out_server_mac_secret.param,
				out->out_server_mac_secret.len);
		if (unlikely(ret)) {
			pr_err(PFX "copy to user failed");
			ret = -EFAULT;
		}
		ret = copy_to_user(out->out_client_write_key.param,
				in->out_client_write_key.param,
				out->out_client_write_key.len);
		if (unlikely(ret)) {
			pr_err(PFX "copy to user failed");
			ret = -EFAULT;
		}
		ret = copy_to_user(out->out_server_write_key.param,
				in->out_server_write_key.param,
				out->out_server_write_key.len);
		if (unlikely(ret)) {
			pr_err(PFX "copy to user failed");
			ret = -EFAULT;
		}
		ret = copy_to_user(out->out_client_write_iv.param,
				in->out_client_write_iv.param,
				out->out_client_write_iv.len);
		if (unlikely(ret)) {
			pr_err(PFX "copy to user failed");
			ret = -EFAULT;
		}
		ret = copy_to_user(out->out_server_write_iv.param,
				in->out_server_write_iv.param,
				out->out_server_write_iv.len);
		if (unlikely(ret)) {
			pr_err(PFX "copy to user failed");
			ret = -EFAULT;
		}
		break;
	}
	case GEN_FINISH_RAND:
		DUMP("finish verify", i,
		((unsigned char *)req->req_u.gen_finish_rand.out_data.param),
				req->req_u.gen_finish_rand.out_data.len);
		ret = copy_to_user(prfiop->req_u.gen_finish_rand.out_data.param,
			req->req_u.gen_finish_rand.out_data.param,
			req->req_u.gen_finish_rand.out_data.len);

		break;
	default:
		pr_err(PFX"cryptodev memory leak !!!");
		break;
	}
#undef DUMP
	return ret;
}

static long
cryptodev_ioctl(struct file *filp, unsigned int cmd, unsigned long arg_)
{
	void __user *arg = (void __user *)arg_;
	int __user *p = arg;
	struct session_op sop;
	struct kernel_hash_op khop;
	struct kernel_crypt_op *kcop;
	struct kernel_crypt_auth_op kcaop;
	struct crypt_priv *pcr = filp->private_data;
	struct fcrypt *fcr;
	struct session_info_op siop;
#ifdef CIOCCPHASH
	struct cphash_op cphop;
#endif
	uint32_t ses;
	int ret = 0, fd;

	if (unlikely(!pcr))
		BUG();

	fcr = &pcr->fcrypt;

	switch (cmd) {
	case CIOCASYMFEAT:
		ses = 0;
		if (crypto_has_alg("pkc(rsa)", 0, 0))
			ses = CRF_MOD_EXP_CRT |	CRF_MOD_EXP | CRF_RSA_GENERATE_KEY;
		if (crypto_has_alg("pkc(dsa)", 0, 0))
			ses |= CRF_DSA_SIGN | CRF_DSA_VERIFY | CRF_DSA_GENERATE_KEY;
		if (crypto_has_alg("pkc(dh)", 0, 0))
			ses |= CRF_DH_COMPUTE_KEY |CRF_DH_GENERATE_KEY;
		return put_user(ses, p);
	case CRIOGET:
		fd = clonefd(filp);
		ret = put_user(fd, p);
		if (unlikely(ret)) {
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4, 17, 0))
			sys_close(fd);
#else
			ksys_close(fd);
#endif
			return ret;
		}
		return ret;
	case CIOCGSESSION:
		if (unlikely(copy_from_user(&sop, arg, sizeof(sop))))
			return -EFAULT;

		ret = crypto_create_session(fcr, &sop);
		if (unlikely(ret))
			return ret;
		ret = copy_to_user(arg, &sop, sizeof(sop));
		if (unlikely(ret)) {
			crypto_finish_session(fcr, sop.ses);
			return -EFAULT;
		}
		return ret;
	case CIOCFSESSION:
		ret = get_user(ses, (uint32_t __user *)arg);
		if (unlikely(ret))
			return ret;
		ret = crypto_finish_session(fcr, ses);
		return ret;
	case CIOCGSESSINFO:
		if (unlikely(copy_from_user(&siop, arg, sizeof(siop))))
			return -EFAULT;

		ret = get_session_info(fcr, &siop);
		if (unlikely(ret))
			return ret;
		return copy_to_user(arg, &siop, sizeof(siop));
#ifdef CIOCCPHASH
	case CIOCCPHASH:
		if (unlikely(copy_from_user(&cphop, arg, sizeof(cphop))))
			return -EFAULT;
		return crypto_copy_hash_state(fcr, cphop.dst_ses, cphop.src_ses);
#endif /* CIOCPHASH */

#ifdef CONFIG_CRYPTO_DEV_FSL_CAAM
	case CIOCPRF:
	{
		struct device *dev = caam_prf_ctx_create();
		struct prf_param prfiop;
		struct prf_req_s *req = NULL;

		if (unlikely(copy_from_user(&prfiop, arg, sizeof(prfiop)))) {
			pr_err(PFX "copy from user failed");
			caam_prf_ctx_del(dev);
			return -EFAULT;
		}
		req = get_and_validate_prf_param(&prfiop);

		if (!req) {
			pr_err(PFX "func get_and_validate_prf_param failed");
			caam_prf_ctx_del(dev);
			return -EFAULT;
		}

		if ((prfiop.prf_op == GEN_SESSION_KEYS) &&
		    (!prfiop.req_u.gen_session_key.out_client_mac_secret.black_key)) {
			struct prf_req_s *ms_req = kzalloc(sizeof(struct prf_req_s), GFP_KERNEL);

			if (!ms_req)
				ret = -ENOMEM;

			if (!ret)
				ret = prf_op(dev, req);

			if (!ret) {
				copy_session_req_to_ms_req(ms_req, req);
				ret = prf_op(dev, ms_req);
			}

			if (!ret) {
				prepare_session_req(req, ms_req);
				ret = prf_cop_to_user(&prfiop, req);
				if (unlikely(ret))
					ret = -EFAULT;
			}

			prf_req_free(&ms_req);
		} else {
			ret = prf_op(dev, req);

			if (!ret) {
				ret = prf_cop_to_user(&prfiop, req);

				if (unlikely(ret))
					ret = -EFAULT;
			}
		}

		prf_req_free(&req);
		caam_prf_ctx_del(dev);

		return ret;
	}
#endif
	case CIOCKEY:
	{
		struct cryptodev_pkc *pkc =
			kzalloc(sizeof(struct cryptodev_pkc), GFP_KERNEL);

		if (!pkc)
			return -ENOMEM;

		ret = kop_from_user(&pkc->kop, arg);
		if (unlikely(ret)) {
			kfree(pkc);
			return ret;
		}
		pkc->type = SYNCHRONOUS;
		ret = crypto_run_asym(pkc);
		kfree(pkc);
	}
	return ret;
	case CIOCCRYPT:
		kcop = kmalloc(sizeof(*kcop), GFP_DMA);
		if (unlikely(!kcop))
			return -ENOMEM;
		if (unlikely(ret = kcop_from_user(kcop, fcr, arg))) {
			dwarning(1, "Error copying from user");
			kfree(kcop);
			return ret;
		}

		ret = crypto_run(fcr, kcop);
		if (unlikely(ret)) {
			kfree(kcop);
			dwarning(1, "Error in crypto_run");
			return ret;
		}
		ret = kcop_to_user(kcop, fcr, arg);
		kfree(kcop);
		return ret;
	case CIOCHASH:
		if (unlikely(copy_from_user(&khop.hash_op, arg, sizeof(struct hash_op_data)))) {
			pr_err("copy from user fault\n");
			return -EFAULT;
		}
		khop.task = current;
		khop.mm = current->mm;

		/* get session */
		ret = hash_create_session(&khop.hash_op);
		if (unlikely(ret)) {
			pr_err("can't get session\n");
			return ret;
		}

		/* do hashing */
		ret = hash_run(&khop);
		if (unlikely(ret)) {
			dwarning(1, "Error in hash run");
			goto hash_err;
		}

		ret = copy_to_user(khop.hash_op.mac_result, khop.hash_output, khop.digestsize);
		if (unlikely(ret)) {
			dwarning(1, "Error in copy to user");
		}

	hash_err:
		hash_destroy_session(khop.hash_op.ses);
		return ret;
	case CIOCAUTHCRYPT:
		if (unlikely(ret = kcaop_from_user(&kcaop, fcr, arg))) {
			dwarning(1, "Error copying from user");
			return ret;
		}

		ret = crypto_auth_run(fcr, &kcaop);
		if (unlikely(ret)) {
			dwarning(1, "Error in crypto_auth_run");
			return ret;
		}
		return kcaop_to_user(&kcaop, fcr, arg);
#ifdef ENABLE_ASYNC
	case CIOCASYNCCRYPT:
		kcop = kmalloc(sizeof(*kcop), GFP_DMA);
		if (unlikely(!kcop))
			return -ENOMEM;

		if (unlikely(ret = kcop_from_user(kcop, fcr, arg))) {
			kfree(kcop);
			return ret;
		}

		ret = crypto_async_run(pcr, kcop);
		kree(kcop);
		return ret;
	case CIOCASYNCFETCH:
		kcop = kmalloc(sizeof(*kcop), GFP_DMA);
		if (unlikely(!kcop))
			return -ENOMEM;

		ret = crypto_async_fetch(pcr, kcop);
		if (unlikely(ret)) {
			kfree(kcop);
			return ret;
		}

		ret = kcop_to_user(kcop, fcr, arg);
		kfree(kcop);
		return ret;
#endif
	case CIOCASYMASYNCRYPT:
	{
		struct cryptodev_pkc *pkc =
			kzalloc(sizeof(struct cryptodev_pkc), GFP_KERNEL);

		if (!pkc)
			return -ENOMEM;

		ret = kop_from_user(&pkc->kop, arg);

		if (unlikely(ret))
			return -EINVAL;

		/* Store associated FD priv data with asymmetric request */
		pkc->priv = pcr;
		pkc->type = ASYNCHRONOUS;
		ret = crypto_run_asym(pkc);
		if (ret == -EINPROGRESS)
			ret = 0;
	}
	return ret;
	case CIOCASYMFETCHCOOKIE:
	{
		struct cryptodev_pkc *pkc;
		int i;
		struct pkc_cookie_list_s cookie_list;

		cookie_list.cookie_available = 0;
		for (i = 0; i < MAX_COOKIES; i++) {
			spin_lock_bh(&pcr->completion_lock);
			if (!list_empty(&pcr->asym_completed_list)) {
				/* Run a loop in the list for upto  elements
				 and copy their response back */
				pkc = list_first_entry(&pcr->asym_completed_list,
						struct cryptodev_pkc, list);
				list_del(&pkc->list);
				spin_unlock_bh(&pcr->completion_lock);
				ret = crypto_async_fetch_asym(pkc);
				if (!ret) {
					cookie_list.cookie_available++;
					cookie_list.cookie[i] =	pkc->kop.kop.cookie;
					cookie_list.status[i] = pkc->result.err;
				}
				kfree(pkc->req);
				kfree(pkc);
			} else {
				spin_unlock_bh(&pcr->completion_lock);
				break;
			}
		}

		/* Reflect the updated request to user-space */
		if (cookie_list.cookie_available) {
			ret = copy_to_user(arg, &cookie_list, sizeof(struct pkc_cookie_list_s));
		} else {
			struct pkc_cookie_list_s *user_ck_list = (void *)arg;
			ret = put_user(0, &(user_ck_list->cookie_available));
		}
	}
	return ret;
	default:
		ddebug(2, "Default");
		return -EINVAL;
	}
}

/* compatibility code for 32bit userlands */
#ifdef CONFIG_COMPAT

static inline void compat_to_crypt_kop(struct compat_crypt_kop *compat,
		 struct crypt_kop *kop)
{
	int i;
	kop->crk_op      = compat->crk_op;
	kop->crk_status  = compat->crk_status;
	kop->crk_iparams = compat->crk_iparams;
	kop->crk_oparams = compat->crk_oparams;

	for (i = 0; i < CRK_MAXPARAM; i++) {
		kop->crk_param[i].crp_p =
			compat_ptr(compat->crk_param[i].crp_p);
		kop->crk_param[i].crp_nbits = compat->crk_param[i].crp_nbits;
	}

	kop->curve_type = compat->curve_type;
	kop->cookie = compat_ptr(compat->cookie);
}

static int compat_kop_from_user(struct kernel_crypt_kop *kop,
	void __user *arg)
{
	struct compat_crypt_kop compat_kop;

	if (unlikely(copy_from_user(&compat_kop, arg, sizeof(compat_kop))))
		return -EFAULT;

	compat_to_crypt_kop(&compat_kop, &kop->kop);
	return fill_kop_from_cop(kop);
}

static inline void crypt_kop_to_compat(struct crypt_kop *kop,
				 struct compat_crypt_kop *compat)
{
	int i;

	compat->crk_op      = kop->crk_op;
	compat->crk_status  = kop->crk_status;
	compat->crk_iparams = kop->crk_iparams;
	compat->crk_oparams = kop->crk_oparams;

	for (i = 0; i < CRK_MAXPARAM; i++) {
		compat->crk_param[i].crp_p =
			 ptr_to_compat(kop->crk_param[i].crp_p);
		compat->crk_param[i].crp_nbits = kop->crk_param[i].crp_nbits;
	}
	compat->cookie = ptr_to_compat(kop->cookie);
	compat->curve_type = kop->curve_type;
}

static inline void
compat_to_session_op(struct compat_session_op *compat, struct session_op *sop)
{
	sop->cipher = compat->cipher;
	sop->mac = compat->mac;
	sop->keylen = compat->keylen;

	sop->key       = compat_ptr(compat->key);
	sop->mackeylen = compat->mackeylen;
	sop->mackey    = compat_ptr(compat->mackey);
	sop->ses       = compat->ses;
}

static inline void
session_op_to_compat(struct session_op *sop, struct compat_session_op *compat)
{
	compat->cipher = sop->cipher;
	compat->mac = sop->mac;
	compat->keylen = sop->keylen;

	compat->key       = ptr_to_compat(sop->key);
	compat->mackeylen = sop->mackeylen;
	compat->mackey    = ptr_to_compat(sop->mackey);
	compat->ses       = sop->ses;
}

static inline void
compat_to_crypt_op(struct compat_crypt_op *compat, struct crypt_op *cop)
{
	cop->ses = compat->ses;
	cop->op = compat->op;
	cop->flags = compat->flags;
	cop->len = compat->len;

	cop->src = compat_ptr(compat->src);
	cop->dst = compat_ptr(compat->dst);
	cop->mac = compat_ptr(compat->mac);
	cop->iv  = compat_ptr(compat->iv);
}

static inline void
crypt_op_to_compat(struct crypt_op *cop, struct compat_crypt_op *compat)
{
	compat->ses = cop->ses;
	compat->op = cop->op;
	compat->flags = cop->flags;
	compat->len = cop->len;

	compat->src = ptr_to_compat(cop->src);
	compat->dst = ptr_to_compat(cop->dst);
	compat->mac = ptr_to_compat(cop->mac);
	compat->iv  = ptr_to_compat(cop->iv);
}

static int compat_kcop_from_user(struct kernel_crypt_op *kcop,
                                 struct fcrypt *fcr, void __user *arg)
{
	struct compat_crypt_op compat_cop;

	if (unlikely(copy_from_user(&compat_cop, arg, sizeof(compat_cop))))
		return -EFAULT;
	compat_to_crypt_op(&compat_cop, &kcop->cop);

	return fill_kcop_from_cop(kcop, fcr);
}

static int compat_kcop_to_user(struct kernel_crypt_op *kcop,
                               struct fcrypt *fcr, void __user *arg)
{
	int ret;
	struct compat_crypt_op compat_cop;

	ret = fill_cop_from_kcop(kcop, fcr);
	if (unlikely(ret)) {
		dwarning(1, "Error in fill_cop_from_kcop");
		return ret;
	}
	crypt_op_to_compat(&kcop->cop, &compat_cop);

	if (unlikely(copy_to_user(arg, &compat_cop, sizeof(compat_cop)))) {
		dwarning(1, "Error copying to user");
		return -EFAULT;
	}
	return 0;
}

int compat_get_gen_ms_param(struct prf_req_s *req,
				struct compat_prf_param *prfiop)
{
	struct compat_gen_master_secret *in_ms_param = &prfiop->req_u.gen_ms;
	struct gen_master_secret_s *gen_ms = &req->req_u.gen_ms;

	req->dma_len = (in_ms_param->label.len + in_ms_param->pre_master_secret.len
			+ gen_ms->server_rand.len +
			gen_ms->client_rand.len +
			gen_ms->out_master_secret.len + GFP_DMA_BUFFER);

	req->dma_buf = kzalloc(req->dma_len, GFP_DMA);
	if (!req->dma_buf)
		return -ENOMEM;

	gen_ms->pre_master_secret.len = in_ms_param->pre_master_secret.len;
	gen_ms->label.len = in_ms_param->label.len;
	gen_ms->server_rand.len = in_ms_param->server_rand.len;
	gen_ms->client_rand.len = in_ms_param->client_rand.len;
	gen_ms->out_master_secret.len = in_ms_param->out_master_secret.len;

	gen_ms->label.param = req->dma_buf4;
	gen_ms->pre_master_secret.param = gen_ms->label.param +
						gen_ms->label.len;
	gen_ms->server_rand.param = gen_ms->pre_master_secret.param +
						gen_ms->pre_master_secret.len;
	gen_ms->client_rand.param = gen_ms->server_rand.param +
						gen_ms->server_rand.len;
	gen_ms->out_master_secret.param = gen_ms->client_rand.param +
						gen_ms->client_rand.len;

	if (unlikely(copy_from_user(gen_ms->label.param,
		compat_ptr(in_ms_param->label.param),
		gen_ms->label.len))) {
		pr_err(PFX"copy from user failed");
		return -EFAULT;
	}
	gen_ms->pre_master_secret.black_key =
		in_ms_param->pre_master_secret.black_key;
	if (unlikely(copy_from_user(gen_ms->pre_master_secret.param,
		compat_ptr(in_ms_param->pre_master_secret.param),
		gen_ms->pre_master_secret.len))) {
		pr_err(PFX"copy from user failed");
		return -EFAULT;
	}
	if (unlikely(copy_from_user(gen_ms->server_rand.param,
		compat_ptr(in_ms_param->server_rand.param),
		gen_ms->server_rand.len))) {
		pr_err(PFX"copy from user failed");
		return -EFAULT;
	}
	if (unlikely(copy_from_user(gen_ms->client_rand.param,
		compat_ptr(in_ms_param->client_rand.param),
		gen_ms->client_rand.len))) {
		pr_err(PFX"copy from user failed");
		return -EFAULT;
	}
	gen_ms->out_master_secret.black_key =
			in_ms_param->out_master_secret.black_key;
	return 0;
}

int compat_get_gen_session_key_param(struct prf_req_s *req,
					struct compat_prf_param *prfiop)
{
	struct compat_gen_session_keys *in = &prfiop->req_u.gen_session_key;
	struct gen_session_keys_s *gen_ses_key = &req->req_u.gen_session_key;

	req->dma_len = (in->label.len + in->master_secret.len + in->server_rand.len
			+ in->client_rand.len + in->out_client_mac_secret.len
			+ in->out_server_mac_secret.len
			+ in->out_client_write_key.len
			+ in->out_server_write_key.len
			+ in->out_client_write_iv.len
			+ in->out_server_write_iv.len + GFP_DMA_BUFFER);
	req->dma_buf = kzalloc(req->dma_len, GFP_DMA);
	if (!req->dma_buf)
		return -ENOMEM;

	gen_ses_key->cipher = in->cipher;
	gen_ses_key->label.len = in->label.len;
	gen_ses_key->master_secret.len = in->master_secret.len;
	gen_ses_key->server_rand.len = in->server_rand.len;
	gen_ses_key->client_rand.len = in->client_rand.len;
	gen_ses_key->out_client_mac_secret.len = in->out_client_mac_secret.len;
	gen_ses_key->out_server_mac_secret.len = in->out_server_mac_secret.len;
	gen_ses_key->out_client_write_key.len = in->out_client_write_key.len;
	gen_ses_key->out_server_write_key.len = in->out_server_write_key.len;
	gen_ses_key->out_client_write_iv.len = in->out_client_write_iv.len;
	gen_ses_key->out_server_write_iv.len = in->out_server_write_iv.len;

	gen_ses_key->label.param = req->dma_buf;
	gen_ses_key->client_rand.param = gen_ses_key->label.param
					+ gen_ses_key->label.len;
	gen_ses_key->server_rand.param = gen_ses_key->client_rand.param
					+ gen_ses_key->client_rand.len;
	gen_ses_key->master_secret.param = gen_ses_key->server_rand.param
					+ gen_ses_key->server_rand.len;
	gen_ses_key->out_client_mac_secret.param =
					gen_ses_key->master_secret.param
					+ gen_ses_key->master_secret.len;
	gen_ses_key->out_server_mac_secret.param =
					gen_ses_key->out_client_mac_secret.param
				+ gen_ses_key->out_client_mac_secret.len;
	gen_ses_key->out_client_write_key.param =
					gen_ses_key->out_server_mac_secret.param
				+ gen_ses_key->out_server_mac_secret.len;
	gen_ses_key->out_server_write_key.param =
					gen_ses_key->out_client_write_key.param
					+ gen_ses_key->out_client_write_key.len;
	gen_ses_key->out_client_write_iv.param =
					gen_ses_key->out_server_write_key.param
					+ gen_ses_key->out_server_write_key.len;
	gen_ses_key->out_server_write_iv.param =
					gen_ses_key->out_client_write_iv.param
					+ gen_ses_key->out_client_write_iv.len;

	if (unlikely(copy_from_user(gen_ses_key->label.param,
					compat_ptr(in->label.param),
					gen_ses_key->label.len))) {
		pr_err(PFX"copy from user failed");
		return -EFAULT;
	}
	if (unlikely(copy_from_user(gen_ses_key->master_secret.param,
		compat_ptr(in->master_secret.param),
		gen_ses_key->master_secret.len))) {
		pr_err(PFX"copy from user failed");
		return -EFAULT;
	}

	if (unlikely(copy_from_user(gen_ses_key->server_rand.param,
		compat_ptr(in->server_rand.param),
		gen_ses_key->server_rand.len))) {
		pr_err(PFX"copy from user failed");
		return -EFAULT;
	}
	if (unlikely(copy_from_user(gen_ses_key->client_rand.param,
		compat_ptr(in->client_rand.param),
		gen_ses_key->client_rand.len))) {
		pr_err(PFX"copy from user failed");
		return -EFAULT;
	}


	gen_ses_key->master_secret.black_key = in->master_secret.black_key;
	gen_ses_key->out_client_mac_secret.black_key =
					in->out_client_mac_secret.black_key;
	gen_ses_key->out_server_mac_secret.black_key =
					in->out_server_mac_secret.black_key;
	gen_ses_key->out_client_write_key.black_key =
					in->out_client_write_key.black_key;
	gen_ses_key->out_server_write_key.black_key =
					in->out_server_write_key.black_key;
	return 0;
}

int compat_get_gen_finish_param(struct prf_req_s *req,
					struct compat_prf_param *prfiop)
{
	struct compat_gen_finish_random *in_finish =
			&prfiop->req_u.gen_finish_rand;
	struct gen_finish_random_s *gen_finish = &req->req_u.gen_finish_rand;

	if ((in_finish->master_secret.len > PRF_MS_LEN) ||
		(in_finish->label.len > PRF_LABEL_MAX))
		return -EINVAL;

	req->dma_len = (in_finish->label.len + in_finish->master_secret.len
			+ gen_finish->seed1.len +
			gen_finish->seed2.len +
			gen_finish->out_data.len + GFP_DMA_BUFFER);
	req->dma_buf = kzalloc(req->dma_len, GFP_DMA);
	if (!req->dma_buf)
		return -ENOMEM;

	gen_finish->master_secret.len = in_finish->master_secret.len;
	gen_finish->label.len = in_finish->label.len;
	gen_finish->seed1.len = in_finish->seed1.len;
	gen_finish->seed2.len = in_finish->seed2.len;
	gen_finish->out_data.len = in_finish->out_data.len;

	gen_finish->label.param = req->dma_buf4;
	gen_finish->master_secret.param = gen_finish->label.param +
						gen_finish->label.len;
	gen_finish->seed1.param = gen_finish->master_secret.param +
						gen_finish->master_secret.len;
	gen_finish->seed2.param = gen_finish->seed1.param +
						gen_finish->seed1.len;
	gen_finish->out_data.param = gen_finish->seed2.param +
						gen_finish->seed2.len;

	if (unlikely(copy_from_user(gen_finish->label.param,
		compat_ptr(in_finish->label.param),
		gen_finish->label.len))) {
		pr_err(PFX"copy from user failed");
		return -EFAULT;
	}
	gen_finish->master_secret.black_key =
		in_finish->master_secret.black_key;
	if (unlikely(copy_from_user(gen_finish->master_secret.param,
		compat_ptr(in_finish->master_secret.param),
		gen_finish->master_secret.len))) {
		pr_err(PFX"copy from user failed");
		return -EFAULT;
	}
	if (unlikely(copy_from_user(gen_finish->seed1.param,
		compat_ptr(in_finish->seed1.param),
		gen_finish->seed1.len))) {
		pr_err(PFX"copy from user failed");
		return -EFAULT;
	}
	if (unlikely(copy_from_user(gen_finish->seed2.param,
		compat_ptr(in_finish->seed2.param),
		gen_finish->seed2.len))) {
		pr_err(PFX"copy from user failed");
		return -EFAULT;
	}
	return 0;
}
static struct prf_req_s *compat_get_and_validate_prf_param(
					struct compat_prf_param *prfiop)
{
	struct prf_req_s *req = kzalloc(sizeof(struct prf_req_s), GFP_KERNEL);

	if (!req)
		return NULL;

	req->prf_op = prfiop->prf_op;
	req->tls_version = prfiop->tls_version;

	switch (req->prf_op) {
	case GEN_MASTER_SECRET:
		if (compat_get_gen_ms_param(req, prfiop)) {
			prf_req_free(&req);
			pr_err(PFX"compat_get_gen_ms_param failed!");
			return NULL;
		}
		break;
	case GEN_SESSION_KEYS:
		if (compat_get_gen_session_key_param(req, prfiop)) {
			prf_req_free(&req);
			pr_err(PFX"compat_get_gen_session_key_param failed!");
			return NULL;
		}
		break;
	case GEN_FINISH_RAND:
		if (compat_get_gen_finish_param(req, prfiop)) {
			prf_req_free(&req);
			pr_err(PFX"get_gen_finish_param failed!");
			return NULL;
		}
		break;
	default:
		kfree(req);
		req = NULL;
	}

	return req;
}

static int compat_prf_cop_to_user(struct compat_prf_param *prfiop,
							struct prf_req_s *req)
{
	int ret = 0;
	int i;

#define DUMP(s, i, buf, sz)  { ddebug(1, s);                   \
	for (i = 0; i < (sz); i++)    \
		ddebug(1, "%02x ", buf[i]); \
	ddebug(1, "\n"); }
	switch (req->prf_op) {
	case GEN_MASTER_SECRET:
		DUMP("master secret", i,
		((unsigned char *)req->req_u.gen_ms.out_master_secret.param),
				req->req_u.gen_ms.out_master_secret.len);
		ret = copy_to_user(compat_ptr(
				prfiop->req_u.gen_ms.out_master_secret.param),
				req->req_u.gen_ms.out_master_secret.param,
				req->req_u.gen_ms.out_master_secret.len);
		break;
	case GEN_SESSION_KEYS:
		{
			struct compat_gen_session_keys *out =
				&prfiop->req_u.gen_session_key;
			struct gen_session_keys_s *in =
					&req->req_u.gen_session_key;
			ret = copy_to_user(
				compat_ptr(out->out_client_mac_secret.param),
					in->out_client_mac_secret.param,
					in->out_client_mac_secret.len);
			if (unlikely(ret)) {
				pr_err(PFX "copy to user failed");
				ret = -EFAULT;
			}
			ret = copy_to_user(
				compat_ptr(out->out_server_mac_secret.param),
					in->out_server_mac_secret.param,
					in->out_server_mac_secret.len);
			if (unlikely(ret)) {
				pr_err(PFX "copy to user failed");
				ret = -EFAULT;
			}
			ret = copy_to_user(
				compat_ptr(out->out_client_write_key.param),
					in->out_client_write_key.param,
					in->out_client_write_key.len);
			if (unlikely(ret)) {
				pr_err(PFX "copy to user failed");
				ret = -EFAULT;
			}
			ret = copy_to_user(
				compat_ptr(out->out_server_write_key.param),
					in->out_server_write_key.param,
					in->out_server_write_key.len);
			if (unlikely(ret)) {
				pr_err(PFX "copy to user failed");
				ret = -EFAULT;
			}
			ret = copy_to_user(
				compat_ptr(out->out_client_write_iv.param),
					in->out_client_write_iv.param,
					in->out_client_write_iv.len);
			if (unlikely(ret)) {
				pr_err(PFX "copy to user failed");
				ret = -EFAULT;
			}
			ret = copy_to_user(
				compat_ptr(out->out_server_write_iv.param),
					in->out_server_write_iv.param,
					in->out_server_write_iv.len);
			if (unlikely(ret)) {
				pr_err(PFX "copy to user failed");
				ret = -EFAULT;
			}
			break;
		}
	case GEN_FINISH_RAND:
		ret = copy_to_user(compat_ptr(
			prfiop->req_u.gen_finish_rand.out_data.param),
			req->req_u.gen_finish_rand.out_data.param,
			req->req_u.gen_finish_rand.out_data.len);

		break;

	default:
		pr_err(PFX"cryptodev memory leak !!!");
		break;
	}
#undef DUMP
	return ret;
}

static long
cryptodev_compat_ioctl(struct file *file, unsigned int cmd, unsigned long arg_)
{
	void __user *arg = (void __user *)arg_;
	struct crypt_priv *pcr = file->private_data;
	struct fcrypt *fcr;
	struct session_op sop;
	struct compat_session_op compat_sop;
	struct kernel_hash_op khop;
	struct kernel_crypt_op kcop;
	struct kernel_crypt_auth_op kcaop;
	struct compat_hash_op_data compat_hash_op_data;

	int ret = 0;

	if (unlikely(!pcr))
		BUG();
	fcr = &pcr->fcrypt;
	switch (cmd) {
	case CIOCASYMFEAT:
	case CRIOGET:
	case CIOCFSESSION:
	case CIOCGSESSINFO:
	case CIOCPRF:
		return cryptodev_ioctl(file, cmd, arg_);
#ifdef CONFIG_CRYPTO_DEV_FSL_CAAM
	case COMPAT_CIOCPRF:
	{
		struct device *dev = caam_prf_ctx_create();
		struct compat_prf_param prfiop;
		struct prf_req_s *req = NULL;

		if (unlikely(copy_from_user(&prfiop, arg, sizeof(prfiop)))) {
			pr_err(PFX "copy from user failed");
			return -EFAULT;
		}
		req = compat_get_and_validate_prf_param(&prfiop);

		if (!req) {
			pr_err(PFX "func get_and_validate_prf_param failed");
			return -EFAULT;
		}

		if ((prfiop.prf_op == GEN_SESSION_KEYS) &&
		    (!prfiop.req_u.gen_session_key.out_client_mac_secret.black_key)) {
			struct prf_req_s *ms_req = kzalloc(sizeof(struct prf_req_s), GFP_KERNEL);

			if (!ms_req)
				ret = -ENOMEM;

			if (!ret)
				ret = prf_op(dev, req);

			if (!ret) {
				copy_session_req_to_ms_req(ms_req, req);
				ret = prf_op(dev, ms_req);
			}

			if (!ret) {
				prepare_session_req(req, ms_req);
				ret = compat_prf_cop_to_user(&prfiop, req);
				if (unlikely(ret))
					ret = -EFAULT;
			}

			prf_req_free(&ms_req);
			prf_req_free(&req);
		} else {
			ret = prf_op(dev, req);
			if (!ret)
				ret = compat_prf_cop_to_user(&prfiop, req);
			if (unlikely(ret))
				ret = -EFAULT;

			prf_req_free(&req);
		}

		caam_prf_ctx_del(dev);
		return ret;

	}
#endif
	case COMPAT_CIOCGSESSION:
		if (unlikely(copy_from_user(&compat_sop, arg,
					    sizeof(compat_sop))))
			return -EFAULT;
		compat_to_session_op(&compat_sop, &sop);

		ret = crypto_create_session(fcr, &sop);
		if (unlikely(ret))
			return ret;

		session_op_to_compat(&sop, &compat_sop);
		ret = copy_to_user(arg, &compat_sop, sizeof(compat_sop));
		if (unlikely(ret)) {
			crypto_finish_session(fcr, sop.ses);
			return -EFAULT;
		}
		return ret;
	case COMPAT_CIOCKEY:
	{
		struct cryptodev_pkc *pkc =
			 kzalloc(sizeof(struct cryptodev_pkc), GFP_KERNEL);

		if (!pkc)
			return -ENOMEM;

		ret = compat_kop_from_user(&pkc->kop, arg);

		if (unlikely(ret)) {
			kfree(pkc);
			return ret;
		}

		pkc->type = SYNCHRONOUS;
		ret = crypto_run_asym(pkc);
		kfree(pkc);
	}
	return ret;
	case COMPAT_CIOCCRYPT:
		ret = compat_kcop_from_user(&kcop, fcr, arg);
		if (unlikely(ret))
			return ret;

		ret = crypto_run(fcr, &kcop);
		if (unlikely(ret))
			return ret;

		return compat_kcop_to_user(&kcop, fcr, arg);

	case COMPAT_CIOCHASH:
		/* get session */
		if (unlikely(copy_from_user(&compat_hash_op_data, arg,
					sizeof(struct compat_hash_op_data)))) {
			pr_err("copy from user fault\n");
			return -EFAULT;
		}

		khop.task = current;
		khop.mm = current->mm;

		khop.hash_op.mac_op = compat_hash_op_data.mac_op;
		khop.hash_op.mackey = compat_ptr(compat_hash_op_data.mackey);
		khop.hash_op.mackeylen = compat_hash_op_data.mackeylen;
		khop.hash_op.flags = compat_hash_op_data.flags;
		khop.hash_op.len = compat_hash_op_data.len;
		khop.hash_op.src = compat_ptr(compat_hash_op_data.src);
		khop.hash_op.mac_result =
				compat_ptr(compat_hash_op_data.mac_result);

		ret = hash_create_session(&khop.hash_op);
		if (unlikely(ret)) {
			pr_err("can't get session\n");
			return ret;
		}

		/* do hashing */
		ret = hash_run(&khop);
		if (unlikely(ret)) {
			dwarning(1, "Error in hash run");
			goto hash_err;
		}

		ret = copy_to_user(khop.hash_op.mac_result, khop.hash_output,
				   khop.digestsize);
		if (unlikely(ret)) {
			dwarning(1, "Error in copy to user");
			goto hash_err;
		}

		ret = copy_to_user(arg, &compat_hash_op_data,
			     sizeof(struct compat_hash_op_data));
		if (unlikely(ret)) {
			dwarning(1, "Error in copy to user");
		}

	hash_err:
		hash_destroy_session(khop.hash_op.ses);
		return ret;

	case COMPAT_CIOCAUTHCRYPT:
		if (unlikely(ret = compat_kcaop_from_user(&kcaop, fcr, arg))) {
			dprintk(1, KERN_WARNING, "Error copying from user\n");
			return ret;
		}

		ret = crypto_auth_run(fcr, &kcaop);
		if (unlikely(ret)) {
			dprintk(1, KERN_WARNING, "Error in crypto_auth_run\n");
			return ret;
		}

		return compat_kcaop_to_user(&kcaop, fcr, arg);

#ifdef ENABLE_ASYNC
	case COMPAT_CIOCASYNCCRYPT:
		if (unlikely(ret = compat_kcop_from_user(&kcop, fcr, arg)))
			return ret;

		return crypto_async_run(pcr, &kcop);
	case COMPAT_CIOCASYNCFETCH:
		ret = crypto_async_fetch(pcr, &kcop);
		if (unlikely(ret))
			return ret;

		return compat_kcop_to_user(&kcop, fcr, arg);
#endif
	case COMPAT_CIOCASYMASYNCRYPT:
	{
		struct cryptodev_pkc *pkc =
			kzalloc(sizeof(struct cryptodev_pkc), GFP_KERNEL);

		if (!pkc)
			return -ENOMEM;

		ret = compat_kop_from_user(&pkc->kop, arg);
		if (unlikely(ret))
			return -EINVAL;

		/* Store associated FD priv data with asymmetric request */
		pkc->priv = pcr;
		pkc->type = ASYNCHRONOUS;
		ret = crypto_run_asym(pkc);
		if (ret == -EINPROGRESS)
			ret = 0;
	}
	return ret;
	case COMPAT_CIOCASYMFETCHCOOKIE:
	{
		struct cryptodev_pkc *pkc;
		int i = 0;
		struct compat_pkc_cookie_list_s cookie_list;

		ret = 0;
		cookie_list.cookie_available = 0;

		for (i = 0; i < MAX_COOKIES; i++) {
			spin_lock_bh(&pcr->completion_lock);
			if (!list_empty(&pcr->asym_completed_list)) {
				/* Run a loop in the list for upto  elements
				 and copy their response back */
				pkc =
				 list_first_entry(&pcr->asym_completed_list,
						struct cryptodev_pkc, list);
				list_del(&pkc->list);
				spin_unlock_bh(&pcr->completion_lock);
				ret = crypto_async_fetch_asym(pkc);
				if (!ret) {
					cookie_list.cookie_available++;
					cookie_list.cookie[i] = ptr_to_compat(
							pkc->kop.kop.cookie);
				}
				kfree(pkc);
			} else {
				spin_unlock_bh(&pcr->completion_lock);
				break;
			}
		}

		/* Reflect the updated request to user-space */
		if (cookie_list.cookie_available) {
			ret = copy_to_user(arg, &cookie_list,
				sizeof(struct compat_pkc_cookie_list_s));
		}
	}
	return ret;
	default:
		return -EINVAL;
	}
}

#endif /* CONFIG_COMPAT */

static unsigned int cryptodev_poll(struct file *file, poll_table *wait)
{
	struct crypt_priv *pcr = file->private_data;
	unsigned int ret = 0;

	poll_wait(file, &pcr->user_waiter, wait);

	if (!list_empty_careful(&pcr->done.list) ||
	    !list_empty_careful(&pcr->asym_completed_list))
		ret |= POLLIN | POLLRDNORM;
	if (!list_empty_careful(&pcr->free.list) ||
	    pcr->itemcount < MAX_COP_RINGSIZE)
		ret |= POLLOUT | POLLWRNORM;

	return ret;
}

static const struct file_operations cryptodev_fops = {
	.owner = THIS_MODULE,
	.open = cryptodev_open,
	.release = cryptodev_release,
	.unlocked_ioctl = cryptodev_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl = cryptodev_compat_ioctl,
#endif /* CONFIG_COMPAT */
	.poll = cryptodev_poll,
};

static struct miscdevice cryptodev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "crypto",
	.fops = &cryptodev_fops,
	.mode = S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH,
};

static int __init
cryptodev_register(void)
{
	int rc;

	rc = misc_register(&cryptodev);
	if (unlikely(rc)) {
		pr_err(PFX "registration of /dev/crypto failed\n");
		return rc;
	}

	return 0;
}

static void __exit
cryptodev_deregister(void)
{
	misc_deregister(&cryptodev);
}

/* ====== Module init/exit ====== */
static struct ctl_table verbosity_ctl_dir[] = {
	{
		.procname       = "cryptodev_verbosity",
		.data           = &cryptodev_verbosity,
		.maxlen         = sizeof(int),
		.mode           = 0644,
		.proc_handler   = proc_dointvec,
	},
	{},
};

static struct ctl_table verbosity_ctl_root[] = {
	{
		.procname       = "ioctl",
		.mode           = 0555,
		.child          = verbosity_ctl_dir,
	},
	{},
};
static struct ctl_table_header *verbosity_sysctl_header;
static int __init init_cryptodev(void)
{
	int rc;

	cryptodev_wq = create_workqueue("cryptodev_queue");
	if (unlikely(!cryptodev_wq)) {
		pr_err(PFX "failed to allocate the cryptodev workqueue\n");
		return -EFAULT;
	}

	rc = cryptodev_register();
	if (unlikely(rc)) {
		destroy_workqueue(cryptodev_wq);
		return rc;
	}

	verbosity_sysctl_header = register_sysctl_table(verbosity_ctl_root);

	pr_info(PFX "driver %s  + Cyphre BlackTIE loaded.\n", VERSION);

	return 0;
}

static void __exit exit_cryptodev(void)
{
	flush_workqueue(cryptodev_wq);
	destroy_workqueue(cryptodev_wq);

	if (verbosity_sysctl_header)
		unregister_sysctl_table(verbosity_sysctl_header);

	cryptodev_deregister();
	pr_info(PFX "driver unloaded.\n");
}

module_init(init_cryptodev);
module_exit(exit_cryptodev);

