/* cipher stuff
 * Copyright 2012 Freescale Semiconductor, Inc.
 */
#ifndef CRYPTODEV_INT_H
# define CRYPTODEV_INT_H

#include <linux/version.h>

#if (LINUX_VERSION_CODE < KERNEL_VERSION(3, 13, 0))
#  define reinit_completion(x) INIT_COMPLETION(*(x))
#endif

#include <linux/init.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/fdtable.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/scatterlist.h>
#include <crypto/cryptodev.h>
#include <crypto/aead.h>

#define PFX "cryptodev: "
#define dprintk(level, severity, format, a...)			\
	do {							\
		if (level <= cryptodev_verbosity)		\
			printk(severity PFX "%s[%u] (%s:%u): " format "\n",	\
			       current->comm, current->pid,	\
			       __func__, __LINE__,		\
			       ##a);				\
	} while (0)
#define derr(level, format, a...) dprintk(level, KERN_ERR, format, ##a)
#define dwarning(level, format, a...) dprintk(level, KERN_WARNING, format, ##a)
#define dinfo(level, format, a...) dprintk(level, KERN_INFO, format, ##a)
#define ddebug(level, format, a...) dprintk(level, KERN_DEBUG, format, ##a)

#define PRF_ENC_HMAC_SECRET_LEN	48

extern int cryptodev_verbosity;

struct fcrypt {
	struct list_head list;
	struct mutex sem;
};

/* kernel-internal extension to struct crypt_kop */
struct kernel_crypt_kop {
	struct crypt_kop kop;

	struct task_struct *task;
	struct mm_struct *mm;
};

/* kernel-internal extension to struct crypt_op */
struct kernel_crypt_op {
	struct crypt_op cop;

	int ivlen;
	__u8 iv[EALG_MAX_BLOCK_LEN];

	int digestsize;
	uint8_t hash_output[AALG_MAX_RESULT_LEN];

	struct task_struct *task;
	struct mm_struct *mm;
};

struct kernel_hash_op {
	struct hash_op_data hash_op;

	int digestsize;
	uint8_t hash_output[AALG_MAX_RESULT_LEN];
	struct task_struct *task;
	struct mm_struct *mm;
};

struct kernel_crypt_auth_op {
	struct crypt_auth_op caop;

	int dst_len; /* based on src_len + pad + tag */
	int ivlen;
	__u8 iv[EALG_MAX_BLOCK_LEN];

	struct task_struct *task;
	struct mm_struct *mm;
};

/* auth */

int kcaop_from_user(struct kernel_crypt_auth_op *kcop,
			struct fcrypt *fcr, void __user *arg);
int kcaop_to_user(struct kernel_crypt_auth_op *kcaop,
		struct fcrypt *fcr, void __user *arg);
int crypto_auth_run(struct fcrypt *fcr, struct kernel_crypt_auth_op *kcaop);
int crypto_run(struct fcrypt *fcr, struct kernel_crypt_op *kcop);
int hash_run(struct kernel_hash_op *khop);

#include "cryptlib.h"

/* Cryptodev Key operation handler */
int crypto_bn_modexp(struct cryptodev_pkc *);
int crypto_modexp_crt(struct cryptodev_pkc *);
int crypto_kop_dsasign(struct cryptodev_pkc *);
int crypto_kop_dsaverify(struct cryptodev_pkc *);
int crypto_run_asym(struct cryptodev_pkc *);
void cryptodev_complete_asym(struct crypto_async_request *, int);

/* other internal structs */
struct csession {
	struct list_head entry;
	struct mutex sem;
	struct cipher_data cdata;
	struct hash_data hdata;
	uint32_t sid;
	uint32_t alignmask;

	unsigned int array_size;
	unsigned int used_pages; /* the number of pages that are used */
	/* the number of pages marked as NOT-writable; they preceed writeables */
	unsigned int readonly_pages;
	struct page **pages;
	struct scatterlist *sg;
};

struct csession *crypto_get_session_by_sid(struct fcrypt *fcr, uint32_t sid);

static inline void crypto_put_session(struct csession *ses_ptr)
{
	mutex_unlock(&ses_ptr->sem);
}
int adjust_sg_array(struct csession *ses, int pagecount);

#endif /* CRYPTODEV_INT_H */
