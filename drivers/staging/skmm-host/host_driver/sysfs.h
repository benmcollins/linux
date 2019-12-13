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

#ifndef _SYSFS_H
#define _SYSFS_H

#include "common.h"
/*#include "fsl_c2x0_driver.h"*/

/** SYSFS RELATED INLINE FUNCTIONS **/
#define NUM_OF_FW_SYSFS_FILES		4
#define NUM_OF_PCI_SYSFS_FILES		1
#define NUM_OF_CRYPTO_SYSFS_FILES	1
#define NUM_OF_STATS_SYSFS_FILES	2
#define NUM_OF_TEST_SYSFS_FILES		4

#define MAX_SYSFS_BUFFER		200

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 19))
#define KOBJECT_INIT_AND_ADD(_kobj, _ktype, _parent, _name) {\
					_kobj->ktype = _ktype; \
					_kobj->parent = _parent; \
					kobject_init(_kobj);\
					kobject_set_name(_kobj, _name); \
					kobject_add(_kobj);
}
#else
#define KOBJECT_INIT_AND_ADD(_kobj, _ktype, _parent, _name) \
	ret = kobject_init_and_add(_kobj, _ktype, _parent, _name);
#endif

typedef enum sys_files_id {
	/* Block of enums for files in dev dir */
	DEVICE_SYS_FILES_START,
	DEVICE_STATE_SYSFILE,
	DEVICE_SYS_FILES_END,

	/* Block of enums for files in fw dir */
	FIRMWARE_SYS_FILES_START,
	FIRMWARE_STATE_SYSFILE,
	FIRMWARE_VERSION_SYSFILE,
	FIRMWARE_PATH_SYSFILE,
	FIRMWARE_TRIGGER_SYSFILE,
	FIRMWARE_SYS_FILE_END,

	/* Block of enums for files in pci dir */
	PCI_SYS_FILES_START,
	PCI_INFO_SYS_FILE,
	PCI_SYS_FILES_END,

	/* Block of enums for files in crypto dir */
	CRYPTO_SYS_FILES_START,
	CRYPTO_INFO_SYS_FILE,
	CRYPTO_SYS_FILES_END,

	/* Block of enums for files in stat dir */
	STATS_SYS_FILES_START,
	STATS_REQ_COUNT_SYS_FILE,
	STATS_RESP_COUNT_SYS_FILE,
	STATS_SYS_FILES_END,

	/* Block of enums for files in test dir */
	TEST_SYS_FILES_START,
	TEST_NAME_SYS_FILE,
	TEST_RES_SYS_FILE,
	TEST_PERF_SYS_FILE,
	TEST_REPEAT_SYS_FILE,
	TEST_SYS_FILES_END
} sys_files_id_t;

typedef struct sysfs_file {
	int8_t *name;
	void *file;
	void (*cb) (int8_t *, int8_t *, int, char);
} sysfs_file_t;

typedef struct dev_sysfs_entries {
	void *dev_dir;

	void *fw_sub_dir;
	void *pci_sub_dir;
	void *crypto_sub_dir;
	void *stats_sub_dir;
	void *test_sub_dir;

	sysfs_file_t dev_file;

	sysfs_file_t fw_files[NUM_OF_FW_SYSFS_FILES];

	sysfs_file_t pci_files[NUM_OF_PCI_SYSFS_FILES];

	sysfs_file_t crypto_files[NUM_OF_CRYPTO_SYSFS_FILES];

	sysfs_file_t stats_files[NUM_OF_STATS_SYSFS_FILES];

	sysfs_file_t test_files[NUM_OF_TEST_SYSFS_FILES];
} dev_sysfs_entries_t;

struct k_obj_attribute {
	struct attribute attr;
	 ssize_t(*show) (struct kobject *, struct attribute *attr, char *buf);
	 ssize_t(*store) (struct kobject *, struct attribute *attr,
			  const char *buf, size_t count);
};

struct sysfs_dir {
	struct kobject kobj;
	uint8_t name[16];
};

struct k_sysfs_file {
	struct k_obj_attribute attr;
	uint8_t name[16];
	uint8_t str_flag;
	uint8_t buf[MAX_SYSFS_BUFFER];
	uint32_t num;
	uint32_t buf_len;
	void (*cb) (int8_t *, int8_t *, int, char);
};

/* TODO :
 * Renamed typedef struct fsl_pci_dev fsl_pci_dev_t
 *       to typedef struct fsl_pci_dev fsl_pci_dev_t_1
 * so as to avoid compilation error in old gcc version(gcc-4.5.2)
 * This error doesnt occur in later gcc versions
 * Need to find proper solution other than renaming
 */
typedef struct fsl_pci_dev fsl_pci_dev_t_1;

/* Head of all the sysfs entries */
extern void *fsl_sysfs_entries;

/* CALLBACK FUN FOR FW TRIGGER */
extern void set_device(int8_t *, int8_t *, int, char);

extern void c2x0_test_func(int8_t *fname, int8_t *test_name, int len,
			   char flag);

void set_sysfs_value(fsl_pci_dev_t_1 *fsl_pci_dev, sys_files_id_t id,
		     uint8_t *value, uint8_t len);

void get_sysfs_value(fsl_pci_dev_t_1 *fsl_pci_dev, sys_files_id_t id,
		     uint8_t *value, uint8_t *len);

int32_t init_sysfs(fsl_pci_dev_t_1 *fsl_pci_dev);
int32_t init_common_sysfs(void);
void sysfs_cleanup(fsl_pci_dev_t_1 *fsl_pci_dev);
void clean_common_sysfs(void);

static ssize_t common_sysfs_show(struct kobject *kobj, struct attribute *attr,
				 char *buf)
{
	struct k_obj_attribute *pci_attr =
	    container_of(attr, struct k_obj_attribute, attr);
	struct k_sysfs_file *sysfs_file =
	    container_of(pci_attr, struct k_sysfs_file, attr);
	uint32_t buf_len = 0;
	if (sysfs_file->str_flag) {
		sprintf((char *)buf, "%s\n", sysfs_file->buf);
		buf_len = sysfs_file->buf_len;
	} else {
		sprintf((char *)(buf), "%u\n", sysfs_file->num);
		buf_len = sizeof(sysfs_file->num);
		buf_len = strlen(buf);
	}

	return buf_len;
}

static ssize_t common_sysfs_store(struct kobject *kobj, struct attribute *attr,
				  const char *buf, size_t size)
{
	struct k_obj_attribute *pci_attr =
	    container_of(attr, struct k_obj_attribute, attr);
	struct k_sysfs_file *sysfs_file =
	    container_of(pci_attr, struct k_sysfs_file, attr);

	if (sysfs_file->str_flag) {
		strncpy(sysfs_file->buf, buf, (size - 1));
		sysfs_file->buf[size - 1] = '\0';
		sysfs_file->buf_len = size;
		sysfs_file->cb(sysfs_file->name, sysfs_file->buf,
			       sysfs_file->buf_len, sysfs_file->str_flag);

	} else {
		sysfs_file->num = simple_strtol(buf, NULL, 10);
		sysfs_file->cb(sysfs_file->name,
			       (uint8_t *) (&(sysfs_file->num)), size,
			       sysfs_file->str_flag);
	}

	return size;
}

static const struct sysfs_ops common_sysfs_ops = {
	.show = common_sysfs_show,
	.store = common_sysfs_store
};

static struct kobj_type sysfs_entry_type = {
	.sysfs_ops = &common_sysfs_ops
};

static inline void *create_sysfs_file(int8_t *name, void *parent,
				      uint8_t str_flag)
{
	int err = 0;
	struct k_sysfs_file *newfile =
	    kzalloc(sizeof(struct k_sysfs_file), GFP_KERNEL);
	struct sysfs_dir *p_sysfs_dir = (struct sysfs_dir *)parent;

	strcpy(newfile->name, name);

	newfile->str_flag = str_flag;
	newfile->cb = NULL;

	newfile->attr.attr.name = newfile->name;
	newfile->attr.attr.mode = S_IRUGO | S_IWUSR;
	newfile->attr.show = NULL;
	newfile->attr.store = NULL;

	err = sysfs_create_file(&(p_sysfs_dir->kobj), &(newfile->attr.attr));
	if (err) {
		kfree(newfile);
		return NULL;
	}
	return (void *)newfile;
}

static inline void *create_sysfs_file_cb(int8_t *name, void *parent,
					 uint8_t str_flag, void (*cb) (int8_t *,
								       int8_t *,
								       int,
								       char))
{
	struct k_sysfs_file *file = create_sysfs_file(name, parent, str_flag);
	if (file)
		file->cb = cb;
	return file;
}

static inline void *create_sysfs_dir(char *name, void *parent)
{
	int ret = 0;
	struct sysfs_dir *p_sysfs_dir = NULL;

	struct sysfs_dir *newdir =
	    kzalloc(sizeof(struct sysfs_dir), GFP_KERNEL);

	if(!newdir)
		return NULL;

	p_sysfs_dir = (struct sysfs_dir *)parent;

	strcpy(newdir->name, name);

	KOBJECT_INIT_AND_ADD((&(newdir->kobj)), &sysfs_entry_type,
			     ((parent == NULL) ? NULL : &(p_sysfs_dir->kobj)),
			     name);

	if (ret) {
		kfree(newdir);
		return NULL;
	}

	return (void *)newdir;
}

static inline void delete_sysfs_file(void *file, void *parent)
{
	struct k_sysfs_file *sysfs_file = (struct k_sysfs_file *)file;

	if (NULL == file)
		return;

	sysfs_remove_file(&(((struct sysfs_dir *)parent)->kobj),
			  &(sysfs_file->attr.attr));
	kfree(sysfs_file);
}

static inline void delete_sysfs_dir(void *dir)
{
	struct sysfs_dir *sys_dir = (struct sysfs_dir *)dir;
	if (NULL == dir)
		return;

	kobject_put(&(sys_dir->kobj));
	kobject_del(&(sys_dir->kobj));
	kfree(sys_dir);
}

#endif
