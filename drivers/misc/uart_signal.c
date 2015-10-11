#include <linux/sched.h>
#include <asm/siginfo.h>
#include <linux/pid_namespace.h>
#include <linux/pid.h>

typedef enum
{
	THIS_MODULE_IOCTL_SET_OWNER = 0x111,
}MODULE_IOCTL_CMD;


static int owner = 0;
static struct task_struct * current_task;

ssize_t kopin_proc_read(struct file *filp, char *buf,
		size_t count, loff_t *f_pos) {
	printk("%s,%d.sending to owner %d\n",__func__, __LINE__, owner);

	struct siginfo info;
	memset(&info, 0, sizeof(struct siginfo));
	info.si_signo = SIGUSR1;
	info.si_code = 0;
	info.si_int = 1234;
	if (current_task == NULL){
		rcu_read_lock();
		current_task = pid_task(find_vpid(owner), PIDTYPE_PID);
		rcu_read_unlock();
	}
	int ret = send_sig_info(sig_num, &info, current_task);
	if (ret < 0) {
		printk("error sending signal\n");
	}
}

static struct file_operations kopin_proc_fops = {
	        .read = proc_read,
}

static int create_proc_file(void)
{
	 create_proc_entry("signal_test", S_IFREG | S_IWUGO, NULL,&proc_fops,NULL);
	return 0;
}


int sig2pid_init_module(void)
{
	return create_proc_file();
}

void sig2pid_exit_module(void)
{
	remove_proc_entry(PROC_NAME, NU
}

MODULE_INIT(sig2pid_init_module);
MODULE_EXIT(sig2pid_exit_module);
MODULE_LICENSE("GPL");
