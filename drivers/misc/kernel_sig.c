#include <linux/sched.h>
#include <asm/siginfo.h>
#include <linux/pid_namespace.h>
#include <linux/pid.h>
#include <linux/proc_fs.h>
#include <linux/pid.h>
#include <linux/slab.h>
#include <linux/delay.h>
#include <linux/interrupt.h>
#include <linux/module.h>
#include <linux/gpio.h>
#include <asm/uaccess.h>
#include <linux/platform_device.h>

typedef enum
{
	THIS_MODULE_IOCTL_SET_OWNER = 0x111,
}MODULE_IOCTL_CMD;

int p_id;
int irq_pin, flag = 1;
static int app_flag = 0;
unsigned int gpio_num = 246;
unsigned int gpio_rts_num = 244;
static int owner = 0;
static struct task_struct * current_task_sig;
static int sig_num = SIGUSR1;
struct pid *pid_struct;
struct siginfo info;
struct platform_device *device;

int temp = 3;
ssize_t proc_write(struct file *filp,const char *buf,
         size_t count, loff_t *f_pos) 
{
	char *id;

	app_flag = 1;
	id = (char *)kmalloc(1000*sizeof(char),GFP_KERNEL);
	current_task_sig = kmalloc(sizeof(struct task_struct ),GFP_KERNEL);
	if(copy_from_user(id,buf,count))
		return -EFAULT;
	p_id = simple_strtoul(id,NULL,0);
	memset(&info, 0, sizeof(struct siginfo));
	info.si_signo = SIGUSR1;
	info.si_code = SI_QUEUE;
	info.si_int = 1234;
	if(flag == 0)
		enable_irq(irq_pin);
	flag = 1;
	if(gpio_request(gpio_rts_num,"T4_to_bmc_rts")) {
		return -EINVAL;
	}
	if (gpio_direction_output(gpio_rts_num, 0) < 0 ) {
		return -EINVAL;
	}
	gpio_set_value(gpio_rts_num,0);
	gpio_free(gpio_rts_num);

	return count;
}

ssize_t usb_hub_proc_write(struct file *filp,const char *buf,
         size_t count, loff_t *f_pos) 
{
	printk(KERN_INFO "usb hub reset\n");
	if(gpio_request(137,"hub_reset")) {
		printk(KERN_INFO "unable to request gpio\n");	
	}
	if(gpio_direction_output(137,1) < 0 ){
		printk(KERN_INFO "failed to set gpio direction\n");	
	}
	gpio_set_value(137,1);
	gpio_free(137);
	return count;
}

ssize_t usb_hub_proc_write1(struct file *filp,const char *buf,
         size_t count, loff_t *f_pos) 
{
	printk(KERN_INFO "usb hub out of reset\n");
	if(gpio_request(137,"hub_reset")){
		printk(KERN_INFO "unable to request gpio\n");	
	}
	if(gpio_direction_output(137,0) < 0 ){
		printk(KERN_INFO "failed to set gpio direction\n");	
	}
	gpio_set_value(137,0);
	gpio_free(137);
	return count;
}


static irqreturn_t interrupt_handler(int irq, void *var)
{
	int ret;

	if(app_flag) {
		pid_struct = find_get_pid(p_id);
		rcu_read_lock();
		current_task_sig = pid_task(pid_struct, PIDTYPE_PID);
		rcu_read_unlock();
		ret = send_sig_info(sig_num, &info, current_task_sig);
		if (ret < 0) {
			printk(KERN_INFO "error sending signal\n");
		}
	}
	return IRQ_HANDLED;
}

static struct file_operations proc_fops = {
              .write = proc_write,
};

static struct file_operations usb_proc_fops = {
              .write = usb_hub_proc_write,
};

static struct file_operations usb_proc_fops1 = {
              .write = usb_hub_proc_write1,
};


int t4_id_read(struct file *filp,char *buf,size_t count,loff_t *offp ) 
{
	char data[3] = {0};
	int value;
	gpio_free(203);
	if(gpio_request(203, "T4_ID")) {
		printk(KERN_INFO "Unable to request gpio 203\n");
		return -1;
	}
	if(gpio_direction_input(203)) {
		printk(KERN_INFO "Unable to set input direction 203\n");
		return -1;
	}
	value = gpio_get_value(203);
	if(value == 0)
		data[0] = '0';
	else
		data[0] = '1';
	data[1] = '\n';
	if(count > temp) {
		count = temp;
	}
	temp = temp - count;
	copy_to_user(buf,data, 3);
	if(count == 0)
		temp = 3;
	return count;
}

static struct file_operations t4_id_fops = {
	.read = t4_id_read,
};

static int create_proc_file(void)
{
	proc_create_data("sig_uart", S_IFREG | S_IWUGO, NULL, &proc_fops, NULL);
	proc_create_data("usb_hub_reset", S_IFREG | S_IWUGO, NULL, &usb_proc_fops, NULL);
	proc_create_data("usb_hub_out_of_reset", S_IFREG | S_IWUGO, NULL, &usb_proc_fops1, NULL);
	proc_create_data("t4_id", 0444, NULL, &t4_id_fops, NULL);
	return 0;
}

static int t4_to_bmc_probe(struct platform_device *devptr)
{
	
	create_proc_file();		//Creating a proc entry
	if(!gpio_is_valid(gpio_num) ) {
		return  -EINVAL;
	}
	gpio_free(gpio_num);
	if(gpio_request(gpio_num ,"T4_to_bmc")) {
		return -EINVAL;
	}
	if (gpio_direction_input(gpio_num) < 0 ) {
		return -EINVAL;
	}
	if((irq_pin = gpio_to_irq(gpio_num)) < 0 ) {
		return -EINVAL;
	}
	if (request_irq(irq_pin, interrupt_handler, IRQF_TRIGGER_FALLING, "signal to uart", NULL)) {
		flag = 0;
		return -EIO;
	}
	flag = 1;
	return 0;
}

static int t4_to_bmc_remove(struct platform_device *devptr)
{
	gpio_free(gpio_num);
	free_irq(irq_pin, NULL);
	return 0;
}

static struct platform_driver t4_to_bmc_driver = {
	.probe          = t4_to_bmc_probe,
	.remove         = t4_to_bmc_remove,
	.driver         = {
		.name   = "T4_TO_BMC_UART_DRIVER",
		.owner  = THIS_MODULE,
	},
};

static int __init sig2pid_init_module(void)
{
	int err;

	err = platform_driver_register(&t4_to_bmc_driver);
	if (err < 0)
		return err;
	device = platform_device_register_simple("T4_TO_BMC_UART_DRIVER", 0, NULL, 0);
	if (IS_ERR(device))
		return -1;
	return 0;
}


static void __exit sig2pid_exit_module(void)
{
	platform_device_unregister(device);
	platform_driver_unregister(&t4_to_bmc_driver);
	return;
}

module_init(sig2pid_init_module);
module_exit(sig2pid_exit_module);
//MODULE_LICENSE("GPL"); 
