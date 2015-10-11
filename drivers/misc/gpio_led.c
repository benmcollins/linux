
#include <linux/module.h>
#include <linux/kernel.h>
#include <asm/uaccess.h>
#include <linux/cdev.h>
#include <linux/proc_fs.h>
#include <linux/gpio.h>
#define MAX_PROC_SIZE 100
static char proc_data[MAX_PROC_SIZE];

static struct proc_dir_entry *proc_write_entry;

static struct gpio leds_gpios[] = {
	{ 192, GPIOF_OUT_INIT_LOW, "red LED" }, /* default to OFF */
	{ 194, GPIOF_OUT_INIT_HIGH, "yellow LED" }, /* default to OFF */

};

int led_set(void){
	int err;
	err = gpio_request_array(leds_gpios, ARRAY_SIZE(leds_gpios));
	if (err){
		printk(KERN_INFO "Error gpio request not accepted");
		return -ENOMEM;
	}
	gpio_direction_output(192, 1);
	gpio_direction_output(194, 0);

	//gpio_free_array(leds_gpios, ARRAY_SIZE(leds_gpios));

}


int read_proc(char *buf,char **start,off_t offset,int count,int *eof,void *data )
{
	int len=0;
	len = sprintf(buf,"\n %s\n ",proc_data);

	return len;
}

int write_proc(struct file *file,const char *buf,int count,void *data )
{

	if(count > MAX_PROC_SIZE)
		count = MAX_PROC_SIZE;
	if(copy_from_user(proc_data, buf, count))
		return -EFAULT;
//	if(proc_data[0] == 1 )
//		if(led_set())
//			return -EFAULT;
	
	printk("in led driver\n");
        led_set();
	return count;
}

static int open_proc(struct inode *inode, struct file *file)
{
	return 0;
}
static int release_proc(struct inode *inode, struct file *file)
{
	return 0;
}

struct file_operations led_fs = {
	.owner = THIS_MODULE,
	.open = open_proc,
	.read = read_proc,
	.write = write_proc,
	.release = release_proc,
};

void create_new_proc_entry()
{
	proc_write_entry = proc_create_data("red_led",0666,NULL,&led_fs,NULL);
	if(!proc_write_entry)
	{
		printk(KERN_INFO "Error creating proc entry");
		return -ENOMEM;
	}
	//proc_write_entry->read_proc = read_proc ;
	//proc_write_entry->write_proc = write_proc;
	printk(KERN_INFO "proc initialized");

}

int proc_init (void) {
	create_new_proc_entry();
        led_set();
	return 0;
}

void proc_cleanup(void) {
	printk(KERN_INFO " Inside cleanup_module\n");
	remove_proc_entry("proc_entry",NULL);
}
MODULE_LICENSE("GPL");   
module_init(proc_init);
module_exit(proc_cleanup);
