#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/printk.h>

#define CMD_START_RECORD 0x1
#define CMD_STOP_RECORD  0x2
#define CMD_GET_RECORD   0x3

u64* schedule_points=NULL;
u64 record_count = 0;

SYSCALL_DEFINE2(schedule_info,unsigned int,cmd,u64*,buf) {
    switch(cmd) {
        case CMD_START_RECORD:
            if (schedule_points == NULL) {
                schedule_points = kmalloc(128*1024*sizeof(u64), GFP_KERNEL);
                if (!schedule_points) {
                    return -ENOMEM;
                }
                printk(KERN_INFO "Recording started\n");
            } else {
                printk(KERN_INFO "Already recording\n");
            }
            break;
        case CMD_STOP_RECORD:
            if (schedule_points != NULL) {
                kfree(schedule_points);
                schedule_points = NULL;
                record_count = 0;
                printk(KERN_INFO "Recording stopped\n");
            } else {
                printk(KERN_INFO "Not recording\n");
            }
            break;
        case CMD_GET_RECORD:
            if (schedule_points != NULL) {
                copy_to_user(buf, &record_count, sizeof(u64));
                copy_to_user(buf+1, schedule_points, record_count * sizeof(u64));
                printk(KERN_INFO "Returning recorded data\n");
            } else {
                printk(KERN_INFO "No data to return\n");
            }
            break;
        default:
            return -EINVAL;
    }
    return 0;
  }

void collect_info(void) {
    if(schedule_points==NULL)return;
    if(record_count >= 128*1024) {
        printk(KERN_INFO "Buffer full, too many schedule points\n");
        return;
    }
    void *return_address = __builtin_return_address(0);
    schedule_points[record_count++] = (u64)return_address;
}
