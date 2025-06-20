#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/printk.h>

#define CMD_START_RECORD 0x1
#define CMD_STOP_RECORD  0x2
//#define CMD_GET_RECORD   0x3
#define CMD_HINT_ADDR    0x4
#define CMD_TEST 0x5
#define CMD_GET_RECORD 0x1234
#define MaxSyscallPointSize 200


u64* sche_points=NULL;
u64 cnt=0;

__attribute__((__noinline__)) void step_hint(void){
    pr_info("I am used to be vm hint addr\n");
    return;
}

// Server for hypercall
__attribute__((__noinline__)) void trampoline_exit(void) {
    asm volatile("nop");
}

// Server for hypercall
void trampoline_entry(void){
    while(1){
        trampoline_exit();
    }
}

void test_kasan(void){
    u64*ptr=kmalloc(100*sizeof(u64),GFP_KERNEL);
    kfree(ptr);
    ptr[0]=0xdeadbeef;
}

SYSCALL_DEFINE2(schedule_info,unsigned int,cmd,u64*,buf) {
    switch(cmd) {
        case CMD_START_RECORD:
            if (sche_points == NULL) {
                sche_points = kmalloc(2*MaxSyscallPointSize*sizeof(u64), GFP_KERNEL);
                if (!sche_points) {
                    return -ENOMEM;
                }
                printk(KERN_INFO "Recording started\n");
            } else {
                printk(KERN_INFO "Already recording\n");
            }
            break;
        case CMD_STOP_RECORD:
            if (sche_points != NULL) {
                kfree(sche_points);
                sche_points = NULL;
                cnt = 0;
                printk(KERN_INFO "Recording stopped\n");
            } else {
                printk(KERN_INFO "Not recording\n");
            }
            break;
        case CMD_GET_RECORD:
            if (sche_points != NULL) {
                if (copy_to_user(buf, sche_points, 2*cnt * sizeof(u64)))
                    return -EFAULT;
                printk(KERN_INFO "Returning recorded data\n");
                return cnt;
            } else {
                printk(KERN_INFO "No data to return\n");
            }
            break;
        case CMD_HINT_ADDR:
            step_hint();
            break;
        case CMD_TEST:
            test_kasan();
        default:
            return -EINVAL;
    }
    return 0;
  }


void store_record(void){
    if(sche_points == NULL)return;
    if(cnt >= MaxSyscallPointSize){
        return;
    }
    void *return_address = __builtin_return_address(0);
    for(int i=0;i < 2*cnt;i++){
        if(return_address==sche_points[i])return;
    }
    sche_points[2*cnt] = return_address;
    sche_points[2*cnt+1] = 1;
    cnt++;
    return;
}


void load_record(void){
    if(sche_points == NULL)return;
    if(cnt >= MaxSyscallPointSize){
        return;
    }
    void *return_address = __builtin_return_address(0);
    for(int i=0;i < 2*cnt;i++){
        if(return_address==sche_points[i])return;
    }
    sche_points[2*cnt] = return_address;
    sche_points[2*cnt+1] = 0;
    cnt++;
    return;
}

