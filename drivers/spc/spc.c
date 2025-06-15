#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/printk.h>

#define CMD_START_RECORD 0x1
#define CMD_STOP_RECORD  0x2
//#define CMD_GET_RECORD   0x3
#define CMD_HINT_ADDR    0x4
#define CMD_TEST 0x5
#define CMD_GET_LOAD_RECORD 0x1234
#define CMD_GET_STORE_RECORD 0X2345
#define MaxSyscallPointSize 200


u64* load_points=NULL;
u64* store_points=NULL;
u64 load_cnt = 0;
u64 store_cnt = 0;

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
            if ((load_points == NULL) && (store_points == NULL)) {
                load_points = kmalloc(MaxSyscallPointSize*sizeof(u64), GFP_KERNEL);
                if (!load_points) {
                    return -ENOMEM;
                }
                store_points = kmalloc(MaxSyscallPointSize*sizeof(u64), GFP_KERNEL);
                printk(KERN_INFO "Recording started\n");
            } else {
                printk(KERN_INFO "Already recording\n");
            }
            break;
        case CMD_STOP_RECORD:
            if ((store_points != NULL) && (load_points != NULL)) {
                kfree(store_points);
                store_points = NULL;
                store_cnt = 0;
                kfree(load_points);
                load_points = NULL;
                load_cnt = 0;
                printk(KERN_INFO "Recording stopped\n");
            } else {
                printk(KERN_INFO "Not recording\n");
            }
            break;
        case CMD_GET_LOAD_RECORD:
            if (load_points != NULL) {
                if (copy_to_user(buf, load_points, load_cnt * sizeof(u64)))
                    return -EFAULT;
                printk(KERN_INFO "Returning recorded data\n");
                return load_cnt;
            } else {
                printk(KERN_INFO "No data to return\n");
            }
            break;
        case CMD_GET_STORE_RECORD:
            if (store_points != NULL) {
                if (copy_to_user(buf, store_points, store_cnt * sizeof(u64)))
                    return -EFAULT;
                printk(KERN_INFO "Returning recorded data\n");
                return store_cnt;
            }
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
    if(store_points == NULL)return;
    if(store_cnt >= MaxSyscallPointSize){
        return;
    }
    void *return_address = __builtin_return_address(0);
    for(int i=0;i < store_cnt;i++){
        if(return_address==store_points[i])return;
    }
    store_points[store_cnt++] = (u64)return_address;
    return;
}


void load_record(void){
    if(load_points == NULL)return;
    if(load_cnt >= MaxSyscallPointSize){
        return;
    }
    void *return_address = __builtin_return_address(0);
    for(int i=0;i < load_cnt;i++){
        if(return_address==load_points[i])return;
    }
    load_points[store_cnt++] = (u64)return_address;
    return;
}

