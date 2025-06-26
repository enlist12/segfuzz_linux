#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/printk.h>
#include <linux/xxhash.h>
#include <linux/sched/signal.h> 
#include <linux/spinlock.h>

static DEFINE_SPINLOCK(record_lock);

#define CMD_START_RECORD 0x1
#define CMD_STOP_RECORD 0x2
//#define CMD_GET_RECORD   0x3
#define CMD_HINT_ADDR 0x4
#define CMD_TEST 0x5
#define CMD_GET_RECORD 0x1234
#define CMD_CLEAR_TASK 0x3333
#define MaxSyscallPointSize 200
#define magic 0xffff
#define NUM_STACK_ENTRIES 64
#define traceLen 2 * 1024

typedef struct point {
	u64 addr;
	u64 type;
	u64 ctx;
} Point;

Point *sche_points = NULL;
u64 cnt = 0;
int trust_val;
unsigned long flags;

struct task_struct *task;

__attribute__((__noinline__)) void step_hint(void)
{
	//pr_info("I am used to be vm hint addr\n");
	asm volatile("nop");
}

// Server for hypercall
__attribute__((__noinline__)) void trampoline_exit(void)
{
	asm volatile("nop");
}

// Server for hypercall
void trampoline_entry(void)
{
	while (1) {
		trampoline_exit();
	}
}

void clear_task(void){
	for_each_process(task){
		task->current_syscall_nr = magic;
	}
	cnt=0;
	sche_points = NULL;
}

void test_kasan(void)
{
	u64 *ptr = kmalloc(100 * sizeof(u64), GFP_KERNEL);
	kfree(ptr);
	ptr[0] = 0xdeadbeef;
}

SYSCALL_DEFINE3(schedule_info, unsigned int, cmd, u64 __user *, buf, int, pre_val)
{
	switch (cmd) {
	case CMD_START_RECORD:
		if (sche_points == NULL) {
			sche_points = kmalloc_array(MaxSyscallPointSize,sizeof(Point),GFP_KERNEL);
			if (!sche_points) {
				return -ENOMEM;
			}
			trust_val = pre_val;
			//set magic num
			current->current_syscall_nr = pre_val;
			printk(KERN_INFO "Recording started\n");
		} else {
			printk(KERN_INFO "Already recording\n");
		}
		break;
	case CMD_STOP_RECORD:
		if (sche_points != NULL) {
			kfree(sche_points);
			sche_points = NULL;
			trust_val = 0;
			current->current_syscall_nr = magic;
			cnt = 0;
			printk(KERN_INFO "Recording stopped\n");
		} else {
			printk(KERN_INFO "Not recording\n");
		}
		break;
	case CMD_GET_RECORD:
		if (sche_points != NULL) {
			// add spinlock would cause bug
			if (copy_to_user(buf, sche_points, cnt * sizeof(Point))){
				return -EFAULT;
			}
			printk(KERN_INFO "Returning recorded data\n");
			return cnt;
		} else {
			printk(KERN_INFO "No data to return\n");
		}
		break;
	case CMD_CLEAR_TASK:
		clear_task();
		break;
	case CMD_HINT_ADDR:
		step_hint();
		break;
	case CMD_TEST:
		test_kasan();
		break;
	default:
		return -EINVAL;
	}
	return 0;
}

u64 getCtx(void)
{
	char *traceBuf = kmalloc(traceLen, GFP_ATOMIC);
	unsigned long *stack_entries = kmalloc_array(NUM_STACK_ENTRIES, sizeof(unsigned long), GFP_ATOMIC);

    if (!traceBuf || !stack_entries) {
		kfree(traceBuf);
		kfree(stack_entries);
		return 0;
	}

	int num_stack_entries =
		stack_trace_save(stack_entries, NUM_STACK_ENTRIES, 0);
	stack_trace_snprint(traceBuf, traceLen, stack_entries,
			    NUM_STACK_ENTRIES, 0);
	u64 hash_val = xxh64(traceBuf, traceLen, 0);

    kfree(traceBuf);
	kfree(stack_entries);

	return hash_val;
}

void store_record(void)
{
	if (in_interrupt())
		return;

	if (current->current_syscall_nr != trust_val) {
		return;
	}
	if (sche_points == NULL)
		return;

    spin_lock_irqsave(&record_lock,flags);

	if (cnt >= MaxSyscallPointSize) {
		spin_unlock_irqrestore(&record_lock,flags);
		return;
	}
	Point tmp = {};
	void *return_address = __builtin_return_address(0);
	u64 ctx = getCtx();
	for (int i = 0; i < cnt; i++) {
		if (return_address == sche_points[i].addr){
            spin_unlock_irqrestore(&record_lock,flags);
			return;
        }
	}
	tmp.addr = (u64)return_address;
	tmp.type = 1;
	tmp.ctx = ctx;
	memcpy(&sche_points[cnt], &tmp, sizeof(Point));
	cnt++;

    spin_unlock_irqrestore(&record_lock,flags);

	return;
}

void load_record(void)
{
	if (in_interrupt())
		return;

	if (current->current_syscall_nr != trust_val) {
		return;
	}
	if (sche_points == NULL)
		return;

    spin_lock_irqsave(&record_lock,flags);

	if (cnt >= MaxSyscallPointSize) {
		spin_unlock_irqrestore(&record_lock,flags);
		return;
	}
	Point tmp = {};
	void *return_address = __builtin_return_address(0);
	u64 ctx = getCtx();
	for (int i = 0; i < cnt; i++) {
		if (ctx == sche_points[i].ctx &&
		    return_address == sche_points[i].addr){
            spin_unlock_irqrestore(&record_lock,flags);
			return;
        }
	}
	tmp.addr = (u64)return_address;
	tmp.type = 0;
	tmp.ctx = ctx;
	memcpy(&sche_points[cnt], &tmp, sizeof(Point));
	cnt++;

    spin_unlock_irqrestore(&record_lock,flags);

	return;
}
