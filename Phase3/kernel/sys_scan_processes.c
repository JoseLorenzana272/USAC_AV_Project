
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/pid.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/string.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/sched/signal.h>
#include <linux/sched/mm.h>
#include <linux/sched/task.h>

struct process_info {
    pid_t pid;
    pid_t ppid;
    char comm[TASK_COMM_LEN];
    long state;
    unsigned long vsize;
    unsigned long rss;
    int nice;
    unsigned long start_time;
    unsigned long utime;
    unsigned long stime;
};

static long get_task_state(struct task_struct *task)
{

    if (task_is_running(task))
        return TASK_RUNNING;
    else if (task_is_stopped_or_traced(task))
        return TASK_STOPPED;
    else
        return TASK_INTERRUPTIBLE;  
}

SYSCALL_DEFINE0(scan_processes)
{
    struct task_struct *task;
    struct process_info *proc_array;
    int count = 0, i = 0;
    struct mm_struct *mm;
    
    printk(KERN_INFO "sys_scan_processes: Iniciando escaneo de procesos\n");
    
   
    rcu_read_lock();
    for_each_process(task) {
        count++;
    }
    rcu_read_unlock();
    
    if (count == 0) {
        printk(KERN_WARNING "sys_scan_processes: No se encontraron procesos\n");
        return 0;
    }
    

    proc_array = kmalloc(count * sizeof(struct process_info), GFP_KERNEL);
    if (!proc_array) {
        printk(KERN_ERR "sys_scan_processes: Error al asignar memoria\n");
        return -ENOMEM;
    }
    

    rcu_read_lock();
    for_each_process(task) {
        if (i >= count) break;
        
        proc_array[i].pid = task->pid;
        proc_array[i].ppid = task->real_parent ? task->real_parent->pid : 0;
        strncpy(proc_array[i].comm, task->comm, TASK_COMM_LEN);
        proc_array[i].state = get_task_state(task);
        proc_array[i].nice = task_nice(task);
        proc_array[i].start_time = task->start_time;
        proc_array[i].utime = task->utime;
        proc_array[i].stime = task->stime;
        
  
        mm = task->mm;
        if (mm) {
            proc_array[i].vsize = mm->total_vm;
            proc_array[i].rss = get_mm_rss(mm);
        } else {
            proc_array[i].vsize = 0;
            proc_array[i].rss = 0;
        }
        
        i++;
    }
    rcu_read_unlock();
    

    printk(KERN_INFO "=== SCAN DE PROCESOS ===\n");
    printk(KERN_INFO "Total de procesos: %d\n", count);
    printk(KERN_INFO "PID\tPPID\tNOMBRE\t\tESTADO\tVSIZE\tRSS\tNICE\n");
    
    for (i = 0; i < count; i++) {
        printk(KERN_INFO "%d\t%d\t%-15s\t%ld\t%lu\t%lu\t%d\n",
               proc_array[i].pid,
               proc_array[i].ppid,
               proc_array[i].comm,
               proc_array[i].state,
               proc_array[i].vsize,
               proc_array[i].rss,
               proc_array[i].nice);
    }
    
    printk(KERN_INFO "=== FIN SCAN PROCESOS ===\n");
    
    kfree(proc_array);
    return count;
}