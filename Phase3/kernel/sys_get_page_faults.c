#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>


SYSCALL_DEFINE2(get_page_faults, pid_t, pid, struct page_faults_data __user *, info_user) {
    struct task_struct *pid_taskstruct;
    struct page_faults_data page_data_num;

    if (pid <= 0) {
        printk(KERN_WARNING "[ERROR!] get_page_faults: PID INVALIDO ( %d )\n", pid);
        return -EINVAL;
    }

    rcu_read_lock();

    pid_taskstruct = find_task_by_vpid(pid);
    if (!pid_taskstruct) {

        rcu_read_unlock();
        printk(KERN_ERR "[!ERROR] get_page_faults: no se encontro el pid o data del pid %d\n", pid);
        return -ESRCH; 
    }

    task_lock(pid_taskstruct);
  
    page_data_num.minor_faults = pid_taskstruct->min_flt;
    page_data_num.major_faults = pid_taskstruct->maj_flt;

    task_unlock(pid_taskstruct);

    rcu_read_unlock();
 
    if (copy_to_user(info_user, &page_data_num, sizeof(page_data_num))) {
        printk(KERN_ERR "[ERROR!] get_page_faults: Error al usas copy_to_user --- pid  %d\n", pid);
        return -EFAULT;
    }

    printk(KERN_INFO "[SUCCESS! - DATA] get_page_faults : PID %d ====> [MINOR %lu ], [MAJOR %lu ]\n",pid, page_data_num.minor_faults, page_data_num.major_faults);

    return 0;
}