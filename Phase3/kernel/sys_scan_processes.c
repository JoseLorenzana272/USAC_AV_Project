
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

// Eliminar la definición duplicada de process_info ya que está en el header

// Función auxiliar para obtener el estado del proceso de manera segura
static long get_task_state(struct task_struct *task)
{
    // Método más compatible - usar task_is_running y otros helpers
    if (task_is_running(task))
        return TASK_RUNNING;
    else if (task_is_stopped_or_traced(task))
        return TASK_STOPPED;
    else
        return TASK_INTERRUPTIBLE;  // Estado por defecto
}

SYSCALL_DEFINE2(scan_processes, struct process_info __user *, buffer, int __user *, count)
{
    struct task_struct *task;
    struct process_info *proc_array;
    int proc_count = 0, i = 0;
    struct mm_struct *mm;
    int user_buffer_size;
    
    printk(KERN_INFO "sys_scan_processes: Iniciando escaneo de procesos\n");
    
    // Verificar parámetros del usuario
    if (!buffer || !count) {
        printk(KERN_ERR "sys_scan_processes: Parámetros inválidos\n");
        return -EINVAL;
    }
    
    // Obtener el tamaño del buffer del usuario
    if (copy_from_user(&user_buffer_size, count, sizeof(int))) {
        printk(KERN_ERR "sys_scan_processes: Error al leer tamaño del buffer\n");
        return -EFAULT;
    }
    
    // Primer paso: contar procesos
    rcu_read_lock();
    for_each_process(task) {
        proc_count++;
    }
    rcu_read_unlock();
    
    if (proc_count == 0) {
        printk(KERN_WARNING "sys_scan_processes: No se encontraron procesos\n");
        if (copy_to_user(count, &proc_count, sizeof(int)))
            return -EFAULT;
        return 0;
    }
    
    // Verificar si el buffer del usuario es suficiente
    if (user_buffer_size < proc_count) {
        printk(KERN_INFO "sys_scan_processes: Buffer insuficiente. Necesario: %d, Disponible: %d\n", 
               proc_count, user_buffer_size);
        if (copy_to_user(count, &proc_count, sizeof(int)))
            return -EFAULT;
        return -ENOSPC;  // No space left on device
    }
    
    // Asignar memoria para el array de procesos
    proc_array = kmalloc(proc_count * sizeof(struct process_info), GFP_KERNEL);
    if (!proc_array) {
        printk(KERN_ERR "sys_scan_processes: Error al asignar memoria\n");
        return -ENOMEM;
    }
    
    // Segundo paso: recopilar información
    rcu_read_lock();
    for_each_process(task) {
        if (i >= proc_count) break;
        
        proc_array[i].pid = task->pid;
        proc_array[i].ppid = task->real_parent ? task->real_parent->pid : 0;
        strncpy(proc_array[i].comm, task->comm, TASK_COMM_LEN);
        proc_array[i].state = get_task_state(task);
        proc_array[i].nice = task_nice(task);
        proc_array[i].start_time = task->start_time;
        proc_array[i].utime = task->utime;
        proc_array[i].stime = task->stime;
        
        // Información de memoria
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
    
    // Copiar datos al espacio de usuario
    if (copy_to_user(buffer, proc_array, proc_count * sizeof(struct process_info))) {
        printk(KERN_ERR "sys_scan_processes: Error al copiar datos al usuario\n");
        kfree(proc_array);
        return -EFAULT;
    }
    
    // Actualizar el conteo de procesos para el usuario
    if (copy_to_user(count, &proc_count, sizeof(int))) {
        printk(KERN_ERR "sys_scan_processes: Error al copiar conteo al usuario\n");
        kfree(proc_array);
        return -EFAULT;
    }
    
    printk(KERN_INFO "sys_scan_processes: %d procesos copiados exitosamente\n", proc_count);
    
    kfree(proc_array);
    return proc_count;
}