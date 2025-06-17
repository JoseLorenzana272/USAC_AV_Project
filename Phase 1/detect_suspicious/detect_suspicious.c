#include <linux/syscalls.h>
#include <linux/uaccess.h>
#include <linux/sched.h>
#include <linux/string.h>

SYSCALL_DEFINE1(detect_suspicious, const char __user *filename)
{
    char k_filename[256];
    long len;

    len = strncpy_from_user(k_filename, filename, sizeof(k_filename) - 1);
    if (len < 0)
        return -EFAULT;

    k_filename[len] = '\0';

    if (strstr(k_filename, "nmap") || strstr(k_filename, "netcat") || strstr(k_filename, "ssh")) {
        printk(KERN_ALERT "Advertencia: intento de uso de herramienta de red por PID %d (%s)\n",
               current->pid, k_filename);
    }

    return 0;
}
