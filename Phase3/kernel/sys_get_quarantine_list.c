#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/namei.h>

#define MAX_QUARANTINE_FILES 128
#define MAX_FILENAME_LEN 256
#define QUARANTINE_PATH "/var/quarantine/"

SYSCALL_DEFINE1(get_quarantine_list, char __user *, user_buf)
{
    struct file *dir;
    struct dir_context *ctx;
    struct linux_dirent64 *d;
    char *kbuf;
    int ret = 0;
    mm_segment_t old_fs;

    kbuf = kzalloc(PAGE_SIZE, GFP_KERNEL);
    if (!kbuf)
        return -ENOMEM;

    old_fs = get_fs();
    set_fs(KERNEL_DS);

    dir = filp_open(QUARANTINE_PATH, O_RDONLY | O_DIRECTORY, 0);
    if (IS_ERR(dir)) {
        printk(KERN_ERR "get_quarantine_list: No se pudo abrir el directorio %s\n", QUARANTINE_PATH);
        ret = PTR_ERR(dir);
        goto out;
    }

    ret = kernel_read(dir, kbuf, PAGE_SIZE, &dir->f_pos);

    if (ret < 0) {
        printk(KERN_ERR "get_quarantine_list: Error al leer el directorio\n");
        filp_close(dir, NULL);
        goto out;
    }

    if (copy_to_user(user_buf, kbuf, ret)) {
        printk(KERN_ERR "get_quarantine_list: Error en copy_to_user\n");
        ret = -EFAULT;
    }

    filp_close(dir, NULL);

out:
    set_fs(old_fs);
    kfree(kbuf);
    return ret;
}
