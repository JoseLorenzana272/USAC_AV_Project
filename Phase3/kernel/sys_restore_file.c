#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>

#define QUARANTINE_PATH "/var/quarantine/"
#define META_SUFFIX ".meta"
#define MAX_PATH_LEN 512

SYSCALL_DEFINE1(restore_file, const char __user *, filename)
{
    char *kfilename, *src_path, *meta_path, *original_path;
    struct file *meta_file;
    mm_segment_t old_fs;
    int ret = 0;

    kfilename = kzalloc(MAX_PATH_LEN, GFP_KERNEL);
    src_path = kzalloc(MAX_PATH_LEN, GFP_KERNEL);
    meta_path = kzalloc(MAX_PATH_LEN, GFP_KERNEL);
    original_path = kzalloc(MAX_PATH_LEN, GFP_KERNEL);

    if (!kfilename || !src_path || !meta_path || !original_path) {
        ret = -ENOMEM;
        goto out_free;
    }

    if (copy_from_user(kfilename, filename, MAX_PATH_LEN)) {
        ret = -EFAULT;
        goto out_free;
    }

    snprintf(src_path, MAX_PATH_LEN, "%s%s", QUARANTINE_PATH, kfilename);
    snprintf(meta_path, MAX_PATH_LEN, "%s%s%s", QUARANTINE_PATH, kfilename, META_SUFFIX);

    old_fs = get_fs();
    set_fs(KERNEL_DS);

    meta_file = filp_open(meta_path, O_RDONLY, 0);
    if (IS_ERR(meta_file)) {
        printk(KERN_ERR "restore_file: No se encontró el archivo de metadata para %s\n", kfilename);
        ret = PTR_ERR(meta_file);
        goto out_setfs;
    }

    ret = kernel_read(meta_file, original_path, MAX_PATH_LEN, &meta_file->f_pos);
    filp_close(meta_file, NULL);

    if (ret <= 0) {
        printk(KERN_ERR "restore_file: No se pudo leer la ruta original\n");
        ret = -EIO;
        goto out_setfs;
    }

    original_path[strcspn(original_path, "\n")] = '\0';  // quitar newline

    ret = vfs_rename(src_path, original_path);
    if (ret < 0) {
        printk(KERN_ERR "restore_file: Error al restaurar archivo: %d\n", ret);
    } else {
        printk(KERN_INFO "restore_file: Archivo restaurado a %s\n", original_path);
    }

out_setfs:
    set_fs(old_fs);
out_free:
    kfree(kfilename);
    kfree(src_path);
    kfree(meta_path);
    kfree(original_path);
    return ret;
}
