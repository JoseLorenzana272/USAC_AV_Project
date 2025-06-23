#include <linux/syscalls.h>
#include <linux/sysinfo.h>
#include <linux/vmstat.h>
#include <linux/uaccess.h>
#include <linux/namei.h>
#include <linux/fs.h>
#include <linux/usac_syscalls.h>
#include <linux/user_namespace.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/crypto.h>
#include <linux/scatterlist.h>
#include <linux/file.h>
#include <crypto/hash.h>

// Variables for scan path
#define MAX_PATH 256
#define HASH_LEN 33
#define MD5_DIGEST_LENGTH 16

struct signature {
    const char *hash;
    int severity; // 0: clean, 1: suspicious, 2: malicious
};

// Simulation of signatures.db
static const struct signature sig_db[] = {
    {"5d41402abc4b2a76b9719d911017c592", 2}, // Malicious
    {"098f6bcd4621d373cade4e832627b4f6", 1}, // Suspicious
    {"e99a18c428cb38d5f260853678922e03", 0}, // Clean
    {NULL, 0}
};

// Calculate md5
static int calculate_md5(struct file *file, char *hash_out)
{
    struct crypto_shash *tfm;
    struct shash_desc *desc;
    unsigned char *buffer;
    unsigned char *hash;
    int ret = 0;
    loff_t pos = 0;
    ssize_t bytes;
    int i;

    // Reserve memory
    buffer = kmalloc(PAGE_SIZE, GFP_KERNEL);
    if (!buffer) return -ENOMEM;

    hash = kmalloc(MD5_DIGEST_LENGTH, GFP_KERNEL);
    if (!hash) {
        kfree(buffer);
        return -ENOMEM;
    }

    // Initialize MD5
    tfm = crypto_alloc_shash("md5", 0, 0);
    if (IS_ERR(tfm)) {
        ret = PTR_ERR(tfm);
        goto cleanup;
    }

    desc = kmalloc(sizeof(struct shash_desc) + crypto_shash_descsize(tfm), GFP_KERNEL);
    if (!desc) {
        ret = -ENOMEM;
        goto cleanup_tfm;
    }
    desc->tfm = tfm;

    ret = crypto_shash_init(desc);
    if (ret) goto cleanup_desc;

    // Read file
    while ((bytes = kernel_read(file, buffer, PAGE_SIZE, &pos)) > 0) {
        ret = crypto_shash_update(desc, buffer, bytes);
        if (ret) goto cleanup_desc;
    }

    if (bytes < 0) {
        ret = bytes;
        goto cleanup_desc;
    }

    // Finish hash
    ret = crypto_shash_final(desc, hash);
    if (ret) goto cleanup_desc;

    // Transform to HEX
    for (i = 0; i < MD5_DIGEST_LENGTH; i++)
        sprintf(&hash_out[i * 2], "%02x", hash[i]);
    hash_out[HASH_LEN - 1] = '\0';

cleanup_desc:
    kfree(desc);
cleanup_tfm:
    crypto_free_shash(tfm);
cleanup:
    kfree(hash);
    kfree(buffer);
    return ret;
}

// Compare with simulated  signatures.db
static int lookup_hash(const char *hash)
{
    int i;
    for (i = 0; sig_db[i].hash; i++) {
        if (strcmp(hash, sig_db[i].hash) == 0)
            return sig_db[i].severity;
    }
    return 0; // Clean by default
}


SYSCALL_DEFINE1(antivirus_stats, struct antivirus_stats __user *, stats)
{
    struct sysinfo si;
    struct antivirus_stats kstats;

    si_meminfo(&si);

    kstats.mem_used = (si.totalram - si.freeram) * si.mem_unit / 1024;
    kstats.mem_free = si.freeram * si.mem_unit / 1024;
    kstats.mem_cache = si.bufferram * si.mem_unit / 1024;
    kstats.swap_used = (si.totalswap - si.freeswap) * si.mem_unit / 1024;
    kstats.active_pages = global_node_page_state(NR_ACTIVE_ANON) +
                          global_node_page_state(NR_ACTIVE_FILE);
    kstats.inactive_pages = global_node_page_state(NR_INACTIVE_ANON) +
                            global_node_page_state(NR_INACTIVE_FILE);

    if (copy_to_user(stats, &kstats, sizeof(struct antivirus_stats))) {
        pr_err("USAC-AV: Failed to copy stats to user space\n");
        return -EFAULT;
    }

    return 0;
}

// QUARANTINE FILE
SYSCALL_DEFINE1(quarantine_file, const char __user *, path)
{
    struct path src_path, dest_dir, parent_path;
    struct dentry *quarantine_dentry, *dest_dentry;
    struct renamedata rd;
    char *kpath, *filename;
    char dest_path[PATH_MAX];
    struct mnt_idmap *idmap = &nop_mnt_idmap; // Usar idmap sin cambios
    int ret;

    // Copiar la ruta desde el espacio de usuario
    kpath = kmalloc(PATH_MAX, GFP_KERNEL);
    if (!kpath)
        return -ENOMEM;
    if (strncpy_from_user(kpath, path, PATH_MAX) < 0) {
        pr_err("USAC-AV: Failed to copy path from user space\n");
        ret = -EFAULT;
        goto out_kpath;
    }
    kpath[PATH_MAX - 1] = '\0';

    // Obtener el nombre del archivo
    filename = strrchr(kpath, '/');
    if (!filename) {
        pr_err("USAC-AV: Invalid path\n");
        ret = -EINVAL;
        goto out_kpath;
    }
    filename++;

    // Resolver la ruta del archivo fuente
    ret = kern_path(kpath, LOOKUP_FOLLOW, &src_path);
    if (ret) {
        pr_err("USAC-AV: Failed to resolve source path %s\n", kpath);
        goto out_kpath;
    }

    // Resolver o crear /var/quarantine
    ret = kern_path("/var/quarantine", LOOKUP_FOLLOW | LOOKUP_DIRECTORY, &dest_dir);
    if (ret) {
        // Resolver /var como directorio padre
        ret = kern_path("/var", LOOKUP_FOLLOW | LOOKUP_DIRECTORY, &parent_path);
        if (ret) {
            pr_err("USAC-AV: Failed to resolve /var\n");
            path_put(&src_path);
            goto out_kpath;
        }

        // Crear /var/quarantine
        quarantine_dentry = kern_path_create(AT_FDCWD, "/var/quarantine", &parent_path, 0700);
        if (IS_ERR(quarantine_dentry)) {
            pr_err("USAC-AV: Failed to create quarantine dentry\n");
            path_put(&src_path);
            path_put(&parent_path);
            ret = PTR_ERR(quarantine_dentry);
            goto out_kpath;
        }

        ret = vfs_mkdir(idmap, d_inode(parent_path.dentry), quarantine_dentry, 0700);
        if (ret) {
            pr_err("USAC-AV: Failed to create /var/quarantine\n");
            path_put(&src_path);
            path_put(&parent_path);
            dput(quarantine_dentry);
            goto out_kpath;
        }

        path_put(&parent_path);
        dput(quarantine_dentry);

        // Resolver de nuevo /var/quarantine
        ret = kern_path("/var/quarantine", LOOKUP_FOLLOW | LOOKUP_DIRECTORY, &dest_dir);
        if (ret) {
            pr_err("USAC-AV: Failed to resolve /var/quarantine after creation\n");
            path_put(&src_path);
            goto out_kpath;
        }
    }

    // Construir la ruta de destino
    snprintf(dest_path, PATH_MAX, "%s/%s", "/var/quarantine", filename);

    // Crear la entrada de destino
    dest_dentry = kern_path_create(AT_FDCWD, dest_path, &dest_dir, 0);
    if (IS_ERR(dest_dentry)) {
        pr_err("USAC-AV: Failed to create destination path %s\n", dest_path);
        path_put(&src_path);
        path_put(&dest_dir);
        ret = PTR_ERR(dest_dentry);
        goto out_kpath;
    }

    // Preparar la estructura renamedata
    rd.old_mnt_idmap = idmap;
    rd.old_dir = d_inode(src_path.dentry->d_parent);
    rd.old_dentry = src_path.dentry;
    rd.new_mnt_idmap = idmap;
    rd.new_dir = d_inode(dest_dir.dentry);
    rd.new_dentry = dest_dentry;
    rd.flags = 0;
    rd.delegated_inode = NULL;

    // Mover el archivo
    ret = vfs_rename(&rd);
    if (ret) {
        pr_err("USAC-AV: Failed to move file to %s\n", dest_path);
        dput(dest_dentry);
        goto out_paths;
    }

    // Liberar recursos
    path_put(&src_path);
    path_put(&dest_dir);
    dput(dest_dentry);

out_kpath:
    kfree(kpath);
    return ret;

out_paths:
    path_put(&src_path);
    path_put(&dest_dir);
    kfree(kpath);
    return ret;
}

// Scan File Sys Call
SYSCALL_DEFINE1(scan_file, const char __user *, filepath)
{
    char *kpath;
    struct file *file;
    char hash[HASH_LEN];
    int ret;

    // Reserve memory for route
    kpath = kmalloc(MAX_PATH, GFP_KERNEL);
    if (!kpath) return -ENOMEM;

    // Copy route from user space
    if (copy_from_user(kpath, filepath, MAX_PATH)) {
        ret = -EFAULT;
        goto free_kpath;
    }
    kpath[MAX_PATH - 1] = '\0';

    printk(KERN_INFO "[USAC-AV] Scanning File: %s\n", kpath);

    // Open file
    file = filp_open(kpath, O_RDONLY, 0);
    if (IS_ERR(file)) {
        ret = PTR_ERR(file);
        printk(KERN_ERR "[USAC-AV] Error opening the file: %d\n", ret);
        goto free_kpath;
    }

    // Calculate hash
    ret = calculate_md5(file, hash);
    if (ret) {
        printk(KERN_ERR "[USAC-AV] Error calculating MD5: %d\n", ret);
        goto close_file;
    }

    printk(KERN_INFO "[USAC-AV] Hash calculated: %s\n", hash);

    // Compare with signatures.db simulation
    ret = lookup_hash(hash);

close_file:
    filp_close(file, NULL);
free_kpath:
    kfree(kpath);
    return ret;
}