#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/sysinfo.h>
#include <linux/vmstat.h>
#include <linux/uaccess.h>
#include <linux/namei.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <crypto/hash.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>

// Definitions for scan file
#define MAX_PATH 256
#define HASH_LEN 33 // MD5 hash in hex (32 chars + null terminator)
#define MD5_DIGEST_LENGTH 16 // MD5 hash size in bytes

// Structure for page faults data
struct page_faults_data {
    unsigned long minor_faults;
    unsigned long major_faults;
};

// Structure for antivirus stats
struct antivirus_stats {
    unsigned long mem_used;
    unsigned long mem_free;
    unsigned long mem_cache;
    unsigned long swap_used;
    unsigned long active_pages;
    unsigned long inactive_pages;
};

// Structure for signatures simulation
struct signature {
    const char *hash;
    int severity; // 0: clean, 1: suspicious, 2: malicious
};

// Simulated signatures.db
static const struct signature sig_db[] = {
    {"5d41402abc4b2a76b9719d911017c592", 2}, // Malicious
    {"098f6bcd4621d373cade4e832627b4f6", 1}, // Suspicious
    {"e99a18c428cb38d5f260853678922e03", 0}, // Clean
    {NULL, 0}
};

// Calculate MD5 hash
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

    buffer = kmalloc(PAGE_SIZE, GFP_KERNEL);
    if (!buffer)
        return -ENOMEM;

    hash = kmalloc(MD5_DIGEST_LENGTH, GFP_KERNEL);
    if (!hash) {
        kfree(buffer);
        return -ENOMEM;
    }

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
    if (ret)
        goto cleanup_desc;

    while ((bytes = kernel_read(file, buffer, PAGE_SIZE, &pos)) > 0) {
        ret = crypto_shash_update(desc, buffer, bytes);
        if (ret)
            goto cleanup_desc;
    }

    if (bytes < 0) {
        ret = bytes;
        goto cleanup_desc;
    }

    ret = crypto_shash_final(desc, hash);
    if (ret)
        goto cleanup_desc;

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

// Lookup hash in simulated signatures.db
static int lookup_hash(const char *hash)
{
    int i;
    for (i = 0; sig_db[i].hash; i++) {
        if (strcmp(hash, sig_db[i].hash) == 0)
            return sig_db[i].severity;
    }
    return 0; // Clean by default
}

// Syscall: get_page_faults
SYSCALL_DEFINE2(get_page_faults, pid_t, pid, struct page_faults_data __user *, info_user)
{
    struct task_struct *pid_taskstruct;
    struct page_faults_data page_data_num;

    if (pid <= 0) {
        printk(KERN_WARNING "[USAC-AV] get_page_faults: Invalid PID (%d)\n", pid);
        return -EINVAL;
    }

    rcu_read_lock();

    pid_taskstruct = find_task_by_vpid(pid);
    if (!pid_taskstruct) {
        rcu_read_unlock();
        printk(KERN_ERR "[USAC-AV] get_page_faults: PID %d not found\n", pid);
        return -ESRCH;
    }

    task_lock(pid_taskstruct);

    page_data_num.minor_faults = pid_taskstruct->min_flt;
    page_data_num.major_faults = pid_taskstruct->maj_flt;

    task_unlock(pid_taskstruct);

    rcu_read_unlock();

    if (copy_to_user(info_user, &page_data_num, sizeof(page_data_num))) {
        printk(KERN_ERR "[USAC-AV] get_page_faults: Failed to copy to user for PID %d\n", pid);
        return -EFAULT;
    }

    printk(KERN_INFO "[USAC-AV] get_page_faults: PID %d => [Minor %lu, Major %lu]\n",
           pid, page_data_num.minor_faults, page_data_num.major_faults);

    return 0;
}

// Syscall: antivirus_stats
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
        pr_err("[USAC-AV] antivirus_stats: Failed to copy stats to user space\n");
        return -EFAULT;
    }

    return 0;
}

// Syscall: quarantine_file
SYSCALL_DEFINE1(quarantine_file, const char __user *, path)
{
    struct path src_path, dest_dir, parent_path;
    struct dentry *quarantine_dentry, *dest_dentry;
    struct renamedata rd;
    char *kpath, *filename;
    char dest_path[PATH_MAX];
    struct mnt_idmap *idmap = &nop_mnt_idmap;
    int ret;

    kpath = kmalloc(PATH_MAX, GFP_KERNEL);
    if (!kpath)
        return -ENOMEM;
    if (strncpy_from_user(kpath, path, PATH_MAX) < 0) {
        pr_err("[USAC-AV] quarantine_file: Failed to copy path from user space\n");
        ret = -EFAULT;
        goto out_kpath;
    }
    kpath[PATH_MAX - 1] = '\0';

    filename = strrchr(kpath, '/');
    if (!filename) {
        pr_err("[USAC-AV] quarantine_file: Invalid path\n");
        ret = -EINVAL;
        goto out_kpath;
    }
    filename++;

    ret = kern_path(kpath, LOOKUP_FOLLOW, &src_path);
    if (ret) {
        pr_err("[USAC-AV] quarantine_file: Failed to resolve source path %s\n", kpath);
        goto out_kpath;
    }

    ret = kern_path("/var/quarantine", LOOKUP_FOLLOW | LOOKUP_DIRECTORY, &dest_dir);
    if (ret) {
        ret = kern_path("/var", LOOKUP_FOLLOW | LOOKUP_DIRECTORY, &parent_path);
        if (ret) {
            pr_err("[USAC-AV] quarantine_file: Failed to resolve /var\n");
            path_put(&src_path);
            goto out_kpath;
        }

        quarantine_dentry = kern_path_create(AT_FDCWD, "/var/quarantine", &parent_path, 0700);
        if (IS_ERR(quarantine_dentry)) {
            pr_err("[USAC-AV] quarantine_file: Failed to create quarantine dentry\n");
            path_put(&src_path);
            path_put(&parent_path);
            ret = PTR_ERR(quarantine_dentry);
            goto out_kpath;
        }

        ret = vfs_mkdir(idmap, d_inode(parent_path.dentry), quarantine_dentry, 0700);
        if (ret) {
            pr_err("[USAC-AV] quarantine_file: Failed to create /var/quarantine\n");
            path_put(&src_path);
            path_put(&parent_path);
            dput(quarantine_dentry);
            goto out_kpath;
        }

        path_put(&parent_path);
        dput(quarantine_dentry);

        ret = kern_path("/var/quarantine", LOOKUP_FOLLOW | LOOKUP_DIRECTORY, &dest_dir);
        if (ret) {
            pr_err("[USAC-AV] quarantine_file: Failed to resolve /var/quarantine after creation\n");
            path_put(&src_path);
            goto out_kpath;
        }
    }

    snprintf(dest_path, PATH_MAX, "%s/%s", "/var/quarantine", filename);

    dest_dentry = kern_path_create(AT_FDCWD, dest_path, &dest_dir, 0);
    if (IS_ERR(dest_dentry)) {
        pr_err("[USAC-AV] quarantine_file: Failed to create destination path %s\n", dest_path);
        path_put(&src_path);
        path_put(&dest_dir);
        ret = PTR_ERR(dest_dentry);
        goto out_kpath;
    }

    rd.old_mnt_idmap = idmap;
    rd.old_dir = d_inode(src_path.dentry->d_parent);
    rd.old_dentry = src_path.dentry;
    rd.new_mnt_idmap = idmap;
    rd.new_dir = d_inode(dest_dir.dentry);
    rd.new_dentry = dest_dentry;
    rd.flags = 0;
    rd.delegated_inode = NULL;

    ret = vfs_rename(&rd);
    if (ret) {
        pr_err("[USAC-AV] quarantine_file: Failed to move file to %s\n", dest_path);
        dput(dest_dentry);
        goto out_paths;
    }

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

// Syscall: scan_file
SYSCALL_DEFINE1(scan_file, const char __user *, filepath)
{
    char *kpath;
    struct file *file;
    char hash[HASH_LEN];
    int ret;

    kpath = kmalloc(MAX_PATH, GFP_KERNEL);
    if (!kpath)
        return -ENOMEM;

    if (copy_from_user(kpath, filepath, MAX_PATH)) {
        ret = -EFAULT;
        goto free_kpath;
    }
    kpath[MAX_PATH - 1] = '\0';

    printk(KERN_INFO "[USAC-AV] Scanning File: %s\n", kpath);

    file = filp_open(kpath, O_RDONLY, 0);
    if (IS_ERR(file)) {
        ret = PTR_ERR(file);
        printk(KERN_ERR "[USAC-AV] Error opening file: %d\n", ret);
        goto free_kpath;
    }

    ret = calculate_md5(file, hash);
    if (ret) {
        printk(KERN_ERR "[USAC-AV] Error calculating MD5: %d\n", ret);
        goto close_file;
    }

    printk(KERN_INFO "[USAC-AV] Hash calculated: %s\n", hash);

    ret = lookup_hash(hash);

close_file:
    filp_close(file, NULL);
free_kpath:
    kfree(kpath);
    return ret;
}