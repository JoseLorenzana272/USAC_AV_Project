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
#include <linux/mm.h>
#include <linux/pid.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/sched/mm.h>
#include <linux/sched/task.h>
#include <linux/usac_syscalls.h>
#include <linux/types.h>

// Definitions for scan file
#define MAX_PATH 256
#define HASH_LEN 33 // MD5 hash in hex (32 chars + null terminator)
#define MD5_DIGEST_LENGTH 16 // MD5 hash size in bytes

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

// Get task state
static long get_task_state(struct task_struct *task)
{
    if (task_is_running(task))
        return TASK_RUNNING;
    else if (task_is_stopped_or_traced(task))
        return TASK_STOPPED;
    else
        return TASK_INTERRUPTIBLE;
}

// Syscall: scan_processes
SYSCALL_DEFINE2(scan_processes, struct process_info __user *, buffer, int __user *, count)
{
    struct task_struct *task;
    struct process_info *proc_array;
    int proc_count = 0, i = 0;
    struct mm_struct *mm;
    int user_buffer_size;

    printk(KERN_INFO "[USAC-AV] sys_scan_processes: Starting process scan\n");

    if (!buffer || !count) {
        printk(KERN_ERR "[USAC-AV] sys_scan_processes: Invalid parameters\n");
        return -EINVAL;
    }

    if (copy_from_user(&user_buffer_size, count, sizeof(int))) {
        printk(KERN_ERR "[USAC-AV] sys_scan_processes: Error reading buffer size\n");
        return -EFAULT;
    }

    rcu_read_lock();
    for_each_process(task) {
        proc_count++;
    }
    rcu_read_unlock();

    if (proc_count == 0) {
        printk(KERN_WARNING "[USAC-AV] sys_scan_processes: No processes found\n");
        if (copy_to_user(count, &proc_count, sizeof(int)))
            return -EFAULT;
        return 0;
    }

    if (user_buffer_size < proc_count) {
        printk(KERN_INFO "[USAC-AV] sys_scan_processes: Buffer too small. Needed: %d, Provided: %d\n",
               proc_count, user_buffer_size);
        if (copy_to_user(count, &proc_count, sizeof(int)))
            return -EFAULT;
        return -ENOSPC;
    }

    proc_array = kmalloc_array(proc_count, sizeof(struct process_info), GFP_KERNEL);
    if (!proc_array) {
        printk(KERN_ERR "[USAC-AV] sys_scan_processes: Memory allocation failed\n");
        return -ENOMEM;
    }

    rcu_read_lock();
    for_each_process(task) {
        if (i >= proc_count) break;

        proc_array[i].pid = task->pid;
        proc_array[i].ppid = task->real_parent ? task->real_parent->pid : 0;
        strscpy(proc_array[i].comm, task->comm, TASK_COMM_LEN);
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

    if (copy_to_user(buffer, proc_array, proc_count * sizeof(struct process_info))) {
        printk(KERN_ERR "[USAC-AV] sys_scan_processes: Error copying to user\n");
        kfree(proc_array);
        return -EFAULT;
    }

    if (copy_to_user(count, &proc_count, sizeof(int))) {
        printk(KERN_ERR "[USAC-AV] sys_scan_processes: Error copying count to user\n");
        kfree(proc_array);
        return -EFAULT;
    }

    printk(KERN_INFO "[USAC-AV] sys_scan_processes: %d processes copied successfully\n", proc_count);

    kfree(proc_array);
    return proc_count;
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
        printk(KERN_ERR "[USAC-AV] antivirus_stats: Failed to copy stats to user space\n");
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
        printk(KERN_ERR "[USAC-AV] quarantine_file: Failed to copy path from user space\n");
        ret = -EFAULT;
        goto out_kpath;
    }
    kpath[PATH_MAX - 1] = '\0';

    filename = strrchr(kpath, '/');
    if (!filename) {
        printk(KERN_ERR "[USAC-AV] quarantine_file: Invalid path\n");
        ret = -EINVAL;
        goto out_kpath;
    }
    filename++;

    ret = kern_path(kpath, LOOKUP_FOLLOW, &src_path);
    if (ret) {
        printk(KERN_ERR "[USAC-AV] quarantine_file: Failed to resolve source path %s\n", kpath);
        goto out_kpath;
    }

    ret = kern_path(QUARANTINE_PATH, LOOKUP_FOLLOW | LOOKUP_DIRECTORY, &dest_dir);
    if (ret) {
        ret = kern_path("/var", LOOKUP_FOLLOW | LOOKUP_DIRECTORY, &parent_path);
        if (ret) {
            printk(KERN_ERR "[USAC-AV] quarantine_file: Failed to resolve /var\n");
            path_put(&src_path);
            goto out_kpath;
        }

        quarantine_dentry = kern_path_create(AT_FDCWD, QUARANTINE_PATH, &parent_path, 0700);
        if (IS_ERR(quarantine_dentry)) {
            printk(KERN_ERR "[USAC-AV] quarantine_file: Failed to create quarantine dentry\n");
            path_put(&src_path);
            path_put(&parent_path);
            ret = PTR_ERR(quarantine_dentry);
            goto out_kpath;
        }

        ret = vfs_mkdir(idmap, d_inode(parent_path.dentry), quarantine_dentry, 0700);
        if (ret) {
            printk(KERN_ERR "[USAC-AV] quarantine_file: Failed to create /var/quarantine\n");
            path_put(&src_path);
            path_put(&parent_path);
            dput(quarantine_dentry);
            goto out_kpath;
        }

        path_put(&parent_path);
        dput(quarantine_dentry);

        ret = kern_path(QUARANTINE_PATH, LOOKUP_FOLLOW | LOOKUP_DIRECTORY, &dest_dir);
        if (ret) {
            printk(KERN_ERR "[USAC-AV] quarantine_file: Failed to resolve /var/quarantine after creation\n");
            path_put(&src_path);
            goto out_kpath;
        }
    }

    snprintf(dest_path, PATH_MAX, "%s%s", QUARANTINE_PATH, filename);

    dest_dentry = kern_path_create(AT_FDCWD, dest_path, &dest_dir, 0);
    if (IS_ERR(dest_dentry)) {
        printk(KERN_ERR "[USAC-AV] quarantine_file: Failed to create destination path %s\n", dest_path);
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
        printk(KERN_ERR "[USAC-AV] quarantine_file: Failed to move file to %s\n", dest_path);
        dput(dest_dentry);
        goto out_paths;
    }

    // Create .meta file
    char meta_path[PATH_MAX];
    struct file *meta_file;
    snprintf(meta_path, PATH_MAX, "%s%s%s", QUARANTINE_PATH, filename, META_SUFFIX);
    meta_file = filp_open(meta_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (!IS_ERR(meta_file)) {
        kernel_write(meta_file, kpath, strlen(kpath), &meta_file->f_pos);
        filp_close(meta_file, NULL);
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

// Syscall: restore_file
SYSCALL_DEFINE1(restore_file, const char __user *, filename)
{
    char *kfilename, *src_path, *meta_path, *original_path;
    struct file *meta_file;
    struct path src, dest_dir;
    struct dentry *dest_dentry;
    struct renamedata rd;
    struct mnt_idmap *idmap = &nop_mnt_idmap;
    int ret = 0;
    loff_t pos = 0;

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
    kfilename[MAX_PATH_LEN - 1] = '\0';

    snprintf(src_path, MAX_PATH_LEN, "%s%s", QUARANTINE_PATH, kfilename);
    snprintf(meta_path, MAX_PATH_LEN, "%s%s%s", QUARANTINE_PATH, kfilename, META_SUFFIX);

    meta_file = filp_open(meta_path, O_RDONLY, 0);
    if (IS_ERR(meta_file)) {
        printk(KERN_ERR "[USAC-AV] restore_file: Unable to open metadata file %s: %ld\n", meta_path, PTR_ERR(meta_file));
        ret = PTR_ERR(meta_file);
        goto out_free;
    }

    ret = kernel_read(meta_file, original_path, MAX_PATH_LEN - 1, &pos);
    filp_close(meta_file, NULL);

    if (ret <= 0) {
        printk(KERN_ERR "[USAC-AV] restore_file: Unable to read original path: %d\n", ret);
        ret = ret < 0 ? ret : -EIO;
        goto out_free;
    }

    original_path[ret] = '\0';
    original_path[strcspn(original_path, "\n")] = '\0';

    ret = kern_path(src_path, LOOKUP_FOLLOW, &src);
    if (ret) {
        printk(KERN_ERR "[USAC-AV] restore_file: Failed to resolve source path %s: %d\n", src_path, ret);
        goto out_free;
    }

    char *dest_dirname = strrchr(original_path, '/');
    if (!dest_dirname) {
        printk(KERN_ERR "[USAC-AV] restore_file: Invalid original path %s\n", original_path);
        ret = -EINVAL;
        path_put(&src);
        goto out_free;
    }
    *dest_dirname = '\0';
    ret = kern_path(original_path, LOOKUP_FOLLOW | LOOKUP_DIRECTORY, &dest_dir);
    *dest_dirname = '/';
    if (ret) {
        printk(KERN_ERR "[USAC-AV] restore_file: Failed to resolve destination directory %s: %d\n", original_path, ret);
        path_put(&src);
        goto out_free;
    }

    dest_dentry = kern_path_create(AT_FDCWD, original_path, &dest_dir, 0);
    if (IS_ERR(dest_dentry)) {
        printk(KERN_ERR "[USAC-AV] restore_file: Failed to create destination path %s: %ld\n", original_path, PTR_ERR(dest_dentry));
        path_put(&src);
        path_put(&dest_dir);
        ret = PTR_ERR(dest_dentry);
        goto out_free;
    }

    rd.old_mnt_idmap = idmap;
    rd.old_dir = d_inode(src.dentry->d_parent);
    rd.old_dentry = src.dentry;
    rd.new_mnt_idmap = idmap;
    rd.new_dir = d_inode(dest_dir.dentry);
    rd.new_dentry = dest_dentry;
    rd.flags = 0;
    rd.delegated_inode = NULL;

    ret = vfs_rename(&rd);
    if (ret) {
        printk(KERN_ERR "[USAC-AV] restore_file: Failed to restore file to %s: %d\n", original_path, ret);
        dput(dest_dentry);
        path_put(&src);
        path_put(&dest_dir);
        goto out_free;
    }

    struct path meta;
    ret = kern_path(meta_path, LOOKUP_FOLLOW, &meta);
    if (!ret) {
        vfs_unlink(idmap, d_inode(meta.dentry->d_parent), meta.dentry, NULL);
        path_put(&meta);
    }

    printk(KERN_INFO "[USAC-AV] restore_file: File restored to %s\n", original_path);

    path_put(&src);
    path_put(&dest_dir);
    dput(dest_dentry);

out_free:
    kfree(kfilename);
    kfree(src_path);
    kfree(meta_path);
    kfree(original_path);
    return ret;
}

// Syscall: get_quarantine_list
// Callback for directory iteration
struct get_quarantine_list_context {
    struct dir_context ctx; // Must be first for container_of
    char *kbuf;
    size_t buf_size;
    size_t offset;
    int error;
};

static bool fill_quarantine_dir(struct dir_context *ctx, const char *name, int namlen,
                                loff_t off, u64 ino, unsigned d_type)
{
    struct get_quarantine_list_context *qctx = container_of(ctx, struct get_quarantine_list_context, ctx);
    
    if (d_type != DT_REG || strstr(name, META_SUFFIX))
        return false; // Skip non-regular files and .meta files

    size_t entry_size = namlen + 1;
    if (qctx->offset + entry_size > qctx->buf_size) {
        qctx->error = -ENOBUFS;
        return true; // Stop iteration
    }

    strncpy(qctx->kbuf + qctx->offset, name, namlen);
    qctx->kbuf[qctx->offset + namlen] = '\0';
    qctx->offset += entry_size;
    return false;
}

// Syscall: get_quarantine_list
SYSCALL_DEFINE2(get_quarantine_list, char __user *, user_buf, size_t, buf_size)
{
    struct path dir_path;
    struct file *dir_file;
    struct get_quarantine_list_context qctx = {
        .ctx = {
            .actor = fill_quarantine_dir,
            .pos = 0
        },
        .kbuf = NULL,
        .buf_size = buf_size,
        .offset = 0,
        .error = 0
    };
    int ret;

    qctx.kbuf = kmalloc(buf_size, GFP_KERNEL);
    if (!qctx.kbuf)
        return -ENOMEM;

    ret = kern_path(QUARANTINE_PATH, LOOKUP_FOLLOW | LOOKUP_DIRECTORY, &dir_path);
    if (ret) {
        printk(KERN_ERR "[USAC-AV] get_quarantine_list: Failed to open %s: %d\n", QUARANTINE_PATH, ret);
        kfree(qctx.kbuf);
        return ret;
    }

    dir_file = filp_open(QUARANTINE_PATH, O_RDONLY | O_DIRECTORY, 0);
    if (IS_ERR(dir_file)) {
        printk(KERN_ERR "[USAC-AV] get_quarantine_list: Failed to open directory: %ld\n", PTR_ERR(dir_file));
        path_put(&dir_path);
        kfree(qctx.kbuf);
        return PTR_ERR(dir_file);
    }

    ret = iterate_dir(dir_file, &qctx.ctx);
    if (ret || qctx.error) {
        printk(KERN_ERR "[USAC-AV] get_quarantine_list: Failed to iterate directory: %d\n", ret ?: qctx.error);
        ret = ret ?: qctx.error;
        goto cleanup;
    }

    if (copy_to_user(user_buf, qctx.kbuf, qctx.offset)) {
        printk(KERN_ERR "[USAC-AV] get_quarantine_list: Failed to copy to user\n");
        ret = -EFAULT;
        goto cleanup;
    }

    ret = qctx.offset;

cleanup:
    filp_close(dir_file, NULL);
    path_put(&dir_path);
    kfree(qctx.kbuf);
    return ret;
}