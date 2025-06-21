#include <linux/syscalls.h>
#include <linux/sysinfo.h>
#include <linux/vmstat.h>
#include <linux/uaccess.h>
#include <linux/namei.h>
#include <linux/fs.h>
#include <linux/usac_syscalls.h>
#include <linux/user_namespace.h>

// ANTIVIRYS STATS
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
    struct mnt_idmap *idmap = &nop_mnt_idmap; // Use idmap without changes
    int ret;

    // Copy the path from user space
    kpath = kmalloc(PATH_MAX, GFP_KERNEL);
    if (!kpath)
        return -ENOMEM;
    if (strncpy_from_user(kpath, path, PATH_MAX) < 0) {
        pr_err("USAC-AV: Failed to copy path from user space\n");
        ret = -EFAULT;
        goto out_kpath;
    }
    kpath[PATH_MAX - 1] = '\0';

    // Get the file name
    filename = strrchr(kpath, '/');
    if (!filename) {
        pr_err("USAC-AV: Invalid path\n");
        ret = -EINVAL;
        goto out_kpath;
    }
    filename++;

    // Resolve the source file path
    ret = kern_path(kpath, LOOKUP_FOLLOW, &src_path);
    if (ret) {
        pr_err("USAC-AV: Failed to resolve source path %s\n", kpath);
        goto out_kpath;
    }

    // Resolve or create /var/quarantine
    ret = kern_path("/var/quarantine", LOOKUP_FOLLOW | LOOKUP_DIRECTORY, &dest_dir);
    if (ret) {
        // Resolve /var as parent directory
        ret = kern_path("/var", LOOKUP_FOLLOW | LOOKUP_DIRECTORY, &parent_path);
        if (ret) {
            pr_err("USAC-AV: Failed to resolve /var\n");
            path_put(&src_path);
            goto out_kpath;
        }

        // Create /var/quarantine
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

        // Resolve /var/quarantine again
        ret = kern_path("/var/quarantine", LOOKUP_FOLLOW | LOOKUP_DIRECTORY, &dest_dir);
        if (ret) {
            pr_err("USAC-AV: Failed to resolve /var/quarantine after creation\n");
            path_put(&src_path);
            goto out_kpath;
        }
    }

    // Build the destination path
    snprintf(dest_path, PATH_MAX, "%s/%s", "/var/quarantine", filename);

    // Create the destination entry
    dest_dentry = kern_path_create(AT_FDCWD, dest_path, &dest_dir, 0);
    if (IS_ERR(dest_dentry)) {
        pr_err("USAC-AV: Failed to create destination path %s\n", dest_path);
        path_put(&src_path);
        path_put(&dest_dir);
        ret = PTR_ERR(dest_dentry);
        goto out_kpath;
    }

    // Prepare the renamedata structure
    rd.old_mnt_idmap = idmap;
    rd.old_dir = d_inode(src_path.dentry->d_parent);
    rd.old_dentry = src_path.dentry;
    rd.new_mnt_idmap = idmap;
    rd.new_dir = d_inode(dest_dir.dentry);
    rd.new_dentry = dest_dentry;
    rd.flags = 0;
    rd.delegated_inode = NULL;

    // Move the file
    ret = vfs_rename(&rd);
    if (ret) {
        pr_err("USAC-AV: Failed to move file to %s\n", dest_path);
        dput(dest_dentry);
        goto out_paths;
    }

    // Release resources
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
