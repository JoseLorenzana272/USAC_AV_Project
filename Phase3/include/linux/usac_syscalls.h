#ifndef _SYSCALLS_USAC_H
#define _SYSCALLS_USAC_H

#include <linux/syscalls.h>
#include <linux/kernel.h>

#define MAX_PATH 256
#define HASH_LEN 33
#define QUARANTINE_PATH "/var/quarantine/"
#define META_SUFFIX ".meta"
#define MAX_PATH_LEN 512

struct antivirus_stats {
    unsigned long mem_used;
    unsigned long mem_free;
    unsigned long mem_cache;
    unsigned long swap_used;
    unsigned long active_pages;
    unsigned long inactive_pages;
};

struct page_faults_data {
    unsigned long minor_faults;
    unsigned long major_faults;
};

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



asmlinkage long sys_xor_encrypt(const char __user *input_file, 
                               const char __user *output_file, 
                               const char __user *key_file, 
                                int num_threads);

asmlinkage long sys_xor_decrypt(const char __user *input_file, 
                               const char __user *output_file, 
                               const char __user *key_file, 
                                int num_threads);

asmlinkage long sys_antivirus_stats(struct antivirus_stats __user *stats);
asmlinkage long sys_quarantine_file(const char __user *path);
asmlinkage long sys_get_page_faults(pid_t pid, struct page_faults_data __user *info);
asmlinkage long sys_scan_file(const char __user *filepath);
asmlinkage long sys_scan_processes(struct process_info __user *buffer, int __user *count);
asmlinkage long sys_restore_file(const char __user *filename);
asmlinkage long sys_get_quarantine_list(char __user *user_buf, size_t buf_size);

#endif
