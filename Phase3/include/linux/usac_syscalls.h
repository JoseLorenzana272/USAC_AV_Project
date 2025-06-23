#ifndef _SYSCALLS_USAC_H
#define _SYSCALLS_USAC_H

#include <linux/syscalls.h>
#include <linux/kernel.h>

struct antivirus_stats {
    unsigned long mem_used;
    unsigned long mem_free;
    unsigned long mem_cache;
    unsigned long swap_used;
    unsigned long active_pages;
    unsigned long inactive_pages;
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
#endif
