#ifndef _SYSCALLS_USAC_H
#define _SYSCALLS_USAC_H

#include <linux/syscalls.h>
#include <linux/kernel.h>

asmlinkage long sys_xor_encrypt(const char __user *input_file, 
                               const char __user *output_file, 
                               const char __user *key_file, 
                               int num_threads);

asmlinkage long sys_xor_decrypt(const char __user *input_file, 
                               const char __user *output_file, 
                               const char __user *key_file, 
                               int num_threads);

#endif