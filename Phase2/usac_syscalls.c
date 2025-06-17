#include <linux/syscalls.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/completion.h>
#include <linux/printk.h>
#include <linux/syscalls_usac.h>
#include <linux/vmalloc.h>

typedef struct {
    unsigned char *data;
    size_t data_size;
    unsigned char *key;
    size_t key_size;
    size_t start;
    size_t end;
} DataFragment;

struct task_parameters {
    DataFragment fragment;
    struct completion done;
};

int xor_task(void *arg) {
    struct task_parameters *params = (struct task_parameters *)arg;
    DataFragment *fragment = &params->fragment;
    size_t i;

    printk(KERN_INFO "Thread started: start=%zu, end=%zu\n", fragment->start, fragment->end);

    for (i = fragment->start; i < fragment->end; i++) {
        fragment->data[i] ^= fragment->key[i % fragment->key_size];
    }

    printk(KERN_INFO "Thread completed: start=%zu, end=%zu\n", fragment->start, fragment->end);
    complete(&params->done);
    return 0;
}

int process_file(const char *input_path, const char *output_path, const char *key_path, int num_threads) {
    struct file *input_file, *output_file, *key_file;
    loff_t input_offset = 0, output_offset = 0, key_offset = 0;
    unsigned char *key_buffer, *data_buffer;
    size_t input_file_size, key_file_size;
    struct task_parameters *task_params;
    struct task_struct **threads;
    DataFragment *fragments;
    size_t fragment_size, remainder;
    int i, ret = 0;

    if (num_threads <= 0) {
        printk(KERN_ERR "Invalid number of threads: %d\n", num_threads);
        return -EINVAL;
    }

    printk(KERN_INFO "Opening Files: input=%s, output=%s, key=%s\n", input_path, output_path, key_path);

    input_file = filp_open(input_path, O_RDONLY, 0);
    output_file = filp_open(output_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    key_file = filp_open(key_path, O_RDONLY, 0);

    if (IS_ERR(input_file)) {
        ret = PTR_ERR(input_file);
        printk(KERN_ERR "Error opening input file: %d\n", ret);
        goto out;
    }
    if (IS_ERR(output_file)) {
        ret = PTR_ERR(output_file);
        printk(KERN_ERR "Error opening output file: %d\n", ret);
        goto close_input_file;
    }
    if (IS_ERR(key_file)) {
        ret = PTR_ERR(key_file);
        printk(KERN_ERR "Error opening key file: %d\n", ret);
        goto close_output_file;
    }

    key_file_size = i_size_read(file_inode(key_file));
    if (key_file_size <= 0) {
        ret = -EINVAL;
        printk(KERN_ERR "Invalid size of key: %zu\n", key_file_size);
        goto close_key_file;
    }

    key_buffer = vmalloc(key_file_size);
    if (!key_buffer) {
        ret = -ENOMEM;
        printk(KERN_ERR "Memory cannot be assign\n");
        goto close_key_file;
    }

    ret = kernel_read(key_file, key_buffer, key_file_size, &key_offset);
    if (ret < 0) {
        printk(KERN_ERR "Error reading the key: %d\n", ret);
        goto free_key_buffer;
    }

    input_file_size = i_size_read(file_inode(input_file));
    if (input_file_size <= 0) {
        ret = -EINVAL;
        printk(KERN_ERR "Invalid size of input size: %zu\n", input_file_size);
        goto free_key_buffer;
    }

    data_buffer = vmalloc(input_file_size);
    if (!data_buffer) {
        ret = -ENOMEM;
        printk(KERN_ERR "Cannot assign memory for data\n");
        goto free_key_buffer;
    }

    ret = kernel_read(input_file, data_buffer, input_file_size, &input_offset);
    if (ret < 0) {
        printk(KERN_ERR "Error reading the input file: %d\n", ret);
        goto free_data_buffer;
    }

    threads = kmalloc(sizeof(struct task_struct *) * num_threads, GFP_KERNEL);
    task_params = kmalloc(sizeof(struct task_parameters) * num_threads, GFP_KERNEL);
    fragments = kmalloc(sizeof(DataFragment) * num_threads, GFP_KERNEL);

    if (!threads || !task_params || !fragments) {
        ret = -ENOMEM;
        printk(KERN_ERR "Failed to allocate memory for threads, task parameters, or fragments\n");
        goto free_data_buffer;
    }

    fragment_size = input_file_size / num_threads;
    remainder = input_file_size % num_threads;

    for (i = 0; i < num_threads; i++) {
        fragments[i].data = data_buffer;
        fragments[i].data_size = input_file_size;
        fragments[i].key = key_buffer;
        fragments[i].key_size = key_file_size;
        fragments[i].start = i * fragment_size;
        fragments[i].end = (i == num_threads - 1) ? (i + 1) * fragment_size + remainder : (i + 1) * fragment_size;

        printk(KERN_INFO "Creating thread %d: start=%zu, end=%zu\n", i, fragments[i].start, fragments[i].end);

        task_params[i].fragment = fragments[i];
        init_completion(&task_params[i].done);

        threads[i] = kthread_run(xor_task, &task_params[i], "xor_thread_%d", i);
        if (IS_ERR(threads[i])) {
            ret = PTR_ERR(threads[i]);
            printk(KERN_ERR "Error creating the thread %d: %d\n", i, ret);
            for (int j = 0; j < i; j++) {
                kthread_stop(threads[j]);
            }
            goto free_task_resources;
        }
    }

    for (i = 0; i < num_threads; i++) {
        printk(KERN_INFO "Waiting for the thread to end %d\n", i);
        wait_for_completion(&task_params[i].done);
    }

    ret = kernel_write(output_file, data_buffer, input_file_size, &output_offset);
    if (ret < 0) {
        printk(KERN_ERR "Error writing in the output file: %d\n", ret);
        goto free_task_resources;
    }

    printk(KERN_INFO "Data successfully written to the output file\n");

free_task_resources:
    kfree(threads);
    kfree(task_params);
    kfree(fragments);

free_data_buffer:
    vfree(data_buffer);

free_key_buffer:
    vfree(key_buffer);

close_key_file:
    filp_close(key_file, NULL);

close_output_file:
    filp_close(output_file, NULL);

close_input_file:
    filp_close(input_file, NULL);

out:
    return ret;
}

SYSCALL_DEFINE4(xor_encrypt, const char __user *, input_path, const char __user *, output_path, 
                const char __user *, key_path, int, num_threads) {
    char *k_input_path, *k_output_path, *k_key_path;
    int ret;

    k_input_path = kmalloc(PATH_MAX, GFP_KERNEL);
    k_output_path = kmalloc(PATH_MAX, GFP_KERNEL);
    k_key_path = kmalloc(PATH_MAX, GFP_KERNEL);

    if (!k_input_path || !k_output_path || !k_key_path) {
        ret = -ENOMEM;
        goto free_paths;
    }

    if (strncpy_from_user(k_input_path, input_path, PATH_MAX) < 0 ||
        strncpy_from_user(k_output_path, output_path, PATH_MAX) < 0 ||
        strncpy_from_user(k_key_path, key_path, PATH_MAX) < 0) {
        ret = -EFAULT;
        goto free_paths;
    }

    ret = process_file(k_input_path, k_output_path, k_key_path, num_threads);

free_paths:
    kfree(k_input_path);
    kfree(k_output_path);
    kfree(k_key_path);
    return ret;
}

SYSCALL_DEFINE4(xor_decrypt, const char __user *, input_path, const char __user *, output_path, 
                const char __user *, key_path, int, num_threads) {
    char *k_input_path, *k_output_path, *k_key_path;
    int ret;

    k_input_path = kmalloc(PATH_MAX, GFP_KERNEL);
    k_output_path = kmalloc(PATH_MAX, GFP_KERNEL);
    k_key_path = kmalloc(PATH_MAX, GFP_KERNEL);

    if (!k_input_path || !k_output_path || !k_key_path) {
        ret = -ENOMEM;
        goto free_paths;
    }

    if (strncpy_from_user(k_input_path, input_path, PATH_MAX) < 0 ||
        strncpy_from_user(k_output_path, output_path, PATH_MAX) < 0 ||
        strncpy_from_user(k_key_path, key_path, PATH_MAX) < 0) {
        ret = -EFAULT;
        goto free_paths;
    }

    ret = process_file(k_input_path, k_output_path, k_key_path, num_threads);

free_paths:
    kfree(k_input_path);
    kfree(k_output_path);
    kfree(k_key_path);
    return ret;
}