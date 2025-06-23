#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <errno.h>
#include <string.h>
#include <signal.h>

#define SYS_ANTIVIRUS_STATS 550
#define SYS_QUARANTINE_FILE 551
#define SYS_get_page_faults 552
#define SYS_scan_file 553

// Structure for antivirus system statistics
struct antivirus_stats {
    unsigned long mem_used;
    unsigned long mem_free;
    unsigned long mem_cache;
    unsigned long swap_used;
    unsigned long active_pages;
    unsigned long inactive_pages;
};

// Structure for page fault data
struct page_faults_data {
    unsigned long minor_faults;
    unsigned long major_faults;
};

int main(int argc, char *argv[]) {
    // Check for exactly 3 arguments
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <pid> <file_path>\n", argv[0]);
        return 1;
    }

    // Convert PID argument to pid_t
    pid_t pid = atoi(argv[1]);
    if (pid <= 0) {
        fprintf(stderr, "Invalid PID: %s\n", argv[1]);
        return 1;
    }

    // Verify if the PID exists
    if (kill(pid, 0) < 0 && errno != EPERM) {
        fprintf(stderr, "PID %d does not exist or is inaccessible: %s\n", pid, strerror(errno));
        return 1;
    }

    // Call sys_antivirus_stats
    struct antivirus_stats stats;
    long ret = syscall(SYS_ANTIVIRUS_STATS, &stats);
    if (ret < 0) {
        fprintf(stderr, "sys_antivirus_stats failed: %s\n", strerror(errno));
        return 1;
    }

    printf("System Statistics:\n");
    printf("Memory Used: %lu KB\n", stats.mem_used);
    printf("Free Memory: %lu KB\n", stats.mem_free);
    printf("Cache Memory: %lu KB\n", stats.mem_cache);
    printf("Used SWAP: %lu KB\n", stats.swap_used);
    printf("Active Pages: %lu\n", stats.active_pages);
    printf("Inactive Pages: %lu\n", stats.inactive_pages);

    // Call sys_get_page_faults
    struct page_faults_data faults;
    ret = syscall(SYS_get_page_faults, pid, &faults);
    if (ret < 0) {
        fprintf(stderr, "sys_get_page_faults failed for PID %d: %s (errno: %d)\n", pid, strerror(errno), errno);
        return 1;
    }

    printf("\nProcess Statistics (PID: %d):\n", pid);
    printf("Minor Faults: %lu\n", faults.minor_faults);
    printf("Major Faults: %lu\n", faults.major_faults);

    // Call sys_scan_file
    printf("\nScanning file: %s\n", argv[2]);
    ret = syscall(SYS_scan_file, argv[2]);
    if (ret < 0) {
        fprintf(stderr, "sys_scan_file failed: %s\n", strerror(errno));
        return 1;
    }

    switch (ret) {
        case 0:
            printf("✅ File is clean\n");
            break;
        case 1:
            printf("⚠️ File is suspicious\n");
            // Proceed to quarantine suspicious files
            ret = syscall(SYS_QUARANTINE_FILE, argv[2]);
            if (ret < 0) {
                fprintf(stderr, "sys_quarantine_file failed: %s\n", strerror(errno));
                return 1;
            }
            printf("File %s moved to /var/quarantine/\n", argv[2]);
            break;
        case 2:
            printf("❌ File is malicious\n");
            // Quarantine malicious files
            ret = syscall(SYS_QUARANTINE_FILE, argv[2]);
            if (ret < 0) {
                fprintf(stderr, "sys_quarantine_file failed: %s\n", strerror(errno));
                return 1;
            }
            printf("File %s moved to /var/quarantine/\n", argv[2]);
            break;
        default:
            printf("❗ Unknown scan result: %ld\n", ret);
            return 1;
    }

    return 0;
}
