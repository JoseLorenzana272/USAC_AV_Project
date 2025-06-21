#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <errno.h>
#include <string.h>


#define SYS_ANTIVIRUS_STATS 550
#define SYS_QUARANTINE_FILE 551

struct antivirus_stats {
    unsigned long mem_used;
    unsigned long mem_free;
    unsigned long mem_cache;
    unsigned long swap_used;
    unsigned long active_pages;
    unsigned long inactive_pages;
};


int main(int argc, char *argv[]) {
    //Antivirus stats
    struct antivirus_stats stats;
    long ret = syscall(SYS_ANTIVIRUS_STATS, &stats);

    if (ret < 0) {
        fprintf(stderr, "sys_antivirus_stats failed: %s\n", strerror(errno));
        return 1;
    }

    printf("Memory Used: %lu KB\n", stats.mem_used);
    printf("Free Memory: %lu KB\n", stats.mem_free);
    printf("Cache Memory: %lu KB\n", stats.mem_cache);
    printf("Used SWAP: %lu KB\n", stats.swap_used);
    printf("Active Pages: %lu\n", stats.active_pages);
    printf("Inactive Pages: %lu\n", stats.inactive_pages);

    // sys_quarantine_file
    if (argc != 2) {
        fprintf(stderr, "Use: %s <ruta_del_archivo>\n", argv[0]);
        return 1;
    }

    ret = syscall(SYS_QUARANTINE_FILE, argv[1]);
    if (ret < 0) {
        fprintf(stderr, "sys_quarantine_file failed: %s\n", strerror(errno));
        return 1;
    }
    printf("File %s moved to /var/quarantine/\n", argv[1]);

    return 0;
}