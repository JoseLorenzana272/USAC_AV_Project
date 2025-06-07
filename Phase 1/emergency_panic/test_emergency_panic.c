#include <stdio.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <errno.h>

#define SYS_emergency_panic 548

int main() {
    long ret;

    printf("Warning: This call will cause a panic mode in kernel.\n");

    ret = syscall(SYS_emergency_panic);
    if (ret < 0) {
        perror("Error in sys_emergency_panic");
        return 1;
    }

    printf("This won't print if panic works\n");
    return 0;
}