#include <stdio.h>
#include <sys/syscall.h>
#include <unistd.h>

#define __NR_mi_tiempo 548

int main() {
    long tiempo = syscall(__NR_mi_tiempo);
    printf("Tiempo actual (epoch): %ld\n", tiempo);
    return 0;
}
