#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <errno.h>
#include <string.h>

#define SYS_scan_file 553

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Uso: %s <ruta_del_archivo>\n", argv[0]);
        return 1;
    }

    const char *path = argv[1];
    long result = syscall(SYS_scan_file, path);

    if (result < 0) {
        fprintf(stderr, "Error en sys_scan_file: %s\n", strerror(errno));
        return 1;
    }

    printf("🔍 Escaneando: %s\n", path);
    switch (result) {
        case 0:
            printf("✅ Archivo limpio\n");
            break;
        case 1:
            printf("⚠️ Archivo sospechoso\n");
            break;
        case 2:
            printf("❌ Archivo malicioso\n");
            break;
        default:
            printf("❗ Resultado desconocido: %ld\n", result);
            break;
    }

    return 0;
}