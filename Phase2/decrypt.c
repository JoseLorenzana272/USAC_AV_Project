#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>

#define sys_xor_decrypt 549

void mostrar_uso(const char *nombre_programa) {
    fprintf(stderr, "Usage: %s -p <input_file_path> -o <output_file_path> -j <num_threads> -k <key_file_path>\n", nombre_programa);
}

int generar_clave(const char *ruta_clave, size_t tamano) {
    int fd = open(ruta_clave, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        perror("Error creating key file");
        return -1;
    }

    unsigned char *clave = malloc(tamano);
    if (!clave) {
        close(fd);
        perror("Error allocating memory for key");
        return -1;
    }

    for (size_t i = 0; i < tamano; i++) {
        clave[i] = (unsigned char)(i % 256);
    }

    ssize_t escritos = write(fd, clave, tamano);
    free(clave);
    close(fd);

    if (escritos != (ssize_t)tamano) {
        perror("Error writing key");
        return -1;
    }

    printf("Key file %s generated successfully (%zu bytes)\n", ruta_clave, tamano);
    return 0;
}

int main(int argc, char *argv[]) {
    char *archivo_entrada = NULL;
    char *archivo_salida = NULL;
    char *archivo_clave = NULL;
    int num_hilos = 0;
    int opcion;

    while ((opcion = getopt(argc, argv, "p:o:j:k:")) != -1) {
        switch (opcion) {
            case 'p':
                archivo_entrada = optarg;
                break;
            case 'o':
                archivo_salida = optarg;
                break;
            case 'j':
                num_hilos = atoi(optarg);
                break;
            case 'k':
                archivo_clave = optarg;
                break;
            default:
                mostrar_uso(argv[0]);
                return EXIT_FAILURE;
        }
    }

    if (!archivo_entrada || !archivo_salida || !archivo_clave || num_hilos <= 0) {
        mostrar_uso(argv[0]);
        return EXIT_FAILURE;
    }

    if (access(archivo_clave, F_OK) == -1) {
        printf("Key file %s does not exist. Generating one of 256 bytes...\n", archivo_clave);
        if (generar_clave(archivo_clave, 256) != 0) {
            return EXIT_FAILURE;
        }
    }

    long resultado = syscall(sys_xor_decrypt, archivo_entrada, archivo_salida, archivo_clave, num_hilos);
    if (resultado < 0) {
        perror("Error in xor_decrypt system call");
        return EXIT_FAILURE;
    }

    printf("Decryption successful\n");
    return EXIT_SUCCESS;
}