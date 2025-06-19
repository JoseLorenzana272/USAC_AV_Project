#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>

#define SYS_XOR_ENCRYPT 548
#define SYS_XOR_DECRYPT 549

// Global variables
const char *input_file = NULL;
const char *encrypted_file = NULL;
const char *key_file = NULL;
int num_threads = 0;

// Auto-generated output files
char decrypted_syscall[256];
char encrypted_python[256];
char decrypted_python[256];
char encrypted_openssl[256];
char decrypted_openssl[256];

// Measure time of any void(void) function
double measure_time(void (*func)(void)) {
    struct timespec start, end;
    clock_gettime(CLOCK_REALTIME, &start);
    func();
    clock_gettime(CLOCK_REALTIME, &end);
    return (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;
}

// XOR via syscall
void xor_encrypt_syscall() {
    long result = syscall(SYS_XOR_ENCRYPT, input_file, encrypted_file, key_file, num_threads);
    if (result < 0) perror("Error in xor_encrypt syscall");
}
void xor_decrypt_syscall() {
    long result = syscall(SYS_XOR_DECRYPT, encrypted_file, decrypted_syscall, key_file, num_threads);
    if (result < 0) perror("Error in xor_decrypt syscall");
}

// XOR via Python
void xor_encrypt_python() {
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "python3 xor.py -p %s -o %s -k %s", input_file, encrypted_python, key_file);
    system(cmd);
}
void xor_decrypt_python() {
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "python3 xor.py -p %s -o %s -k %s", encrypted_python, decrypted_python, key_file);
    system(cmd);
}

// AES via OpenSSL
void openssl_encrypt() {
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "openssl enc -aes-256-cbc -in %s -out %s -pass file:%s -pbkdf2", input_file, encrypted_openssl, key_file);
    system(cmd);
}
void openssl_decrypt() {
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "openssl enc -d -aes-256-cbc -in %s -out %s -pass file:%s -pbkdf2", encrypted_openssl, decrypted_openssl, key_file);
    system(cmd);
}

void print_usage(const char *prog) {
    printf("Usage: %s -p <input_file> -o <encrypted_file> -k <key_file> -j <threads>\n", prog);
}

int main(int argc, char *argv[]) {
    int opt;
    while ((opt = getopt(argc, argv, "p:o:k:j:")) != -1) {
        switch (opt) {
            case 'p': input_file = optarg; break;
            case 'o': encrypted_file = optarg; break;
            case 'k': key_file = optarg; break;
            case 'j': num_threads = atoi(optarg); break;
            default: print_usage(argv[0]); return 1;
        }
    }

    if (!input_file || !encrypted_file || !key_file || num_threads <= 0) {
        print_usage(argv[0]);
        return 1;
    }

    // Prepare filenames for outputs
    snprintf(decrypted_syscall, sizeof(decrypted_syscall), "decrypted_syscall.txt");
    snprintf(encrypted_python, sizeof(encrypted_python), "encrypted_python.txt");
    snprintf(decrypted_python, sizeof(decrypted_python), "decrypted_python.txt");
    snprintf(encrypted_openssl, sizeof(encrypted_openssl), "encrypted_openssl.txt");
    snprintf(decrypted_openssl, sizeof(decrypted_openssl), "decrypted_openssl.txt");

    // Run and time all
    double t1 = measure_time(xor_encrypt_syscall);
    double t2 = measure_time(xor_decrypt_syscall);
    double t3 = measure_time(xor_encrypt_python);
    double t4 = measure_time(xor_decrypt_python);
    double t5 = measure_time(openssl_encrypt);
    double t6 = measure_time(openssl_decrypt);

    // Show results
    printf("\n Benchmark Results:\n");
    printf("XOR Encrypt (syscall):         %.6f s\n", t1);
    printf("XOR Decrypt (syscall):         %.6f s\n", t2);
    printf("XOR Encrypt (Python):          %.6f s\n", t3);
    printf("XOR Decrypt (Python):          %.6f s\n", t4);
    printf("AES-256 Encrypt (OpenSSL):     %.6f s\n", t5);
    printf("AES-256 Decrypt (OpenSSL):     %.6f s\n", t6);

    return 0;
}