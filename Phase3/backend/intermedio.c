#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <errno.h>
#include <time.h>
#include <signal.h>
#include <curl/curl.h>
#include <json-c/json.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

// Definiciones de syscalls personalizadas
#define __NR_scan_processes     551
#define __NR_get_page_faults    552
#define __NR_scan_file          553
#define __NR_quarantine_file    554
#define __NR_get_quarantine_list 555
#define __NR_restore_file       556
#define __NR_antivirus_stats    557

// Constantes
#define MAX_PROCESSES 1000
#define MAX_PATH 512
#define BUFFER_SIZE 4096
#define DEFAULT_INTERVAL 5
#define SERVER_URL "http://localhost:5000/api/stats"

// Estructuras que coinciden con el kernel
struct antivirus_stats {
    unsigned long mem_used;
    unsigned long mem_free;
    unsigned long mem_cache;
    unsigned long swap_used;
    unsigned long active_pages;
    unsigned long inactive_pages;
};

struct page_faults_data {
    unsigned long minor_faults;
    unsigned long major_faults;
};

struct process_info {
    pid_t pid;
    pid_t ppid;
    char comm[16]; // TASK_COMM_LEN
    long state;
    unsigned long vsize;
    unsigned long rss;
    int nice;
    unsigned long start_time;
    unsigned long utime;
    unsigned long stime;
};

// Variables globales
static int running = 1;
static int scan_interval = DEFAULT_INTERVAL;
static char server_url[256] = SERVER_URL;

// Wrappers para las syscalls
long sys_scan_processes(struct process_info *buffer, int *count) {
    return syscall(__NR_scan_processes, buffer, count);
}

long sys_get_page_faults(pid_t pid, struct page_faults_data *info) {
    return syscall(__NR_get_page_faults, pid, info);
}

long sys_scan_file(const char *filepath) {
    return syscall(__NR_scan_file, filepath);
}

long sys_quarantine_file(const char *path) {
    return syscall(__NR_quarantine_file, path);
}

long sys_get_quarantine_list(char *buffer, size_t buf_size) {
    return syscall(__NR_get_quarantine_list, buffer, buf_size);
}

long sys_restore_file(const char *filename) {
    return syscall(__NR_restore_file, filename);
}

long sys_antivirus_stats(struct antivirus_stats *stats) {
    return syscall(__NR_antivirus_stats, stats);
}

// Manejador de señales
void signal_handler(int sig) {
    if (sig == SIGINT || sig == SIGTERM) {
        printf("\n[INFO] Recibida señal de terminación. Cerrando...\n");
        running = 0;
    }
}

// Función para calcular porcentaje de memoria
double calculate_memory_percentage(unsigned long used_mem, unsigned long total_mem) {
    if (total_mem == 0) return 0.0;
    return ((double)used_mem / (double)total_mem) * 100.0;
}

// Función para crear JSON con datos del sistema
json_object* create_system_json() {
    struct antivirus_stats stats;
    struct process_info processes[MAX_PROCESSES];
    int process_count = MAX_PROCESSES;
    json_object *root, *processes_array;
    
    // Obtener estadísticas del sistema
    if (sys_antivirus_stats(&stats) != 0) {
        fprintf(stderr, "[ERROR] Error al obtener estadísticas del sistema: %s\n", strerror(errno));
        return NULL;
    }
    
    // Obtener lista de procesos
    if (sys_scan_processes(processes, &process_count) < 0) {
        fprintf(stderr, "[ERROR] Error al escanear procesos: %s\n", strerror(errno));
        return NULL;
    }
    
    // Crear objeto JSON raíz
    root = json_object_new_object();
    if (!root) {
        fprintf(stderr, "[ERROR] Error al crear objeto JSON\n");
        return NULL;
    }
    
    // Añadir timestamp
    time_t now = time(NULL);
    json_object_object_add(root, "timestamp", json_object_new_int64(now));
    
    // Añadir estadísticas de memoria
    json_object_object_add(root, "memoria_usada", json_object_new_int64(stats.mem_used));
    json_object_object_add(root, "memoria_libre", json_object_new_int64(stats.mem_free));
    json_object_object_add(root, "memoria_cache", json_object_new_int64(stats.mem_cache));
    json_object_object_add(root, "swap_usada", json_object_new_int64(stats.swap_used));
    json_object_object_add(root, "paginas_activas", json_object_new_int64(stats.active_pages));
    json_object_object_add(root, "paginas_inactivas", json_object_new_int64(stats.inactive_pages));
    
    // Calcular totales para fallos de página
    unsigned long total_minor_faults = 0;
    unsigned long total_major_faults = 0;
    
    // Crear array de procesos top (top 10 por uso de memoria)
    processes_array = json_object_new_array();
    
    // Ordenar procesos por RSS (memoria residente) - implementación simple
    for (int i = 0; i < process_count - 1; i++) {
        for (int j = i + 1; j < process_count; j++) {
            if (processes[i].rss < processes[j].rss) {
                struct process_info temp = processes[i];
                processes[i] = processes[j];
                processes[j] = temp;
            }
        }
    }
    
    // Añadir top 10 procesos
    int top_count = (process_count > 10) ? 10 : process_count;
    unsigned long total_memory = stats.mem_used + stats.mem_free;
    
    for (int i = 0; i < top_count; i++) {
        json_object *proc_obj = json_object_new_object();
        double mem_percentage = calculate_memory_percentage(processes[i].rss * 4, total_memory); // RSS en páginas de 4KB
        
        json_object_object_add(proc_obj, "nombre", json_object_new_string(processes[i].comm));
        json_object_object_add(proc_obj, "pid", json_object_new_int(processes[i].pid));
        json_object_object_add(proc_obj, "memoria_pct", json_object_new_double(mem_percentage));
        json_object_object_add(proc_obj, "memoria_rss", json_object_new_int64(processes[i].rss));
        json_object_object_add(proc_obj, "estado", json_object_new_int64(processes[i].state));
        
        // Obtener fallos de página para este proceso
        struct page_faults_data faults;
        if (sys_get_page_faults(processes[i].pid, &faults) == 0) {
            json_object_object_add(proc_obj, "fallos_menores", json_object_new_int64(faults.minor_faults));
            json_object_object_add(proc_obj, "fallos_mayores", json_object_new_int64(faults.major_faults));
            total_minor_faults += faults.minor_faults;
            total_major_faults += faults.major_faults;
        }
        
        json_object_array_add(processes_array, proc_obj);
    }
    
    json_object_object_add(root, "procesos_top", processes_array);
    json_object_object_add(root, "fallos_menores", json_object_new_int64(total_minor_faults));
    json_object_object_add(root, "fallos_mayores", json_object_new_int64(total_major_faults));
    
    return root;
}

// Función para enviar datos al servidor
int send_data_to_server(const char *json_data) {
    CURL *curl;
    CURLcode res;
    struct curl_slist *headers = NULL;
    
    curl = curl_easy_init();
    if (!curl) {
        fprintf(stderr, "[ERROR] Error al inicializar CURL\n");
        return -1;
    }
    
    // Configurar headers
    headers = curl_slist_append(headers, "Content-Type: application/json");
    
    // Configurar CURL
    curl_easy_setopt(curl, CURLOPT_URL, server_url);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_data);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
    
    // Realizar petición
    res = curl_easy_perform(curl);
    
    if (res != CURLE_OK) {
        fprintf(stderr, "[ERROR] Error al enviar datos: %s\n", curl_easy_strerror(res));
    } else {
        printf("[INFO] Datos enviados correctamente al servidor\n");
    }
    
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    
    return (res == CURLE_OK) ? 0 : -1;
}

// Función para escanear archivo
void scan_file_command(const char *filepath) {
    long result = sys_scan_file(filepath);
    
    switch (result) {
        case 0:
            printf("[SCAN] Archivo limpio: %s\n", filepath);
            break;
        case 1:
            printf("[SCAN] Archivo sospechoso: %s\n", filepath);
            break;
        case 2:
            printf("[SCAN] Archivo MALICIOSO: %s\n", filepath);
            printf("[ACTION] Poniendo en cuarentena: %s\n", filepath);
            if (sys_quarantine_file(filepath) == 0) {
                printf("[SUCCESS] Archivo puesto en cuarentena exitosamente\n");
            } else {
                printf("[ERROR] Error al poner archivo en cuarentena: %s\n", strerror(errno));
            }
            break;
        default:
            printf("[ERROR] Error al escanear archivo: %s\n", strerror(errno));
            break;
    }
}

// Función para listar archivos en cuarentena
void list_quarantine() {
    char buffer[BUFFER_SIZE];
    int bytes_read = sys_get_quarantine_list(buffer, BUFFER_SIZE);
    
    if (bytes_read < 0) {
        printf("[ERROR] Error al obtener lista de cuarentena: %s\n", strerror(errno));
        return;
    }
    
    if (bytes_read == 0) {
        printf("[INFO] No hay archivos en cuarentena\n");
        return;
    }
    
    printf("[INFO] Archivos en cuarentena:\n");
    printf("================================\n");
    
    char *token = strtok(buffer, "\n");
    int count = 1;
    while (token != NULL) {
        printf("%d. %s\n", count++, token);
        token = strtok(NULL, "\n");
    }
}

// Función para restaurar archivo
void restore_file_command(const char *filename) {
    if (sys_restore_file(filename) == 0) {
        printf("[SUCCESS] Archivo restaurado exitosamente: %s\n", filename);
    } else {
        printf("[ERROR] Error al restaurar archivo: %s\n", strerror(errno));
    }
}

// Función principal de monitoreo
void monitor_system() {
    printf("[INFO] Iniciando monitoreo del sistema (intervalo: %d segundos)\n", scan_interval);
    printf("[INFO] Presiona Ctrl+C para detener\n");
    
    while (running) {
        json_object *json_data = create_system_json();
        if (json_data) {
            const char *json_string = json_object_to_json_string(json_data);
            if (json_string) {
                printf("[INFO] Enviando datos al servidor...\n");
                send_data_to_server(json_string);
            }
            json_object_put(json_data);
        }
        
        // Esperar el intervalo especificado
        for (int i = 0; i < scan_interval && running; i++) {
            sleep(1);
        }
    }
}

// Función para mostrar ayuda
void show_help() {
    printf("USAC Antivirus - Cliente del Sistema\n");
    printf("=====================================\n\n");
    printf("Uso: %s [opciones]\n\n", "usac_av_client");
    printf("Opciones:\n");
    printf("  -m, --monitor           Iniciar monitoreo continuo\n");
    printf("  -i, --interval <seg>    Intervalo de monitoreo (default: 5)\n");
    printf("  -s, --scan <archivo>    Escanear archivo específico\n");
    printf("  -q, --quarantine        Listar archivos en cuarentena\n");
    printf("  -r, --restore <archivo> Restaurar archivo de cuarentena\n");
    printf("  -u, --url <url>         URL del servidor (default: %s)\n", SERVER_URL);
    printf("  -h, --help              Mostrar esta ayuda\n\n");
    printf("Ejemplos:\n");
    printf("  %s -m                   # Monitoreo continuo\n", "usac_av_client");
    printf("  %s -s /path/file        # Escanear archivo\n", "usac_av_client");
    printf("  %s -q                   # Listar cuarentena\n", "usac_av_client");
    printf("  %s -r filename          # Restaurar archivo\n", "usac_av_client");
}

int main(int argc, char *argv[]) {
    // Configurar manejadores de señales
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    // Inicializar CURL
    curl_global_init(CURL_GLOBAL_DEFAULT);
    
    // Verificar permisos (necesita ser root para syscalls del kernel)
    if (geteuid() != 0) {
        fprintf(stderr, "[WARNING] Este programa puede necesitar permisos de root para funcionar correctamente\n");
    }
    
    // Procesar argumentos de línea de comandos
    if (argc < 2) {
        show_help();
        goto cleanup;
    }
    
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-m") == 0 || strcmp(argv[i], "--monitor") == 0) {
            monitor_system();
            break;
        } else if (strcmp(argv[i], "-i") == 0 || strcmp(argv[i], "--interval") == 0) {
            if (i + 1 < argc) {
                scan_interval = atoi(argv[++i]);
                if (scan_interval <= 0) scan_interval = DEFAULT_INTERVAL;
            }
        } else if (strcmp(argv[i], "-s") == 0 || strcmp(argv[i], "--scan") == 0) {
            if (i + 1 < argc) {
                scan_file_command(argv[++i]);
            } else {
                fprintf(stderr, "[ERROR] Falta especificar archivo para escanear\n");
            }
            break;
        } else if (strcmp(argv[i], "-q") == 0 || strcmp(argv[i], "--quarantine") == 0) {
            list_quarantine();
            break;
        } else if (strcmp(argv[i], "-r") == 0 || strcmp(argv[i], "--restore") == 0) {
            if (i + 1 < argc) {
                restore_file_command(argv[++i]);
            } else {
                fprintf(stderr, "[ERROR] Falta especificar archivo para restaurar\n");
            }
            break;
        } else if (strcmp(argv[i], "-u") == 0 || strcmp(argv[i], "--url") == 0) {
            if (i + 1 < argc) {
                strncpy(server_url, argv[++i], sizeof(server_url) - 1);
                server_url[sizeof(server_url) - 1] = '\0';
            }
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            show_help();
            break;
        } else {
            fprintf(stderr, "[ERROR] Opción desconocida: %s\n", argv[i]);
            show_help();
            break;
        }
    }
    
cleanup:
    curl_global_cleanup();
    return 0;
}
