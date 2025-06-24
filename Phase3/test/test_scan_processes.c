#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <errno.h>
#include <string.h>

#define __NR_scan_processes 548  // Reemplazar con tu número de syscall
#define MAX_PROCESSES 1000
#define TASK_COMM_LEN 16

struct process_info {
    pid_t pid;
    pid_t ppid;
    char comm[TASK_COMM_LEN];
    long state;
    unsigned long vsize;
    unsigned long rss;
    int nice;
    unsigned long start_time;
    unsigned long utime;
    unsigned long stime;
};

const char* get_state_name(long state) {
    switch(state) {
        case 0: return "RUNNING";
        case 1: return "INTERRUPTIBLE";
        case 2: return "UNINTERRUPTIBLE";
        case 4: return "STOPPED";
        case 8: return "TRACED";
        case 16: return "DEAD";
        case 32: return "ZOMBIE";
        default: return "UNKNOWN";
    }
}

int main() {
    struct process_info *processes;
    int count = MAX_PROCESSES;
    long result;
    
    printf("=== ESCANEADOR DE PROCESOS ===\n");
    
    // Asignar memoria para el buffer
    processes = malloc(MAX_PROCESSES * sizeof(struct process_info));
    if (!processes) {
        perror("Error al asignar memoria");
        return 1;
    }
    
    printf("Ejecutando sys_scan_processes()...\n");
    
    // Llamar a la syscall
    result = syscall(__NR_scan_processes, processes, &count);
    
    if (result == -1) {
        if (errno == ENOSPC) {
            printf("Buffer insuficiente. Se necesitan %d procesos, buffer para %d\n", 
                   count, MAX_PROCESSES);
            free(processes);
            
            // Reasignar con el tamaño correcto
            processes = malloc(count * sizeof(struct process_info));
            if (!processes) {
                perror("Error al reasignar memoria");
                return 1;
            }
            
            printf("Reintentando con buffer más grande...\n");
            result = syscall(__NR_scan_processes, processes, &count);
        }
        
        if (result == -1) {
            perror("Error en syscall");
            free(processes);
            return 1;
        }
    }
    
    printf("Syscall ejecutada exitosamente\n");
    printf("Procesos encontrados: %d\n\n", count);
    
    // Mostrar información de los procesos
    printf("%-8s %-8s %-16s %-12s %-10s %-10s %-6s\n", 
           "PID", "PPID", "NOMBRE", "ESTADO", "VSIZE", "RSS", "NICE");
    printf("--------------------------------------------------------------------\n");
    
    for (int i = 0; i < count && i < 50; i++) {  // Mostrar solo los primeros 50
        printf("%-8d %-8d %-16s %-12s %-10lu %-10lu %-6d\n",
               processes[i].pid,
               processes[i].ppid,
               processes[i].comm,
               get_state_name(processes[i].state),
               processes[i].vsize,
               processes[i].rss,
               processes[i].nice);
    }
    
    if (count > 50) {
        printf("... y %d procesos más\n", count - 50);
    }
    
    printf("\nESTADÍSTICAS:\n");
    printf("Total de procesos: %d\n", count);
    
    // Contar procesos por estado
    int running = 0, sleeping = 0, stopped = 0, zombie = 0;
    for (int i = 0; i < count; i++) {
        switch(processes[i].state) {
            case 0: running++; break;
            case 1: case 2: sleeping++; break;
            case 4: case 8: stopped++; break;
            case 32: zombie++; break;
        }
    }
    
    printf("En ejecución: %d\n", running);
    printf("Durmiendo: %d\n", sleeping);
    printf("Detenidos: %d\n", stopped);
    printf("Zombies: %d\n", zombie);
    
    free(processes);
    return 0;
}