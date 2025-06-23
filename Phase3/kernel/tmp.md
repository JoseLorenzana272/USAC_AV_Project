###  sys_get_page_faults(pid)

El objetivo de esta sys call es obtener el numero de fallos de pagina de **un proceso especifico**, esto incluye fallos de pagina menores y mayores. 

Un fallo de pagina ocurre cuando un proceso necesita una pagina de memoria que actualmente no se encuentra en la RAM. Estos fallos, como se menciona anteriormente, pueden ser de dos tipos:

* Fallo menor
    Este ocurre cuando un proceso accede a una pagina que no esta cargada en la tabla de paginas del proceso pero no es necesario un acceso al disco, ya que ya se encuentra en memoria RAM

* Fallo Mayor
    Este tipo de fallo hace referencia a los fallos de pagina en los cuales es necesario acceder al disco para obtener la pagina.


Primero fue necesario definir la syscall: El nombre y la informacion que llevara. Con el objetivo de simplificar el manejo de los fallos y su informacion dentro de la syscall se definio una stuct llamada: **page_faults_data**, como su nombre indica almacena la informacion del proceso en relacion con sus fallos de pagina. Los dos atributos de dicha struct son: minor_faults y major_faults. Para esto se modifico el archivo: syscall_usac.h

```bash
    cd include/linux
    nano syscalls_usac.h
```
y se agrego las siguientes lineas de codigo.

```c
#include <linux/types.h>

asmlinkage long sys_get_page_faults(pid_t pid, struct page_faults_data __user *info);

```

Luego se esto se procedio a definir el codigo de la syscall como tal, al igual que en la fase 2, esto se realiza en /kernel/my_syscalls.c. Dentro de ese archivo se agregaron las siguientes librerias y el codigo de la syscall


```bash
    nano my_syscalls.c
```
Dentro de archivo se agrego:

```c

#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>


SYSCALL_DEFINE2(get_page_faults, pid_t, pid, struct page_faults_data __user *, info_user) {
    struct task_struct *pid_taskstruct;
    struct page_faults_data page_data_num;

    if (pid <= 0) {
        printk(KERN_WARNING "[ERROR!] get_page_faults: PID INVALIDO ( %d )\n", pid);
        return -EINVAL;
    }

    rcu_read_lock();
    // permite encontrar el task_strc
    pid_taskstruct = find_task_by_vpid(pid);
    if (!pid_taskstruct) {
        // en caso se que no se encuentre libera la lectura segura, manda un mensaje y regresa
        rcu_read_unlock();
        printk(KERN_ERR "[!ERROR] get_page_faults: no se encontro el pid o data del pid %d\n", pid);
        return -ESRCH; 
    }

// ------------- EXTRACCION DE DATA
    // se loquea el taskstruct para poder obetener la page_data_num sin problema
    task_lock(pid_taskstruct);
    //solo se agrega la data al struct
    page_data_num.minor_faults = pid_taskstruct->min_flt;
    page_data_num.major_faults = pid_taskstruct->maj_flt;
     // se suelta
    task_unlock(pid_taskstruct);
    // SE TERMINA LA LECTURA
    rcu_read_unlock();
    // USER, se usa para ver que el valor no tenga fallos y si si se retorna
    if (copy_to_user(info_user, &page_data_num, sizeof(page_data_num))) {
        printk(KERN_ERR "[ERROR!] get_page_faults: Error al usas copy_to_user --- pid  %d\n", pid);
        return -EFAULT;
    }
//-----------------------------------------------------------------------------
    printk(KERN_INFO "[SUCCESS! - DATA] get_page_faults : PID %d ====> [MINOR %lu ], [MAJOR %lu ]\n",pid, page_data_num.minor_faults, page_data_num.major_faults);

    return 0;
}

```

Una vez se agrego el codigo para la recoleccion de la data, se procede a agregar la syscall a la tabla de syscalls bajo el No. 557

```bash
cd arch/x86/entry/syscalls
nano syscall_64.tbl
```

```bash
557     common   get_page_faults       sys_get_page_faults
```

