
# Documentation: Implementation of Syscalls in the Linux Kernel

## Teamates

| Full name | carné |
|---|---|
| Juan Pérez | 202200000 |
| Roberto García | 202201724 |
| Carlos Rodríguez | 202200000 |
| Ana López | 202100000 |


## System Information

- **Date and Time**: June 7, 2025, 10:40 AM CST  
- **Environment**: Ubuntu-based virtual machine (x86_64 architecture) - Linux Mint 
- **Kernel Version**: 6.6.44
- **Make version**: 4.3
- **Objective**: Implement system calls 

---

## Steps Followed

### 1. Downloading the Kernel Source

```bash
wget https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.6.44.tar.xz
tar -xf linux-6.6.44.tar.xz
cd linux-6.6.44
```
---

### 2. Setting Up the Build Environment


Copy current kernel config and launch config menu:

```bash
cp -v /boot/config-$(uname -r) .config
```

---

### 3. Implementing the `sys_emergency_panic` System Call

#### 3.1 Declaring the System Call

Edit the syscall header:

```bash
vim include/linux/syscalls.h
```

Add before the `#endif`:

```c
asmlinkage long sys_emergency_panic(void);
```

#### 3.2 Registering the System Call

We'll edit the syscall table:

```bash
vim arch/x86/entry/syscalls/syscall_64.tbl
```

Then we add the following line:

```
548   common   emergency_panic     sys_emergency_panic
```

#### 3.3 Implementing the System Call

Create implementation file:

```bash
nano kernel/usac_syscalls.c
```

Add the following code:

```c
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/uidgid.h>

SYSCALL_DEFINE0(emergency_panic)
{
    panic("USAC Linux: Panic mode activated bu user:  %d", current_uid().val);
    return 0;
}
```

#### 3.4 Updating the Kernel Makefile

We'll edit the kernel Makefile:

```bash
vim kernel/Makefile
```

Then in the source file:

```makefile
obj-y += usac_syscalls.o
```

---

### 4. Personalized message on `kernel`
Make sure your system is up to date and install the necessary build tools.

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install build-essential libncurses-dev bison flex libssl-dev libelf-dev -y
```
Create a directory for the kernel, download the source code, and prepare it for configuration.

```bash
mkdir -p ~/kernel/usac-linux
cd ~/kernel/usac-linux

wget https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.6.30.tar.xz
tar -xf linux-6.6.30.tar.xz
cd linux-6.6.30

cp /boot/config-$(uname -r) .config
make olddefconfig
```

Edit the file `init/main.c` to add a welcome message:

```bash
nano init/main.c
```

Find the function `asmlinkage void __init start_kernel(void)` and insert:

```c
printk(KERN_INFO "hola soy el Kernel y esto lo hizo 202201724\n");
```

### Change the System Name (UTS_SYSNAME)

Edit `include/linux/uts.h`:

```bash
nano include/linux/uts.h
```

Find the line:

```c
#define UTS_SYSNAME "Linux"
```

And replace it with:

```c
#define UTS_SYSNAME "USAC Linux"
```

Make sure the `#` is included.

### Add a New System Call (Syscall)

#### Implement the Syscall

Edit `kernel/sys.c` and add the following at the end:

```bash
nano kernel/sys.c
```

```c
#include <linux/time.h>
#include <linux/ktime.h>
#include <linux/syscalls.h>

SYSCALL_DEFINE0(mi_tiempo)
{
    struct timespec64 ts;
    ktime_get_real_ts64(&ts);
    return ts.tv_sec;  // Returns time in seconds
}
```

#### Register the New Syscall

Edit `arch/x86/entry/syscalls/syscall_64.tbl` and add this line:

```bash
nano arch/x86/entry/syscalls/syscall_64.tbl
```

```txt
548     common  mi_tiempo    sys_mi_tiempo
```

#### Declare the Syscall Header

Edit `include/linux/syscalls.h`:

```bash
nano include/linux/syscalls.h
```

Add at the end:

```c
asmlinkage long sys_mi_tiempo(void);
```

## **Step 4: Compile and Install the Kernel**

```bash
make -j$(nproc)
sudo make modules_install
sudo make install
sudo update-grub
```

Then reboot and select "USAC Linux" from the GRUB menu at startup.

To test the syscall, use the following C program in `test_tiempo.c`:

```c
#include <stdio.h>
#include <sys/syscall.h>
#include <unistd.h>

#define __NR_mi_tiempo 548

int main() {
    long tiempo = syscall(__NR_mi_tiempo);
    printf("Epoch Time: %ld\n", tiempo);
    return 0;
}
```

Compile and run:

```bash
gcc test_tiempo.c -o test_tiempo
./test_tiempo
```

---

### 5. Compiling and Installing the Kernel

```bash
fakeroot make -j$(nproc)
sudo make modules_install
sudo make install
sudo update-grub
sudo reboot
```

---

### 6. Testing the System Call

We create a test program:

```bash
nano test_emergency_panic.c
```

The, we add the code:

```c
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
```

Compile and run:

```bash
gcc -o test_emergency_panic test_emergency_panic.c
./test_emergency_panic
```

Result: Triggers a panic and kills the VM.

---

### 6. Verification

After rebooting into another kernel:

```bash
dmesg | grep "USAC Linux"
```

Confirms that the panic message was logged.

---

## Problems Encountered and Solutions

### Problem 1: System Call Number Conflict

- **Description**: Chose number 548 without verifying.
- **Solution**: Checked syscall table to confirm it's unused.

### Problem 2: Missing Dependencies

- **Description**: Compilation failed due to missing `bison`, `flex`, etc.
- **Solution**: Installed all dependencies listed in the setup step.

### Problem 3: Panic Not Triggering

- **Description**: We where in the incorrect kernel version.
- **Solution**: Enter the GRUB and selecting manually the kernel.

---

## Recommendations

- Always test in a VM.
- Verify syscall numbers before use.
- Use `dmesg` to check logs.
- Modify syscall tables for other architectures if needed.