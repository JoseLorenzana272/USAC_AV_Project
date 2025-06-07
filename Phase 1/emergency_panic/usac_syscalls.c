#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/uidgid.h>


// Emergency Panic mode
SYSCALL_DEFINE0(emergency_panic)
{
    panic("USAC Linux: Panic mode activated bu user:  %d", current_uid().val);
    return 0;
}