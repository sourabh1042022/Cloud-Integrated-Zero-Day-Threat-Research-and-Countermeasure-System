#include <stdio.h>
#include <unistd.h>
#include <sys/syscall.h>

int main() {
    long pid = syscall(SYS_getpid);
    printf("Syscall getpid returned: %ld\n", pid);
    return 0;
}
