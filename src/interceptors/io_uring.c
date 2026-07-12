/* io_uring stub: intercept libc's `syscall()` to block io_uring entry points
 * (callers fall back to epoll on ENOSYS). Everything else passes through
 * unmodified to libc's real wrapper via dlsym(RTLD_NEXT). */

#include <dlfcn.h>
#include <errno.h>
#include <stdarg.h>
#include <stddef.h>
#include <sys/syscall.h>
#include <unistd.h>

long syscall(long number, ...) {
#ifdef SYS_io_uring_setup
    if (number == SYS_io_uring_setup) {
        errno = ENOSYS;
        return -1;
    }
#endif
#ifdef SYS_io_uring_enter
    if (number == SYS_io_uring_enter) {
        errno = ENOSYS;
        return -1;
    }
#endif
#ifdef SYS_io_uring_register
    if (number == SYS_io_uring_register) {
        errno = ENOSYS;
        return -1;
    }
#endif

    static long (*real_syscall)(long, long, long, long, long, long, long) = NULL;
    if (!real_syscall) {
        real_syscall = (long (*)(long, long, long, long, long, long, long))dlsym(RTLD_NEXT, "syscall");
        if (!real_syscall) {
            errno = ENOSYS;
            return -1;
        }
    }

    va_list ap;
    va_start(ap, number);
    const long a1 = va_arg(ap, long);
    const long a2 = va_arg(ap, long);
    const long a3 = va_arg(ap, long);
    const long a4 = va_arg(ap, long);
    const long a5 = va_arg(ap, long);
    const long a6 = va_arg(ap, long);
    va_end(ap);

    return real_syscall(number, a1, a2, a3, a4, a5, a6);
}
