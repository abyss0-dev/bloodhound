#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <unistd.h>

int main(void) {
    int audit = open("/proc/self/loginuid", O_WRONLY);
    if (audit < 0 || write(audit, "1000", 4) != 4) return 1;
    close(audit);
    if (setgid(1000) || setuid(1000)) return 1;
    int directory = open("/etc", O_RDONLY | O_DIRECTORY);
    if (directory < 0) return 1;
    char long_path[4200];
    memset(long_path, 'x', sizeof(long_path) - 1);
    long_path[sizeof(long_path) - 1] = 0;
    const char *paths[] = {(char *)1, long_path, "", "hostname", "hostname"};
    const char *names[] = {"bad_pointer", "long_path", "empty", "relative", "bad_dirfd"};
    for (unsigned i = 0; i < 5; i++) {
        int dirfd = i == 3 ? directory : -100;
        if (i == 4) dirfd = -99;
        long fd = syscall(SYS_openat, dirfd, paths[i], O_RDONLY, 0);
        long ret = fd < 0 ? -errno : fd;
        struct stat st = {0};
        if (fd >= 0) {
            if (fstat(fd, &st)) return 1;
            close(fd);
        }
        printf("{\"case\":\"%s\",\"pid\":%d,\"dirfd\":%d,\"ret\":%ld,"
               "\"major\":%u,\"minor\":%u,\"ino\":%lu}\n",
               names[i], getpid(), dirfd, ret, major(st.st_dev), minor(st.st_dev), st.st_ino);
    }
    close(directory);
    return 0;
}
