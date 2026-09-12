#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

int main(void) {
    int audit = open("/proc/self/loginuid", O_WRONLY);
    if (audit < 0 || write(audit, "1000", 4) != 4) return 1;
    close(audit);
    const char *cases[] = {"short", "empty", "twenty", "twenty_one", "long_arg",
                          "total_limit", "bad_vector", "bad_string", "invalid_utf8",
                          "exact_arg_limit"};
    for (int at = 0; at < 2; at++) {
        for (unsigned c = 0; c < sizeof(cases) / sizeof(*cases); c++) {
            char long_arg[257];
            memset(long_arg, 'x', 256);
            long_arg[256] = 0;
            char utf8[] = {(char)0xff, 0};
            char *args[23] = {(char *)cases[c], "test", NULL};
            char **vector = args;
            if (c == 1) { args[1] = ""; args[2] = "last"; args[3] = ""; }
            if (c == 2 || c == 3) {
                int count = c == 2 ? 20 : 21;
                for (int i = 1; i < count; i++) args[i] = "a";
                args[count] = NULL;
            }
            if (c == 4) args[1] = long_arg;
            if (c == 5) {
                long_arg[255] = 0;
                for (int i = 1; i < 19; i++) args[i] = long_arg;
                args[19] = NULL;
            }
            if (c == 6) vector = (char **)1;
            if (c == 7) args[1] = (char *)1;
            if (c == 8) args[1] = utf8;
            if (c == 9) { long_arg[255] = 0; args[1] = long_arg; }
            pid_t child = fork();
            if (child < 0) return 1;
            if (child == 0) {
                if (setgid(1000) || setuid(1000)) _exit(2);
                char *env[] = {NULL};
                const char *filename = "/usr/bin/true";
                /* Probe helpers do not fault in user pages. Warm valid input
                 * pages in this child; invalid-pointer cases remain invalid. */
                volatile unsigned char touched = 0;
                for (const volatile char *p = filename; *p; p++) touched ^= *p;
                if (c != 6) {
                    for (char *volatile *p = vector; *p; p++) {
                        if ((uintptr_t)*p == 1) continue;
                        for (const volatile char *s = *p; *s; s++) touched ^= *s;
                    }
                }
                (void)touched;
                if (at) syscall(SYS_execveat, AT_FDCWD, filename, vector, env, 0);
                else syscall(SYS_execve, filename, vector, env);
                _exit(100);
            }
            int status;
            if (waitpid(child, &status, 0) != child) return 1;
            printf("{\"case\":\"%s\",\"pid\":%d,\"execveat\":%d,\"status\":%d}\n",
                   cases[c], child, at, status);
        }
    }
    return 0;
}
