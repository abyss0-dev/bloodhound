#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc != 3) return 1;
    pid_t workers[4];
    for (int i = 0; i < 4; i++) {
        workers[i] = fork();
        if (workers[i] < 0) return 2;
        if (workers[i] == 0) {
            while (access(argv[1], F_OK) != 0) {
                pid_t child = fork();
                if (child < 0) _exit(3);
                if (child == 0) {
                    // One open per task: another enter must not overwrite an
                    // orphaned entry before task-exit cleanup can expose it.
                    int fd = openat(AT_FDCWD, "/etc/hostname", O_RDONLY);
                    if (fd < 0) _exit(4);
                    close(fd);
                    _exit(0);
                }
                int status;
                if (waitpid(child, &status, 0) != child || status != 0) _exit(5);
            }
            _exit(0);
        }
    }
    FILE *ready = fopen(argv[2], "w");
    if (!ready) return 6;
    fprintf(ready, "%ld\n", (long)getpid());
    fclose(ready);
    int failed = 0;
    for (int i = 0; i < 4; i++) {
        int status;
        if (waitpid(workers[i], &status, 0) != workers[i] || status != 0) failed = 1;
    }
    return failed;
}
