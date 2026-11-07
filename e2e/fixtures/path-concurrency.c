#define _GNU_SOURCE
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#define WORKERS 8
#define ROUNDS 4
static void fail(const char *s) { perror(s); exit(1); }
static void pin(pid_t pid, int cpu) {
    cpu_set_t set;
    CPU_ZERO(&set); CPU_SET(cpu, &set);
    if (sched_setaffinity(pid, sizeof(set), &set)) fail("affinity");
}
static int blocked_truncate(pid_t pid) {
    char path[80], text[1024];
    snprintf(path, sizeof(path), "/proc/%d/syscall", pid);
    int fd = open(path, O_RDONLY);
    if (fd < 0) return 0;
    ssize_t n = read(fd, text, sizeof(text) - 1);
    close(fd);
    if (n <= 0) return 0;
    text[n] = 0;
    return strtol(text, NULL, 10) == SYS_truncate;
}
int main(void) {
    alarm(20);
    int audit = open("/proc/self/loginuid", O_WRONLY);
    if (audit < 0 || write(audit, "1000", 4) != 4) fail("loginuid");
    close(audit);
    char root[] = "/tmp/bh-path-XXXXXX";
    if (!mkdtemp(root)) fail("mkdtemp");
    pin(0, 0);
    signal(SIGIO, SIG_IGN);
    for (int round = 0; round < ROUNDS; round++) {
        pid_t children[WORKERS];
        char paths[WORKERS][256];
        int leases[WORKERS];
        for (int i = 0; i < WORKERS; i++) {
            snprintf(paths[i], sizeof(paths[i]), "%s/file-%d-%d", root, round, i);
            int fd = open(paths[i], O_CREAT | O_WRONLY, 0644);
            if (fd < 0) fail("create");
            close(fd);
            leases[i] = open(paths[i], O_RDONLY);
            if (leases[i] < 0 || fcntl(leases[i], F_SETLEASE, F_RDLCK)) fail("lease");
            children[i] = fork();
            if (children[i] < 0) fail("fork");
            if (!children[i]) {
                for (int j = 0; j <= i; j++) close(leases[j]);
                int before = sched_getcpu();
                int ret = truncate(paths[i], 0);
                int after = sched_getcpu();
                if (ret) fail("truncate");
                char report[768];
                int n = snprintf(report, sizeof(report),
                    "{\"pid\":%d,\"name\":\"truncate\",\"path\":\"%s\","
                    "\"before_cpu\":%d,\"after_cpu\":%d}\n", getpid(),
                    paths[i], before, after);
                if (write(1, report, n) != n) fail("report");
                _exit(0);
            }
        }
        /* Leases keep sys_exit behind the scratch overwrite and migration. */
        for (int i = 0; i < WORKERS; i++) {
            int attempts = 0;
            while (!blocked_truncate(children[i])) {
                if (++attempts > 1000) fail("child did not enter truncate");
                usleep(1000);
            }
        }
        for (int i = 0; i < WORKERS; i++) pin(children[i], i % 2);
        for (int i = 0; i < 64; i++) {
            if (chmod(root, 0700)) fail("scratch noise");
        }
        for (int i = 0; i < WORKERS; i++) {
            if (fcntl(leases[i], F_SETLEASE, F_UNLCK)) fail("unlock lease");
            close(leases[i]);
        }
        for (int i = 0; i < WORKERS; i++) {
            int status;
            if (waitpid(children[i], &status, 0) != children[i]
                || !WIFEXITED(status) || WEXITSTATUS(status)) fail("child status");
            if (unlink(paths[i])) fail("unlink");
        }
    }
    if (rmdir(root)) fail("rmdir");
    return 0;
}
