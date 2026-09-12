#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/* Block eight distinct opens on CPU 0, overwrite scratch on CPU 0, then
 * move half of the blocked actors to CPU 1 before allowing syscall exit.
 * Assertions use fstat on the actual returned FD, not a later path lookup.
 */
#define WORKERS 8
#define ROUNDS 4

static void fail(const char *message) { perror(message); exit(1); }

static void pin(pid_t pid, int cpu) {
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(cpu, &set);
    if (sched_setaffinity(pid, sizeof(set), &set)) fail("sched_setaffinity");
}

static int blocked_open(pid_t pid) {
    char path[80], text[1024];
    snprintf(path, sizeof(path), "/proc/%d/syscall", pid);
    int fd = open(path, O_RDONLY);
    if (fd < 0) return 0;
    ssize_t n = read(fd, text, sizeof(text) - 1);
    close(fd);
    if (n <= 0) return 0;
    text[n] = 0;
    return strtol(text, NULL, 10) == 257; /* x86_64 openat */
}

int main(void) {
    alarm(20);
    int audit = open("/proc/self/loginuid", O_WRONLY);
    if (audit < 0 || write(audit, "1000", 4) != 4) fail("loginuid");
    close(audit);
    char root[] = "/tmp/bh-openat-XXXXXX";
    if (!mkdtemp(root) || chmod(root, 0755)) fail("fixture directory");
    pin(0, 0);
    for (int round = 0; round < ROUNDS; round++) {
        pid_t children[WORKERS];
        char paths[WORKERS][256];
        for (int i = 0; i < WORKERS; i++) {
            snprintf(paths[i], sizeof(paths[i]), "%s/fifo-%d-%d", root, round, i);
            if (mkfifo(paths[i], 0644)) fail("mkfifo");
            children[i] = fork();
            if (children[i] < 0) fail("fork");
            if (!children[i]) {
                if (setgid(1000) || setuid(1000)) fail("setuid");
                int before = sched_getcpu();
                int fd = open(paths[i], O_RDONLY);
                int after = sched_getcpu();
                struct stat st;
                if (fd < 0 || fstat(fd, &st)) fail("open/fstat");
                char result[768];
                int n = snprintf(result, sizeof(result),
                    "{\"pid\":%d,\"path\":\"%s\",\"fd\":%d,"
                    "\"before_cpu\":%d,\"after_cpu\":%d,\"major\":%u,"
                    "\"minor\":%u,\"ino\":%lu}\n",
                    getpid(), paths[i], fd, before, after,
                    major(st.st_dev), minor(st.st_dev), st.st_ino);
                if (write(STDOUT_FILENO, result, n) != n) fail("report");
                close(fd);
                _exit(0);
            }
        }
        /* Every child is demonstrably inside openat, not merely scheduled. */
        for (int i = 0; i < WORKERS; i++) {
            int attempts = 0;
            while (!blocked_open(children[i])) {
                if (++attempts > 1000) fail("child did not enter openat");
                usleep(1000);
            }
        }
        for (int i = 0; i < WORKERS; i++) pin(children[i], i % 2);
        for (int i = 0; i < 64; i++) {
            int noise = open("/etc/hostname", O_RDONLY);
            if (noise < 0) fail("scratch noise");
            close(noise);
        }
        for (int i = 0; i < WORKERS; i++) {
            int writer = open(paths[i], O_WRONLY);
            if (writer < 0) fail("unblock fifo");
            close(writer);
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
