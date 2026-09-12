#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/bpf.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

/* Test-only fault injection into a specified live map. Keys use impossible
 * Linux task IDs and are all removed before returning. Never run on production.
 */
int main(int argc, char **argv) {
    if (argc != 2) return 2;
    union bpf_attr attr = {.map_id = strtoul(argv[1], NULL, 10)};
    int fd = syscall(SYS_bpf, BPF_MAP_GET_FD_BY_ID, &attr, sizeof(attr));
    if (fd < 0) { perror("get map"); return 1; }
    struct bpf_map_info info = {0};
    attr = (union bpf_attr){.info = {.bpf_fd = fd, .info_len = sizeof(info),
                                   .info = (uintptr_t)&info}};
    if (syscall(SYS_bpf, BPF_OBJ_GET_INFO_BY_FD, &attr, sizeof(attr))) return 1;
    if (info.type != BPF_MAP_TYPE_HASH || info.key_size != 8 || info.value_size < 4096
        || strcmp(info.name, "OPENAT_ENTRY_MA"))
        return 2;
    void *value = calloc(1, info.value_size);
    if (!value) return 1;
    uint64_t key;
    unsigned inserted = 0;
    for (; inserted <= info.max_entries; inserted++) {
        key = UINT64_C(0xfffffffe00000000) + inserted;
        attr = (union bpf_attr){.map_fd = fd, .key = (uintptr_t)&key,
                               .value = (uintptr_t)value, .flags = BPF_NOEXIST};
        if (syscall(SYS_bpf, BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr))) break;
    }
    int map_errno = errno;
    int status = -1;
    pid_t child = fork();
    if (child == 0) {
        int audit = open("/proc/self/loginuid", O_WRONLY);
        if (audit < 0 || write(audit, "1000", 4) != 4) _exit(2);
        close(audit);
        if (setgid(1000) || setuid(1000)) _exit(3);
        int source = open("/etc/hostname", O_RDONLY);
        if (source < 0) _exit(4);
        close(source);
        _exit(0);
    }
    if (child > 0) waitpid(child, &status, 0);
    int cleanup_failed = 0;
    for (unsigned i = 0; i < inserted; i++) {
        key = UINT64_C(0xfffffffe00000000) + i;
        attr = (union bpf_attr){.map_fd = fd, .key = (uintptr_t)&key};
        if (syscall(SYS_bpf, BPF_MAP_DELETE_ELEM, &attr, sizeof(attr))) cleanup_failed = 1;
    }
    free(value);
    close(fd);
    printf("{\"inserted\":%u,\"capacity\":%u,\"map_errno\":%d,\"child_status\":%d,"
           "\"cleanup_failed\":%d}\n", inserted, info.max_entries, map_errno, status,
           cleanup_failed);
    return cleanup_failed || status != 0 || inserted == 0 || inserted > info.max_entries;
}
