// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
/* Independent direct-libbpf control. No bridge or test seam is linked. */
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <dirent.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

static volatile sig_atomic_t interrupted;
static int64_t external_deadline;
static void stop(int signo) { (void)signo; interrupted = 1; }
static int64_t now_ns(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts)) return INT64_MAX;
    return (int64_t)ts.tv_sec * 1000000000 + ts.tv_nsec;
}

static int empty_owned_directory(const char *path) {
    struct stat st;
    if (stat(path, &st) || !S_ISDIR(st.st_mode) || st.st_uid != geteuid()) return 0;
    DIR *dir = opendir(path);
    if (!dir) return 0;
    int empty = 1;
    struct dirent *entry;
    while ((entry = readdir(dir)))
        if (strcmp(entry->d_name, ".") && strcmp(entry->d_name, "..")) { empty = 0; break; }
    closedir(dir);
    return empty;
}

static int publish(const char *dir, const char *name, const char *text) {
    char tmp[PATH_MAX], final[PATH_MAX];
    if (snprintf(tmp, sizeof(tmp), "%s/%s.tmp", dir, name) >= (int)sizeof(tmp) ||
        snprintf(final, sizeof(final), "%s/%s", dir, name) >= (int)sizeof(final)) return -ENAMETOOLONG;
    int fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
    if (fd < 0) return -errno;
    size_t size = strlen(text);
    ssize_t count = write(fd, text, size);
    int rc = count == (ssize_t)size && fsync(fd) == 0 ? 0 : -EIO;
    if (close(fd) && !rc) rc = -errno;
    if (!rc && rename(tmp, final)) rc = -errno;
    return rc;
}

static int barrier(const char *dir, const char *phase, const char *text) {
    char name[64], ack[PATH_MAX];
    if (snprintf(name, sizeof(name), "%s.json", phase) >= (int)sizeof(name) ||
        snprintf(ack, sizeof(ack), "%s/%s.ack", dir, phase) >= (int)sizeof(ack)) return -ENAMETOOLONG;
    int rc = publish(dir, name, text);
    if (rc) return rc;
    int64_t limit = now_ns() + INT64_C(15000000000);
    if (external_deadline < limit) limit = external_deadline;
    while (!interrupted && now_ns() < limit) {
        int fd = open(ack, O_RDONLY | O_NOFOLLOW);
        if (fd >= 0) {
            char answer[16] = {0};
            ssize_t n = read(fd, answer, sizeof(answer) - 1);
            close(fd);
            return n == 9 && !memcmp(answer, "continue\n", 9) ? 0 : -ECANCELED;
        }
        if (errno != ENOENT) return -errno;
        struct timespec pause = {0, 5000000};
        nanosleep(&pause, NULL);
    }
    return interrupted ? -EINTR : -ETIMEDOUT;
}

static void hexkey(char out[9], uint32_t key) {
    const unsigned char *p = (const unsigned char *)&key;
    for (int i = 0; i < 4; ++i) snprintf(out + i * 2, 3, "%02x", p[i]);
}

/* Exactly one initial call plus at most three successors. No order promise. */
static int walk(int fd, char *out, size_t capacity, unsigned *calls) {
    uint32_t key = 0, next;
    size_t used = 0;
    const void *cursor = NULL;
    *calls = 0;
    int rc;
    do {
        rc = bpf_map_get_next_key(fd, cursor, &next);
        ++*calls;
        if (rc) break;
        char hex[9]; hexkey(hex, next);
        int n = snprintf(out + used, capacity - used, "%s\"%s\"", used ? "," : "", hex);
        if (n < 0 || (size_t)n >= capacity - used) return -EOVERFLOW;
        used += (size_t)n;
        key = next; cursor = &key;
    } while (*calls < 4);
    return rc;
}

static int owned_bpf_fds(void) {
    DIR *dir = opendir("/proc/self/fdinfo");
    if (!dir) return -1;
    int count = 0;
    struct dirent *entry;
    while ((entry = readdir(dir))) {
        if (entry->d_name[0] == '.') continue;
        char path[PATH_MAX], line[1024];
        if (snprintf(path, sizeof(path), "/proc/self/fdinfo/%s", entry->d_name) >= (int)sizeof(path)) { count = -1; break; }
        FILE *file = fopen(path, "r");
        if (!file) { count = -1; break; }
        while (fgets(line, sizeof(line), file))
            if (!strncmp(line, "map_id:", 7) || !strncmp(line, "prog_id:", 8)) ++count;
        fclose(file);
    }
    closedir(dir);
    return count;
}

static void credential_record(const char *stage, int rc, int before, int after) {
    printf("{\"stage\":\"%s\",\"native_code\":%d,\"uid\":%u,\"euid\":%u,\"bpf_fds_before_close\":%d,\"bpf_fds_after_close\":%d,\"status_raw\":\"", stage, rc, (unsigned)getuid(), (unsigned)geteuid(), before, after);
    FILE *status = fopen("/proc/self/status", "r");
    if (status) {
        int c;
        while ((c = fgetc(status)) != EOF) {
            if (c == '\n') fputs("\\n", stdout);
            else if (c == '\t') fputs("\\t", stdout);
            else if (c == '"' || c == '\\') { putchar('\\'); putchar(c); }
            else if (c >= 32 && c < 127) putchar(c);
        }
        fclose(status);
    }
    puts("\"}"); fflush(stdout);
}

int main(int argc, char **argv) {
    int negative = argc == 3 && !strcmp(argv[1], "--permission-negative");
    if ((!negative && argc != 4) || (argc > 1 && argv[1][0] == '-' && !negative)) return 2;
    const char *object_path = argv[negative ? 2 : 1];
    const char *dir = negative ? NULL : argv[2];
    if (!negative) {
        char resolved[PATH_MAX], result[PATH_MAX];
        if (!realpath(dir, resolved) || !empty_owned_directory(resolved) || snprintf(result, sizeof(result), "%s/result.json", resolved) >= (int)sizeof(result) || strcmp(argv[3], result)) return 2;
        const char *deadline = getenv("LMB_LIVE_DEADLINE_MONOTONIC_NS");
        char *end = NULL;
        if (!deadline) return 2;
        errno = 0; external_deadline = strtoll(deadline, &end, 10);
        if (errno || !end || *end || external_deadline <= now_ns()) return 2;
    }
    signal(SIGTERM, stop); signal(SIGINT, stop);
    static char log[1048576];
    LIBBPF_OPTS(bpf_object_open_opts, options,
        .kernel_log_buf = log, .kernel_log_size = sizeof(log), .kernel_log_level = 1);
    struct bpf_object *obj = bpf_object__open_file(object_path, &options);
    int rc = (int)libbpf_get_error(obj);
    if (!obj || rc) {
        if (!rc) rc = -errno;
        if (negative) credential_record("open", rc, owned_bpf_fds(), owned_bpf_fds());
        return 3;
    }
    rc = bpf_object__load(obj);
    if (negative) {
        int before = owned_bpf_fds();
        bpf_object__close(obj);
        credential_record("load", rc, before, owned_bpf_fds());
        fwrite(log, 1, strnlen(log, sizeof(log)), stderr);
        return rc == -EPERM || rc == -EACCES ? 0 : 3;
    }
    const char *stage = "load";
    if (rc) goto done;
    int counter = bpf_object__find_map_fd_by_name(obj, "counter");
    int values = bpf_object__find_map_fd_by_name(obj, "values");
    struct bpf_program *program = bpf_object__find_program_by_name(obj, "lmb_map_live");
    if (counter < 0 || values < 0 || !program) { rc = -ENOENT; goto done; }
#define CHECK(call) do { rc = (call); if (rc) goto done; } while (0)
#define PHASE(name, data) do { stage = name; CHECK(barrier(dir, name, data)); } while (0)
    PHASE("loaded", "{}");
    uint32_t zero = 0, seven = 7, high = UINT32_MAX, absent = 99, key;
    uint64_t value = 41;
    CHECK(bpf_map_update_elem(counter, &zero, &value, BPF_ANY));
    CHECK(bpf_map_lookup_elem(counter, &zero, &value));
    char data[16384];
    snprintf(data, sizeof(data), "{\"counter\":%" PRIu64 "}", value);
    PHASE("initialized", data);
    unsigned char packet[60] = {0}, output[60] = {0};
    packet[12] = 8; packet[14] = 0x45; packet[16] = 0; packet[17] = 46;
    LIBBPF_OPTS(bpf_test_run_opts, run, .data_in = packet, .data_size_in = 60,
        .data_out = output, .data_size_out = 60, .repeat = 1);
    CHECK(bpf_prog_test_run_opts(bpf_program__fd(program), &run));
    CHECK(bpf_map_lookup_elem(counter, &zero, &value));
    snprintf(data, sizeof(data), "{\"counter\":%" PRIu64 ",\"retval\":%u,\"data_actual\":%u,\"ctx_actual\":%u,\"duration_ns\":%u}", value, run.retval, run.data_size_out, run.ctx_size_out, run.duration);
    PHASE("executed", data); /* Mutants remain alive here until the observer replies. */
    if (value != 42) { rc = -ERANGE; goto done; }
    int empty_first = bpf_map_get_next_key(values, NULL, &key);
    value = UINT64_C(0x0123456789abcdef); CHECK(bpf_map_update_elem(values, &zero, &value, BPF_ANY));
    CHECK(bpf_map_get_next_key(values, NULL, &key));
    char zero_first[9]; hexkey(zero_first, key);
    int zero_next = bpf_map_get_next_key(values, &zero, &key);
    value = UINT64_C(0xfedcba9876543210); CHECK(bpf_map_update_elem(values, &seven, &value, BPF_ANY));
    value = UINT64_C(0x1122334455667788); CHECK(bpf_map_update_elem(values, &high, &value, BPF_ANY));
    char seeded[128] = {0}, remaining[128] = {0}, first[9], restart[9];
    unsigned calls, after_calls;
    int terminal = walk(values, seeded, sizeof(seeded), &calls);
    CHECK(bpf_map_get_next_key(values, NULL, &key)); hexkey(first, key);
    CHECK(bpf_map_get_next_key(values, &absent, &key)); hexkey(restart, key);
    snprintf(data, sizeof(data), "{\"empty_first_code\":%d,\"zero_first\":\"%s\",\"zero_next_code\":%d,\"seeded\":[%s],\"calls\":%u,\"terminal\":{\"operation\":19,\"domain\":3,\"code\":%d},\"first\":\"%s\",\"restart\":\"%s\"}", empty_first, zero_first, zero_next, seeded, calls, terminal, first, restart);
    PHASE("keys-seeded", data);
    CHECK(bpf_map_delete_elem_flags(values, &seven, 0));
    int after_terminal = walk(values, remaining, sizeof(remaining), &after_calls);
    int missing_delete = bpf_map_delete_elem_flags(values, &seven, 0);
    int missing_lookup = bpf_map_lookup_elem(values, &seven, &value);
    snprintf(data, sizeof(data), "{\"after_delete\":[%s],\"after_calls\":%u,\"after_terminal\":{\"operation\":19,\"domain\":3,\"code\":%d},\"missing_delete\":{\"operation\":18,\"domain\":3,\"code\":%d},\"missing_lookup\":{\"operation\":7,\"domain\":3,\"code\":%d}}", remaining, after_calls, after_terminal, missing_delete, missing_lookup);
    PHASE("key-deleted", data);
    CHECK(bpf_map_delete_elem_flags(values, &zero, 0)); CHECK(bpf_map_delete_elem_flags(values, &high, 0));
    int empty_final = bpf_map_get_next_key(values, NULL, &key);
    CHECK(bpf_map_get_next_key(counter, NULL, &key)); char array_first[9]; hexkey(array_first, key);
    int array_next = bpf_map_get_next_key(counter, &zero, &key);
    CHECK(bpf_map_get_next_key(counter, &absent, &key)); char array_restart[9]; hexkey(array_restart, key);
    int array_delete = bpf_map_delete_elem_flags(counter, &zero, 0);
    snprintf(data, sizeof(data), "{\"empty_final_code\":%d,\"array_first\":\"%s\",\"array_next_code\":%d,\"array_restart\":\"%s\",\"array_delete\":%d}", empty_final, array_first, array_next, array_restart, array_delete);
    PHASE("keys-empty", data);
    /* Direct C keeps its owner; only the typed consumer claims parent release. */
    CHECK(bpf_map_lookup_elem(counter, &zero, &value));
    int retained_first = bpf_map_get_next_key(values, NULL, &key);
    snprintf(data, sizeof(data), "{\"counter\":%" PRIu64 ",\"first_code\":%d}", value, retained_first);
    PHASE("owner-released", data);
    bpf_object__close(obj); obj = NULL;
    CHECK(publish(dir, "closed.json", "{}"));
done:
    if (obj) bpf_object__close(obj);
    snprintf(data, sizeof(data), "{\"native_code\":%d,\"stage\":\"%s\"}", rc, stage);
    if (publish(dir, "result.json", data) && !rc) rc = -EIO;
    if (rc) fprintf(stderr, "stock_map_live stage=%s native_code=%d\n", stage, rc);
    fwrite(log, 1, strnlen(log, sizeof(log)), stderr);
    return rc ? 3 : 0;
}
