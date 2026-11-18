// smnet: network hooks for libSpidermanI.so (arm64 4.6.0c), part of libsmfix.so.
//
// patch_lib.py renames the game's send/recv/getaddrinfo imports to smfix_*; they forward to
// libc. If files/smfix_net exists, all traffic is appended to files/smfix_net.log:
//   - host lookups (getaddrinfo)
//   - plain TCP data (send/recv)
//   - decrypted TLS data, by swapping the ssl3_read/ssl3_write pointers in OpenSSL's
//     SSL_METHOD tables for logging wrappers.

#include <fcntl.h>
#include <link.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "smcommon.h"

#define SSL3_READ_OFF   SM_OFF(0x1241cd4)
#define SSL3_WRITE_OFF  SM_OFF(0x1241af4)

typedef int (*ssl_io_fn)(void *ssl, void *buf, int len);

static int g_net_log = -1;  // fd, -1 when logging is off
static pthread_mutex_t g_log_lock = PTHREAD_MUTEX_INITIALIZER;
static ssl_io_fn g_ssl3_read, g_ssl3_write;

void sm_net_log(const char *kind, const void *ctx, const void *data, long len) {
    if (g_net_log < 0) return;
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    char hdr[128];
    int n = snprintf(hdr, sizeof(hdr), "\n=== %ld.%03ld %s %p len=%ld\n", (long)ts.tv_sec,
                     ts.tv_nsec / 1000000, kind, ctx, len);
    pthread_mutex_lock(&g_log_lock);
    if (write(g_net_log, hdr, n) < 0 || (len > 0 && write(g_net_log, data, len) < 0))
        SM_LOGW("net log write failed");
    pthread_mutex_unlock(&g_log_lock);
}

static int ssl_read_hook(void *ssl, void *buf, int len) {
    int r = g_ssl3_read(ssl, buf, len);
    if (r > 0) sm_net_log("TLS-IN", ssl, buf, r);
    return r;
}

static int ssl_write_hook(void *ssl, void *buf, int len) {
    if (len > 0) sm_net_log("TLS-OUT", ssl, buf, len);
    return g_ssl3_write(ssl, buf, len);
}

__attribute__((visibility("default"))) ssize_t smfix_send(int fd, const void *buf, size_t len, int flags) {
    ssize_t r = send(fd, buf, len, flags);
    if (r > 0) sm_net_log("TCP-OUT", (void *)(intptr_t)fd, buf, r);
    return r;
}

__attribute__((visibility("default"))) ssize_t smfix_recv(int fd, void *buf, size_t len, int flags) {
    ssize_t r = recv(fd, buf, len, flags);
    if (r > 0) sm_net_log("TCP-IN", (void *)(intptr_t)fd, buf, r);
    return r;
}

// The game's curl drops loopback/private addresses after resolving, so SM_FAKE_HOST resolves
// to SM_FAKE_IP (a benchmarking-range address) and smfix_connect turns connections to it into
// connections to the fake server on 127.0.0.1.
static const struct in_addr kFakeIp = {.s_addr = SM_FAKE_IP};

__attribute__((visibility("default"))) struct hostent *smfix_gethostbyname(const char *name) {
    static char *addrs[] = {(char *)&kFakeIp, NULL};
    static char *aliases[] = {NULL};
    static struct hostent fake = {.h_name = (char *)SM_FAKE_HOST, .h_aliases = aliases,
                                  .h_addrtype = AF_INET, .h_length = 4, .h_addr_list = addrs};
    struct hostent *r = name && strcmp(name, SM_FAKE_HOST) == 0 ? &fake : gethostbyname(name);
    if (g_net_log >= 0) {
        char line[300];
        int n = snprintf(line, sizeof(line), "gethostbyname %s -> %s", name ? name : "(null)",
                         r ? "ok" : "fail");
        sm_net_log("DNS", NULL, line, n);
    }
    return r;
}

__attribute__((visibility("default"))) int smfix_getaddrinfo(const char *host, const char *port,
                                                             const struct addrinfo *hints,
                                                             struct addrinfo **res) {
    if (host && strcmp(host, SM_FAKE_HOST) == 0) host = SM_FAKE_IP_STR;
    int r = getaddrinfo(host, port, hints, res);
    if (g_net_log >= 0) {
        char line[512];
        int n = snprintf(line, sizeof(line), "%s:%s -> %s", host ? host : "(null)",
                         port ? port : "", r == 0 ? "ok" : gai_strerror(r));
        sm_net_log("DNS", NULL, line, n);
    }
    return r;
}

__attribute__((visibility("default"))) int smfix_connect(int fd, const struct sockaddr *addr,
                                                         socklen_t len) {
    if (addr && addr->sa_family == AF_INET && len >= sizeof(struct sockaddr_in) &&
        ((const struct sockaddr_in *)addr)->sin_addr.s_addr == SM_FAKE_IP) {
        struct sockaddr_in local = *(const struct sockaddr_in *)addr;
        local.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        return connect(fd, (const struct sockaddr *)&local, sizeof(local));
    }
    return connect(fd, addr, len);
}

static const ElfW(Phdr) *g_phdr;
static int g_phnum;

static int find_phdrs(struct dl_phdr_info *info, size_t size, void *data) {
    (void)size;
    if (info->dlpi_addr != *(uintptr_t *)data) return 0;
    g_phdr = info->dlpi_phdr;
    g_phnum = info->dlpi_phnum;
    return 1;
}

// Replace every pointer to ssl3_read/ssl3_write in the game's writable segment (the
// SSL_METHOD tables live in RELRO there). Leaves that segment RW (debug builds only).
static int hook_ssl_methods(uintptr_t base) {
    dl_iterate_phdr(find_phdrs, &base);
    uintptr_t rd = base + SSL3_READ_OFF, wr = base + SSL3_WRITE_OFF;
    g_ssl3_read = (ssl_io_fn)rd;
    g_ssl3_write = (ssl_io_fn)wr;
    uintptr_t psz = (uintptr_t)sysconf(_SC_PAGESIZE);
    int count = 0;
    for (int i = 0; i < g_phnum; i++) {
        const ElfW(Phdr) *ph = &g_phdr[i];
        if (ph->p_type != PT_LOAD || !(ph->p_flags & PF_W)) continue;
        uintptr_t lo = base + ph->p_vaddr, hi = lo + ph->p_filesz;
        uintptr_t start = lo & ~(psz - 1), end = (hi + psz - 1) & ~(psz - 1);
        if (mprotect((void *)start, end - start, PROT_READ | PROT_WRITE) != 0) return -1;
        for (uintptr_t *p = (uintptr_t *)lo; (uintptr_t)(p + 1) <= hi; p++) {
            if (*p == rd) { *p = (uintptr_t)ssl_read_hook; count++; }
            else if (*p == wr) { *p = (uintptr_t)ssl_write_hook; count++; }
        }
    }
    return count;
}

__attribute__((constructor)) static void smnet_init(void) {
    if (access(SM_FILES_DIR "/smfix_net", F_OK) != 0) return;
    g_net_log = open(SM_FILES_DIR "/smfix_net.log", O_WRONLY | O_CREAT | O_APPEND, 0600);
    if (g_net_log < 0) {
        SM_LOGW("net: cannot open log");
        return;
    }
    uintptr_t base = sm_game_base();
    if (!base) {
        SM_LOGW("net: libSpidermanI.so not found");
        return;
    }
    SM_LOGI("net: logging on, %d TLS method slots hooked", hook_ssl_methods(base));
}
