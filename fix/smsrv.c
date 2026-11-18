// smsrv: in-process stand-in for Gameloft's (dead) servers, part of libsmfix.so.
//
// curl_easy_setopt(CURLOPT_URL) is hooked: every http(s) URL the game asks for is rewritten to
//   https://127.0.0.1:<port>/<original host><original path and query>
// and answered by a small HTTP server running on a thread inside the game process.
// Nothing leaves the phone.
//
// The game's libcurl only has the HTTPS handler compiled in, so that handler is switched to
// plain HTTP (protocol HTTP, no PROTOPT_SSL): the "https" URLs then talk plain HTTP to us.
//
// Responses come from route handlers (smsrv_routes.c) and, during development, from files
// under files/srv/<host>/<path>.json which override them.
// Always on; creating files/smfix_nosrv turns it off (the game then hangs where it needs a server).

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include "smcommon.h"
#include "smsrv.h"

#define CURLOPT_URL 10002
#define SETOPT_OFF SM_OFF(0x1207374)
// curl_easy_setopt prolog, replayed by the stub:
//   sub sp, sp, #0x100 ; str x30, [sp, #0xf0] ; stp q6, q7, [sp, #0x60] ; stp q4, q5, [sp, #0x40]
static const uint32_t kSetoptProlog[4] = {0xd10403ff, 0xf9007bfe, 0xad031fe6, 0xad0217e4};

// curl's Curl_handler_https (7.59): +0x00 scheme, +0x30 connecting, +0x80 protocol, +0x84 flags
#define HTTPS_HANDLER_OFF SM_OFF(0x1ac4e18)
#define HTTPS_SCHEME_OFF  SM_OFF(0x17a66e5)
#define CURLPROTO_HTTP  1u
#define CURLPROTO_HTTPS 2u
#define PROTOPT_SSL     1u

uintptr_t smsrv_setopt_resume;
static int g_port;

static int make_https_plain(uintptr_t base) {
    uint8_t *h = (uint8_t *)(base + HTTPS_HANDLER_OFF);
    uint32_t *proto = (uint32_t *)(h + 0x80), *flags = (uint32_t *)(h + 0x84);
    if (*(uintptr_t *)h != base + HTTPS_SCHEME_OFF || *proto != CURLPROTO_HTTPS) return -1;
    uintptr_t psz = (uintptr_t)sysconf(_SC_PAGESIZE);
    uintptr_t page = (uintptr_t)h & ~(psz - 1);
    if (mprotect((void *)page, ((uintptr_t)h + 0x88 - page + psz - 1) & ~(psz - 1),
                 PROT_READ | PROT_WRITE) != 0)
        return -1;
    *(uintptr_t *)(h + 0x30) = 0;  // no TLS handshake step
    *proto = CURLPROTO_HTTP;
    *flags &= ~PROTOPT_SSL;
    return 0;
}

// ---------------------------------------------------------------- URL rewrite

static __thread char t_url[4096];

#define CURLOPT_VERBOSE 41
#define CURLOPT_DEBUGFUNCTION 20094
#define CURLOPT_OPENSOCKETFUNCTION 20163
typedef int (*setopt_fn)(void *handle, int option, ...);

static int curl_debug_cb(void *handle, int type, char *data, size_t size, void *userp) {
    (void)userp;
    char kind[32];
    snprintf(kind, sizeof(kind), "CURL-DBG%d", type);
    sm_net_log(kind, handle, data, (long)size);
    return 0;
}

// Called by the stub for every curl_easy_setopt; returns the (possibly replaced) argument.
__attribute__((visibility("hidden"))) const void *smsrv_filter_setopt(void *handle, int option,
                                                                     const void *arg) {
    if (g_port) {
        char line[600];
        int n = (option >= 10000 && option < 20000 && arg)
                    ? snprintf(line, sizeof(line), "%p opt %d = \"%.500s\"", handle, option, (const char *)arg)
                    : snprintf(line, sizeof(line), "%p opt %d = %ld", handle, option, (long)(intptr_t)arg);
        sm_net_log("SETOPT", NULL, line, n);
    }
    if (option == 10015 /* CURLOPT_POSTFIELDS */ && arg && g_port &&
        strncmp((const char *)arg, "encrypt=", 8) == 0) {
        // Heuristic backtrace: game code addresses found on the stack (original offsets).
        char bt[1024];
        int n = 0;
        uintptr_t base = sm_game_base();
        uintptr_t *sp = __builtin_frame_address(0);
        for (int i = 0; i < 2048 && n < 1000; i++) {
            uintptr_t v = sp[i];
            if (v > base + 0x1c0000 && v < base + 0x1a40000 && (v & 3) == 0)
                n += snprintf(bt + n, sizeof(bt) - n, "%lx ", (unsigned long)(v - base - 0x1000));
        }
        sm_net_log("BT-ENC", NULL, bt, n);
    }
    if (option != CURLOPT_URL || !arg || !g_port) return arg;
    const char *url = arg;
    const char *rest;
    if (strncasecmp(url, "https://", 8) == 0) rest = url + 8;
    else if (strncasecmp(url, "http://", 7) == 0) rest = url + 7;
    else if (!strstr(url, "://")) rest = url;  // the game passes some URLs without a scheme
    else return arg;
    if (strncmp(rest, SM_FAKE_HOST, strlen(SM_FAKE_HOST)) == 0) return arg;
    const char *slash = strchr(rest, '/');
    size_t hostlen = slash ? (size_t)(slash - rest) : strlen(rest);
    const char *colon = memchr(rest, ':', hostlen);  // drop an explicit port
    size_t namelen = colon ? (size_t)(colon - rest) : hostlen;
    snprintf(t_url, sizeof(t_url), "https://" SM_FAKE_HOST ":%d/%.*s%s", g_port, (int)namelen, rest,
             slash ? slash : "/");
    sm_net_log("URL", NULL, url, (long)strlen(url));
    setopt_fn setopt_orig = (setopt_fn)(sm_game_base() + SETOPT_OFF);
    // The game's opensocket callback refuses loopback addresses; use curl's default socket().
    setopt_orig(handle, CURLOPT_OPENSOCKETFUNCTION, (void *)NULL);
    if (access(SM_FILES_DIR "/smfix_curldbg", F_OK) == 0) {  // curl's own trace into the net log
        setopt_fn setopt = (setopt_fn)(sm_game_base() + SETOPT_OFF);
        setopt(handle, CURLOPT_VERBOSE, 1L);
        setopt(handle, CURLOPT_DEBUGFUNCTION, curl_debug_cb);
    }
    return t_url;
}

__attribute__((naked)) static void setopt_stub(void) {
    __asm__ volatile(
        "stp x29, x30, [sp, #-0x60]!\n"
        "stp x0, x1, [sp, #0x10]\n"
        "stp x2, x3, [sp, #0x20]\n"
        "stp x4, x5, [sp, #0x30]\n"
        "stp x6, x7, [sp, #0x40]\n"
        "bl smsrv_filter_setopt\n"
        "mov x2, x0\n"
        "ldp x0, x1, [sp, #0x10]\n"
        "ldr x3, [sp, #0x28]\n"
        "ldp x4, x5, [sp, #0x30]\n"
        "ldp x6, x7, [sp, #0x40]\n"
        "ldp x29, x30, [sp], #0x60\n"
        "sub sp, sp, #0x100\n"
        "str x30, [sp, #0xf0]\n"
        "stp q6, q7, [sp, #0x60]\n"
        "stp q4, q5, [sp, #0x40]\n"
        "adrp x16, smsrv_setopt_resume\n"
        "ldr x16, [x16, :lo12:smsrv_setopt_resume]\n"
        "br x16\n");
}

// ---------------------------------------------------------------- responses

void sm_resp_set(sm_resp *r, int status, const char *type, const char *body, size_t len) {
    r->status = status;
    snprintf(r->type, sizeof(r->type), "%s", type);
    free(r->body);
    r->body = malloc(len + 1);
    memcpy(r->body, body, len);
    r->body[len] = 0;
    r->len = len;
}

void sm_resp_json(sm_resp *r, int status, const char *json) {
    sm_resp_set(r, status, "application/json", json, strlen(json));
}

// Development override: files/srv/<host>/<path without query>.json
static int serve_file(const sm_req *q, sm_resp *r) {
    char path[1024];
    snprintf(path, sizeof(path), SM_FILES_DIR "/srv/%s%s", q->host, q->path);
    size_t n = strlen(path);
    snprintf(path + n, sizeof(path) - n, "%s.json", n && path[n - 1] == '/' ? "_index" : "");
    int fd = open(path, O_RDONLY);
    if (fd < 0) return 0;
    struct stat st;
    fstat(fd, &st);
    char *buf = malloc(st.st_size + 1);
    ssize_t got = read(fd, buf, st.st_size);
    close(fd);
    sm_resp_set(r, 200, "application/json", buf, got > 0 ? (size_t)got : 0);
    free(buf);
    return 1;
}

// ---------------------------------------------------------------- HTTP server

static int read_full(int fd, char *buf, size_t len) {
    size_t got = 0;
    while (got < len) {
        ssize_t n = read(fd, buf + got, len - got);
        if (n <= 0) return -1;
        got += n;
    }
    return 0;
}

static int write_full(int fd, const char *buf, size_t len) {
    while (len) {
        ssize_t n = write(fd, buf, len);
        if (n <= 0) return -1;
        buf += n;
        len -= n;
    }
    return 0;
}

static const char *find_header(const char *headers, const char *name) {
    size_t nl = strlen(name);
    for (const char *p = headers; p && *p; p = strstr(p, "\r\n")) {
        if (*p == '\r') p += 2;
        if (strncasecmp(p, name, nl) == 0 && p[nl] == ':') {
            p += nl + 1;
            while (*p == ' ') p++;
            return p;
        }
    }
    return NULL;
}

// Handles one request; returns 0 to keep the connection, -1 to close it.
static int handle_request(int fd) {
    static const size_t kMaxHead = 65536;
    char *head = malloc(kMaxHead + 1);
    size_t used = 0;
    char *end = NULL;
    while (!end) {
        if (used == kMaxHead) { free(head); return -1; }
        ssize_t n = read(fd, head + used, kMaxHead - used);
        if (n <= 0) { free(head); return -1; }
        used += n;
        head[used] = 0;
        end = strstr(head, "\r\n\r\n");
    }
    size_t head_len = end - head + 4;

    sm_req q = {0};
    char target[2048] = "";
    sscanf(head, "%15s %2047s", q.method, target);
    const char *cl = find_header(head, "Content-Length");
    size_t body_len = cl ? strtoul(cl, NULL, 10) : 0;
    const char *expect = find_header(head, "Expect");
    if (expect && strncasecmp(expect, "100-continue", 12) == 0)
        write_full(fd, "HTTP/1.1 100 Continue\r\n\r\n", 25);

    q.body = malloc(body_len + 1);
    size_t have = used - head_len;
    if (have > body_len) have = body_len;
    memcpy(q.body, head + head_len, have);
    if (have < body_len && read_full(fd, q.body + have, body_len - have) != 0) {
        free(q.body);
        free(head);
        return -1;
    }
    q.body[body_len] = 0;
    q.body_len = body_len;

    // target = /<host><path>?<query>
    char *t = target[0] == '/' ? target + 1 : target;
    char *path = strchr(t, '/');
    snprintf(q.host, sizeof(q.host), "%.*s", path ? (int)(path - t) : (int)strlen(t), t);
    snprintf(q.path, sizeof(q.path), "%s", path ? path : "/");
    char *qm = strchr(q.path, '?');
    if (qm) {
        snprintf(q.query, sizeof(q.query), "%s", qm + 1);
        *qm = 0;
    }

    sm_net_log("SRV-REQ", NULL, head, (long)head_len);
    if (body_len) sm_net_log("SRV-REQ-BODY", NULL, q.body, (long)body_len);

    sm_resp r = {0};
    if (!serve_file(&q, &r) && !sm_route(&q, &r)) {
        sm_resp_json(&r, 404, "{\"error\":\"not implemented\"}");
        sm_net_log("SRV-MISS", NULL, target, (long)strlen(target));
    }

    char hdr[256];
    int hn = snprintf(hdr, sizeof(hdr),
                      "HTTP/1.1 %d %s\r\nContent-Type: %s\r\nContent-Length: %zu\r\n"
                      "Connection: keep-alive\r\n\r\n",
                      r.status, r.status == 200 ? "OK" : "Error", r.type, r.len);
    sm_net_log("SRV-RESP", NULL, r.body, (long)r.len);
    int rc = write_full(fd, hdr, hn) || write_full(fd, r.body, r.len) ? -1 : 0;
    free(r.body);
    free(q.body);
    free(head);
    return rc;
}

static void *conn_thread(void *arg) {
    int fd = (int)(intptr_t)arg;
    while (handle_request(fd) == 0) {}
    close(fd);
    return NULL;
}

static void *server_thread(void *arg) {
    int ls = (int)(intptr_t)arg;
    for (;;) {
        int fd = accept(ls, NULL, NULL);
        if (fd < 0) {
            if (errno == EINTR) continue;
            SM_LOGW("srv: accept failed: %s", strerror(errno));
            break;
        }
        pthread_t th;
        pthread_attr_t at;
        pthread_attr_init(&at);
        pthread_attr_setdetachstate(&at, PTHREAD_CREATE_DETACHED);
        if (pthread_create(&th, &at, conn_thread, (void *)(intptr_t)fd) != 0) close(fd);
        pthread_attr_destroy(&at);
    }
    return NULL;
}

static int start_server(void) {
    int ls = socket(AF_INET, SOCK_STREAM, 0);
    if (ls < 0) return -1;
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    socklen_t al = sizeof(a);
    if (bind(ls, (struct sockaddr *)&a, sizeof(a)) != 0 || listen(ls, 16) != 0 ||
        getsockname(ls, (struct sockaddr *)&a, &al) != 0) {
        close(ls);
        return -1;
    }
    pthread_t th;
    if (pthread_create(&th, NULL, server_thread, (void *)(intptr_t)ls) != 0) {
        close(ls);
        return -1;
    }
    pthread_detach(th);
    return ntohs(a.sin_port);
}

__attribute__((constructor)) static void smsrv_init(void) {
    if (access(SM_FILES_DIR "/smfix_nosrv", F_OK) == 0) return;
    uintptr_t base = sm_game_base();
    if (!base) {
        SM_LOGW("srv: libSpidermanI.so not found");
        return;
    }
    if (make_https_plain(base) != 0) {
        SM_LOGW("srv: unexpected curl HTTPS handler, not redirecting");
        return;
    }
    int port = start_server();
    if (port <= 0) {
        SM_LOGW("srv: could not start server");
        return;
    }
    uintptr_t target = base + SETOPT_OFF;
    smsrv_setopt_resume = target + 16;
    if (sm_hook4(target, kSetoptProlog, (void *)setopt_stub) != 0) {
        SM_LOGW("srv: could not hook curl_easy_setopt");
        return;
    }
    g_port = port;
    sm_api_init(base);
    SM_LOGI("srv: fake server on 127.0.0.1:%d", port);
}
