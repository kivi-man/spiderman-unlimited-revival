// smfix: compact heap for libSpidermanI.so on 64-bit Android 11+.
//
// The game stores links between heap objects as 32-bit relative offsets. Android 11+
// (Scudo) places allocations gigabytes apart on arm64, so those offsets overflow and the
// game crashes while loading. libSpidermanI's malloc/calloc/realloc/free imports are
// renamed to smfix_* and served from a single arena smaller than 2 GB.
// Pointers not from the arena (e.g. strdup/realpath results) are passed to libc.

#include <android/log.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

#define TAG "smfix"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, TAG, __VA_ARGS__)

#define ARENA_SIZE   ((size_t)1920 << 20)  // 1.875 GB: any two arena addresses fit in int32
#define HDR          16
#define PAGE         4096
#define SMALL_MAX    65536
#define MAGIC_SMALL  0x534d4c31u
#define MAGIC_LARGE  0x534d4c32u
#define MAGIC_FREE   0x534d4c46u

typedef struct {
    uint32_t magic;
    uint32_t cls;
    uint64_t cap;  // usable payload bytes
} hdr_t;

typedef struct lfree {  // free large block, kept sorted by address
    uint64_t total;     // bytes including header, multiple of PAGE
    struct lfree *prev, *next;
} lfree_t;

static uint8_t *g_base, *g_end, *g_bump;
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_once_t g_once = PTHREAD_ONCE_INIT;

#define NCLASS 48
static uint32_t g_cls_size[NCLASS];
static int g_ncls;
static void *g_free_small[NCLASS];
static lfree_t *g_free_large;

static void init_arena(void) {
    // Size classes: 16..128 step 16, then 4 steps per power of two up to SMALL_MAX.
    int n = 0;
    for (uint32_t s = 16; s <= 128; s += 16) g_cls_size[n++] = s;
    for (uint32_t p = 128; p < SMALL_MAX; p *= 2)
        for (int k = 1; k <= 4; k++) g_cls_size[n++] = p + p / 4 * k;
    g_ncls = n;

    void *m = mmap(NULL, ARENA_SIZE, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
    if (m == MAP_FAILED) {
        LOGW("arena mmap failed, falling back to libc malloc");
        return;
    }
    g_base = g_bump = (uint8_t *)m;
    g_end = g_base + ARENA_SIZE;
    LOGI("arena %p-%p (%zu MB), %d size classes", g_base, g_end, ARENA_SIZE >> 20, g_ncls);
}

static inline int in_arena(const void *p) {
    return g_base && (const uint8_t *)p >= g_base && (const uint8_t *)p < g_end;
}

static int class_of(size_t n) {
    int lo = 0, hi = g_ncls - 1;
    while (lo < hi) {
        int mid = (lo + hi) / 2;
        if (g_cls_size[mid] >= n) hi = mid; else lo = mid + 1;
    }
    return lo;
}

static void *bump(size_t total) {
    if ((size_t)(g_end - g_bump) < total) return NULL;
    void *p = g_bump;
    g_bump += total;
    return p;
}

static void large_insert(lfree_t *b) {
    lfree_t *prev = NULL, *cur = g_free_large;
    while (cur && cur < b) { prev = cur; cur = cur->next; }
    b->prev = prev; b->next = cur;
    if (prev) prev->next = b; else g_free_large = b;
    if (cur) cur->prev = b;
    // Coalesce with the following and preceding neighbours.
    if (cur && (uint8_t *)b + b->total == (uint8_t *)cur) {
        b->total += cur->total;
        b->next = cur->next;
        if (cur->next) cur->next->prev = b;
    }
    if (prev && (uint8_t *)prev + prev->total == (uint8_t *)b) {
        prev->total += b->total;
        prev->next = b->next;
        if (b->next) b->next->prev = prev;
    }
}

static void large_unlink(lfree_t *b) {
    if (b->prev) b->prev->next = b->next; else g_free_large = b->next;
    if (b->next) b->next->prev = b->prev;
}

// Caller holds g_lock. Returns payload or NULL when the arena is exhausted.
static void *arena_alloc(size_t n) {
    if (n == 0) n = 1;
    if (n <= SMALL_MAX) {
        int c = class_of(n);
        hdr_t *h;
        if (g_free_small[c]) {
            h = (hdr_t *)((uint8_t *)g_free_small[c] - HDR);
            g_free_small[c] = *(void **)g_free_small[c];
        } else {
            h = bump(HDR + g_cls_size[c]);
            if (!h) return NULL;
        }
        h->magic = MAGIC_SMALL; h->cls = c; h->cap = g_cls_size[c];
        return (uint8_t *)h + HDR;
    }
    if (n > ARENA_SIZE) return NULL;
    size_t total = (n + HDR + PAGE - 1) & ~(size_t)(PAGE - 1);
    hdr_t *h = NULL;
    for (lfree_t *b = g_free_large; b; b = b->next) {
        if (b->total < total) continue;
        large_unlink(b);
        if (b->total - total >= PAGE) {
            lfree_t *rest = (lfree_t *)((uint8_t *)b + total);
            rest->total = b->total - total;
            large_insert(rest);
        } else {
            total = b->total;
        }
        h = (hdr_t *)b;
        break;
    }
    if (!h) {
        // Keep large blocks page aligned so they can be split and returned to the OS.
        size_t pad = (PAGE - ((uintptr_t)g_bump & (PAGE - 1))) & (PAGE - 1);
        if (pad) {
            if ((size_t)(g_end - g_bump) < pad) return NULL;
            g_bump += pad;  // wasted, at most one page per bump allocation
        }
        h = bump(total);
        if (!h) return NULL;
    }
    h->magic = MAGIC_LARGE; h->cls = 0; h->cap = total - HDR;
    return (uint8_t *)h + HDR;
}

static void arena_free(void *p) {
    hdr_t *h = (hdr_t *)((uint8_t *)p - HDR);
    if (h->magic == MAGIC_SMALL) {
        h->magic = MAGIC_FREE;
        *(void **)p = g_free_small[h->cls];
        g_free_small[h->cls] = p;
    } else if (h->magic == MAGIC_LARGE) {
        size_t total = h->cap + HDR;
        // Give the RAM back but keep the address range reserved.
        if (total > PAGE) madvise((uint8_t *)h + PAGE, total - PAGE, MADV_DONTNEED);
        lfree_t *b = (lfree_t *)h;
        b->total = total;
        large_insert(b);
    } else {
        LOGW("free of unknown/double-freed pointer %p ignored", p);
    }
}

__attribute__((visibility("default"))) void *smfix_malloc(size_t n) {
    pthread_once(&g_once, init_arena);
    void *p = NULL;
    if (g_base) {
        pthread_mutex_lock(&g_lock);
        p = arena_alloc(n);
        pthread_mutex_unlock(&g_lock);
    }
    return p ? p : malloc(n);
}

__attribute__((visibility("default"))) void smfix_free(void *p) {
    if (!p) return;
    if (!in_arena(p)) { free(p); return; }
    pthread_mutex_lock(&g_lock);
    arena_free(p);
    pthread_mutex_unlock(&g_lock);
}

__attribute__((visibility("default"))) void *smfix_calloc(size_t a, size_t b) {
    size_t n;
    if (__builtin_mul_overflow(a, b, &n)) return NULL;
    void *p = smfix_malloc(n);
    if (p) memset(p, 0, n);
    return p;
}

__attribute__((visibility("default"))) void *smfix_realloc(void *p, size_t n) {
    if (!p) return smfix_malloc(n);
    if (!in_arena(p)) return realloc(p, n);
    if (n == 0) { smfix_free(p); return NULL; }
    hdr_t *h = (hdr_t *)((uint8_t *)p - HDR);
    size_t cap = h->cap;
    if (n <= cap) return p;
    void *q = smfix_malloc(n);
    if (!q) return NULL;
    memcpy(q, p, cap);
    smfix_free(p);
    return q;
}
