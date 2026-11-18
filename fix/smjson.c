// smjson: trace which JSON keys the game reads (debug, files/smfix_jsontrace), part of
// libsmfix.so. Hooks the game's JsonCpp lookups:
//   0x126d48c  Value::find(const char *key)               (const operator[], isMember)
//   0x126d1d4  Value::resolveReference(const char *key, bool) (operator[])
// Each new (key, caller) pair is logged once to the net log as "JSON-KEY key @caller", where
// caller is the original-library offset of the code that asked (looked up through the
// one-instruction wrappers), so response fields can be mapped to their handlers.

#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "smcommon.h"

#define JSON_FIND_OFF    SM_OFF(0x126d48c)
#define JSON_RESOLVE_OFF SM_OFF(0x126d1d4)
//   stp x23, x22, [sp, #-0x30]! ; stp x21, x20, [sp, #0x10] ; stp x19, x30, [sp, #0x20] ;
//   ldrb w8, [x0, #8]
static const uint32_t kFindProlog[4] = {0xa9bd5bf7, 0xa90153f5, 0xa9027bf3, 0x39402008};
//   sub sp, sp, #0x60 ; str x24, [sp, #0x20] ; stp x23, x22, [sp, #0x30] ; stp x21, x20, [sp, #0x40]
static const uint32_t kResolveProlog[4] = {0xd10183ff, 0xf90013f8, 0xa9035bf7, 0xa90453f5};

uintptr_t smjson_find_resume, smjson_resolve_resume;

static uint64_t g_seen[1 << 16];

// lr: return address into the caller; sp: caller stack (wrappers keep their caller's LR at [sp]).
__attribute__((visibility("hidden"))) void smjson_on_key(const char *key, uintptr_t lr, uintptr_t *sp) {
    if (!key) return;
    uintptr_t base = sm_game_base();
    uintptr_t caller = lr;
    // operator[](std::string) / isMember wrappers are 7-12 instructions long; report their caller.
    if (lr - base - 0x1000 >= 0x126d1c0 && lr - base - 0x1000 < 0x126dc40) caller = sp[0];
    uint64_t h = 1469598103934665603ull;
    for (const char *p = key; *p; p++) h = (h ^ (uint8_t)*p) * 1099511628211ull;
    h ^= caller * 0x9E3779B97F4A7C15ull;
    if (!h) h = 1;
    for (uint32_t i = (uint32_t)h & 0xffff;; i = (i + 1) & 0xffff) {
        if (g_seen[i] == h) return;
        if (!g_seen[i]) {
            g_seen[i] = h;  // races only cause a duplicate line
            break;
        }
    }
    char line[300];
    int n = snprintf(line, sizeof(line), "%.200s @%lx", key,
                     (unsigned long)(caller - base - 0x1000));
    sm_net_log("JSON-KEY", NULL, line, n);
}

#define SAVE_AND_CALL                       \
    "stp x29, x30, [sp, #-0x60]!\n"         \
    "stp x0, x1, [sp, #0x10]\n"             \
    "stp x2, x3, [sp, #0x20]\n"             \
    "stp x4, x5, [sp, #0x30]\n"             \
    "stp x6, x7, [sp, #0x40]\n"             \
    "str x8, [sp, #0x50]\n"                 \
    "mov x0, x1\n"                          \
    "mov x1, x30\n"                         \
    "add x2, sp, #0x60\n"                   \
    "bl smjson_on_key\n"                    \
    "ldp x0, x1, [sp, #0x10]\n"             \
    "ldp x2, x3, [sp, #0x20]\n"             \
    "ldp x4, x5, [sp, #0x30]\n"             \
    "ldp x6, x7, [sp, #0x40]\n"             \
    "ldr x8, [sp, #0x50]\n"                 \
    "ldp x29, x30, [sp], #0x60\n"

__attribute__((naked)) static void find_stub(void) {
    __asm__ volatile(SAVE_AND_CALL
                     "stp x23, x22, [sp, #-0x30]!\n"
                     "stp x21, x20, [sp, #0x10]\n"
                     "stp x19, x30, [sp, #0x20]\n"
                     "ldrb w8, [x0, #8]\n"
                     "adrp x16, smjson_find_resume\n"
                     "ldr x16, [x16, :lo12:smjson_find_resume]\n"
                     "br x16\n");
}

__attribute__((naked)) static void resolve_stub(void) {
    __asm__ volatile(SAVE_AND_CALL
                     "sub sp, sp, #0x60\n"
                     "str x24, [sp, #0x20]\n"
                     "stp x23, x22, [sp, #0x30]\n"
                     "stp x21, x20, [sp, #0x40]\n"
                     "adrp x16, smjson_resolve_resume\n"
                     "ldr x16, [x16, :lo12:smjson_resolve_resume]\n"
                     "br x16\n");
}

__attribute__((constructor)) static void smjson_init(void) {
    if (access(SM_FILES_DIR "/smfix_jsontrace", F_OK) != 0) return;
    uintptr_t base = sm_game_base();
    if (!base) return;
    smjson_find_resume = base + JSON_FIND_OFF + 16;
    smjson_resolve_resume = base + JSON_RESOLVE_OFF + 16;
    if (sm_hook4(base + JSON_FIND_OFF, kFindProlog, (void *)find_stub) != 0 ||
        sm_hook4(base + JSON_RESOLVE_OFF, kResolveProlog, (void *)resolve_stub) != 0)
        SM_LOGW("json: could not hook JsonCpp lookups");
    else
        SM_LOGI("json: tracing JSON key lookups");
}
