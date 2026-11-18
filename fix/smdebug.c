// smdebug: test-only helpers for libSpidermanI.so (arm64 4.6.0c), part of libsmfix.so.
//
// If files/smfix_dump exists in the app's private dir, the game's XXTEA encrypt function
// (used for player.dat and other saves) is hooked and every call writes its 16-byte key and
// plaintext to files/smfix_dump_<n>_<len>.bin, so saves can be decrypted and edited offline.
// The decrypt function is hooked too: files/smfix_dec_<n>_<len>.bin = 16-byte key + ciphertext.

#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

#include "smcommon.h"

#define XXTEA_ENC_OFF SM_OFF(0x11a753c)
// First four instructions of the encrypt function, replayed by the hook stub:
//   str x22, [sp, #-0x30]! ; stp x21, x20, [sp, #0x10] ; stp x19, x30, [sp, #0x20] ; mov x21, x1
static const uint32_t kXxteaProlog[4] = {0xf81d0ff6, 0xa90153f5, 0xa9027bf3, 0xaa0103f5};

uintptr_t smdebug_xxtea_resume;  // XXTEA_ENC_OFF + 16 in the loaded library

static int g_dump_count;

static void write_file(const char *path, const void *a, size_t alen, const void *b, size_t blen) {
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) return;
    if (write(fd, a, alen) < 0 || write(fd, b, blen) < 0) SM_LOGW("short write %s", path);
    close(fd);
}

// Called from the hook stub with the encrypt function's arguments.
__attribute__((visibility("hidden"))) void smdebug_on_xxtea(const void *data, size_t len,
                                                            void *out, size_t cap, const void *key) {
    (void)out; (void)cap;
    char path[160];
    snprintf(path, sizeof(path), SM_FILES_DIR "/smfix_dump_%03d_%zu.bin", g_dump_count++, len);
    write_file(path, key, 16, data, len);  // file = 16-byte key + plaintext
    SM_LOGI("xxtea encrypt %zu bytes -> %s", len, path);
}

// Saves the argument registers, calls smdebug_on_xxtea, replays the overwritten prolog and
// continues in the original function.
__attribute__((naked)) static void xxtea_hook_stub(void) {
    __asm__ volatile(
        "stp x29, x30, [sp, #-0x60]!\n"
        "stp x0, x1, [sp, #0x10]\n"
        "stp x2, x3, [sp, #0x20]\n"
        "stp x4, x5, [sp, #0x30]\n"
        "stp x6, x7, [sp, #0x40]\n"
        "str x8, [sp, #0x50]\n"
        "bl smdebug_on_xxtea\n"
        "ldp x0, x1, [sp, #0x10]\n"
        "ldp x2, x3, [sp, #0x20]\n"
        "ldp x4, x5, [sp, #0x30]\n"
        "ldp x6, x7, [sp, #0x40]\n"
        "ldr x8, [sp, #0x50]\n"
        "ldp x29, x30, [sp], #0x60\n"
        "str x22, [sp, #-0x30]!\n"
        "stp x21, x20, [sp, #0x10]\n"
        "stp x19, x30, [sp, #0x20]\n"
        "mov x21, x1\n"
        "adrp x16, smdebug_xxtea_resume\n"
        "ldr x16, [x16, :lo12:smdebug_xxtea_resume]\n"
        "br x16\n");
}

#define XXTEA_DEC_OFF SM_OFF(0x11a76f4)
//   stp x21, x20, [sp, #-0x20]! ; stp x19, x30, [sp, #0x10] ; mov x8, x1 ; mov x19, x4
static const uint32_t kXxteaDecProlog[4] = {0xa9be53f5, 0xa9017bf3, 0xaa0103e8, 0xaa0403f3};
uintptr_t smdebug_xxtea_dec_resume;
static int g_dec_count;

__attribute__((visibility("hidden"))) void smdebug_on_xxtea_dec(const void *data, size_t len,
                                                                void *out, size_t cap, const void *key) {
    (void)out; (void)cap;
    char path[160];
    snprintf(path, sizeof(path), SM_FILES_DIR "/smfix_dec_%03d_%zu.bin", g_dec_count++, len);
    write_file(path, key, 16, data, len);  // file = 16-byte key + ciphertext
}

__attribute__((naked)) static void xxtea_dec_stub(void) {
    __asm__ volatile(
        "stp x29, x30, [sp, #-0x60]!\n"
        "stp x0, x1, [sp, #0x10]\n"
        "stp x2, x3, [sp, #0x20]\n"
        "stp x4, x5, [sp, #0x30]\n"
        "stp x6, x7, [sp, #0x40]\n"
        "str x8, [sp, #0x50]\n"
        "bl smdebug_on_xxtea_dec\n"
        "ldp x0, x1, [sp, #0x10]\n"
        "ldp x2, x3, [sp, #0x20]\n"
        "ldp x4, x5, [sp, #0x30]\n"
        "ldp x6, x7, [sp, #0x40]\n"
        "ldr x8, [sp, #0x50]\n"
        "ldp x29, x30, [sp], #0x60\n"
        "stp x21, x20, [sp, #-0x20]!\n"
        "stp x19, x30, [sp, #0x10]\n"
        "mov x8, x1\n"
        "mov x19, x4\n"
        "adrp x16, smdebug_xxtea_dec_resume\n"
        "ldr x16, [x16, :lo12:smdebug_xxtea_dec_resume]\n"
        "br x16\n");
}

// ---- EVP_CipherInit_ex logging (files/smfix_net): cipher nid, key and IV of every init.
#define EVP_CIPHERINIT_OFF SM_OFF(0x12a1b40)
//   stp x25, x24, [sp, #-0x40]! ; stp x23, x22, [sp, #0x10] ; stp x21, x20, [sp, #0x20] ;
//   stp x19, x30, [sp, #0x30]
static const uint32_t kEvpInitProlog[4] = {0xa9bc63f9, 0xa9015bf7, 0xa90253f5, 0xa9037bf3};
uintptr_t smdebug_evp_resume;

// OpenSSL 1.0.2 EVP_CIPHER starts with: int nid, block_size, key_len, iv_len.
__attribute__((visibility("hidden"))) void smdebug_on_evp_init(void *ctx, const int *cipher,
                                                               void *impl, const uint8_t *key,
                                                               const uint8_t *iv, int enc) {
    (void)impl;
    char line[512];
    int n = snprintf(line, sizeof(line), "ctx=%p nid=%d block=%d keylen=%d ivlen=%d enc=%d key=",
                     ctx, cipher ? cipher[0] : -1, cipher ? cipher[1] : -1,
                     cipher ? cipher[2] : -1, cipher ? cipher[3] : -1, enc);
    int klen = cipher && key ? cipher[2] : 0, ilen = cipher && iv ? cipher[3] : 0;
    for (int i = 0; i < klen && i < 64 && n < 480; i++) n += snprintf(line + n, sizeof(line) - n, "%02x", key[i]);
    n += snprintf(line + n, sizeof(line) - n, " iv=");
    for (int i = 0; i < ilen && i < 32 && n < 500; i++) n += snprintf(line + n, sizeof(line) - n, "%02x", iv[i]);
    sm_net_log("EVP-INIT", NULL, line, n);
}

__attribute__((naked)) static void evp_hook_stub(void) {
    __asm__ volatile(
        "stp x29, x30, [sp, #-0x60]!\n"
        "stp x0, x1, [sp, #0x10]\n"
        "stp x2, x3, [sp, #0x20]\n"
        "stp x4, x5, [sp, #0x30]\n"
        "stp x6, x7, [sp, #0x40]\n"
        "bl smdebug_on_evp_init\n"
        "ldp x0, x1, [sp, #0x10]\n"
        "ldp x2, x3, [sp, #0x20]\n"
        "ldp x4, x5, [sp, #0x30]\n"
        "ldp x6, x7, [sp, #0x40]\n"
        "ldp x29, x30, [sp], #0x60\n"
        "stp x25, x24, [sp, #-0x40]!\n"
        "stp x23, x22, [sp, #0x10]\n"
        "stp x21, x20, [sp, #0x20]\n"
        "stp x19, x30, [sp, #0x30]\n"
        "adrp x16, smdebug_evp_resume\n"
        "ldr x16, [x16, :lo12:smdebug_evp_resume]\n"
        "br x16\n");
}

// ---- BF_set_key logging (files/smfix_net): Blowfish keys (game API request encryption).
#define BF_SET_KEY_OFF SM_OFF(0x12f541c)
//   sub sp, sp, #0x30 ; stp x21, x20, [sp, #0x10] ; stp x19, x30, [sp, #0x20] ; mov w21, w1
static const uint32_t kBfProlog[4] = {0xd100c3ff, 0xa90153f5, 0xa9027bf3, 0x2a0103f5};
uintptr_t smdebug_bf_resume;

__attribute__((visibility("hidden"))) void smdebug_on_bf_key(void *key, int len, const uint8_t *data) {
    char line[300];
    int n = snprintf(line, sizeof(line), "bfkey=%p len=%d data=", key, len);
    for (int i = 0; i < len && i < 72 && n < 290; i++) n += snprintf(line + n, sizeof(line) - n, "%02x", data[i]);
    sm_net_log("BF-KEY", NULL, line, n);
}

__attribute__((naked)) static void bf_hook_stub(void) {
    __asm__ volatile(
        "stp x29, x30, [sp, #-0x40]!\n"
        "stp x0, x1, [sp, #0x10]\n"
        "stp x2, x3, [sp, #0x20]\n"
        "bl smdebug_on_bf_key\n"
        "ldp x0, x1, [sp, #0x10]\n"
        "ldp x2, x3, [sp, #0x20]\n"
        "ldp x29, x30, [sp], #0x40\n"
        "sub sp, sp, #0x30\n"
        "stp x21, x20, [sp, #0x10]\n"
        "stp x19, x30, [sp, #0x20]\n"
        "mov w21, w1\n"
        "adrp x16, smdebug_bf_resume\n"
        "ldr x16, [x16, :lo12:smdebug_bf_resume]\n"
        "br x16\n");
}

__attribute__((constructor)) static void smdebug_bf_init(void) {
    if (access(SM_FILES_DIR "/smfix_net", F_OK) != 0) return;
    uintptr_t base = sm_game_base();
    if (!base) return;
    uintptr_t target = base + BF_SET_KEY_OFF;
    smdebug_bf_resume = target + 16;
    if (sm_hook4(target, kBfProlog, (void *)bf_hook_stub) != 0)
        SM_LOGW("dump: could not hook BF_set_key");
}

__attribute__((constructor)) static void smdebug_evp_init(void) {
    if (access(SM_FILES_DIR "/smfix_net", F_OK) != 0) return;
    uintptr_t base = sm_game_base();
    if (!base) return;
    uintptr_t target = base + EVP_CIPHERINIT_OFF;
    smdebug_evp_resume = target + 16;
    if (sm_hook4(target, kEvpInitProlog, (void *)evp_hook_stub) != 0)
        SM_LOGW("dump: could not hook EVP_CipherInit_ex");
}

__attribute__((constructor)) static void smdebug_init(void) {
    if (access(SM_FILES_DIR "/smfix_dump", F_OK) != 0) return;
    uintptr_t base = sm_game_base();
    if (!base) {
        SM_LOGW("dump: libSpidermanI.so not found");
        return;
    }
    uintptr_t target = base + XXTEA_ENC_OFF;
    smdebug_xxtea_resume = target + 16;
    if (sm_hook4(target, kXxteaProlog, (void *)xxtea_hook_stub) != 0) {
        SM_LOGW("dump: could not hook xxtea encrypt");
        return;
    }
    SM_LOGI("dump: hooked xxtea encrypt at %p", (void *)target);
    smdebug_xxtea_dec_resume = base + XXTEA_DEC_OFF + 16;
    if (sm_hook4(base + XXTEA_DEC_OFF, kXxteaDecProlog, (void *)xxtea_dec_stub) != 0)
        SM_LOGW("dump: could not hook xxtea decrypt");
}
