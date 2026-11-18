// Shared helpers for libsmfix.so hooks into libSpidermanI.so (arm64 4.6.0c).
#pragma once

#include <android/log.h>
#include <stddef.h>
#include <stdint.h>

#define SM_TAG "smfix"
#define SM_LOGI(...) __android_log_print(ANDROID_LOG_INFO, SM_TAG, __VA_ARGS__)
#define SM_LOGW(...) __android_log_print(ANDROID_LOG_WARN, SM_TAG, __VA_ARGS__)

#define SM_FILES_DIR "/data/data/com.gameloft.android.ANMP.GloftSIHM/files"

// Host name the rewritten URLs use. smfix_gethostbyname/getaddrinfo resolve it to SM_FAKE_IP
// (198.18.77.77, network order) because the game's curl refuses loopback and private
// addresses; smfix_connect sends connections to SM_FAKE_IP to 127.0.0.1 instead.
#define SM_FAKE_HOST   "smfix.local"
#define SM_FAKE_IP     0x4d4d12c6u
#define SM_FAKE_IP_STR "198.18.77.77"

// Offsets are for the LIEF-patched library: original address + 0x1000 (build_native.sh checks).
#define SM_OFF(orig) ((uintptr_t)(orig) + 0x1000)

// Load address of libSpidermanI.so, 0 if not loaded yet.
uintptr_t sm_game_base(void);

// Overwrite `count` instructions at `addr` (makes the page writable, flushes the icache).
int sm_patch_code(uintptr_t addr, const uint32_t *insns, size_t count);

// Replace the 4 instructions at `addr` with `ldr x16, #8; br x16; .quad dest` after checking
// that they match `expect`. The caller's stub must replay `expect` and resume at addr + 16.
int sm_hook4(uintptr_t addr, const uint32_t expect[4], void *dest);

// Log to files/smfix_net.log (no-op unless network logging is on).
void sm_net_log(const char *kind, const void *ctx, const void *data, long len);
