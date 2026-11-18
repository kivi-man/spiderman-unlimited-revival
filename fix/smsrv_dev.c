// Development endpoints of the fake server, enabled by files/smfix_dev. Reach them from the
// PC with `adb forward tcp:<p> tcp:<server port>` (the port is in logcat, tag smfix):
//   GET /__mem/<hex offset>/<hex len>   hex dump of libSpidermanI memory at base + offset
//   GET /__str/<hex offset>             the libc++ std::string stored at base + offset
// Offsets are in the patched library (original + 0x1000).

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "smcommon.h"
#include "smsrv.h"

// libc++ std::string (arm64): short if the first byte's low bit is 0 (size = byte >> 1, data
// at +1); otherwise long: size at +8, data pointer at +16.
static const char *std_string(const uint8_t *s, size_t *len) {
    if (!(s[0] & 1)) {
        *len = s[0] >> 1;
        return (const char *)s + 1;
    }
    *len = *(const size_t *)(s + 8);
    return *(const char *const *)(s + 16);
}

int sm_route_dev(const sm_req *q, sm_resp *r) {
    if (strncmp(q->path, "/__", 3) != 0) return 0;
    if (access(SM_FILES_DIR "/smfix_dev", F_OK) != 0) return 0;
    uintptr_t base = sm_game_base();
    unsigned long off = 0, len = 0;
    if (sscanf(q->path, "/__mem/%lx/%lx", &off, &len) == 2 && len <= 0x10000) {
        const uint8_t *p = (const uint8_t *)(base + off);
        char *out = malloc(len * 2 + 1);
        for (unsigned long i = 0; i < len; i++) sprintf(out + i * 2, "%02x", p[i]);
        sm_resp_set(r, 200, "text/plain", out, len * 2);
        free(out);
        return 1;
    }
    if (sscanf(q->path, "/__str/%lx", &off) == 1) {
        size_t n;
        const char *s = std_string((const uint8_t *)(base + off), &n);
        sm_resp_set(r, 200, "text/plain", s, n);
        return 1;
    }
    sm_resp_json(r, 404, "{\"error\":\"bad dev request\"}");
    return 1;
}
