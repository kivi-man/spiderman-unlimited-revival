#include "smcommon.h"

#include <link.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

static uintptr_t g_base;

static int find_game(struct dl_phdr_info *info, size_t size, void *data) {
    (void)size; (void)data;
    const char *name = info->dlpi_name;
    size_t n = name ? strlen(name) : 0;
    if (n >= 16 && strcmp(name + n - 16, "libSpidermanI.so") == 0) {
        g_base = info->dlpi_addr;
        return 1;
    }
    return 0;
}

uintptr_t sm_game_base(void) {
    if (!g_base) dl_iterate_phdr(find_game, NULL);
    return g_base;
}

int sm_patch_code(uintptr_t addr, const uint32_t *insns, size_t count) {
    uintptr_t psz = (uintptr_t)sysconf(_SC_PAGESIZE);  // 4 KB or 16 KB depending on device
    uintptr_t page = addr & ~(psz - 1);
    size_t len = (addr + count * 4 - page + psz - 1) & ~(psz - 1);
    if (mprotect((void *)page, len, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) return -1;
    memcpy((void *)addr, insns, count * 4);
    __builtin___clear_cache((char *)addr, (char *)addr + count * 4);
    mprotect((void *)page, len, PROT_READ | PROT_EXEC);
    return 0;
}

int sm_hook4(uintptr_t addr, const uint32_t expect[4], void *dest) {
    if (memcmp((void *)addr, expect, 16) != 0) return -1;
    uint64_t d = (uint64_t)(uintptr_t)dest;
    uint32_t tramp[4] = {0x58000050, 0xd61f0200, (uint32_t)d, (uint32_t)(d >> 32)};
    return sm_patch_code(addr, tramp, 4);
}
