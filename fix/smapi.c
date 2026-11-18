// smapi: the game's own API (game_portal .../mrmeesyncs/2009/api/...), part of libsmfix.so.
//
// Requests are form posts "encrypt=&params=<urlenc(base64(XTEA(json)))>" (see api_crypto.py);
// responses are plain JSON objects with at least {"success":1,"srequestID":"<echo>"}
// ("success" must be an integer: the game ignores a boolean).

#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "smcommon.h"
#include "smsrv.h"

static const uint32_t kXteaKey[4] = {2524, 9534, 4591, 7218};  // 0x1af30b0 in the game

static void xtea_decrypt(uint32_t v[2]) {
    uint32_t v0 = v[0], v1 = v[1], sum = 0x9E3779B9u * 32;
    for (int i = 0; i < 32; i++) {
        v1 -= (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + kXteaKey[(sum >> 11) & 3]);
        sum -= 0x9E3779B9u;
        v0 -= (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + kXteaKey[sum & 3]);
    }
    v[0] = v0;
    v[1] = v1;
}

static int hexval(int c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static size_t url_decode(const char *in, size_t n, char *out) {
    size_t o = 0;
    for (size_t i = 0; i < n; i++) {
        if (in[i] == '%' && i + 2 < n + 1 && hexval(in[i + 1]) >= 0 && hexval(in[i + 2]) >= 0) {
            out[o++] = (char)(hexval(in[i + 1]) * 16 + hexval(in[i + 2]));
            i += 2;
        } else {
            out[o++] = in[i] == '+' ? ' ' : in[i];
        }
    }
    return o;
}

static int b64val(int c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+' || c == '-') return 62;
    if (c == '/' || c == '_') return 63;
    return -1;
}

static size_t b64_decode(const char *in, size_t n, uint8_t *out) {
    uint32_t acc = 0;
    int bits = 0;
    size_t o = 0;
    for (size_t i = 0; i < n; i++) {
        int v = b64val((unsigned char)in[i]);
        if (v < 0) continue;
        acc = (acc << 6) | (uint32_t)v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out[o++] = (uint8_t)(acc >> bits);
        }
    }
    return o;
}

char *sm_api_decode(const sm_req *q) {
    const char *p = strstr(q->body, "params=");
    if (!p) return NULL;
    p += 7;
    const char *e = strchr(p, '&');
    size_t n = e ? (size_t)(e - p) : strlen(p);
    char *b64 = malloc(n + 1);
    size_t bn = url_decode(p, n, b64);
    uint8_t *raw = malloc(bn + 8);
    size_t rn = b64_decode(b64, bn, raw) & ~(size_t)7;
    free(b64);
    for (size_t i = 0; i < rn; i += 8) {
        uint32_t v[2];
        memcpy(v, raw + i, 8);
        xtea_decrypt(v);
        memcpy(raw + i, v, 8);
    }
    raw[rn] = 0;  // zero padding terminates the JSON
    return (char *)raw;
}

// Copies the string value of "key" from a flat JSON text (no unescaping).
int sm_json_str(const char *json, const char *key, char *out, size_t outlen) {
    char pat[128];
    snprintf(pat, sizeof(pat), "\"%s\":", key);
    const char *p = json ? strstr(json, pat) : NULL;
    if (!p) return 0;
    p += strlen(pat);
    while (*p == ' ') p++;
    if (*p == '"') {
        const char *e = strchr(p + 1, '"');
        if (!e) return 0;
        snprintf(out, outlen, "%.*s", (int)(e - p - 1), p + 1);
    } else {
        size_t k = strcspn(p, ",}]");
        snprintf(out, outlen, "%.*s", (int)k, p);
    }
    return 1;
}

// ---------------------------------------------------------------- portals (gacha)

#define GAMEDATA_PATH "/sdcard/Android/data/com.gameloft.android.ANMP.GloftSIHM/files/GameData.json"

static char *read_file(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *buf = malloc(n + 1);
    size_t got = fread(buf, 1, n, f);
    fclose(f);
    buf[got] = 0;
    return buf;
}

// Picks a reward for `portal` from GameData.json, whose portals look like
//   {"Name": "Portal_Premium_00", ..., "RewardObject": [[["Costume_X_R1:50", 20.0], ...]]}
// Writes the item ("Costume_X_R1") and the number after ':' (count) into out/count.
static int pick_portal_reward(const char *portal, char *out, size_t outlen, int *count) {
    char *gd = read_file(GAMEDATA_PATH);
    if (!gd) return 0;
    char pat[128];
    snprintf(pat, sizeof(pat), "\"%s\"", portal);
    char *p = strstr(gd, pat);
    char *ro = p ? strstr(p, "\"RewardObject\"") : NULL;
    int ok = 0;
    if (ro && (ro = strchr(ro, '['))) {
        // Entries are ["<item>:<count>", <weight>] pairs anywhere inside the nested arrays.
        // First pass: total weight; second pass: pick.
        double total = 0, pickw = 0;
        for (int pass = 0; pass < 2 && !ok; pass++) {
            if (pass == 1) pickw = total * ((double)rand() / ((double)RAND_MAX + 1));
            double acc = 0;
            int depth = 0;
            for (char *c = ro; *c; c++) {
                if (*c == '[') depth++;
                else if (*c == ']' && --depth == 0) break;
                else if (*c == '"') {
                    char *e = strchr(c + 1, '"');
                    if (!e) break;
                    char item[128];
                    snprintf(item, sizeof(item), "%.*s", (int)(e - c - 1), c + 1);
                    char *n = e + 1;
                    while (*n == ' ' || *n == '\n' || *n == '\r' || *n == '\t' || *n == ',') n++;
                    double w = strtod(n, NULL);
                    c = e;
                    if (pass == 0) { total += w; continue; }
                    acc += w;
                    if (acc > pickw) {
                        char *colon = strchr(item, ':');
                        *count = colon ? atoi(colon + 1) : 1;
                        if (colon) *colon = 0;
                        snprintf(out, outlen, "%s", item);
                        ok = 1;
                        break;
                    }
                }
            }
        }
    }
    free(gd);
    return ok;
}

// Base power of a new costume: Ranks[Rarity - 1].RankPower[0] for the costume's Rarity.
static float costume_base_power(const char *item) {
    char *gd = read_file(GAMEDATA_PATH);
    if (!gd) return 2.0f;
    float power = 2.0f;
    char pat[160];
    snprintf(pat, sizeof(pat), "\"Name\": \"%s\"", item);
    char *p = strstr(gd, pat);
    char *r = p ? strstr(p, "\"Rarity\":") : NULL;
    int rarity = r ? atoi(r + 9) : 0;
    char *rp = strstr(gd, "\"Ranks\"");
    for (int i = 0; rp && i < rarity; i++) rp = strstr(rp + 1, "\"RankPower\"");
    if (rp && rarity > 0 && (rp = strchr(rp, '['))) power = strtof(rp + 1, NULL);
    free(gd);
    return power;
}

// ---------------------------------------------------------------- granting recruited costumes
//
// The game does not add OpenPortal rewards to the inventory itself: the server owned the item
// list and the game applies such a list with its item-list handler 0x60e524
// (Inventory, const std::string &"name:cards:rank:time:power[:timer],..."), which replaces the
// whole list. So OpenPortal queues its reward here, and a hook at the end of the OpenPortal
// response handler (0x2f4f20, game thread, after the reveal animation has been set up) rebuilds
// the list from the current items plus the new costumes. Granting any earlier makes the
// processedRewards handler see the costume as owned: it then shows a "required spider" popup
// instead of the reveal animation.

#define PORTAL_END_OFF SM_OFF(0x2f4f20)
#define GET_INV_OFF    SM_OFF(0x2f79b8)   // Inventory *()
#define SET_ITEMS_OFF  SM_OFF(0x60e524)   // void (Inventory *, const std::string &)
#define DEF_TIMER_OFF  SM_OFF(0x7e2ffc)   // int (CostumeDef *), base of an item's timer field
//   bl 0x2caf28 ; ldr x0, [x0, #0x140] ; bl 0x63d2dc ; bl 0x2caf28   (no live scratch registers)
static const uint32_t kPortalEnd[4] = {0x97ff5802, 0xf940a000, 0x940d20ed, 0x97ff57ff};

uintptr_t smapi_portal_resume, smapi_fn_2caf28, smapi_fn_63d2dc;

// Inventory changes waiting for the game thread: a recruited costume (new, or `cards` more
// copies of an owned one), or a rank up costing `cost` coins (vials).
typedef struct {
    char name[128];
    int cards;
    int rankup, cost;
} sm_change;

typedef struct {
    pthread_mutex_t lock;
    sm_change c[8];
    int n;
} sm_queue;

static sm_queue g_recruits = {.lock = PTHREAD_MUTEX_INITIALIZER};  // applied after OpenPortal
static sm_queue g_rankups = {.lock = PTHREAD_MUTEX_INITIALIZER};   // applied with the next response

static void queue_change(sm_queue *q, const char *item, int cards, int rankup, int cost) {
    pthread_mutex_lock(&q->lock);
    if (q->n < 8) {
        sm_change *c = &q->c[q->n++];
        snprintf(c->name, sizeof(c->name), "%s", item);
        c->cards = cards, c->rankup = rankup, c->cost = cost;
    }
    pthread_mutex_unlock(&q->lock);
}

// libc++ std::string contents.
static const char *cxx_str(const uint8_t *s, size_t *len) {
    if (s[0] & 1) {
        *len = *(const size_t *)(s + 8);
        return *(char *const *)(s + 16);
    }
    *len = s[0] >> 1;
    return (const char *)s + 1;
}

static void append(char **buf, size_t *len, size_t *cap, const char *s, size_t n) {
    if (*len + n + 1 > *cap) {
        *cap = (*len + n + 1) * 2;
        *buf = realloc(*buf, *cap);
    }
    memcpy(*buf + *len, s, n);
    *len += n;
    (*buf)[*len] = 0;
}

static void smapi_charge_portal(uintptr_t base);

#define GAME_PTR_GOT SM_OFF(0x1b0ed90)  // GOT slot of the global the game reads at 0x2cb4a8

// Profile: *(*(game global) + 0x150) + 0xaa0, as 0x2cb4a8 / 0x70224c read it.
static uint8_t *profile_ptr(uintptr_t base) {
    uint8_t *g = *(uint8_t **)(base + GAME_PTR_GOT);
    uint8_t *game = g ? *(uint8_t **)(g + 0x150) : NULL;
    return game ? *(uint8_t **)(game + 0xaa0) : NULL;
}

// ---------------------------------------------------------------- spider power
//
// The team's spider power is Profile._inventoryPower: the summed power of the owned costumes
// per rarity (floats at Profile +0xd8: Common, Uncommon, Rare1..Rare5 for Rarity 1..7). The
// server kept it up to date and the game only loads it (0x6d9c6c), so we recompute it from the
// inventory whenever the game handles an API response (hook on 0x2e080c, which also applies
// queued rank ups) and after a recruit.

#define RESPONSE_OFF SM_OFF(0x2e080c)
//   sub sp, sp, #0x110 ; stp x28, x22, [sp, #0xe0] ; stp x21, x20, [sp, #0xf0] ;
//   stp x19, x30, [sp, #0x100]
static const uint32_t kResponseProlog[4] = {0xd10443ff, 0xa90e5bfc, 0xa90f53f5, 0xa9107bf3};

uintptr_t smapi_response_resume;

static char (*g_rarity_name)[64];  // costume names from GameData.json Characters
static signed char *g_rarity;
static int g_rarity_n = -1;

static void load_rarities(void) {
    g_rarity_n = 0;
    char *gd = read_file(GAMEDATA_PATH);
    if (!gd) return;
    char *p = strstr(gd, "\"Characters\"");
    char *stop = p ? strstr(p, "\"Abilities\"") : NULL;
    g_rarity_name = calloc(1024, sizeof(*g_rarity_name));
    g_rarity = calloc(1024, 1);
    while (p && (p = strstr(p, "\"Name\": \"")) && (!stop || p < stop) && g_rarity_n < 1024) {
        p += 9;
        char *e = strchr(p, '"');
        char *r = e ? strstr(e, "\"Rarity\":") : NULL;
        if (!r) break;
        snprintf(g_rarity_name[g_rarity_n], 64, "%.*s", (int)(e - p), p);
        g_rarity[g_rarity_n++] = (signed char)atoi(r + 9);
        p = r;
    }
    free(gd);
}

static int costume_rarity(const char *name, size_t nl) {
    for (int i = 0; i < g_rarity_n; i++)
        if (strlen(g_rarity_name[i]) == nl && memcmp(g_rarity_name[i], name, nl) == 0)
            return g_rarity[i];
    return 0;
}

// GameData.json Ranks[Rarity - 1]: per rank, the copies (Duplicates) and coins
// (DuplicatesSoft) needed to reach it and the power it gives (RankPower, -1 past the last rank).
typedef struct {
    int cards[9], coins[9];
    float power[9];
} sm_rank;

static sm_rank g_ranks[7];
static int g_ranks_n;

static void parse_list(const char *row, const char *key, const char *end, float out[9]) {
    const char *p = strstr(row, key);
    if (!p || p > end || !(p = strchr(p, '['))) return;
    for (int i = 0; i < 9 && *p != ']'; i++) {
        char *e;
        out[i] = strtof(p + 1, &e);
        p = e;
    }
}

static void load_ranks(void) {
    char *gd = read_file(GAMEDATA_PATH);
    char *p = gd ? strstr(gd, "\"Ranks\"") : NULL;
    for (; p && g_ranks_n < 7; g_ranks_n++) {
        char *row = strchr(p, '{'), *end = row ? strchr(row, '}') : NULL;
        if (!end) break;
        float cards[9] = {0}, coins[9] = {0};
        sm_rank *rk = &g_ranks[g_ranks_n];
        parse_list(row, "\"Duplicates\":", end, cards);
        parse_list(row, "\"DuplicatesSoft\":", end, coins);
        parse_list(row, "\"RankPower\":", end, rk->power);
        for (int i = 0; i < 9; i++) rk->cards[i] = (int)cards[i], rk->coins[i] = (int)coins[i];
        p = end;
    }
    free(gd);
}

static pthread_once_t g_tables_once = PTHREAD_ONCE_INIT;

static void load_tables(void) {
    load_rarities();
    load_ranks();
}

static const sm_rank *rank_info(int rarity) {
    pthread_once(&g_tables_once, load_tables);
    return rarity >= 1 && rarity <= g_ranks_n ? &g_ranks[rarity - 1] : NULL;
}

// Takes `cost` coins (vials) off the profile with the game's setter (0x6d9aec, coins at +0x100).
static void charge_coins(uintptr_t base, int cost) {
    uint8_t *profile = profile_ptr(base);
    if (!profile || cost <= 0) return;
    int have = *(int *)(profile + 0x100);
    ((void (*)(void *, int))(base + SM_OFF(0x6d9aec)))(profile, have > cost ? have - cost : 0);
}

__attribute__((visibility("hidden"))) void smapi_update_power(void) {
    uintptr_t base = sm_game_base();
    uint8_t *inv = ((void *(*)(void))(base + GET_INV_OFF))();
    uint8_t *profile = profile_ptr(base);
    if (!inv || !profile) return;
    pthread_once(&g_tables_once, load_tables);
    float power[7] = {0};
    uint8_t **it = *(uint8_t ***)(inv + 0x38), **end = *(uint8_t ***)(inv + 0x40);
    int counted = 0;
    for (; it < end; it += 2) {
        uint8_t *item = it[0], *def = item ? *(uint8_t **)item : NULL;
        if (!def) continue;
        size_t nl;
        const char *name = cxx_str(def + 8, &nl);
        int r = costume_rarity(name, nl);
        if (r >= 1 && r <= 7) power[r - 1] += *(float *)(item + 0x28), counted++;
    }
    if (counted) memcpy(profile + 0xd8, power, sizeof(power));
}

__attribute__((naked)) static void response_stub(void) {
    __asm__ volatile("stp x29, x30, [sp, #-0x20]!\n"
                     "stp x0, x1, [sp, #0x10]\n"
                     "bl smapi_on_response\n"
                     "ldp x0, x1, [sp, #0x10]\n"
                     "ldp x29, x30, [sp], #0x20\n"
                     "sub sp, sp, #0x110\n"
                     "stp x28, x22, [sp, #0xe0]\n"
                     "stp x21, x20, [sp, #0xf0]\n"
                     "stp x19, x30, [sp, #0x100]\n"
                     "adrp x16, smapi_response_resume\n"
                     "ldr x16, [x16, :lo12:smapi_response_resume]\n"
                     "br x16\n");
}

static void apply_changes(sm_queue *q, int charge_portal) {
    sm_change pending[8];
    pthread_mutex_lock(&q->lock);
    int n = q->n;
    memcpy(pending, q->c, sizeof(pending));
    q->n = 0;
    pthread_mutex_unlock(&q->lock);
    if (!n) return;

    uintptr_t base = sm_game_base();
    if (charge_portal) smapi_charge_portal(base);
    uint8_t *inv = ((void *(*)(void))(base + GET_INV_OFF))();
    int (*def_timer)(void *) = (int (*)(void *))(base + DEF_TIMER_OFF);
    if (!inv) return;
    // Items: std::vector<std::shared_ptr<Item>> at +0x38. Item: +0 CostumeDef * (name string at
    // +8), +0x10 timer, +0x14 cards (copies), +0x18 rank, +0x20 time, +0x28 power.
    uint8_t **it = *(uint8_t ***)(inv + 0x38), **end = *(uint8_t ***)(inv + 0x40);
    char *buf = NULL;
    size_t len = 0, cap = 0;
    int changed = 0;
    for (; it < end; it += 2) {
        uint8_t *item = it[0], *def = item ? *(uint8_t **)item : NULL;
        if (!def) continue;
        size_t nl;
        const char *name = cxx_str(def + 8, &nl);
        int cards = *(int *)(item + 0x14), rank = *(int *)(item + 0x18);
        float power = *(float *)(item + 0x28);
        for (int i = 0; i < n; i++) {
            if (!pending[i].name[0] || strlen(pending[i].name) != nl ||
                memcmp(pending[i].name, name, nl) != 0)
                continue;
            if (pending[i].rankup) {
                const sm_rank *rk = rank_info(costume_rarity(name, nl));
                if (rk && rank >= 1 && rank < 9 && rk->power[rank] > 0) {
                    cards = cards > rk->cards[rank] ? cards - rk->cards[rank] : 0;
                    power = rk->power[rank++];
                    charge_coins(base, pending[i].cost);
                }
            } else {  // already owned: the copies go to its card count
                cards += pending[i].cards;
            }
            pending[i].name[0] = 0;
            changed++;
        }
        char f[256];
        int fl = snprintf(f, sizeof(f), "%s%.*s:%d:%d:%lld:%f", len ? "," : "", (int)nl, name,
                          cards, rank, *(long long *)(item + 0x20), power);
        if (*(int *)(item + 0x10) >= 1)
            fl += snprintf(f + fl, sizeof(f) - fl, ":%d", def_timer(def) - *(int *)(item + 0x10));
        append(&buf, &len, &cap, f, (size_t)fl);
    }
    for (int i = 0; i < n; i++) {
        if (!pending[i].name[0] || pending[i].rankup) continue;
        char f[256];
        int fl = snprintf(f, sizeof(f), "%s%s:1:1:0:%f", len ? "," : "", pending[i].name,
                          costume_base_power(pending[i].name));
        append(&buf, &len, &cap, f, (size_t)fl);
        changed++;
    }
    if (changed) {
        // const std::string & in libc++'s long form: capacity|1, size, data.
        size_t str[3] = {((len + 16) & ~(size_t)15) | 1, len, (size_t)buf};
        ((void (*)(void *, const void *))(base + SET_ITEMS_OFF))(inv, str);
    }
    sm_net_log("GRANT", NULL, buf ? buf : "", (long)len);
    free(buf);
    smapi_update_power();
}

__attribute__((visibility("hidden"))) void smapi_grant_pending(void) {
    apply_changes(&g_recruits, 1);
}

__attribute__((visibility("hidden"))) void smapi_on_response(void) {
    apply_changes(&g_rankups, 0);
    smapi_update_power();
}

__attribute__((naked)) static void portal_end_stub(void) {
    __asm__ volatile("bl smapi_grant_pending\n"
                     "adrp x16, smapi_fn_2caf28\n"
                     "ldr x16, [x16, :lo12:smapi_fn_2caf28]\n"
                     "blr x16\n"
                     "ldr x0, [x0, #0x140]\n"
                     "adrp x16, smapi_fn_63d2dc\n"
                     "ldr x16, [x16, :lo12:smapi_fn_63d2dc]\n"
                     "blr x16\n"
                     "adrp x16, smapi_fn_2caf28\n"
                     "ldr x16, [x16, :lo12:smapi_fn_2caf28]\n"
                     "blr x16\n"
                     "adrp x16, smapi_portal_resume\n"
                     "ldr x16, [x16, :lo12:smapi_portal_resume]\n"
                     "br x16\n");
}

// The server also charged for the portal. The OpenPortal response handler (0x2f48e8) gets the
// request context the game built at 0x2ea638: +0x10 ads flag, +0x14 currency (tracking id),
// +0x18 price. Its entry hook keeps them, and smapi_charge_portal takes the price off the
// profile's currency with the game's own setters (they notify the UI and the save).

#define PORTAL_BEGIN_OFF SM_OFF(0x2f48e8)
//   str x28, [sp, #-0x60]! ; stp x27, x26, [sp, #0x10] ; stp x25, x24, [sp, #0x20] ;
//   stp x23, x22, [sp, #0x30]
static const uint32_t kPortalBegin[4] = {0xf81a0ffc, 0xa9016bfb, 0xa90263f9, 0xa9035bf7};

uintptr_t smapi_portal_begin_resume;
static int g_portal_currency, g_portal_price;

__attribute__((visibility("hidden"))) void smapi_portal_begin(const uint8_t *ctx) {
    g_portal_price = ctx[0x10] ? 0 : *(const int *)(ctx + 0x18);
    g_portal_currency = *(const int *)(ctx + 0x14);
}

static void smapi_charge_portal(uintptr_t base) {
    int price = g_portal_price;
    g_portal_price = 0;
    if (price <= 0) return;
    uint8_t *profile = profile_ptr(base);
    if (!profile) return;
    // Currency ids from 0x2ea8a4: cash (crystals) 0x1da27, keys 0x47a1f, else coins (vials).
    uintptr_t setter = SM_OFF(0x6d9aec);  // coins at +0x100
    int field = 0x100;
    if (g_portal_currency == 0x1da27) setter = SM_OFF(0x6d9a40), field = 0xfc;
    else if (g_portal_currency == 0x47a1f) setter = SM_OFF(0x6d9b90), field = 0x104;
    int have = *(int *)(profile + field);
    ((void (*)(void *, int))(base + setter))(profile, have > price ? have - price : 0);
}

__attribute__((naked)) static void portal_begin_stub(void) {
    __asm__ volatile("stp x29, x30, [sp, #-0x20]!\n"
                     "stp x0, x1, [sp, #0x10]\n"
                     "bl smapi_portal_begin\n"
                     "ldp x0, x1, [sp, #0x10]\n"
                     "ldp x29, x30, [sp], #0x20\n"
                     "str x28, [sp, #-0x60]!\n"
                     "stp x27, x26, [sp, #0x10]\n"
                     "stp x25, x24, [sp, #0x20]\n"
                     "stp x23, x22, [sp, #0x30]\n"
                     "adrp x16, smapi_portal_begin_resume\n"
                     "ldr x16, [x16, :lo12:smapi_portal_begin_resume]\n"
                     "br x16\n");
}

// Extra JSON members for specific endpoints (appended after success/srequestID).
static void api_extra(const char *path, const char *json, char *out, size_t outlen) {
    out[0] = 0;
    if (strstr(path, "/Validation/OpenPortal.php")) {
        char portal[96] = "", item[128];
        int count = 1;
        sm_json_str(json, "portal_name", portal, sizeof(portal));
        if (portal[0] && pick_portal_reward(portal, item, sizeof(item), &count)) {
            // The object form plays the reveal animation; a bare string only shows a popup.
            snprintf(out, outlen, ",\"processedRewards\":[{\"item\":\"%s\",\"quantity\":1}]", item);
            queue_change(&g_recruits, item, count, 0, 0);
        }
    } else if (strstr(path, "/Alliances/GetSuggestedAlliance.php")) {
        // An empty list makes the game ask again at once (0x6611d4 only sets its 30 minute
        // retry time when "alliances" has entries or the request failed), so fail it.
        snprintf(out, outlen, ",\"alliances\":[]");
    } else if (strstr(path, "/PortalData/GetEvents.php")) {
        // Events by category (0x692f40: Flash, Regular, MultiDay, Alliance, TeamPower,
        // SocialMap), each {"General": {...}} plus its own data. The story map's special world
        // (Symbiote World in 4.6.0) unlocks while a SocialMap event is active and not locked.
        // The end date must stay before 2038: the remaining seconds are kept in an int32 and a
        // later date makes the menu crash.
        snprintf(out, outlen,
                 ",\"events\":{\"SocialMap\":[{\"General\":{\"Id\":\"smfix_symbiote_world\","
                 "\"StartDate\":\"2020-01-01 00:00:00\",\"EndDate\":\"2035-12-31 00:00:00\","
                 "\"GatchaName\":\"\",\"LocalizationId\":\"\",\"BannerImage\":\"\","
                 "\"Countries\":\"\",\"MinSpiderPower\":0,\"MaxSpiderPower\":1000000,"
                 "\"League\":0,\"Cluster\":0},\"active\":true,\"locked\":false}]}");
    }
}

// RankUp {"spider_id", "is_free"}: the server checked the coins (vials) and applied the rank.
// Answers 0 when it cannot be done; the game then shows its "out of ISO-8" popup. The rank
// itself changes on the game thread (g_rankups), cards needed for it are taken if there are any.
static int rank_up(const char *json) {
    char name[128] = "", is_free[8] = "";
    sm_json_str(json, "spider_id", name, sizeof(name));
    sm_json_str(json, "is_free", is_free, sizeof(is_free));
    uintptr_t base = sm_game_base();
    uint8_t *inv = ((void *(*)(void))(base + GET_INV_OFF))();
    uint8_t *profile = profile_ptr(base);
    if (!name[0] || !inv || !profile) return 0;
    const sm_rank *rk = rank_info(costume_rarity(name, strlen(name)));
    int rank = 0;
    uint8_t **it = *(uint8_t ***)(inv + 0x38), **end = *(uint8_t ***)(inv + 0x40);
    for (; it < end; it += 2) {
        uint8_t *item = it[0], *def = item ? *(uint8_t **)item : NULL;
        size_t nl;
        const char *n = def ? cxx_str(def + 8, &nl) : NULL;
        if (n && nl == strlen(name) && memcmp(n, name, nl) == 0) rank = *(int *)(item + 0x18);
    }
    if (!rk || rank < 1 || rank >= 9 || rk->power[rank] <= 0) return 0;
    int cost = strcmp(is_free, "true") == 0 ? 0 : rk->coins[rank];
    if (*(int *)(profile + 0x100) < cost) return 0;
    queue_change(&g_rankups, name, 0, 1, cost);
    return 1;
}

int sm_route_api(const sm_req *q, sm_resp *r) {
    if (!strstr(q->path, "/mrmeesyncs/2009/api/")) return 0;
    char *json = sm_api_decode(q);
    if (json) {
        size_t n = strlen(q->path) + strlen(json) + 2;
        char *line = malloc(n);
        snprintf(line, n, "%s\n%s", q->path, json);
        sm_net_log("API-REQ", NULL, line, (long)strlen(line));
        free(line);
    }
    char srid[64] = "0";
    sm_json_str(json, "srequestID", srid, sizeof(srid));
    char extra[512], out[768];
    api_extra(q->path, json, extra, sizeof(extra));
    int ok = !strstr(q->path, "/Alliances/GetSuggestedAlliance.php");
    if (strstr(q->path, "/Validation/RankUp.php")) ok = rank_up(json);
    snprintf(out, sizeof(out), "{\"success\":%d,\"srequestID\":\"%s\"%s}", ok, srid, extra);
    sm_resp_json(r, 200, out);
    free(json);
    return 1;
}

// VIP portals unlock after a real-money purchase (0x2eb164: portal is VIP and UserDefaults
// "is_pau" is 0). The store is gone, so the check always answers "not locked".
#define VIP_LOCKED_OFF SM_OFF(0x2eb164)
//   sub sp, sp, #0x40 ; stp x19, x30, [sp, #0x30]
static const uint32_t kVipLockedProlog[2] = {0xd10103ff, 0xa9037bf3};

static void unlock_vip_portals(uintptr_t base) {
    static const uint32_t ret_false[2] = {0x2a1f03e0, 0xd65f03c0};  // mov w0, wzr ; ret
    if (memcmp((void *)(base + VIP_LOCKED_OFF), kVipLockedProlog, sizeof(kVipLockedProlog)) != 0 ||
        sm_patch_code(base + VIP_LOCKED_OFF, ret_false, 2) != 0)
        SM_LOGW("api: could not unlock the VIP portals");
}

void sm_api_init(uintptr_t base) {
    unlock_vip_portals(base);
    smapi_portal_resume = base + PORTAL_END_OFF + 16;
    smapi_fn_2caf28 = base + SM_OFF(0x2caf28);
    smapi_fn_63d2dc = base + SM_OFF(0x63d2dc);
    if (sm_hook4(base + PORTAL_END_OFF, kPortalEnd, (void *)portal_end_stub) != 0)
        SM_LOGW("api: could not hook the OpenPortal handler");
    smapi_portal_begin_resume = base + PORTAL_BEGIN_OFF + 16;
    if (sm_hook4(base + PORTAL_BEGIN_OFF, kPortalBegin, (void *)portal_begin_stub) != 0)
        SM_LOGW("api: could not hook the OpenPortal handler entry");
    smapi_response_resume = base + RESPONSE_OFF + 16;
    if (sm_hook4(base + RESPONSE_OFF, kResponseProlog, (void *)response_stub) != 0)
        SM_LOGW("api: could not hook the API response handler");
}
