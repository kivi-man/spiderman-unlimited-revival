// In-process fake Gameloft server (smsrv.c) and its route handlers (smsrv_routes.c).
#pragma once

#include <stddef.h>
#include <stdint.h>

typedef struct {
    char method[16];
    char host[256];   // original host, e.g. "eve.gameloft.com"
    char path[1024];  // original path without query, e.g. "/config/.../datacenters"
    char query[2048];
    char *body;       // NUL-terminated
    size_t body_len;
} sm_req;

typedef struct {
    int status;
    char type[64];
    char *body;
    size_t len;
} sm_resp;

void sm_resp_set(sm_resp *r, int status, const char *type, const char *body, size_t len);
void sm_resp_json(sm_resp *r, int status, const char *json);

// Fills `r` and returns 1 if a handler exists for the request, else 0.
int sm_route(const sm_req *q, sm_resp *r);

// Installs the hooks the game API emulation needs (smapi.c); `base` is the game's load address.
void sm_api_init(uintptr_t base);
