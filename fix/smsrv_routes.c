// Route handlers for the in-process fake Gameloft server (see smsrv.c).
//
// Hosts are the ones the game gets from our Eve config (srv/.../urls.json): every service is
// "<service>.gameloft.com", so routes match on the service prefix.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "smsrv.h"

int sm_route_dev(const sm_req *q, sm_resp *r);
int sm_route_api(const sm_req *q, sm_resp *r);

static int host_is(const sm_req *q, const char *service) {
    size_t n = strlen(service);
    return strncmp(q->host, service, n) == 0 && q->host[n] == '.';
}

static int ends_with(const char *s, const char *suffix) {
    size_t a = strlen(s), b = strlen(suffix);
    return a >= b && strcmp(s + a - b, suffix) == 0;
}

// Copies the value of `key` from a query string or form body into out (not URL-decoded).
static int param(const char *qs, const char *key, char *out, size_t outlen) {
    size_t kl = strlen(key);
    for (const char *p = qs; p && *p; p = strchr(p, '&') ? strchr(p, '&') + 1 : NULL) {
        if (strncmp(p, key, kl) == 0 && p[kl] == '=') {
            const char *v = p + kl + 1, *e = strchr(v, '&');
            size_t n = e ? (size_t)(e - v) : strlen(v);
            snprintf(out, outlen, "%.*s", (int)n, v);
            return 1;
        }
    }
    return 0;
}

// Eve config: one data centre whose service URLs all point at "<service>.gameloft.com".
// game_portal (the game's own PHP API) is used as a full URL; the rest as host names.
static const char kEveUrls[] =
    "{\"pandora\":\"https://pandora.gameloft.com\",\"janus\":\"janus.gameloft.com\","
    "\"osiris\":\"osiris.gameloft.com\",\"olympus\":\"olympus.gameloft.com\","
    "\"seshat\":\"seshat.gameloft.com\",\"hermes\":\"hermes.gameloft.com\","
    "\"iris\":\"iris.gameloft.com\",\"chronos\":\"chronos.gameloft.com\","
    "\"feeds\":\"feeds.gameloft.com\",\"matchmaker\":\"matchmaker.gameloft.com\","
    "\"lottery\":\"lottery.gameloft.com\",\"voice\":\"voice.gameloft.com\","
    "\"asset\":\"asset.gameloft.com\",\"alert\":\"alert.gameloft.com\","
    "\"gllive\":\"gllive.gameloft.com\",\"config\":\"config.gameloft.com\","
    "\"game_portal\":\"https://game_portal.gameloft.com\",\"ecomm\":\"ecomm.gameloft.com\","
    "\"trophy\":\"trophy.gameloft.com\",\"confirmation\":\"confirmation.gameloft.com\","
    "\"auth\":\"auth.gameloft.com\",\"storage\":\"storage.gameloft.com\","
    "\"social\":\"social.gameloft.com\",\"leaderboard\":\"leaderboard.gameloft.com\","
    "\"message\":\"message.gameloft.com\",\"transaction\":\"transaction.gameloft.com\","
    "\"bolt\":\"bolt.gameloft.com\",\"federation\":\"federation.gameloft.com\","
    "\"gameapi\":\"gameapi.gameloft.com\",\"gamecircle\":\"gamecircle.gameloft.com\","
    "\"lobby\":\"lobby.gameloft.com\",\"notification\":\"notification.gameloft.com\","
    "\"mrmeesyncs\":\"mrmeesyncs.gameloft.com\",\"game\":\"game.gameloft.com\","
    "\"ecomm_api_root\":\"https://ecomm.gameloft.com\"}";

static int route_eve(const sm_req *q, sm_resp *r) {
    if (strncmp(q->path, "/config/", 8) != 0) return 0;
    if (ends_with(q->path, "/datacenters")) {
        sm_resp_json(r, 200, "[{\"name\":\"smu\",\"status\":\"active\",\"preferred\":true,"
                             "\"country_code\":\"TR\",\"_datacenter_id\":\"smu\"}]");
        return 1;
    }
    if (ends_with(q->path, "/urls")) {  // any data centre name (the game may ask for a cached one)
        sm_resp_json(r, 200, kEveUrls);
        return 1;
    }
    return 0;
}

// Pandora service locator: GET /locate?service=<name> -> host of that service.
static int route_pandora(const sm_req *q, sm_resp *r) {
    if (strcmp(q->path, "/locate") != 0) return 0;
    char service[64] = "unknown", host[128];
    param(q->query, "service", service, sizeof(service));
    snprintf(host, sizeof(host), "%s.gameloft.com", service);
    sm_resp_set(r, 200, "text/plain", host, strlen(host));
    return 1;
}

// Janus (auth): anonymous credentials always exist and every login succeeds.
static int route_auth(const sm_req *q, sm_resp *r) {
    if (ends_with(q->path, "/authenticate")) {
        sm_resp_json(r, 200, "{}");
        return 1;
    }
    if (strcmp(q->path, "/authorize") == 0) {
        char scope[512] = "";
        param(q->body, "scope", scope, sizeof(scope));
        char json[1024];
        snprintf(json, sizeof(json),
                 "{\"access_token\":\"smfix-%08lx\",\"token_type\":\"bearer\","
                 "\"expires_in\":31536000,\"expires\":\"2099-01-01T00:00:00Z\","
                 "\"refresh_token\":\"smfix-refresh\",\"scope\":\"%s\"}",
                 (unsigned long)time(NULL), scope);
        sm_resp_json(r, 200, json);
        return 1;
    }
    return 0;
}

int sm_route(const sm_req *q, sm_resp *r) {
    if (sm_route_dev(q, r)) return 1;
    if (strcmp(q->host, "eve.gameloft.com") == 0) return route_eve(q, r);
    if (host_is(q, "pandora")) return route_pandora(q, r);
    if (host_is(q, "auth") || host_is(q, "janus")) return route_auth(q, r);
    if (host_is(q, "game_portal")) return sm_route_api(q, r);
    return 0;
}
