# AGENT.md: Marvel Spider-Man Unlimited 4.6.0c (offline revival mod)

This is a guide for AI agents (and people) working in this folder. It explains what the project
is, how it is built and tested, how the game works internally as far as we have reverse
engineered it, and the rules to follow when changing it.

> **User language:** the owner of this project speaks Turkish. Always answer them in **simple
> Turkish**. Code, comments and this file stay in English.

---

## 1. Goal

*Marvel Spider-Man Unlimited* (Gameloft, Android, package `com.gameloft.android.ANMP.GloftSIHM`,
version 4.6.0c) is dead: Gameloft's servers are offline and the arm64 build crashes on modern
phones. This project patches the original APK so that:

1. it runs on Android 11–16, 64-bit (arm64-v8a), on modern phones;
2. everything that needed Gameloft's servers works **on the phone with no network**: a fake
   server runs *inside the game process* (no PC, no external host, "nobody gets bothered");
3. game progress (recruiting, rank ups, team power, events) works like it did when online.

The user's requirement, word for word: *"Herşey telefonda gerçekleşecek, kimseyi uğraştırmayacak,
gerçek bir sunucu açmana bile gerek yok, sunucu gibi davranan bir şey yapabilirsin."* In English:
everything happens on the phone, nobody else gets involved, no real server, something that acts
like a server.

## 2. Folder layout

```
MARVEL+Spider-Man+Unlimited_4.6.0c.apk   original APK (never modify)
decompiled/
  apktool/                 apktool output (smali, resources, lib/)
  jadx/                    jadx Java output
  native/arm64-v8a/libSpidermanI.so   ORIGINAL game library: all offsets below refer to it
fix/                       all mod sources and scripts (see §4)
  out/                     build outputs and scratch: patched lib, logs, dumps, decoded saves
  srv_dev/                 development response overrides pushed to the phone (normally empty)
build/                     finished APKs
  SpiderManUnlimited_4.6.0c_fix64.apk   RELEASE: what users install
  SpiderManUnlimited_4.6.0c_debug.apk   same, but android:debuggable=true (allows run-as)
  SpiderManUnlimited_4.6.0c_fix32.apk   old workaround (32-bit only), obsolete
keys/mod-release.jks       signing key (password in keys/keystore-password.txt; never print it)
backup/                    save backups (Redmi app data, S25 save, Redmi save); never delete
tools/                     apktool.jar, jadx
```

## 3. Environment

- Windows 11, Git Bash for shell scripts (`sh fix/...`). PowerShell is also available, but it
  mangles clang arguments and binary redirection, so use Bash for builds.
- Android SDK: `$LOCALAPPDATA/Android/Sdk`, `adb` at `.../platform-tools/adb.exe` (not on PATH).
- NDK 28.2.13676358 (clang `--target=aarch64-linux-android21`).
- Python 3 with `lief`, `pyelftools`, `capstone`. Run project scripts with `python -I`. Use
  `python -E` when user site-packages are needed (pyelftools/lief).
- Git Bash rewrites `/sdcard/...` style arguments: prefix adb commands with `MSYS_NO_PATHCONV=1`.
- Test phones:
  - **Samsung Galaxy S25** (Android 16). Find its serial with `adb devices`. It may ask for USB debugging
    approval again; the user must tap "İzin ver" (Allow) on the phone.
  - **Xiaomi Redmi** (Android 15). Find its serial with `adb devices`. Xiaomi needs "USB üzerinden yükle"
    (Install via USB) enabled.
  - When both are connected, always pass `-s <serial>`.
- An old disassembler helper lives in a previous scratchpad:
  `sodis.py` (path not kept in the repo).
  Usage: `python -E sodis.py <lib.so> 0xADDR`. It prints the function containing the address,
  with string and PLT annotations. If it is gone, rewrite it with capstone, using .eh_frame FDEs
  for function bounds.

## 4. How the mod works

### 4.1 Patching chain

1. `fix/patch_lib.py` (LIEF) renames these imports of `libSpidermanI.so` to `smfix_*`: `malloc`,
   `calloc`, `realloc`, `free`, `send`, `recv`, `getaddrinfo`, `gethostbyname`, `connect`. It
   drops their symbol versions and adds `DT_NEEDED libsmfix.so`.
2. **LIEF shifts the whole image by +0x1000.** In C code, every game address is written as
   `SM_OFF(orig)` = `orig + 0x1000`, where `orig` is the address in
   `decompiled/native/arm64-v8a/libSpidermanI.so`. `build_native.sh` asserts the shift for a list
   of offsets; add new hook sites to that list.
3. `libsmfix.so` (our code) is loaded as a dependency. Its constructors install inline hooks into
   the game's code at load time.
4. `fix/build_apk.py` rebuilds the APK from the original: it replaces
   `lib/arm64-v8a/libSpidermanI.so`, adds `libsmfix.so` (and, with `--debug`, the debuggable
   manifest), then runs zipalign -P 16 and apksigner (v1/v2/v3).

### 4.2 Hooking helpers (`smcommon.c/h`)

- `sm_game_base()` returns the load address of libSpidermanI.so.
- `sm_patch_code(addr, insns, n)` overwrites instructions: it makes the page writable and flushes
  the icache.
- `sm_hook4(addr, expect[4], dest)` checks that the 4 instructions at `addr` equal `expect`, then
  writes `ldr x16,#8; br x16; .quad dest`. The **naked asm stub** in our code saves the argument
  registers, calls a C function, restores them, **replays the 4 original instructions**, and
  jumps to `addr+16` (a `*_resume` global). Prolog instructions must be position independent;
  check them with the disassembler first.
- Pattern for writing a stub: copy an existing one (`smapi.c` `response_stub`,
  `portal_begin_stub`; `smjson.c`; `smdebug.c`).
- **Pitfall:** when generating C with Python heredocs, `"\n"` inside asm strings can turn into
  real newlines and break the build. `scratchpad/fixnl.py` repairs it; prefer the Edit tool.

### 4.3 Components (all in `fix/`)

| File | What it does |
|---|---|
| `smfix.c` | **Arena allocator.** The game stores int32 relative offsets between heap objects; Scudo on arm64 Android 11+ places allocations GBs apart, so the game crashed while loading. All game malloc/free calls go to one 1920 MB `mmap` arena (size classes plus large blocks). This is the core crash fix. |
| `smcommon.c/h` | Base address, code patching, `sm_hook4`, `sm_net_log` declaration, `SM_FAKE_HOST`, `SM_FAKE_IP`, `SM_FILES_DIR`. |
| `smnet.c` | Network hooks. `smfix_gethostbyname` and `smfix_getaddrinfo` resolve `smfix.local` to `198.18.77.77`; `smfix_connect` sends that address to `127.0.0.1` (the game's curl refuses loopback and private IPs). With `files/smfix_net` it also logs `send`/`recv` and the SSL read/write slots (`0x1241cd4`/`0x1241af4`) to `files/smfix_net.log`. |
| `smsrv.c/h` | **The fake server.** A loopback HTTP server on a thread inside the game (keep-alive, Expect: 100-continue, Content-Length). It hooks `curl_easy_setopt` (`0x1207374`): every URL becomes `https://smfix.local:<port>/<host><path>`. It also patches curl's HTTPS handler (`0x1ac4e18`) into plain HTTP: only HTTPS is compiled into the game's curl, and we keep it but drop SSL. It nulls `CURLOPT_OPENSOCKETFUNCTION`. **Always on**; `files/smfix_nosrv` turns it off. Responses come from `files/srv/<host><path>.json` dev overrides first, then the routes. |
| `smsrv_routes.c` | Gaia emulation. Eve (`/config/<client>/datacenters`, `/datacenters/<dc>/urls`), pandora `/locate` (returns `<service>.gameloft.com`), auth/janus (`/authenticate` → `{}`, `/authorize` → OAuth JSON). Dispatch order: dev → eve → pandora → auth/janus → game_portal (`sm_route_api`). |
| `smapi.c` | **Game API emulation** for `game_portal.gameloft.com/mrmeesyncs/2009/api/...`, plus all the gameplay logic hooks (§6). |
| `smsrv_dev.c` | Dev endpoints `/__mem/<hexoff>/<hexlen>` and `/__str/<hexoff>`, which read game memory at original offsets. Only with `files/smfix_dev`. Use them through `fix/mem.sh`. |
| `smjson.c` | Debug tracer. With `files/smfix_jsontrace` it hooks JsonCpp `Value::find` (`0x126d48c`) and `resolveReference` (`0x126d1d4`) and logs every (key, caller) pair once as `JSON-KEY key @caller`. **The best tool for discovering what a server response must contain:** send a dummy JSON, then read which keys the game looks up. |
| `smdebug.c` | Debug only. With `files/smfix_dump` it dumps the XXTEA encrypt input (`0x11a753c`) and decrypt input (`0x11a76f4`) together with their keys (save editing). With `smfix_net` it logs EVP/BF keys (they never fired). |

### 4.4 Debug flag files

These live in the app's private `files/` folder. Create them with
`adb shell run-as <pkg> touch files/<flag>`, which **only works on the debug APK**.

| Flag | Effect |
|---|---|
| `smfix_net` | Write the network/API log to `files/smfix_net.log` (large; it slows the game). |
| `smfix_jsontrace` | Log JSON key lookups (`JSON-KEY`). |
| `smfix_dev` | Enable the `/__mem` and `/__str` endpoints. |
| `smfix_curldbg` | curl verbose trace into the net log. |
| `smfix_dump` | XXTEA key and data dumps (`smfix_dump_*`, `smfix_dec_*`). |
| `smfix_nosrv` | Disable the fake server. |
| `files/srv/...json` | Response overrides (pushed by `push_srv.sh` from `fix/srv_dev/`). |

**Before releasing, delete all flags and `files/srv`:**
`run-as <pkg> sh -c 'cd files && rm -rf smfix_* srv'`.

## 5. Build, install, test

```bash
sh fix/build_native.sh                      # compile libsmfix.so, patch the lib, verify the shift
python -I fix/build_apk.py build/SpiderManUnlimited_4.6.0c_fix64.apk           # release
python -I fix/build_apk.py --debug build/SpiderManUnlimited_4.6.0c_debug.apk   # debug
sh fix/dev_run.sh --build 40   # build + install debug + push srv_dev + set flags + run 40 s + summary
```

- `dev_run.sh` installs the **debug** APK and creates the `smfix_net`, `smfix_dev` and
  `smfix_jsontrace` flags. It then pulls `files/smfix_net.log` to `fix/out/net.log` and
  summarises it with `srv_summary.py`.
- `api_crypto.py dec <net.log>` decodes every encrypted API request in a log.
- Install with `adb install -r` (keeps data). The release and debug APKs share the signature, so
  you can switch between them without losing data. **Never uninstall** without backing up first
  (see §8).
- Seeing the game: take `adb exec-out screencap -p > x.png` and read the image. Tap with
  `adb shell input tap X Y` (physical pixels; Redmi 1220×2712, S25 1440×3120). Useful buttons
  on the Redmi: Takımım (my team) (204,1469), İşe al (recruit) (204,1740), Hikaye (story)
  (1010,1740), Etkinlikler (events) (1003,1464), Özel Etkinlik (special event) (1010,1180), Back
  (130,2577). On the S25 multiply the Redmi numbers by about 1.18; check with a screenshot.
- Check for crashes after every run: `adb logcat -d -b crash | grep Fatal`. Clear the buffer
  first with `adb logcat -b crash -c`.
- The user often plays during tests. Do not tap blindly when the screen shows a run in
  progress.

## 6. Reverse-engineered game facts (original addresses)

### 6.1 Game API protocol

- Request: POST form `encrypt=&params=<urlenc(base64(XTEA_ECB(json, zero padded)))>`. The XTEA
  key is `{2524, 9534, 4591, 7218}` (`0x1af30b0`); encryption happens at `0x11a72d0`, called
  from `0x2e1110`.
- Response: plain JSON. `{"success":1,"srequestID":"<echo>", ...}`. **`success` must be the
  integer 1** (a bool is ignored, and `0` means failure). The generic response handler is
  `0x2e080c`.
- Every successful response may carry `"seshat"` (the server-side profile, parsed at
  `0x7078dc`: `_inventory`, `_pending_rewards`, `_srequests`, ...). We do not send it.
- Endpoint list: strings at `0x15b1257..0x15b1df8`; the URL switch is at `0x2d98c4`.

### 6.2 Inventory and items

- Inventory singleton: `0x2f79b8()`. Items: `std::vector<std::shared_ptr<Item>>` at
  `inv+0x38/+0x40`.
- Item layout:

  | Offset | Field |
  |---|---|
  | `+0` | `CostumeDef*` (name: libc++ `std::string` at `def+8`) |
  | `+0x10` | timer |
  | `+0x14` | **cards** (copies) |
  | `+0x18` | **rank** |
  | `+0x20` | time (int64) |
  | `+0x28` | power (float) |
  | `+0x38`, `+0x40` | stamina-related |

- **The client never adds items itself; the server owned the list.** The item-list handler
  `0x60e524(Inventory*, const std::string&)` takes
  `"name:cards:rank:time:power[:timer],name2:..."` and **replaces the whole list**. Existing
  objects are reused, so their other fields survive. The save writes `name:...,<x>,<y>` (extra
  comma fields); those must not be passed to 0x60e524.
- Item def lookup: `0x7e79cc`. Find an item in the inventory: `0x60da9c(inv, name)`.
- Save: `files/player.dat` = md5(key) followed by XXTEA(JSON). The key is per device: capture it
  with `smfix_dump`. `fix/save_tool.py dec|enc|skiptut <key.bin> <in> <out>`. The key files are
  `backup/s25-save-2020/key-dump.bin` (S25) and `backup/redmi-save/key-dump.bin` (Redmi); the
  key is their first 16 bytes. Save JSON: `Inventory.Costumes`, `Profile.Cash` (crystals) and
  `Profile.Coins` (vials), `Tutorial.groups`.

### 6.3 Profile (currency, power)

- Profile object = `*(*(*GOT[0x1b0ed90]) + 0x150) + 0xaa0`. In code this is `profile_ptr()` in
  smapi.c, the same thing `0x2cb4a8` / `0x70224c` read.
- Currency fields and setters (setters notify the UI and the save):

  | Currency | Field | Setter |
  |---|---|---|
  | cash (crystals) | `+0xfc` | `0x6d9a40` |
  | coins (vials) | `+0x100` | `0x6d9aec` |
  | keys | `+0x104` | `0x6d9b90` |

- **Team power** = `Profile._inventoryPower`: 7 floats at `profile+0xd8`, one per rarity 1..7
  (Common, Uncommon, Rare1..Rare5). Each is the sum of item power for that rarity. The game only
  *loads* it, so we recompute it.
- GameData.json (`/sdcard/Android/data/<pkg>/files/GameData.json`, pretty-printed) contains:
  - `Characters[]`: costume `Name` and `Rarity`;
  - `Ranks[rarity-1]`: `Duplicates` (cards needed per rank), `DuplicatesSoft` (vials per rank)
    and `RankPower`;
  - `Portals.{Premium,Standard,Vip,Special}[].RewardObject`: nested `["Item:count", weight]`;
  - `Missions[]`, `Leagues[]` (power ranges: Çaylak (Rookie) 4, Orta (Intermediate) 30,
    Tecrübeli (Experienced) 80, ...), `GameStaticSection.UnlockFeatures`.

### 6.4 Portals (recruiting)

- OpenPortal request builder: `0x2ea638`. The response handler is `0x2f48e8`; its context holds
  the ads flag at `+0x10`, the currency id at `+0x14` (`0x1da27` = cash, `0x47a1f` = keys, else
  coins) and the price at `+0x18`.
- The response must be `"processedRewards":[{"item":"Costume_X","quantity":1}]`. The **object
  form plays the reveal animation**; a bare string only shows a broken "required spider" popup.
- The reward parser is `0x2e6644`; `0x7085b4` only does mission tracking (does not grant).
- The grant must run **after** the animation is set up (hook at `0x2f4f20`, near the handler's
  end). Granting earlier makes the game think the costume is already owned, and it shows the
  popup instead of the animation.
- VIP portals are locked until a real-money purchase: `0x2eb164` checks the portal type and
  UserDefaults `is_pau`. We patch it to `return 0`; the portals then cost crystals (Gold 100,
  Platinum 130).
- Mystery Box needs ads (not supported). Some portals unlock by league (normal game rule).

### 6.5 Rank up

- Request `/Validation/RankUp.php {"spider_id","is_free"}`. The client shows "SIRALAMA
  YÜKSELTME BAŞARILI!" (rank up successful) but changes nothing locally: the server did it.
- Answering `success:0` makes the game show its own "ISO-8 bitti" (out of ISO-8) popup.

### 6.6 Events and Symbiote World (Venom)

- `GetEvents.php` response:
  `{"events":{"<Category>":[{"General":{...}, ...category data...}]}}`.
  - Categories (factory `0x692f40`): `Flash`, `Regular`, `MultiDay`, `Alliance`, `TeamPower`,
    `SocialMap`.
  - `General` keys: `Id`, `StartDate`, `EndDate` ("YYYY-MM-DD HH:MM:SS"), `GatchaName`,
    `LocalizationId`, `BannerImage`, `Countries`, `MinSpiderPower`, `MaxSpiderPower`, `League`,
    `Cluster`.
- The **story map's special world** (in 4.6.0c this is *Symbiote World / Sembiyot Dünyası*:
  missions 322–337, bosses Venom → Carnage (episode 7) → Scream (episode 13); the art is already
  on the phone) unlocks while a **SocialMap** event exists with `"active":true,"locked":false`.
  The flags are parsed at `0x678894` and land at `+0x238` and `+0x239`.
- **`EndDate` must be before 2038.** The remaining seconds are int32; a 2099 date crashed the
  menu (stack overflow in the 0x4e71bc/0x4faca8 UI recursion). We use `2035-12-31`.

### 6.7 Other

- `GetSuggestedAlliance` with an empty list gets re-requested in a tight loop. Answering
  `success:0` makes the game set a 30-minute retry time (`0x661190`).
- In-app purchases do not work: the shop shows "Şu an hiç uygulama içi satın alım paketi yok"
  (no in-app purchase packs right now). That is expected.
- 32-bit builds never had the crash; the arm64 crash was purely the heap-offset issue (§4.3
  smfix.c).

## 7. What `smapi.c` implements (current behaviour)

| Endpoint / hook | Behaviour |
|---|---|
| any game_portal API | `{"success":1,"srequestID":<echo>}` plus endpoint extras; decrypted request logged as `API-REQ`. |
| `OpenPortal` | Weighted random pick from GameData `RewardObject`. Returns the object-form `processedRewards`, queues the grant (`g_recruits`), and remembers the price from the handler-entry hook `0x2f48e8`. |
| hook `0x2f4f20` (OpenPortal end) | `apply_changes(&g_recruits)`. Charges the price through the currency setter. New costumes are added as `name:1:1:0:<RankPower[rarity][0]>`; for an owned costume the table's `:N` copies are added to its card count. Then calls `0x60e524` with the full list and recomputes power. |
| `RankUp` | Checks the costume is owned, the next rank exists, and there are enough vials (`DuplicatesSoft`, or free when `is_free`). If so it answers 1 and queues the change (`g_rankups`); otherwise it answers 0. |
| hook `0x2e080c` (every API response, game thread) | Applies queued rank ups (cards −= `Duplicates`, rank+1, power = `RankPower`, vials charged), then recomputes team power. |
| `GetSuggestedAlliance` | `success:0` plus `alliances:[]` (stops the request spam). |
| `GetEvents` | One permanent SocialMap event `smfix_symbiote_world` (2020-01-01 → 2035-12-31, active, unlocked). |
| patch `0x2eb164` | VIP portals never locked. |

Threads: the HTTP server runs on its own thread. **Never touch game objects from the server
thread.** Queue the change and apply it from a game-thread hook (the pattern in `sm_queue`,
`apply_changes`). GameData tables are loaded once with `pthread_once` (`load_tables`).

## 8. Data safety rules

- **Back up before anything destructive.** Use `run-as <pkg>` to copy `files/` (`player.dat`,
  `check.dat`, `tuttracking.dat`, `UserDefaults.json`) into `backup/<device>-<desc>/`. Existing
  backups:
  - `backup/com.gameloft.android.ANMP.GloftSIHM`: Redmi app data, early.
  - `backup/s25-save-2020`: S25 save plus key.
  - `backup/redmi-save`: Redmi save plus key, before the tutorial skip.
- Never `adb uninstall` and never `pm clear` without a backup and the user's OK.
- To edit a save: back up → decode with save_tool → edit the JSON → encode → push to
  `/data/local/tmp` → `run-as cp` into `files/player.dat` → **remove the tmp file**. Do this
  while the game is stopped (`am force-stop`), or the game overwrites the file.
- Release builds are not debuggable, so `run-as` fails on them. Temporarily install the debug
  APK (same signature, data kept), do the work, remove all `smfix_*` flags and `files/srv`, then
  reinstall the release APK.
- Never print or commit the keystore password.

## 9. Workflow for adding a server feature

1. Reproduce on the phone with the **debug APK** plus `dev_run.sh` (flags on).
2. Find the request in `fix/out/net.log`: look at the `API-REQ` lines, decrypted JSON included.
3. Find what the client reads:
   - put a guessed response in `fix/srv_dev/game_portal.gameloft.com/mrmeesyncs/2009/api/v460/<Group>/<Name>.php.json`;
   - run `push_srv.sh`, restart the game, then check the `JSON-KEY` lines after the request;
   - iterate. Use dummy keys like `{"x":1}` to reveal the next level of lookups.
4. If the client does not apply something itself (inventory, currency, rank, power), find the
   game's own setter or handler and call it from a **game-thread** hook. Do not poke raw fields
   without the setter if one exists.
5. Implement it in `smapi.c` (`api_extra` / `sm_route_api` / a hook installed in
   `sm_api_init`). Add any new hook offsets to the shift check in `build_native.sh`. Match the
   existing comment style: explain *why*, and cite original addresses.
6. Delete `fix/srv_dev` overrides once the feature is in C. Build the release APK, clean the
   flags on the phone, install, launch, check the crash buffer, and look at the screen.
7. Update §6 and §7 of this file and the memory note (`fake-server-progress`).

## 10. Known gaps / ideas

- Mystery Box (ads) and real-money shop: not supported.
- Leaderboards, social, inbox, storage (`GameSave.dat`, `myprofile`), alliances: answered with
  defaults or not at all. The game tolerates it.
- Symbiote World: only episode 1 has been tested on the phone. The later episodes, the medals
  and the progression rewards are untested.
- Cash and keys pricing for portals relies on the currency ids above; keys portals are untested.
- `seshat` profile sync is not emulated; local save is the source of truth.
