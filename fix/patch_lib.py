"""Redirect libSpidermanI.so (arm64) heap calls to libsmfix.so.
Usage: python patch_lib.py <in libSpidermanI.so> <out libSpidermanI.so>"""
import sys
import lief

RENAMES = {"malloc": "smfix_malloc", "calloc": "smfix_calloc",
           "realloc": "smfix_realloc", "free": "smfix_free",
           # network hooks (smnet.c)
           "send": "smfix_send", "recv": "smfix_recv", "getaddrinfo": "smfix_getaddrinfo",
           "gethostbyname": "smfix_gethostbyname", "connect": "smfix_connect"}

lib = lief.parse(sys.argv[1])
done = set()
for sym in lib.dynamic_symbols:
    if sym.name in RENAMES and sym.imported:
        new = RENAMES[sym.name]
        sym.name = new
        # libsmfix exports unversioned symbols; drop the LIBC version requirement.
        if sym.has_version:
            sym.symbol_version.value = 1
        done.add(new)
missing = set(RENAMES.values()) - done
if missing:
    sys.exit(f"imports not found: {missing}")
lib.add_library("libsmfix.so")
lib.write(sys.argv[2])
print("patched:", sorted(done))
