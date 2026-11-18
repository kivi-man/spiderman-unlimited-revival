"""Decrypt / encrypt Spider-Man Unlimited player.dat (as written by libSpidermanI.so).
File layout: md5(key) (16 bytes) + XXTEA(key, JSON padded to 4 bytes).
Usage:
  python save_tool.py dec      <key.bin|dump.bin> <player.dat> <out.json>
  python save_tool.py enc      <key.bin|dump.bin> <in.json> <out player.dat>
  python save_tool.py skiptut  <key.bin|dump.bin> <player.dat> <out player.dat>
The key is the first 16 bytes of a smfix_dump_*.bin file (see smdebug.c); it is per device."""
import hashlib
import json
import re
import struct
import sys

DELTA = 0x9E3779B9
M = 0xFFFFFFFF


def _mx(z, y, s, k, p, e):
    return (((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4))) ^ ((s ^ y) + (k[(p & 3) ^ e] ^ z))


def xxtea_encrypt(data, key):
    v = list(struct.unpack(f'<{len(data) // 4}I', data))
    k = struct.unpack('<4I', key)
    n = len(v)
    z, s = v[-1], 0
    for _ in range(6 + 52 // n):
        s = (s + DELTA) & M
        e = (s >> 2) & 3
        for p in range(n):
            y = v[(p + 1) % n]
            v[p] = (v[p] + _mx(z, y, s, k, p, e)) & M
            z = v[p]
    return struct.pack(f'<{n}I', *v)


def xxtea_decrypt(data, key):
    v = list(struct.unpack(f'<{len(data) // 4}I', data))
    k = struct.unpack('<4I', key)
    n = len(v)
    rounds = 6 + 52 // n
    s = (rounds * DELTA) & M
    y = v[0]
    for _ in range(rounds):
        e = (s >> 2) & 3
        for p in range(n - 1, -1, -1):
            z = v[p - 1] if p > 0 else v[n - 1]
            v[p] = (v[p] - _mx(z, y, s, k, p, e)) & M
            y = v[p]
        s = (s - DELTA) & M
    return struct.pack(f'<{n}I', *v)


def decode_save(raw, key):
    if raw[:16] != hashlib.md5(key).digest():
        sys.exit('save header does not match this key (save from another device?)')
    return xxtea_decrypt(raw[16:], key).rstrip(b'\0 ').decode()


def encode_save(text, key):
    body = text.encode()
    body += b' ' * (-len(body) % 4)  # JSON-safe padding
    return hashlib.md5(key).digest() + xxtea_encrypt(body, key)


def skip_tutorial(text):
    """Mark every tutorial group as completed (Tutorial.groups -> all true)."""
    m = re.search(r'"Tutorial":\{"groups":\[([^\]]*)\]', text)
    if not m:
        sys.exit('Tutorial.groups not found')
    count = len(m.group(1).split(','))
    text = text[:m.start(1)] + ','.join(['true'] * count) + text[m.end(1):]
    json.loads(text)  # still valid JSON
    return text, count


if __name__ == '__main__':
    mode, keyfile = sys.argv[1], sys.argv[2]
    key = open(keyfile, 'rb').read()[:16]
    src = open(sys.argv[3], 'rb').read()
    if mode == 'dec':
        open(sys.argv[4], 'w', encoding='utf-8', newline='').write(decode_save(src, key))
    elif mode == 'enc':
        open(sys.argv[4], 'wb').write(encode_save(src.decode(), key))
    elif mode == 'skiptut':
        text, count = skip_tutorial(decode_save(src, key))
        open(sys.argv[4], 'wb').write(encode_save(text, key))
        print(f'{count} tutorial groups marked complete')
    else:
        sys.exit(__doc__)
