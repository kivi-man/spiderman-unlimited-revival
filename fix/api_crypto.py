"""Game API (game_portal / mrmeesyncs) request encoding, as in libSpidermanI.so 0x2e1110:
XTEA (32 rounds, ECB, zero padded to 8 bytes) with a fixed key, then base64, then URL-encoded
as the `params` form field.
Usage: python api_crypto.py dec <net.log>   decode every encrypted request in a smfix_net.log"""
import base64
import re
import struct
import sys
import urllib.parse

KEY = (2524, 9534, 4591, 7218)  # 16 bytes at 0x1af30b0
DELTA = 0x9E3779B9
M = 0xFFFFFFFF


def xtea_encrypt_block(v0, v1, k=KEY):
    s = 0
    for _ in range(32):
        v0 = (v0 + ((((v1 << 4) ^ (v1 >> 5)) + v1) ^ (s + k[s & 3]))) & M
        s = (s + DELTA) & M
        v1 = (v1 + ((((v0 << 4) ^ (v0 >> 5)) + v0) ^ (s + k[(s >> 11) & 3]))) & M
    return v0, v1


def xtea_decrypt_block(v0, v1, k=KEY):
    s = (DELTA * 32) & M
    for _ in range(32):
        v1 = (v1 - ((((v0 << 4) ^ (v0 >> 5)) + v0) ^ (s + k[(s >> 11) & 3]))) & M
        s = (s - DELTA) & M
        v0 = (v0 - ((((v1 << 4) ^ (v1 >> 5)) + v1) ^ (s + k[s & 3]))) & M
    return v0, v1


def encrypt(data: bytes) -> bytes:
    data += b'\0' * (-len(data) % 8)
    out = b''
    for i in range(0, len(data), 8):
        out += struct.pack('<2I', *xtea_encrypt_block(*struct.unpack_from('<2I', data, i)))
    return out


def decrypt(data: bytes) -> bytes:
    out = b''
    for i in range(0, len(data) - len(data) % 8, 8):
        out += struct.pack('<2I', *xtea_decrypt_block(*struct.unpack_from('<2I', data, i)))
    return out.rstrip(b'\0')


def decode_params(form: str) -> str:
    p = urllib.parse.parse_qs(form, keep_blank_values=True).get('params', [''])[0]
    return decrypt(base64.b64decode(p + '=' * (-len(p) % 4))).decode('utf-8', 'replace')


if __name__ == '__main__':
    if sys.argv[1] == 'dec':
        log = open(sys.argv[2], 'rb').read().decode('utf-8', 'replace')
        seen = set()
        for m in re.finditer(r'SRV-REQ 0x0 len=\d+\n(\S+) (\S+)[^\n]*\n.*?SRV-REQ-BODY 0x0 len=\d+\n([^\n]*)',
                             log, re.S):
            path, body = m.group(2), m.group(3)
            if 'params=' not in body or path in seen:
                continue
            seen.add(path)
            print(path)
            print('   ', decode_params(body)[:1500])
