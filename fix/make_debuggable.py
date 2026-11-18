"""Set android:debuggable=true in a binary AndroidManifest.xml (in place, same size).
Usage: python make_debuggable.py <in AndroidManifest.xml> <out AndroidManifest.xml>"""
import struct
import sys

DEBUGGABLE = 0x0101000F
data = bytearray(open(sys.argv[1], 'rb').read())

# Resource map chunk: string index -> attribute resource id.
resmap = []
off = 8
while off < len(data):
    ctype, hsize, csize = struct.unpack_from('<HHI', data, off)
    if ctype == 0x0180:
        n = (csize - hsize) // 4
        resmap = list(struct.unpack_from(f'<{n}I', data, off + hsize))
    elif ctype == 0x0102:  # start element
        attr_start, attr_size, attr_count = struct.unpack_from('<HHH', data, off + 16 + 8)
        base = off + 16 + attr_start
        for i in range(attr_count):
            a = base + i * attr_size
            name = struct.unpack_from('<I', data, a + 4)[0]
            if name < len(resmap) and resmap[name] == DEBUGGABLE:
                dtype = data[a + 15]
                old = struct.unpack_from('<I', data, a + 16)[0]
                struct.pack_into('<I', data, a + 16, 0xFFFFFFFF)
                struct.pack_into('<I', data, a + 8, 0xFFFFFFFF)  # no raw string value
                print(f'debuggable attr at {a:#x}: type {dtype:#x}, {old:#x} -> 0xffffffff')
                open(sys.argv[2], 'wb').write(data)
                sys.exit(0)
    off += csize
sys.exit('android:debuggable attribute not found')
