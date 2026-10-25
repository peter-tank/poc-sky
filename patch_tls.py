#!/usr/bin/env python3
"""Make an arm64 static ELF acceptable to Android's bionic loader.

Android requires PT_TLS.p_align >= 64 on arm64. The NDK emits 8 for static
binaries, and the kernel refuses to exec them:

    executable's TLS segment is underaligned: alignment is 8,
    needs to be at least 64 for ARM64 Bionic

Usage: python3 patch_tls.py poc-sky
"""
import struct
import sys

ALIGN = 64


def main(path):
    with open(path, "rb") as f:
        d = bytearray(f.read())

    if d[:4] != b"\x7fELF":
        sys.exit("not an ELF file")
    if d[4] != 2:
        sys.exit("not ELF64 (this patch is arm64 only)")
    if struct.unpack_from("<H", d, 0x12)[0] != 183:  # EM_AARCH64
        sys.exit("not aarch64")

    phoff = struct.unpack_from("<Q", d, 0x20)[0]
    phentsize = struct.unpack_from("<H", d, 0x36)[0]
    phnum = struct.unpack_from("<H", d, 0x38)[0]

    patched = 0
    for i in range(phnum):
        o = phoff + i * phentsize
        if struct.unpack_from("<I", d, o)[0] == 7:  # PT_TLS
            old = struct.unpack_from("<Q", d, o + 0x30)[0]
            if old < ALIGN:
                struct.pack_into("<Q", d, o + 0x30, ALIGN)
                print("PT_TLS p_align: %d -> %d" % (old, ALIGN))
                patched += 1
            else:
                print("PT_TLS p_align already %d, nothing to do" % old)

    if not patched:
        return
    with open(path, "wb") as f:
        f.write(d)
    print("written:", path)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    main(sys.argv[1])
