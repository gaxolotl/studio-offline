import os, struct, sys
from capstone import *

# Path to RobloxStudioBeta.exe. Override with env var STUDIO_EXE (use on a new PC).
EXE = os.environ.get(
    "STUDIO_EXE",
    r"C:\Users\Georgi\AppData\Local\Temp\opencode\so734\RobloxStudioBeta.exe",
)
data = open(EXE, "rb").read()

# Parse PE header
pe = struct.unpack_from("<I", data, 0x3C)[0]
nsec = struct.unpack_from("<H", data, pe + 6)[0]
opt = pe + 24
img_base = struct.unpack_from("<Q", data, opt + 24)[0]
size_opt = struct.unpack_from("<H", data, pe + 20)[0]
sect_off = opt + size_opt

sections = []
for i in range(nsec):
    off = sect_off + i * 40
    name = data[off:off+8].rstrip(b"\x00").decode("latin1")
    vsize = struct.unpack_from("<I", data, off + 8)[0]
    va = struct.unpack_from("<I", data, off + 12)[0]
    raw_size = struct.unpack_from("<I", data, off + 16)[0]
    raw_ptr = struct.unpack_from("<I", data, off + 20)[0]
    sections.append((name, va, vsize, raw_ptr, raw_size))

def file_off(va):
    rva = va - img_base
    for name, sva, svsize, rptr, rsize in sections:
        if sva <= rva < sva + max(svsize, rsize):
            return rptr + (rva - sva)
    return None

def disasm_range(va, length=0x400):
    fo = file_off(va)
    if fo is None:
        print(f"  !! no file mapping for {va:#x}")
        return
    code = data[fo:fo+length]
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    md.skipdata = True
    out = []
    for ins in md.disasm(code, va):
        out.append(f"0x{ins.address:016x}: {ins.mnemonic:<8s} {ins.op_str}")
    return out

if __name__ == "__main__":
    target = int(sys.argv[1], 16)
    length = int(sys.argv[2], 16) if len(sys.argv) > 2 else 0x400
    for name, sva, svsize, rptr, rsize in sections:
        print(f"sec {name:8s} va=0x{sva:08x} vsz=0x{svsize:x} rawptr=0x{rptr:x} rsz=0x{rsize:x}")
    print(f"img_base=0x{img_base:x}")
    fo = file_off(target)
    print(f"target va=0x{target:x} file_off=0x{fo:x}")
    lines = disasm_range(target, length)
    if lines:
        for l in lines:
            print(l)