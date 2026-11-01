import struct

DMP = r"C:\Windows\Minidump\103126-6609-01.dmp"
FAULT = 0xfffff80057001cc3
PAGE = 0x1000
PFN_MASK = 0x000FFFFFFFFFF000

with open(DMP, "rb") as f:
    data = f.read()
print("file size:", len(data))

# DUMP_HEADER64 (x64) key offsets
# 0: Signature(4)=PAGEDU64, 4: ValidDump, 8: MajorVersion, 12: MinorVersion
# 16: DirectoryTableBase(8), 24: PfnDataBase(8), 32: PsLoadedModuleList(8), 40: PsActiveProcessHead(8)
# 48: MachineImageType(4), 52: NumberProcessors(4)
# 56: BugCheckCode(4), 60..76: BugCheckParam1..4
sig = data[0:8]
(major,) = struct.unpack_from("<I", data, 8)
(minor,) = struct.unpack_from("<I", data, 12)
(cr3,) = struct.unpack_from("<Q", data, 16)
(psmodlist,) = struct.unpack_from("<Q", data, 32)
(bugcheck,) = struct.unpack_from("<I", data, 56)
print("sig:", sig, "major:", major, "minor:", minor)
print("CR3 (DirectoryTableBase): 0x%X" % cr3)
print("PsLoadedModuleList VA: 0x%X" % psmodlist)
print("BugCheckCode: 0x%X" % bugcheck)

# Locate PHYSICAL_MEMORY_DESCRIPTOR. Try at offset 0x80 (after 0x80 header).
# DUMP_HEADER64 is 0x80 bytes; then a DUMP64 {Base; Size} (16 bytes) then descriptor.
# Scan for a plausible descriptor: NumberOfRuns in [1,512], NumberOfPages reasonable.
def find_descriptor():
    for off in range(0x80, min(0x2000, len(data)-32), 4):
        (nor,) = struct.unpack_from("<I", data, off)
        (nop,) = struct.unpack_from("<I", data, off+4)
        if 1 <= nor <= 512 and 1000 <= nop <= 0x200000:
            # validate first run base/page plausibility
            (bp,) = struct.unpack_from("<Q", data, off+8)
            (pc,) = struct.unpack_from("<Q", data, off+16)
            if bp < 0x100000 and pc > 0 and pc < nop*2:
                return off
    return None

desc_off = find_descriptor()
print("descriptor offset: 0x%X" % desc_off if desc_off else "descriptor NOT found")

runs = []
phys_pages = 0
if desc_off is not None:
    (nor,) = struct.unpack_from("<I", data, desc_off)
    (nop,) = struct.unpack_from("<I", data, desc_off+4)
    runs = []
    p = desc_off + 8
    for i in range(nor):
        (bp,) = struct.unpack_from("<Q", data, p)
        (pc,) = struct.unpack_from("<Q", data, p+8)
        runs.append((bp, pc))
        p += 16
    # pages are stored sequentially after the descriptor block
    page_data_start = desc_off + 8 + nor*16
    print("runs:", nor, "pages total:", nop, "page_data_start: 0x%X" % page_data_start)

# Build fast lookup: physical page -> file offset (compressed runs). For query, scan runs.
def read_phys(pa):
    pg = pa // PAGE
    off_in_pg = pa % PAGE
    # find run containing pg
    for (bp, pc) in runs:
        if bp <= pg < bp + pc:
            idx = pg - bp
            file_off = page_data_start + idx*PAGE + off_in_pg
            if file_off + 8 <= len(data):
                return struct.unpack_from("<Q", data, file_off)[0]
            return None
    return None

def va2pa(va):
    pml4 = cr3 & PFN_MASK
    pml4_idx = (va >> 39) & 0x1FF
    pdpt_idx = (va >> 30) & 0x1FF
    pd_idx = (va >> 21) & 0x1FF
    pt_idx = (va >> 12) & 0x1FF
    off = va & 0xFFF
    e = read_phys(pml4 + pml4_idx*8)
    if e is None or not (e & 1): return None
    e = read_phys((e & PFN_MASK) + pdpt_idx*8)
    if e is None or not (e & 1): return None
    if e & (1<<7): return (e & PFN_MASK) + (va & 0x3FFFFFFF)
    e = read_phys((e & PFN_MASK) + pd_idx*8)
    if e is None or not (e & 1): return None
    if e & (1<<7): return (e & PFN_MASK) + (va & 0x1FFFFF)
    e = read_phys((e & PFN_MASK) + pt_idx*8)
    if e is None or not (e & 1): return None
    return (e & PFN_MASK) + off

# Test translation on PsLoadedModuleList itself (should work)
test_pa = va2pa(psmodlist)
print("PsLoadedModuleList PA: 0x%X" % (test_pa if test_pa else 0))

def read_unistr(va):
    pa = va2pa(va)
    if pa is None: return "?"
    # UNICODE_STRING: Length(2) at pa, Buffer(8) at pa+8
    (ln,) = struct.unpack_from("<H", data, _pa_to_file(pa))
    (bufva,) = struct.unpack_from("<Q", data, _pa_to_file(pa+8))
    bufpa = va2pa(bufva)
    if bufpa is None: return "?"
    raw = data[_pa_to_file(bufpa): _pa_to_file(bufpa)+ln]
    try: return raw.decode("utf-16-le", errors="replace")
    except: return "?"

def _pa_to_file(pa):
    pg = pa // PAGE
    off_in_pg = pa % PAGE
    for (bp, pc) in runs:
        if bp <= pg < bp + pc:
            idx = pg - bp
            return page_data_start + idx*PAGE + off_in_pg
    return 0

# Walk module list
print("\n=== MODULES (searching fault 0x%X) ===" % FAULT)
fault_name = None
cur = psmodlist  # points to InLoadOrderLinks of first module (LIST_ENTRY)
count = 0
seen = set()
# The LIST_ENTRY Flink is at the start; module entry base = cur - 0 (InLoadOrderLinks IS first field)
# DllBase at offset 0x20, SizeOfImage at 0x30, BaseDllName UNICODE_STRING at 0x48
for _ in range(400):
    pa = va2pa(cur)
    if pa is None: break
    flink = struct.unpack_from("<Q", data, _pa_to_file(pa))[0]
    dllbase = struct.unpack_from("<Q", data, _pa_to_file(pa+0x20))[0]
    sizeimg = struct.unpack_from("<I", data, _pa_to_file(pa+0x30))[0]
    basename_va = struct.unpack_from("<Q", data, _pa_to_file(pa+0x48+8))[0]  # BaseDllName.Buffer at +0x48+8
    name = read_unistr(pa+0x48)
    if cur in seen: break
    seen.add(cur)
    inrange = dllbase <= FAULT < dllbase + sizeimg if dllbase else False
    if inrange: fault_name = name
    if name and ('.sys' in name or inrange):
        flag = "  <<< FAULT HERE" if inrange else ""
        print("  0x%X-0x%X %s%s" % (dllbase, dllbase+sizeimg, name, flag))
    cur = flink
    count += 1
    if flink == 0 or flink == psmodlist: break

print("\nTOTAL modules walked:", count)
print("FAULT MODULE:", fault_name)
