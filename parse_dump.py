import struct, os

DMP = r"C:\Windows\Minidump\103126-6609-01.dmp"
FAULT = 0xfffff80057001cc3

with open(DMP, "rb") as f:
    data = f.read()

# Header
sig = data[0:4]
(num_streams,) = struct.unpack_from("<I", data, 4)
(dir_rva,) = struct.unpack_from("<I", data, 12)
print("SIG:", sig, "streams:", num_streams)

def get_stream(stype):
    off = dir_rva
    for i in range(num_streams):
        (st, sz, rva) = struct.unpack_from("<III", data, off)
        if st == stype:
            return rva, sz
        off += 12
    return None, 0

# Bugcheck stream (0xB)
rva, sz = get_stream(0xB)
if rva:
    (code,) = struct.unpack_from("<I", data, rva)
    # args: at rva+8 are 4 ULONG64
    a1, a2, a3, a4 = struct.unpack_from("<QQQQ", data, rva + 8)
    print("BUGCHECK code: 0x%X" % code)
    print("  arg1=0x%X arg2=0x%X arg3=0x%X arg4=0x%X" % (a1, a2, a3, a4))

# Module list stream (0x4)
rva, sz = get_stream(0x4)
print("\nMODULE LIST:")
fault_mod = None
if rva:
    (nmod,) = struct.unpack_from("<I", data, rva)
    base = rva + 4
    for i in range(nmod):
        mod_off = base + i * 108
        (mod_base,) = struct.unpack_from("<Q", data, mod_off)
        (mod_size,) = struct.unpack_from("<I", data, mod_off + 8)
        (name_rva,) = struct.unpack_from("<I", data, mod_off + 20)
        # name: length(4) + utf16
        (nlen,) = struct.unpack_from("<I", data, name_rva)
        raw = data[name_rva + 4: name_rva + 4 + nlen]
        try:
            name = raw.decode("utf-16-le", errors="replace")
        except Exception:
            name = "?"
        inmod = mod_base <= FAULT < mod_base + mod_size
        flag = "  <<< FAULT HERE" if inmod else ""
        if inmod:
            fault_mod = name
        # only print modules near fault or all small list
        print("  0x%X-0x%X %s%s" % (mod_base, mod_base + mod_size, name, flag))
    print("\nFAULT MODULE:", fault_mod)

# Strings extraction (ascii) to find driver hints
print("\nASCII STRINGS (driver-ish):")
seen = set()
for i in range(0, len(data) - 8):
    # find .sys / .dll names
    if data[i:i+1] in (b'.',) and data[i+4:i+5] in (b'\x00',):
        pass
import re
for m in re.finditer(rb'[A-Za-z0-9_\\:-]{4,}\.(sys|dll|exe)', data):
    s = m.group().decode('latin1')
    if s.lower() not in seen:
        seen.add(s.lower())
        if any(k in s.lower() for k in ['igd','nvld','nv','intel','nvidia','ntos','dxg','watchdog','atik','amd']):
            print("  ", s)
