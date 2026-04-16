# PyKD Script
# Written by corelanc0d3r
# www.corelan.be

import sys
import pykd


def print_ptr(value, arch):
    try:
        value = int(value)
    except Exception:
        value = 0

    width = 16 if arch == 64 else 8
    mask = (1 << (width * 4)) - 1
    return ("%%0%dx" % width) % (value & mask)


def bin2hex(data):
    if data is None:
        return ""

    # bytes / bytearray
    if isinstance(data, (bytes, bytearray)):
        return " ".join("%02x" % b for b in data)

    # string
    if isinstance(data, str):
        return " ".join("%02x" % ord(c) for c in data)

    # list/tuple/iterable of ints
    try:
        return " ".join("%02x" % (int(b) & 0xff) for b in data)
    except Exception:
        return ""


arch = 64 if pykd.is64bitSystem() else 32
stackreg = "rsp" if arch == 64 else "esp"
ptrsize = arch // 8

pykd.dprintln("Reading %d bytes from the stack" % ptrsize)

stackaddress = pykd.reg(stackreg)
pykd.dprintln("  %s = %s" % (stackreg, print_ptr(stackaddress, arch)))

stackbytes = pykd.loadBytes(stackaddress, ptrsize)
pykd.dprintln("  Read %s" % bin2hex(stackbytes))

pykd.dprintln("Writing %d bytes to the stack" % (ptrsize * 2))
data_to_write = b""
data_to_write += b"A" * ((ptrsize*2)-1)
data_to_write += b"\x00"

pykd.writeBytes(stackaddress, list(data_to_write))
pykd.dprintln("  Wrote %s" % bin2hex(data_to_write))

pykd.dprintln("Reading a string from the stack")
string_from_stack = pykd.loadCStr(stackaddress)
pykd.dprintln("  Read %s" % string_from_stack)