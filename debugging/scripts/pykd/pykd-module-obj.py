# PyKD Script
# Written by corelanc0d3r
# www.corelan.be

import pykd
import os


def _to_text(s, encoding='latin-1'):
    if isinstance(s, bytes):
        return s.decode(encoding)
    return s

def printPtr(value):
    try:
        ival = int(value)
    except:
        ival = 0

    if arch == 64:
        width = 16
    else:
        width = 8

    # keep only the relevant pointer-sized bits
    mask = (1 << (width * 4)) - 1
    ival &= mask

    return ("%0" + str(width) + "x") % ival


def getPID():
    teb = pykd.typedVar("_TEB", pykd.getImplicitThread())
    offset = 0x20
    if arch == 64:
        offset = 0x40
    # _TEB.ClientId(CLIENT_ID).UniqueProcess(PVOID)
    pid = pykd.ptrDWord(teb+offset)
    return pid

arch = 32
if pykd.is64bitSystem():
    arch = 64

processID  = getPID()
pebAddress = pykd.getCurrentProcess()

pykd.dprintln("Current PID: 0x%x" % processID)
pykd.dprintln("PEB found at 0x%08x" % pebAddress)

moduleList = pykd.getModulesList()

for thismod in moduleList:
    # thismod is already an object

    pykd.dprintln("\nAccessing thismod object: %s" % thismod.name())

    pykd.dprintln("Creating a new module() using the name")
    thismodobj1 = pykd.module(thismod.name())
    modbase    = thismodobj1.begin()
    modimage   = thismodobj1.image()
    modname    = thismodobj1.name()

    formatted_base = printPtr(modbase)
    pykd.dprintln(f"-> Module at 0x{formatted_base} : Image: {_to_text(modimage)}, Name: {_to_text(modname)}")

    pykd.dprintln("Creating a new module() using the actual object")
    thismodobj2 = pykd.module(thismod)
    modbase    = thismodobj2.begin()
    modimage   = thismodobj2.image()
    modname    = thismodobj2.name()

    formatted_base = printPtr(modbase)
    pykd.dprintln(f"-> Module at 0x{formatted_base} : Image: {_to_text(modimage)}, Name: {_to_text(modname)}")


