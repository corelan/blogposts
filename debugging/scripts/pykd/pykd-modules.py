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

def print_modules(title, moduleList):
    pykd.dprintln("%d modules %s" % (len(moduleList), title))
    for mod in moduleLst:
        thisFullDllName = (pykd.loadUnicodeString(mod.FullDllName)).encode("latin-1")
        thisBaseDllName = (pykd.loadUnicodeString(mod.BaseDllName)).encode("latin-1")
   
        thismodName = os.path.basename(thisFullDllName)
        name, ext = os.path.splitext(thismodName)
        
        name = name.replace(b"+",b"_").replace(b"-",b"_").replace(b".",b"_")

        pykd_mod = pykd.module(name)
        thismodBase = pykd_mod.begin()

        formatted_base = printPtr(thismodBase)
        pykd.dprintln(f"Module at 0x{formatted_base} : {_to_text(thismodName)} :  {_to_text(thisFullDllName)}")
    pykd.dprintln("")



arch = 32
offset = 0x20
if pykd.is64bitSystem():
    arch = 64
    offset = 0x40

processID  = getPID()
pebAddress = pykd.getCurrentProcess()

pykd.dprintln("Current PID: 0x%x" % processID)
pykd.dprintln("PEB found at 0x%08x" % pebAddress)

peb = pykd.typedVar("ntdll!_PEB", pykd.getCurrentProcess())
moduleLst = pykd.typedVarList(
    peb.Ldr.deref().InLoadOrderModuleList,
    "ntdll!_LDR_DATA_TABLE_ENTRY",
    "InLoadOrderLinks.Flink"
)
print_modules("InLoadOrder", moduleLst)

moduleLst = pykd.typedVarList(
    peb.Ldr.deref().InMemoryOrderModuleList,
    "ntdll!_LDR_DATA_TABLE_ENTRY",
    "InMemoryOrderLinks.Flink"
)
print_modules("InMemoryOrder", moduleLst)

moduleLst = pykd.typedVarList(
    peb.Ldr.deref().InInitializationOrderModuleList,
    "ntdll!_LDR_DATA_TABLE_ENTRY",
    "InInitializationOrderLinks.Flink"
)
print_modules("InInitializationOrder", moduleLst)


