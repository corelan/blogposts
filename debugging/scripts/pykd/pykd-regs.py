# PyKD Script
# Written by corelanc0d3r
# www.corelan.be

import pykd

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

Registers32BitsOrder = ["EAX", "ECX", "EDX", "EBX", "ESP", "EBP", "ESI", "EDI", "EIP"]
Registers64BitsOrder = ["RAX", "RCX", "RDX", "RBX", "RSP", "RBP", "RSI", "RDI",
						"R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15", "RIP"]

regs = Registers32BitsOrder

arch = 32
if pykd.is64bitSystem():
    arch = 64
    regs = Registers64BitsOrder

# retrieving register values
pykd.dprintln("%sbit registers before" % arch)
for reg in regs:
    regvalue = pykd.reg(reg.lower())
    pykd.dprintln("%s : 0x%s" % (reg, printPtr(regvalue)))

# changing a register
if arch == 32:
    pykd.setReg(regs[0].lower(),0x41414141)
else:
    pykd.setReg(regs[0].lower(),0x4141414142424242)

# retrieving the updates values
pykd.dprintln("")
pykd.dprintln("%sbit registers after" % arch)
for reg in regs:
    regvalue = pykd.reg(reg.lower())
    pykd.dprintln("%s : 0x%s" % (reg, printPtr(regvalue)))
