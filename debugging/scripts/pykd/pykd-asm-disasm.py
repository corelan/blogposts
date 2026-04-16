# PyKD Script
# Written by corelanc0d3r
# www.corelan.be

import re
import pykd


arch = 64 if pykd.is64bitSystem() else 32
ip_reg = "rip" if arch == 64 else "eip"
ip_val = int(pykd.reg(ip_reg))


def ptrstr(v):
    if arch == 64:
        return "%016x" % (int(v) & 0xffffffffffffffff)
    return "%08x" % (int(v) & 0xffffffff)


def to_hex(data):
    if data is None:
        return ""

    try:
        return " ".join("%02x" % (int(b) & 0xff) for b in data)
    except Exception:
        return str(data)


def hex_to_list(hexstring):
    s = str(hexstring).lower()
    s = s.replace("\\x", "")
    s = s.replace("0x", "")
    s = "".join(c for c in s if c in "0123456789abcdef")

    if len(s) % 2 != 0:
        raise ValueError("Opcode hex string must contain an even number of hex digits")

    return [int(s[i:i+2], 16) for i in range(0, len(s), 2)]


def parse_disasm_line(line):
    """
    Examples:
        77566a31 ffe4            jmp     esp
        77566a31 8bc3            mov     eax,ebx
        00007ff6`12345678 4889d8          mov     rax,rbx

    Returns:
        (opcode, instruction)
    """
    s = str(line).strip()
    m = re.match(r'^[0-9A-Fa-f`]+\s+([0-9A-Fa-f]+)\s+(.+)$', s)
    if not m:
        return "", s
    return m.group(1).lower(), m.group(2).strip()


def get_disasm_parts(address):
    d = pykd.disasm(address)
    line = str(d)
    return parse_disasm_line(line)


def get_current_disasm_line():
    d = pykd.disasm(ip_val)
    return str(d)


# ----------------------------------------------------------------------
# Assemble instruction -> opcode + instruction
# ----------------------------------------------------------------------
def assemble_instruction(instr, address):
    backup_len = 20
    original = None

    try:
        original = pykd.loadBytes(address, backup_len)

        d = pykd.disasm(address)
        d.asm(instr)

        opcode, instruction = get_disasm_parts(address)
        return opcode, instruction

    finally:
        if original is not None:
            try:
                pykd.writeBytes(address, list(original))
            except Exception as e:
                pykd.dprintln("[-] Failed to restore original bytes at 0x%s" % ptrstr(address))
                pykd.dprintln("    %s" % str(e))


# ----------------------------------------------------------------------
# Opcode -> instruction
# ----------------------------------------------------------------------
def disassemble_opcode(opcodes, address):
    backup_len = max(20, len(opcodes))
    original = None

    try:
        original = pykd.loadBytes(address, backup_len)

        pykd.writeBytes(address, list(opcodes))

        opcode, instruction = get_disasm_parts(address)
        return opcode, instruction

    finally:
        if original is not None:
            try:
                pykd.writeBytes(address, list(original))
            except Exception as e:
                pykd.dprintln("[-] Failed to restore original bytes at 0x%s" % ptrstr(address))
                pykd.dprintln("    %s" % str(e))


# ----------------------------------------------------------------------
# Demo
# ----------------------------------------------------------------------

pykd.dprintln("")
pykd.dprintln("[+] Architecture : %d-bit" % arch)
pykd.dprintln("[+] %s = 0x%s" % (ip_reg, ptrstr(ip_val)))
pykd.dprintln("[+] Current instruction:")
pykd.dprintln("    %s" % get_current_disasm_line())

# ----------------------------------------------------------------------
# Instruction -> opcode
# ----------------------------------------------------------------------
instructions = []
if arch == 32:
    instructions = ["jmp esp", "mov eax, ebx"]
else:
    instructions = ["jmp rsp", "mov rax, rbx"]

for instr in instructions:
    pykd.dprintln("")
    pykd.dprintln("[+] Assemble: %s" % instr)

    try:
        opcode, decoded_instr = assemble_instruction(instr, ip_val)
        pykd.dprintln("[+] Opcode      : %s" % opcode)
        pykd.dprintln("[+] Instruction : %s" % decoded_instr)
    except Exception as e:
        pykd.dprintln("[-] Error: %s" % str(e))

# ----------------------------------------------------------------------
# Opcode -> instruction
# ----------------------------------------------------------------------
opcode_sequences = []
if arch == 32:
    opcode_sequences = ["ff e4", "8b c3"]
else:
    opcode_sequences = ["48 89 d8", "ff e4"]

for seq in opcode_sequences:
    pykd.dprintln("")
    pykd.dprintln("[+] Disassemble opcode: %s" % seq)

    try:
        op_list = hex_to_list(seq)
        opcode, instr = disassemble_opcode(op_list, ip_val)

        pykd.dprintln("[+] Opcode      : %s" % opcode)
        pykd.dprintln("[+] Instruction : %s" % instr)

    except Exception as e:
        pykd.dprintln("[-] Error: %s" % str(e))