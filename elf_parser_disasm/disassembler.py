from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_MODE_LITTLE_ENDIAN

def disassemble(code_bytes, base_addr=0):
    md = Cs(CS_ARCH_X86, CS_MODE_64 | CS_MODE_LITTLE_ENDIAN)
    for insn in md.disasm(code_bytes, base_addr):
        yield f"0x{insn.address:016x}: {insn.mnemonic} {insn.op_str}"
