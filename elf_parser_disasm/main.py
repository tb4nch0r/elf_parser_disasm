import sys
from elf_parser import read_bytes, parse_elf_header, parse_sections
from disassembler import disassemble

EI_CLASS    = {1: "ELF32", 2: "ELF64"}
EI_DATA     = {1: "2's complement, little endian", 2: "2's complement, big endian"}
EI_VERSION  = {0: "0 (EV_NONE)", 1: "1 (EV_CURRENT)"}
EI_OSABI    = {0: "UNIX - System V", 3: "Linux"}
ELF_FILE_TYPES = {
    0: "ET_NONE (No file type)",
    1: "ET_REL (Relocatable file)",
    2: "ET_EXEC (Executable file)",
    3: "ET_DYN (Shared object file)",
    4: "ET_CORE (Core file)"
}
MACHINE_ARCH_TYPES = {
        0X00: "No machine",
        0x03: "Intel 80386",
        0x08: "MIPS",
        0x14: "PowerPC",
        0x28: "ARM",
        0x32: "Intel IA-64",
        0x3e: "AMD x86-64",
        0xb7: "ARM AArch64"
}


def print_header(hdr):
    print("ELF Header:")
    print(f"  {'Magic:':<30} {' '.join(f'{b:02x}' for b in hdr['magic'])}")
    print(f"  {'Class:':<30} {EI_CLASS.get(hdr['class'], hdr['class'])}")
    print(f"  {'Data:':<30} {EI_DATA.get(hdr['data'], hdr['data'])}")
    print(f"  {'Version:':<30} {EI_VERSION.get(hdr['version'], hdr['version'])}")
    print(f"  {'OS/ABI:':<30} {EI_OSABI.get(hdr['osabi'], hdr['osabi'])}")
    print(f"  {'ABI Version:':<30} {hdr['abi_ver']}")
    print(f"  {'Type:':<30} {ELF_FILE_TYPES.get(hdr['type'], hdr['type'])}")
    print(f"  {'Machine:':<30} {MACHINE_ARCH_TYPES.get(hdr['machine'], hex(hdr['machine']))}")
    print(f"  {'Version:':<30} {hex(hdr['version2'])}")
    print(f"  {'Entry point address:':<30} {hex(hdr['entry'])}")
    print(f"  {'Start of program headers:':<30} {hdr['phoff']} (bytes into file)")
    print(f"  {'Start of section headers:':<30} {hdr['shoff']} (bytes into file)")
    print(f"  {'Flags:':<30} {hex(hdr['flags'])}")
    print(f"  {'Size of this header:':<30} {hdr['ehsize']} (bytes)")
    print(f"  {'Size of program headers:':<30} {hdr['phentsz']} (bytes)")
    print(f"  {'Number of program headers:':<30} {hdr['phnum']}")
    print(f"  {'Size of section headers:':<30} {hdr['shentsz']} (bytes)")
    print(f"  {'Number of section headers:':<30} {hdr['shnum']}")
    print(f"  {'Section header string table index:':<30} {hdr['shstrndx']}")


def main(path):
    hdr = parse_elf_header(path)
    print_header(hdr)

    sections = parse_sections(path, hdr)
    text = next((s for s in sections if s['name'] == '.text'), None)
    if not text:
        print(".text not found")
        sys.exit(1)

    code = read_bytes(path, text['offset'], text['size'])
    print("\n=== Disassembly (.text) ===")
    for line in disassemble(code, text['addr']):
        print(line)


if __name__ == '__main__':
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <elf-file>")
        sys.exit(1)
    main(sys.argv[1])
