import struct

def read_bytes(path, offset, size):
    with open(path, 'rb') as f:
        f.seek(offset)
        return f.read(size)

def parse_elf_header(path):
    data = read_bytes(path, 0, 64)
    if len(data) < 64:
        raise ValueError("ELF header too small")

    header = {}
    e_ident = data[:16]
    header['magic']    = e_ident
    header['class']    = e_ident[4]
    header['data']     = e_ident[5]
    header['version']  = e_ident[6]
    header['osabi']    = e_ident[7]
    header['abi_ver']  = e_ident[8]

    header['type']     = struct.unpack_from('<H', data, 16)[0]
    header['machine']  = struct.unpack_from('<H', data, 18)[0]
    header['version2'] = struct.unpack_from('<I', data, 20)[0]
    header['entry']    = struct.unpack_from('<Q', data, 24)[0]
    header['phoff']    = struct.unpack_from('<Q', data, 32)[0]
    header['shoff']    = struct.unpack_from('<Q', data, 40)[0]
    header['flags']    = struct.unpack_from('<I', data, 48)[0]
    (
            header['ehsize'], 
            header['phentsz'], 
            header['phnum'],
            header['shentsz'], 
            header['shnum'], 
            header['shstrndx']
    ) =  struct.unpack_from('<HHHHHH', data, 52)

    return header

def parse_sections(path, elf_hdr):
    sections = []
    shoff    = elf_hdr['shoff']
    shentsz  = elf_hdr['shentsz']
    shnum    = elf_hdr['shnum']
    strndx   = elf_hdr['shstrndx']

    strtab_hdr = read_bytes(path, shoff + strndx * shentsz, shentsz)
    (_, _, _, _, strtab_off, strtab_size, *_) = struct.unpack('<IIQQQQIIQQ', strtab_hdr)
    name_table = read_bytes(path, strtab_off, strtab_size)

    for i in range(shnum):
        raw = read_bytes(path, shoff + i * shentsz, shentsz)
        (name_off, stype, flags, addr, offset, size, *_) = struct.unpack('<IIQQQQIIQQ', raw)
        end = name_table.find(b'\x00', name_off)
        name = name_table[name_off:end].decode('utf-8', 'ignore')
        sections.append({
            'name': name,
            'type': stype,
            'flags': flags,
            'addr': addr,
            'offset': offset,
            'size': size
        })
    return sections
