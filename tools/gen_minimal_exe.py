#!/usr/bin/env python3
"""
=== FICHIER : tools/gen_minimal_exe.py ===
Description : Générateur d'un exécutable PE32+ minimal pour tester le loader.
              Produit un .exe valide qui ne fait rien d'autre que retourner
              le code de sortie 42.

              Le PE généré :
              - Pas d'imports (pas de DLLs)
              - Pas de relocations (image based at arbitrary address)
              - Une section .text contenant mov eax, 42; ret
              - Entry point pointant vers cette section

Usage : python3 tools/gen_minimal_exe.py -o test_minimal.exe
"""

import struct
import sys
import os

def align_up(x, a):
    return (x + a - 1) & ~(a - 1)

def generate_minimal_pe64(output_path):
    """
    Génère un PE32+ minimal avec :
    - DOS stub minimal
    - NT headers PE32+
    - Une section .text avec du code x86_64
    - Pas d'imports, pas de relocs
    """

    # === Code x86_64 ===
    # mov eax, 42  ; mov dword [dummy], eax  ; ret
    # Note: dans un vrai context, il faudrait appeler ExitProcess.
    # Pour le test du loader, on fait juste ret.
    code = bytearray([
        0xB8, 0x2A, 0x00, 0x00, 0x00,  # mov eax, 42
        0xC3,                            # ret
    ])

    # === Constantes ===
    file_alignment = 0x200      # 512 bytes
    section_alignment = 0x1000  # 4096 bytes
    image_base = 0x140000000    # Base préférée PE64 typique

    # === Construire le DOS Header ===
    dos_stub = bytearray(64)  # Taille minimale
    dos_stub[0:2] = b'MZ'
    dos_stub[0x3C:0x40] = struct.pack('<I', 64)  # e_lfanew -> juste après le DOS header

    # === NT Headers ===
    nt_headers_offset = 64
    sizeof_optional_header = 112 + 16 * 8  # 240 bytes pour PE32+
    sizeof_nt_headers = 4 + 20 + sizeof_optional_header  # signature + file + optional = 264

    # Section headers commencent après les NT headers
    sections_offset = nt_headers_offset + sizeof_nt_headers

    # Nombre de sections
    num_sections = 1

    # Taille totale des headers (alignée à file_alignment)
    sizeof_headers = align_up(sections_offset + num_sections * 40, file_alignment)

    # Tailles des sections
    virtual_size = align_up(len(code), section_alignment)
    raw_size = align_up(len(code), file_alignment)

    # Image size = première section VA + sa taille virtuelle
    section_va = section_alignment  # .text commence à RVA 0x1000
    size_of_image = align_up(section_va + virtual_size, section_alignment)

    # Entry point
    entry_point = section_va

    # === Construire le fichier ===
    output = bytearray()

    # DOS Header
    output.extend(dos_stub)

    # NT Headers Signature
    output.extend(b'PE\x00\x00')

    # File Header (20 bytes)
    output.extend(struct.pack('<H', 0x8664))  # Machine: AMD64
    output.extend(struct.pack('<H', num_sections))  # NumberOfSections
    output.extend(struct.pack('<I', 0))        # TimeDateStamp
    output.extend(struct.pack('<I', 0))        # PointerToSymbolTable
    output.extend(struct.pack('<I', 0))        # NumberOfSymbols
    output.extend(struct.pack('<H', sizeof_optional_header))  # SizeOfOptionalHeader
    output.extend(struct.pack('<H', 0x0022))   # Characteristics: EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE

    # Optional Header PE32+ (112 bytes + 16*8 = 240 bytes)
    output.extend(struct.pack('<H', 0x020B))   # Magic: PE32+
    output.extend(struct.pack('<BB', 0, 0))    # Major/MinorLinkerVersion
    output.extend(struct.pack('<I', len(code)))# SizeOfCode
    output.extend(struct.pack('<I', 0))        # SizeOfInitializedData
    output.extend(struct.pack('<I', 0))        # SizeOfUninitializedData
    output.extend(struct.pack('<I', entry_point))  # AddressOfEntryPoint
    output.extend(struct.pack('<I', section_va))   # BaseOfCode
    output.extend(struct.pack('<Q', image_base))   # ImageBase
    output.extend(struct.pack('<I', section_alignment))  # SectionAlignment
    output.extend(struct.pack('<I', file_alignment))     # FileAlignment
    output.extend(struct.pack('<H', 6))    # MajorOSVersion
    output.extend(struct.pack('<H', 0))    # MinorOSVersion
    output.extend(struct.pack('<H', 0))    # MajorImageVersion
    output.extend(struct.pack('<H', 0))    # MinorImageVersion
    output.extend(struct.pack('<H', 6))    # MajorSubsystemVersion
    output.extend(struct.pack('<H', 0))    # MinorSubsystemVersion
    output.extend(struct.pack('<I', 0))    # Win32VersionValue
    output.extend(struct.pack('<I', size_of_image))   # SizeOfImage
    output.extend(struct.pack('<I', sizeof_headers))  # SizeOfHeaders
    output.extend(struct.pack('<I', 0))    # CheckSum
    output.extend(struct.pack('<H', 3))    # Subsystem: WINDOWS_CUI (console)
    output.extend(struct.pack('<H', 0x8140))  # DllCharacteristics: DYNAMIC_BASE | NX_COMPAT | TERMINAL_SERVER_AWARE
    output.extend(struct.pack('<Q', 0x100000))  # SizeOfStackReserve: 1MB
    output.extend(struct.pack('<Q', 0x1000))    # SizeOfStackCommit: 4KB
    output.extend(struct.pack('<Q', 0x100000))  # SizeOfHeapReserve: 1MB
    output.extend(struct.pack('<Q', 0x1000))    # SizeOfHeapCommit: 4KB
    output.extend(struct.pack('<I', 0))    # LoaderFlags
    output.extend(struct.pack('<I', 16))   # NumberOfRvaAndSizes

    # Data directories (16 entries of 8 bytes each = 128 bytes)
    for i in range(16):
        output.extend(struct.pack('<II', 0, 0))  # All zero (no imports, no exports, etc.)

    # === Section Header (.text) ===
    name = b'.text\x00\x00\x00'
    output.extend(name[:8])  # Name (8 bytes, padded)
    output.extend(struct.pack('<I', virtual_size))      # VirtualSize
    output.extend(struct.pack('<I', section_va))         # VirtualAddress
    output.extend(struct.pack('<I', raw_size))           # SizeOfRawData
    output.extend(struct.pack('<I', sizeof_headers))     # PointerToRawData
    output.extend(struct.pack('<I', 0))                  # PointerToRelocations
    output.extend(struct.pack('<I', 0))                  # PointerToLinenumbers
    output.extend(struct.pack('<H', 0))                  # NumberOfRelocations
    output.extend(struct.pack('<H', 0))                  # NumberOfLinenumbers
    output.extend(struct.pack('<I', 0x60000020))         # Characteristics: CNT_CODE | MEM_EXECUTE | MEM_READ

    # === Padding jusqu'à sizeof_headers ===
    while len(output) < sizeof_headers:
        output.append(0)

    # === Section .text data ===
    output.extend(code)

    # Padding de la section jusqu'à raw_size
    while len(output) < sizeof_headers + raw_size:
        output.append(0)

    # === Écrire le fichier ===
    with open(output_path, 'wb') as f:
        f.write(output)

    print(f"[gen_minimal_exe] Generated {output_path} ({len(output)} bytes)")
    print(f"  ImageBase:    0x{image_base:X}")
    print(f"  Entry RVA:    0x{entry_point:X}")
    print(f"  Entry VA:     0x{image_base + entry_point:X}")
    print(f"  Sections:     {num_sections}")
    print(f"  Code size:    {len(code)} bytes")
    print(f"  Exit code:    42")

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('-o', '--output', default='test_minimal.exe',
                        help='Output .exe path')
    args = parser.parse_args()
    generate_minimal_pe64(args.output)
