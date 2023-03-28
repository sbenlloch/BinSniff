import elftools
from elftools.elf.segments import InterpSegment
from elftools.elf.dynamic import DynamicSection
from elftools.elf.constants import SH_FLAGS
from elftools.elf.enums import ENUM_D_TAG
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import (
    NoteSection, SymbolTableSection)
from elftools.elf.descriptions import (
    describe_ei_class, describe_ei_data, describe_ei_version,
    describe_ei_osabi, describe_e_type, describe_e_machine,
    describe_e_version_numeric, describe_p_type, describe_p_flags,
    describe_sh_flags,
    describe_symbol_type, describe_symbol_bind, describe_note,
    describe_symbol_other
    )

from pwn import ELF
import math
from .utils import _log

def file_header(file, out=False) -> dict:
    """
        Get the ELF file header
    """

    elffile = ELFFile(file)

    # Magic number
    magicnumber = " ".join("%2.2x" % b for b in elffile.e_ident_raw)
    header = elffile.header
    e_ident = header["e_ident"]
    # File class
    ei_class = describe_ei_class(e_ident["EI_CLASS"])
    # Data encoding
    ei_data = describe_ei_data(e_ident["EI_DATA"])
    # ELF header version
    ei_version = describe_ei_version(e_ident["EI_VERSION"])
    # ABI of ELF
    ei_osabi = describe_ei_osabi(e_ident["EI_OSABI"])
    # ABI Version
    abiversion = e_ident["EI_ABIVERSION"]
    # Object file type
    try:
        e_type = describe_e_type(header["e_type"], elffile)
    except:
        e_type = "<Unknown>"
    # Required Architecture
    e_machine = describe_e_machine(header["e_machine"])
    # Object file version
    e_version = describe_e_version_numeric(header["e_version"])
    # Entry point
    e_entry = header["e_entry"]
    # Program header table offset
    e_phoff = header["e_phoff"]
    # Section header table offset
    e_shoff = header["e_shoff"]
    # Processor specific flags
    e_flags = header['e_flags']
    # Header size
    e_ehsize = header["e_ehsize"]
    # Size of one entry in program header table
    e_phentsize = header["e_phentsize"]
    # Number of entries in Program header table
    e_phnum = header["e_phnum"]
    # Size of entry in sections header
    e_shentsize = header["e_shentsize"]
    # Number of entries in Section header
    e_shnum = header["e_shnum"]
    e_shnum_realcount = elffile.num_sections()
    # Section header table index of the entry associated with the
    # section name string table.
    e_shstrndx = header['e_shstrndx']
    e_shstrndx_realcount = elffile.get_shstrndx()

    file_header = {}

    file_header["MAGIC"] = magicnumber
    file_header["BITNESS"] = 32 if ei_class == 1 else 64
    file_header["ENCODING"] = "LSB" if ei_data == 1 else "MSB"
    file_header["HEADER_VERSION"] = ei_version
    file_header["OS_ABI"] = ei_osabi
    file_header["ABI_VERSION"] = abiversion
    file_header["OBJECT_TYPE"] = e_type
    file_header["ARCH"] = e_machine
    file_header["OBJECT_VERSION"] = e_version
    file_header["ENTRYPOINT"] = e_entry
    file_header["PROGRAM_HEADER"] = e_phoff
    file_header["SECTION_TABLE"] = e_shoff
    file_header["PROCESSOR_FLAGS"] = e_flags
    file_header["HEADER_SIZE"] = e_ehsize
    file_header["PROGRAM_HEADER_SIZE"] = e_phentsize
    file_header["PROGRAM_HEADER_ENTRIES"] = e_phnum
    file_header["SECTION_HEADER_SIZE"] = e_shentsize
    file_header["SECTION_HEADER_ENTRIES"] = e_shnum
    file_header["SECTION_HEADER_ENTRIES_COUNT"] = e_shnum_realcount
    file_header["STRING_TABLE_INDEX"] = e_shstrndx
    file_header["STRING_TABLE_INDEX_COUNT"] = e_shstrndx_realcount

    if out:
        print("ELF Header:")
        print(f"  Magic:   {magicnumber}")
        print(f"  Class:                             {ei_class}")
        print(f"  Data:                              {ei_data}")
        print(f"  Version:                           {ei_version}")
        print(f"  OS/ABI:                            {ei_osabi}")
        print(f"  ABI Version:                       {abiversion}")
        print(f"  Type:                              {e_type}")
        print(f"  Machine:                           {e_machine}")
        print(f"  Version:                           {e_version}")
        print(f"  Entry point address:               {e_entry}")
        print(f"  Start of program headers:          {e_phoff} (bytes into file)")
        print(f"  Start of section headers:          {e_shoff} (bytes into file)")
        print(f"  Flags:                             {e_flags}")
        print(f"  Size of this header:               {e_ehsize} (bytes)")
        print(f"  Size of program headers:           {e_phentsize} (bytes)")
        print(f"  Number of program headers:         {e_phnum}")
        print(f"  Size of section headers:           {e_shentsize} (bytes)")
        print(f"  Number of section headers:         {e_shnum} ({e_shnum_realcount})")
        print(f"  Section header string table index: {e_shstrndx} ({e_shnum_realcount})")

    return file_header

def section_headers(file) -> dict:
    """
        Get info about sections
    """
    elffile = ELFFile(file)

    section_header = {}

    # To know if there are writable and executable sections,
    # something that is not usual in benign programs,
    # this key is used to indicate the number of
    # writable and executable sections.
    section_header["WRITE_AND_EXEC_SECTION"] = 0

    for idx, section in enumerate(elffile.iter_sections()):
        name = section.name
        if section.name == '':
            name = f"nonamesection_{idx}"

        section_header[name] =  {
                                            "SECTION_ADDR"  : section["sh_addr"],
                                            "SECTION_SIZE"  : section["sh_size"],
                                            "SECTION_FLAGS" : section["sh_flags"],
                                        }

        flags = describe_sh_flags(section["sh_flags"])
        if 'X' in flags and 'W' in flags:
            section_header["WRITE_AND_EXEC_SECTION"]+=1


    return section_header

def program_headers(file) -> dict:
    """
        Get info about segments
    """
    elffile = ELFFile(file)

    program_header = {}

    program_header["WRITE_AND_EXEC_SEGMENTS"] = 0

    for idx, segment in enumerate(elffile.iter_segments()):

        program_header[f"SEGMENT_{idx}"] = \
            {
                "TYPE"          : describe_p_type(segment["p_type"]),
                "OFFSET"        : segment["p_offset"],
                "VIRTUAL_ADDR"  : segment["p_vaddr"],
                "PHYSICAL_ADDR" : segment["p_paddr"],
                "FILE_SIZE"     : segment["p_filesz"],
                "MEMORY_SIZE"   : segment["p_memsz"],
                "ALIGN"         : segment["p_align"],
                "FLAGS"         : segment["p_flags"],
            }

        sections = []
        for section in elffile.iter_sections():

            if ( not section.is_null() and
                 not ((section['sh_flags'] & SH_FLAGS.SHF_TLS) != 0 and
                       section['sh_type'] == 'SHT_NOBITS' and
                       segment['p_type'] != 'PT_TLS') and
                 segment.section_in_segment(section)):

                sections.append(section.name)

        program_header[f"SEGMENT_{idx}"]["CONTAINED_SECTIONS"] = sections

        flags = describe_p_flags(segment["p_flags"])
        if 'X' in flags and 'W' in flags:
            program_header["WRITE_AND_EXEC_SEGMENTS"]+=1

        if isinstance(segment, InterpSegment):
            program_header["INTERPRETER"] = segment.get_interp_name()

    return program_header

def dynamic_section(file) -> dict:
    """
        Get info about dynamic section
    """
    elffile = ELFFile(file)

    dynamic_section = {}
    dynamic_section["HAS_DYNAMIC_SECTION"] = False
    dynamic_section["SHARED_LIBRARIES"] = []
    dynamic_section["LIBRARIES_SONAME"] = []
    try:
        for section in elffile.iter_sections():
            if not isinstance(section, DynamicSection):
                continue

            dynamic_section["HAS_DYNAMIC_SECTION"] = True
            dynamic_section[f"DYNAMIC_SECTION_OFFSET"] = section["sh_offset"]
            dynamic_section[f"NUMBER_DYNAMIC_TAGS"] = section.num_tags()

            tags = []
            for tag in section.iter_tags():

                # SWITCH
                match tag.entry.d_tag:
                    case "DT_NEEDED":
                        dynamic_section["SHARED_LIBRARIES"].append(tag.needed)
                        parsed = {"SHARED_LIBRARY" : tag.needed}

                    case "DT_RPATH":
                        parsed = { "LIBRARY_RPATH" : tag.rpath }

                    case "DT_RUNPATH":
                        parsed = { "LIBRARY_RUNPATH" : tag.runpath }

                    case "DT_SONAME":
                        dynamic_section["LIBRARIES_SONAME"].append(tag.soname)
                        parsed = { "LIBRARY_SONAME" : tag.soname }

                    case "DT_FLAGS":
                        parsed = tag.entry.d_val

                    case "DT_FLAGS_1":
                        parsed = tag.entry.d_val

                    case "DT_PLTREL":
                        parsed = tag.entry.d_val

                    case "DT_MIPS_FLAGS":
                        parsed = tag.entry.d_val
                    case "DT_MIPS_SYMTABNO":
                        parsed = tag.entry.d_val

                    case "DT_MIPS_LOCAL_GOTNO":
                        parsed = tag.entry.d_val

                    case _:
                        parsed = tag["d_val"]

                value = ENUM_D_TAG.get(tag.entry.d_tag, tag.entry.d_tag)
                tagtype = tag.entry.d_tag[3:]
                tags.append({
                                "VALUE"    : value,
                                "TAG_TYPE" : tagtype,
                                "CONTENT"     : parsed,
                            })


            dynamic_section[f"DYNAMIC_TAGS"] = tags

    except AttributeError:
        _log("W", "Skipping dynamic sections")
        pass


    return dynamic_section

def symbol_tables(file) -> dict:
    """
        Get info about symbol tables
    """

    elffile = ELFFile(file)

    symbol_tables = [s for s in elffile.iter_sections()
                        if isinstance(s, SymbolTableSection)]

    symbol_tables_out = {}
    symbol_tables_out["SYMBOL_TABLE_SECTIONS"] = []

    for section in symbol_tables:
        if not isinstance(section, SymbolTableSection):
            continue

        if section["sh_entsize"] == 0:
            symbol_tables_out["SYMBOL_TABLE_SECTIONS"].append({"NAME" : section.name, "ENTRIES" : 0})
            continue


        dyn = {
                "NAME" : section.name,
                "NUM_ENTRIES" : section.num_symbols(),
                "SYMBOLS" : []}

        for symbol in section.iter_symbols():

            symbol_name = symbol.name
            try:
                if ( symbol["st_info"]["type"] == "STT_SECTION"  and
                    symbol["st_shndx"] < elffile.num_sections() and
                    symbol["st_name"] == 0
                ):
                    symbol_name = elffile.get_section(symbol["st_shndx"]).name
            except:
                pass

            dyn["SYMBOLS"].append({
                                    "NAME"     : symbol_name,
                                    "ST_VALUE" : symbol["st_value"],
                                    "ST_SIZE"  : symbol["st_size"],
                                    "TYPE"     : describe_symbol_type(symbol["st_info"]["type"]),
                                    "ST_INFO"  : describe_symbol_bind(symbol["st_info"]["bind"]),
                                    "ST_OTHER" : describe_symbol_other(symbol["st_other"]),
                                 })

        symbol_tables_out["SYMBOL_TABLE_SECTIONS"].append(dyn)

    return symbol_tables_out

def notes(file) -> dict:
    """
        Get notes
    """
    elffile = ELFFile(file)
    notes = {"NOTES" : []}

    for section in elffile.iter_sections():
        if not isinstance(section, NoteSection):
            continue

        for note in section.iter_notes():
            n = {
                    "SECTION_NAME" : section.name,
                    "NOTE_NAME"    : note["n_name"],
                    "N_DESC"       : note["n_descsz"],
                    "NOTE"         : describe_note(note),
                }
            notes["NOTES"].append(n)

    return notes

def entropy(data) -> float:

    freq_dict = {}
    file_size = 0
    ent = 0.0

    # Calculate frequency of each byte
    for byte in data:
        freq_dict[byte] = freq_dict.get(byte, 0) + 1
        file_size += 1

    # Calculate entropy
    for count in freq_dict.values():
        probability = count / file_size
        ent -= probability * math.log2(probability)

    return ent


def section_entropy(file) -> dict:
    """
    Calculate the entropy of each section of a binary file.

    Args:
        file: file descriptor with the binary.

    Returns:
        dict: A dictionary with the entropy of each section.
    """
    elf = ELFFile(file)

    entropies = {}
    for section in elf.iter_sections():
        section_data = section.data()
        if section_data:
            entropies[section.name] = entropy(section_data)

    return entropies

def elfparse(binary) -> dict:
    """
    Feature extraction for ELF files

    Extraction of features from an ELF file. The function retrieves
    information from the file header, section header, program header,
    dynamic section, symbol tables, and notes.

    Args:
        binary (str): Path of the ELF file to parse.

    Returns:
        dict: A dictionary containing all the extracted features.

    Raises:
        Exception: Raised when there is an error during feature extraction.

    """

    features = {}
    with open(binary, "rb") as file:
        try:
            features["ENTROPIES"] = section_entropy(file)
            features.update(file_header(file))
            features.update(section_headers(file))
            features.update(program_headers(file))
            features.update(dynamic_section(file))
            features.update(symbol_tables(file))
            features.update(notes(file))
        except elftools.common.exceptions.ELFParseError:
            _log("W", "ELFParseError catched")
            return features
        except:
            raise Exception("ELF file extraction failure")

    return features

def elfsecparse(binary) -> dict:
    """
    Parse file to get security mitigations applied to ELF.
    Args:
        binary (str): Path of the ELF file to parse.

    Returns:
        dict: A dictionary containing all features related to security mitigations.
    """
    try:
        sec = ELF(binary, checksec = False)

        return {
            "Arch": sec.arch,
            "RELRO": sec.relro,
            "Stack": sec.canary,
            "NX": sec.nx,
            "PIE": sec.pie,
            "FORTIFY": sec.fortify
        }

    except:
        _log("W", "Pwnlib parsing error, returning empty dictionary")
        return {}
