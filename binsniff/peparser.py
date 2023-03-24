import hashlib
import base64

import pefile

def peparse(filepath) -> dict:
    """
    Feature extraction for PE files

    Extraction of features from an PE file. The function retrieves
    information from the file header, optional header, and diferent sections.

    Args:
        binary (str): Path of the PE file to parse.

    Returns:
        dict: A dictionary containing all the extracted features.

    """

    pe = pefile.PE(filepath)

    # Extracting basic PE header information
    header = {}
    if pe.FILE_HEADER is not None:
        header = {
            "machine_type": pe.FILE_HEADER.Machine,
            "number_of_sections": pe.FILE_HEADER.NumberOfSections,
            "time_date_stamp": hex(pe.FILE_HEADER.TimeDateStamp),
            "pointer_to_symbol_table": hex(pe.FILE_HEADER.PointerToSymbolTable),
            "number_of_symbols": pe.FILE_HEADER.NumberOfSymbols,
            "size_of_optional_header": pe.FILE_HEADER.SizeOfOptionalHeader,
            "characteristics": hex(pe.FILE_HEADER.Characteristics)
        }

    # Extracting optional header information
    optional_header = {}
    if pe.OPTIONAL_HEADER is not None:
        optional_header = {
            "magic": hex(pe.OPTIONAL_HEADER.Magic),
            "major_linker_version": pe.OPTIONAL_HEADER.MajorLinkerVersion,
            "minor_linker_version": pe.OPTIONAL_HEADER.MinorLinkerVersion,
            "size_of_code": pe.OPTIONAL_HEADER.SizeOfCode,
            "size_of_initialized_data": pe.OPTIONAL_HEADER.SizeOfInitializedData,
            "size_of_uninitialized_data": pe.OPTIONAL_HEADER.SizeOfUninitializedData,
            "address_of_entry_point": hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
            "base_of_code": hex(pe.OPTIONAL_HEADER.BaseOfCode),
            "image_base": hex(pe.OPTIONAL_HEADER.ImageBase),
            "section_alignment": pe.OPTIONAL_HEADER.SectionAlignment,
            "file_alignment": pe.OPTIONAL_HEADER.FileAlignment,
            "major_operating_system_version": pe.OPTIONAL_HEADER.MajorOperatingSystemVersion,
            "minor_operating_system_version": pe.OPTIONAL_HEADER.MinorOperatingSystemVersion,
            "major_image_version": pe.OPTIONAL_HEADER.MajorImageVersion,
            "minor_image_version": pe.OPTIONAL_HEADER.MinorImageVersion,
            "major_subsystem_version": pe.OPTIONAL_HEADER.MajorSubsystemVersion,
            "minor_subsystem_version": pe.OPTIONAL_HEADER.MinorSubsystemVersion,
            "size_of_image": pe.OPTIONAL_HEADER.SizeOfImage,
            "size_of_headers": pe.OPTIONAL_HEADER.SizeOfHeaders,
            "checksum": hex(pe.OPTIONAL_HEADER.CheckSum),
            "subsystem": pe.OPTIONAL_HEADER.Subsystem,
            "dll_characteristics": hex(pe.OPTIONAL_HEADER.DllCharacteristics),
            "size_of_stack_reserve": pe.OPTIONAL_HEADER.SizeOfStackReserve,
            "size_of_stack_commit": pe.OPTIONAL_HEADER.SizeOfStackCommit,
            "size_of_heap_reserve": pe.OPTIONAL_HEADER.SizeOfHeapReserve,
            "size_of_heap_commit": pe.OPTIONAL_HEADER.SizeOfHeapCommit,
            "loader_flags": hex(pe.OPTIONAL_HEADER.LoaderFlags),
            "number_of_rva_and_sizes": pe.OPTIONAL_HEADER.NumberOfRvaAndSizes
        }

    # Extracting section information
    sections = []
    for section in pe.sections:
        section_data = {
            "name": section.Name.decode().rstrip('\x00'),
            "virtual_address": hex(section.VirtualAddress),
            "virtual_size": section.Misc_VirtualSize,
            "raw_size": section.SizeOfRawData,
            "raw_data_offset": hex(section.PointerToRawData),
            "characteristics": hex(section.Characteristics)
        }
        sections.append(section_data)

    # Extracting import table information
    import_table = []
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        import_data = {
            "dll_name": entry.dll.decode().rstrip('\x00'),
            "imports": []
        }
        for imp in entry.imports:
            import_data["imports"].append(imp.name.decode().rstrip('\x00'))
        import_table.append(import_data)

    # Extracting export table information
    export_table = []
    if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
        for entry in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            export_data = {
                "name": entry.name.decode().rstrip('\x00'),
                "address": hex(entry.address),
                "ordinal": entry.ordinal
            }
            export_table.append(export_data)

    # Extracting resources information
    resources = []
    if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
        for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
            if hasattr(resource_type, 'directory'):
                for resource_id in resource_type.directory.entries:
                    if hasattr(resource_id, 'directory'):
                        for resource_lang in resource_id.directory.entries:
                            data = pe.get_data(resource_lang.data.struct.OffsetToData,
                                                        resource_lang.data.struct.Size)
                            data_hash = hashlib.md5(data).hexdigest()
                            try:
                                resource_data = {
                                    "type": resource_type.name,
                                    "name": resource_id.name,
                                    "language": resource_lang.name,
                                    "data": data.decode("utf-8"),
                                    "hash_data" : data_hash,
                                }
                            except:
                                resource_data = {
                                    "type": resource_type.name,
                                    "name": resource_id.name,
                                    "language": resource_lang.name,
                                    "data": base64.b64encode(data).decode("utf-8"),
                                    "hash" : data_hash,
                                    }
                            resources.append(resource_data)

    # Creating dictionary with all the extracted information
    features = {
        "HEADER": header,
        "OPTIONAL_HEADER": optional_header,
        "SECTIONS": sections,
        "IMPORT_TABLE": import_table,
        "EXPORT_TABLE": export_table,
        "RESOURCES": resources
    }

    return features
