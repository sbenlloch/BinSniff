from typing import Tuple
import collections
import datetime
import binascii
import hashlib
import re

import angr
import IPython

import logging
logging.getLogger('angr').setLevel(logging.CRITICAL)
logging.getLogger('claripy').setLevel(logging.CRITICAL)
logging.getLogger('cle').setLevel(logging.CRITICAL)
logging.getLogger('archinfo').setLevel(logging.CRITICAL)
logging.getLogger('ailment').setLevel(logging.CRITICAL)
logging.getLogger('pyvex').setLevel(logging.CRITICAL)

def get_assembly_code(func, debug=False) -> Tuple[list[str], str]:

    asm = []

    # Get the disassembly for each basic block in the function
    for block in func.blocks:
        # Get the assembly code for the block
        assembly = block.capstone.insns

        # Print the assembly code for the block
        for insn in assembly:
            if debug: print("%s\t%s" % (insn.mnemonic, insn.op_str))
            asm.append("%s %s" % (insn.mnemonic, insn.op_str))

    h = hashlib.md5(" ".join(asm).encode('utf-8')).hexdigest()
    return asm, h

def get_code_vex(func, debug=False) -> list:

    vex = []

    # Get the disassembly for each basic block in the function
    for block in func.blocks:
        # Get the VEX IR for the block
        vex_block = block.vex

        # Print the assembly code for the block
        for stmt in vex_block.statements:
            if debug: print("%s\t%s" % (stmt.__class__.__name__, stmt))
            vex.append("%s %s" % (stmt.__class__.__name__, stmt))

    return vex

def extract_program_instruction_features(cfg) -> dict:
    # Initialize counters for instruction types and opcodes
    inst_types = collections.Counter()

    # Iterate over all basic blocks in the CFG
    for function in cfg.functions.values():
        for block in function.blocks:
            for ins in block.disassembly.insns:
                # Update counters for instruction types and opcodes
                inst_types[ins.mnemonic] += 1

    # Compute total number of instructions and unique instruction types
    num_insts = sum(inst_types.values())
    num_inst_types = len(inst_types)

    # Compute frequency of each instruction type and opcode
    inst_type_freq = {k: round(v / num_insts, 4) for k, v in inst_types.items()}

    # Return dictionary of instruction features
    return {
        'num_insts': num_insts,
        'num_inst_types': num_inst_types,
        'inst_type_freq': inst_type_freq,
    }

def get_strings(project, debug=False) -> list:

    # Avoiding duplicates
    strings_vault = set()

    # Taking into account only .rodata

    # Read .rodata if exists
    if '.rodata' in project.loader.main_object.sections_map:
        rodata_addr = project.loader.main_object.sections_map['.rodata'].vaddr
        rodata_size = project.loader.main_object.sections_map['.rodata'].memsize
        rodata_contents = project.loader.memory.load(rodata_addr, rodata_size)
        strings = rodata_contents.split(b'\x00')
        for string in strings:
            if not string:
                continue

            try:

                strings_vault.add(string.decode('utf-8'))
                if debug: print(string.decode('utf-8'), end='')

            except UnicodeDecodeError:

                hex_data = binascii.hexlify(string)
                strings_vault.add(str(hex_data))
                if debug: print(hex_data)


    # Taking all the file

    # Read all the file
    binary_start = project.loader.main_object.min_addr
    binary_end = project.loader.main_object.max_addr
    binary_contents = project.loader.memory.load(binary_start,
                                                    binary_end - binary_start)

    # Finging with regex
    ascii_regex = b'[\x20-\x7E]+'
    matches = re.findall(ascii_regex, binary_contents)
    for string in matches:
        if not string:
            continue
        try:

            strings_vault.add(string.decode('utf-8'))
            if debug: print(string.decode('utf-8'))

        except UnicodeDecodeError:
            pass

    return list(strings_vault)

"""
Based on string extracion, make a intelligence extraction
"""

def extract_emails(strings) -> list:
    pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'  # regular expression pattern for email addresses
    emails = set()  # use set to avoid duplicates

    for string in strings:
        matches = re.findall(pattern, string)
        emails.update(matches)

    return list(emails)

def extract_file_paths(strings) -> list:
    # Compile regular expression pattern to match file paths
    pattern = re.compile(r"/[\w/.\\-]+")
    file_paths = []

    for info in strings:

        # Extract file paths from the text
        file_paths += pattern.findall(info)

    return list(set(file_paths))

def extract_links(strings) -> list:
    pattern = r'\b((?:https?://|www\.)\S+)\b'  # regular expression pattern for internet links
    links = set()  # use set to avoid duplicates

    for string in strings:
        matches = re.findall(pattern, string)
        links.update(matches)

    return list(links)

def extract_ips(strings) -> list:
    """
    Extracts IP addresses from a given text.
    Returns a set of unique IP addresses.
    """

    valid_ips = set()
    for text in strings:

        if isinstance(text, bytes):
            text = text.decode('utf-8')

        ip_pattern = r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"
        ips = set(re.findall(ip_pattern, text))
        for ip in ips:
            octets = ip.split('.')
            if all(0 <= int(octet) < 256 for octet in octets):
                valid_ips.add(ip)

    return list(valid_ips)

def extract_years(strings) -> list:
    current_year = datetime.datetime.now().year
    years = set()

    for string in strings:
        # Use re.search to find the first occurrence of a four-digit year in the string
        m = re.search(r'\b\d{4}\b', string)

        if m:
            year = int(m.group())

            # Check if the year is within a reasonable range (e.g., 1900 to current year + 10)
            if 1900 <= year <= current_year + 10:
                # Append the year to the list if it is not already in the list
                if year not in years:
                    years.add(year)

    return list(years)

def assemparse(binary) -> dict:
    """
    Extract features from binary using Angr.

    Extract features from program from functions, strings and CFG.

    Args:
        binary (str): Path of the Binary file to parse.

    Return:
        dict: A dictionary containing all the extracted features.
    """

    features = {}
    project = angr.Project(binary, auto_load_libs = False)

    # Extract strings
    strings = get_strings(project)
    features["STRINGS"] = strings
    # Extract intelligence from strings
    features["INTELLIGENCE"] = {}
    features["INTELLIGENCE"]["files"] = extract_file_paths(strings)
    features["INTELLIGENCE"]["emails"] = extract_emails(strings)
    features["INTELLIGENCE"]["links"] = extract_links(strings)
    features["INTELLIGENCE"]["years"] = extract_years(strings)
    features["INTELLIGENCE"]["IPs"] = extract_ips(strings)

    # Get CFG
    cfg = project.analyses.CFGFast(normalize = True)
    features["INSTS_STATS" ] = extract_program_instruction_features(cfg)
    # Function feature extraction
    features["FUNCTIONS"] = []
    for _, function in cfg.functions.items():
        if function.size == 0: continue
        foo_feature = {}
        foo_feature["name"] = function.name
        try:
            foo_feature["disassembled"], foo_feature["md5"] = get_assembly_code(function)
            foo_feature["VEX"] = get_code_vex(function)
        except:
            pass

        features["FUNCTIONS"].append(foo_feature)

    return features
