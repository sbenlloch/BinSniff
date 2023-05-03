import collections
import datetime
import hashlib
import r2pipe
import re

def get_strings(file_path, min_length=1):
    strings_vault = set()
    ascii_regex = b'[\x20-\x7E]{' + f'{min_length}'.encode() + b',}'

    with open(file_path, 'rb') as file:
        binary_contents = file.read()
        matches = re.findall(ascii_regex, binary_contents)

        for string in matches:
            if not string:
                continue
            try:
                strings_vault.add(string.decode('utf-8'))
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

def common_features(binary) -> tuple[dict, bool]:
    """
    Analyzes a binary file to extract common features and intelligence from it.

    This function accepts a binary file as input and extracts features such as strings,
    file paths, email addresses, links, years, and IP addresses from it. The extracted
    features are then returned as a dictionary along with a boolean indicating if the
    operation was successful.

    Args:
        binary (bytes): The binary data to be analyzed.

    Returns:
        tuple[dict, bool]: A tuple containing the following elements:
            - A dictionary with the following keys:
                "STRINGS": List of extracted strings from the binary data.
                "INTELLIGENCE": A dictionary with the following keys:
                    "files": List of file paths found in the strings.
                    "emails": List of email addresses found in the strings.
                    "links": List of links found in the strings.
                    "years": List of years found in the strings.
                    "IPs": List of IP addresses found in the strings.
            - A boolean indicating if the operation was successful (True) or not (False).
    """

    features = {}

    try:
        strings = get_strings(binary)
        features["STRINGS"] = strings

        # Extract intelligence from strings
        features["INTELLIGENCE"] = {}
        features["INTELLIGENCE"]["files"] = extract_file_paths(strings)
        features["INTELLIGENCE"]["emails"] = extract_emails(strings)
        features["INTELLIGENCE"]["links"] = extract_links(strings)
        features["INTELLIGENCE"]["years"] = extract_years(strings)
        features["INTELLIGENCE"]["IPs"] = extract_ips(strings)

        return (features, False)

    except Exception as e:
        return (features, True)

"""
Assembly code related features
"""

def get_function_disassembly(binary_path) -> list:
    r2 = r2pipe.open(binary_path, flags=['-2'])
    r2.cmd('aaa')  # Run automatic analysis

    # Get a list of functions
    functions = r2.cmdj('aflj')

    disassembly_dict = {}

    for function in functions:
        # Get the function address
        function_address = function['offset']

        # Get the function name or use the address if the name is not available
        function_name = function.get('name', f"0x{function_address:x}")

        # Get the disassembly of the function
        disassembly = r2.cmdj(f'pdfj @{function_address}')

        # Store the disassembly in the dictionary
        if disassembly and 'ops' in disassembly:
            disassembly_dict[function_name] = disassembly['ops']

    r2.quit()

    ## Convert data to correct format
    functions = []
    for function_name, instructions in disassembly_dict.items():
        current = {}
        current["name"] = function_name
        assembly = []
        for inst in instructions:
            if 'disasm' in inst:
                 assembly.append(inst["disasm"])
        current["disassembled"] = assembly
        current["md5"] = hashlib.md5(" ".join(assembly).encode('utf-8')).hexdigest()

        functions.append(current)

    return functions

def assembly_statistics(functions) -> dict:

    inst_type = collections.Counter()
    for function in functions:
        assembly = function["disassembled"]
        for asm in assembly:
            inst_type[asm.split(" ")[0]] += 1

    num_inst = sum(inst_type.values())
    num_types = len(inst_type)
    inst_type_freq = {k: round(v / num_inst, 4) for k, v in inst_type.items()}

    return {
        'num_insts': num_inst,
        'num_inst_types': num_types,
        'inst_type_freq': inst_type_freq,
    }

def assembly_features(binary) -> tuple[dict, bool]:

    features = {}
    try:

        functions = get_function_disassembly(binary)
        features["FUNCTIONS"] = functions
        features["INSTS_STATS"] = assembly_statistics(functions)

        return (features, False)
    except:
        return (features, True)
