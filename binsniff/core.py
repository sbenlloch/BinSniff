from elfparser import elfparse, elfsecparse
from peparser import peparse
from assemparser import assemparse

import IPython
import json

# Logic for general features

import hashlib
import math
import os

def entropy(binary : str) -> float:
    """
    Calculate the entropy of a binary file.

    The entropy of a binary file is a measure of the amount of randomness or
    unpredictability in its data. It is calculated by first counting the
    frequency of each byte in the file, then using the counts to calculate
    the probability of each byte occurring, and finally using the probabilities
    to calculate the entropy using the formula:

        H = - sum(p * log2(p))

    where p is the probability of each byte and log2 is the binary logarithm.

    This function reads the entire file into memory, so it may not be suitable
    for large files.

    Args:
        binary (str): The path to the binary file.

    Returns:
        float: The entropy of the binary file, in bits.
    """

    freq_dict = {}
    file_size = 0
    ent = 0.0

    with open(binary, 'rb') as file:
        data = file.read()

    # Calculate frequency of each byte
    for byte in data:
        freq_dict[byte] = freq_dict.get(byte, 0) + 1
        file_size += 1

    # Calculate entropy
    for count in freq_dict.values():
        probability = count / file_size
        ent -= probability * math.log2(probability)

    return ent

def size(binary) -> int:
    return os.path.getsize(binary)

def md5(binary) -> str:
    return hashlib.md5(open(binary, "rb").read()).hexdigest()

def sha256(binary) -> str:
    return hashlib.sha256(open(binary, "rb").read()).hexdigest()

def magic(binary):
    with open(binary, 'rb') as f:
        header = f.read(64)

        # Check for MZ magic value
        if header[0:2] == b'MZ':
            pe_offset = int.from_bytes(header[60:64], 'little')
            f.seek(pe_offset)
            pe_header = f.read(6)

            # Check for PE magic value
            if pe_header == b'\x50\x45\x00\x00\x64\x86':
                return str(pe_header, 'latin-1')

            # Check for PE+ magic value
            elif pe_header == b'\x50\x45\x00\x00\x64\x8B':
                return str(pe_header, 'latin-1')

            else:
                return str(header[0:2], 'ascii')

        # Check for ELF magic value
        elif header[0:4] == b'\x7fELF':
            return str(header[0:4], 'ascii')

    return "<Unknown>"

class BinSniff():
    """

    """
    def __init__(
            self,
            binary,
            output,
            output_name = "features.json",
            verbosity = 0,
            ):

        if not os.path.isfile(binary):
            print("[!] File not exists")
            raise Exception("File not exists")

        self.binary = binary
        self.verbosity = verbosity
        self.name = os.path.basename(binary)

        self.features = {}

        self.output_name = output_name
        os.makedirs(output, exist_ok=True)
        self.output = output

    def list_features(self) -> list:
        if not self.features:
            self.extract_features()

        return list(self.features.keys())

    def extract_features(self) -> dict:

        if self.features:
            return self.features

        self.features["NAME"] = self.name
        self.features["MD5"] = md5(self.binary)
        self.features["SHA256"] = sha256(self.binary)
        self.features["MAGIC"] = magic(self.binary)
        self.features["SIZE"] = size(self.binary)
        self.features["ENTROPY"] = entropy(self.binary)

        if "ELF" in self.features["MAGIC"]:
            try:
                self.features["TYPE"] = "ELF"
                self.features["STATIC"] = elfparse(self.binary)
                self.features["MITIGATIONS"] = elfsecparse(self.binary)
            except:
                raise Exception("Error trying feature extraction in ELF file")

        elif "PE" in self.features["MAGIC"]:
            try:
                self.features["TYPE"] = "PE"
                self.features["STATIC"] = peparse(self.binary)
            except Exception as e:
                raise Exception("Error trying feature extraction in PE file")


        try:
            self.features["CODE"] = assemparse(self.binary)
        except Exception as e:
            IPython.embed()
            raise Exception("File not compatible with Angr")

        return self.features

    def dump_json(self):
        if not self.features:
            self.extract_features()

        with open(f"{self.output}/{self.output_name}", "w") as file:
            features = json.dumps(self.features, indent = 4)
            file.write(features)
