from .elfparser import elfparse, elfsecparse
from .peparser import peparse
from .assemparser import assemparse

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
    A class for extracting features from binary files and dumping them as a JSON file.

    Args:
        binary (str): The path to the binary file.
        output (str): The path to the directory where the JSON file will be saved.
        output_name (str, optional): The name of the JSON file to be saved. Defaults to "features.json".
        verbosity (int, optional): The verbosity level. A higher level means more output. Defaults to 0.

    Raises:
        Exception: If the `binary` file does not exist.

    Methods:
        list_features() -> list:
            Returns a list of the available features extracted from the binary file.

        extract_features() -> dict:
            Extracts the features from the binary file and returns them as a dictionary.

        dump_json():
            Dumps the extracted features as a JSON file to the specified directory.

    """
    def __init__(
            self,
            binary,
            output,
            output_name = "features.json",
            verbosity = 0,
            hardcode = {},
            timeout=None,
            only_static = False,
            ):
        """
        Initializes the `BinSniff` instance.

        Args:
            binary (str): The path to the binary file.
            output (str): The path to the directory where the JSON file will be saved.
            output_name (str, optional): The name of the JSON file to be saved. Defaults to "features.json".
            verbosity (int, optional): The verbosity level. A higher level means more output. Defaults to 0.
            hardcode (dict, optional): Dictionary to harcode options in the features
            timeout (int/None, optional): max time to perform CFG, if is None not timeout aplied
        """
        if not os.path.isfile(binary):
            print("[!] File not exists")
            raise Exception("File not exists")

        self.binary = binary
        self.verbosity = verbosity
        self.name = os.path.basename(binary)

        self.features = {}
        self.hardcode = hardcode

        self.output_name = output_name
        os.makedirs(output, exist_ok=True)
        self.output = output

        self.timeout = timeout
        self.only_static = only_static

    def list_features(self) -> list:
        """
        Returns a list of the available features extracted from the binary file.

        Returns:
            list: A list of strings containing the available features.
        """

        if not self.features:
            self.extract_features()

        return list(self.features.keys())

    def extract_features(self) -> tuple[dict, bool]:
        """
        Extracts the features from the binary file and returns them as a dictionary.

        Returns:
            dict: A dictionary containing the extracted features.
        """

        # Error variables to get posible errors
        errorassemparse = False
        errorelfparse = False
        errorsecparse = False
        errorpeparse = False

        if self.features:
            return self.features
        self.features = self.hardcode
        self.features["NAME"] = self.name
        self.features["MD5"] = md5(self.binary)
        self.features["SHA256"] = sha256(self.binary)
        self.features["MAGIC"] = magic(self.binary)
        self.features["SIZE"] = size(self.binary)
        self.features["ENTROPY"] = entropy(self.binary)

        if "ELF" in self.features["MAGIC"]:
            try:
                self.features["TYPE"] = "ELF"
                (self.features["STATIC"], errorelfparse) = elfparse(self.binary)
                (self.features["MITIGATIONS"], errorsecparse) = elfsecparse(self.binary)
            except:
                errorelfparse = True

        elif "PE" in self.features["MAGIC"] or "MZ" in self.features["MAGIC"]:
            try:
                if "PE" in self.features["MAGIC"]:
                    self.features["TYPE"] = "PE"
                if "PE" not in self.features["MAGIC"]:
                    self.features["TYPE"] = "MZ"

                self.features["STATIC"] = peparse(self.binary)
            except:
                errorpeparse = True

        if self.only_static:
            errors = errorassemparse or errorelfparse or errorpeparse or errorsecparse
            return (self.features, errors)

        try:
            (self.features["CODE"], errorassemparse) = assemparse(self.binary, self.timeout)
        except:
            errorassemparse = True

        errors = errorassemparse or errorelfparse or errorpeparse or errorsecparse
        return (self.features, errors)

    def dump_json(self):
        """
        Dumps the extracted features as a JSON file to the specified directory.
        """
        ret = (None, False)
        if not self.features:
            ret = self.extract_features()

        output_path = f"{self.output}/{self.output_name}"

        if os.path.exists(output_path):
            with open(output_path, "r") as file:
                existing_data = json.load(file)

            # update the existing dictionary with new data
            existing_data.update(self.features)
            self.features = existing_data

        with open(output_path, "w") as file:
            features = json.dumps(self.features, indent=4)
            file.write(features)

        return ret

