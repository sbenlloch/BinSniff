from .core import BinSniff

import argparse
import json
import os

def main():
    """
    Define logic to make command line tool
    """
    parser = argparse.ArgumentParser()

    parser.add_argument("-b", "--binary", required=True,
            help = "Input file to parse and extract features.")
    parser.add_argument("-o", "--output", required = True,
            help = "Path to return JSON with extracted features.")
    parser.add_argument("-j", "--json-name", default="features.json", dest="json",
            help = "Name to JSON file. Default: features.json")
    parser.add_argument("--harcode", default="",
            help = "Pass values to harcode in the JSON file."
            " Pass json file to convert to dictionary")

    arguments = parser.parse_args()

    input_file = os.path.abspath(arguments.binary)
    output_folder = os.path.abspath(arguments.output)
    json_name = arguments.json

    harcode = {}
    if os.path.isfile(arguments.harcode):
        harcode = json.load(open(arguments.harcode, "r"))

    print("[+] Start sniffing.")

    sniffer = BinSniff(input_file,
                       output_folder,
                       output_name=json_name,
                       hardcode=harcode)

    print("[*] Parsing File")
    sniffer.dump_json()
    print("[!] Dumped file")
