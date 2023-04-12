#!/usr/bin/env python3

from binsniff import BinSniff

import argparse
import shutil
import json
import sys
import os

parser = argparse.ArgumentParser()

parser.add_argument("-i", "--input-folder", required=True, dest="input",
                    help="Folder to get all the files to sniff.")

parser.add_argument("-o", "--output-folder", required=True, dest="output",
                    help="Path to create the hierarchy of sniffed files.")

parser.add_argument("--hard",
                    help = "JSON file to be used as a hardcoded dictionary")

parser.add_argument("-t", "--time", default=None,
                    help = "Set timeout to get CFG")

parser.add_argument("-d", "--discard", default = False, action='store_true',
                    help = "Discard errored binaries and write path in error.txt file")

arguments = parser.parse_args()

def _log(tag, text):

    colors = {'W': '\033[33m', 'E': '\033[31m', 'S': '\033[32m', 'I': '\033[36m'}
    symbols = {'W': '⚠', 'E': '✖', 'S': '✔', 'I': 'ℹ'}
    print(colors[tag] + symbols[tag] + " " + text + "\033[0m")


"""
Hierarchy of folders

<folder with filename>
    ↳ input file
    ↳ features.json
    ↳ json_keys (files with the list of all the keys of the json)

"""

# Preparing Environment
input_folder = os.path.abspath(arguments.input)
output_folder = os.path.abspath(arguments.output)

timeout = None
if arguments.time is not None:
    timeout = int(arguments.time)

hardcode = {}
if arguments.hard:
    try:
        hardcode = json.load(open(arguments.hard, "r"))
    except:
        _log("E", "Problem with dictionary to harcode")
        sys.exit()

_log("I", f"Dictionary to harcode: {hardcode}")

if not os.path.exists(output_folder):
    _log("E", "Output folder not exists")
    sys.exit()

_log("I", f"Start sniffing in {input_folder}")

for file in os.listdir(input_folder):

    _log("I", f"Sniffing {file}")
    absfile = os.path.join(input_folder, file)

    # Create destination folder
    _log("I", "Creating output folder")
    actual_output = f"{output_folder}/{file}"

    if not os.path.exists(actual_output):
        os.makedirs(actual_output, exist_ok=True)

    if os.path.isfile(f"{actual_output}/features.json"):
        _log("W", f"{actual_output} exists. Continue to next target")
        continue

    # Copy file to destination folder
    if not os.path.isfile(f"{actual_output}/{file}"):
        shutil.copy(absfile, f"{actual_output}/{file}")

    sniffer = BinSniff(absfile, actual_output, hardcode = hardcode, timeout=timeout)

    # Dump json
    _log("W", "Parsing file")
    (_, error) = sniffer.dump_json()
    _log("S", "Dumped file")

    if error:
        _log("E", "Dropping, deleting output folder")
        if arguments.discard:
            shutil.rmtree(actual_output)
            errorfile = open("errors.txt", "a")
            errorfile.write(f"{file}\n")
            errorfile.close()
            continue

    # Get list of keys
    keys = sniffer.list_features()
    _log("W", "Writing keys file")
    with open(f"{actual_output}/keys.txt", "w") as keys_file:
        keys_file.write("\n".join(keys))

    _log("S", f"End with {file}")
