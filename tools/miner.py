#!/usr/bin/env python3

from binsniff import BinSniff

import multiprocessing
import argparse
import shutil
import signal
import json
import sys
import os

def _log(tag, text):

    colors = {'W': '\033[33m', 'E': '\033[31m', 'S': '\033[32m', 'I': '\033[36m'}
    symbols = {'W': '⚠', 'E': '✖', 'S': '✔', 'I': 'ℹ'}
    print(colors[tag] + symbols[tag] + " " + text + "\033[0m")

def handle_signal(signal, frame):
    _log("W", "User interrupted the script with Ctrl+\\.")
    sys.exit(0)

signal.signal(signal.SIGQUIT, handle_signal)

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

def check_if_errored(errors, file):
    for error in errors:
        if file in error:
            return True

    return False

errorvault = []
if arguments.discard:
    if os.path.isfile("errors.txt"):
        errorfile = open("errors.txt", "r")
        errorvault = [x for x in errorfile]
        errorfile.close()

if not os.path.exists(output_folder):
    _log("E", "Output folder not exists")
    sys.exit()

_log("I", f"Start sniffing in {input_folder}")


def sniffing(timeout, file, hardcode, output, conn):
    try:

        sniffer = BinSniff(file, output, hardcode = hardcode, timeout=timeout)

        # Dump json
        _log("W", "Parsing file")
        (_, error) = sniffer.dump_json()
        _log("S", "Dumped file")
        # Get list of keys
        keys = sniffer.list_features()

        conn.send((error, keys))

    except Exception as e:
        # Send the exception back to the parent process
        conn.send_exception(e)

for file in os.listdir(input_folder):

    if arguments.discard and check_if_errored(errorvault, file):
        _log("W", f"{file} in history of errors")
        continue

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

    # Error in BinSniff will be caught

    try:
        # Set up a pipe for communicating with the child process
        parent_conn, child_conn = multiprocessing.Pipe()

        # Launch the sniffing function in a subprocess
        sniffing_process = multiprocessing.Process(target=sniffing,
                                                    args=(
                                                            timeout,
                                                            absfile,
                                                            hardcode,
                                                            actual_output,
                                                            child_conn))
        sniffing_process.start()

        # Wait for the subprocess to finish or time out
        if timeout:
            sniffing_process.join(timeout + 3)
        else:
            sniffing_process.join()

        if sniffing_process.is_alive():
            # The subprocess is still running, terminate it
            sniffing_process.terminate()
            sniffing_process.join()
            raise TimeoutError("The sniffing process timed out.")

        # Get the return values from the pipe
        error, keys = parent_conn.recv()

        if error:
            _log("E", "Dropping, deleting output folder")
            if arguments.discard:
                errorvault.append(file)
                shutil.rmtree(actual_output)
                errorfile = open("errors.txt", "a")
                errorfile.write(f"{file}\n")
                errorfile.close()
                continue

        _log("W", "Writing keys file")
        with open(f"{actual_output}/keys.txt", "w") as keys_file:
            keys_file.write("\n".join(keys))

        _log("S", f"End with {file}")

    except TimeoutError as e:
        _log("E", f"The sniffing process timed out: {e}")
        shutil.rmtree(actual_output)
        errorvault.append(file)
        errorfile = open("errors.txt", "a")
        errorfile.write(f"Timeout error: {file}\n")
        errorfile.close()
        continue

    except KeyboardInterrupt:
        _log("E", f"Continue to next file")
        shutil.rmtree(actual_output)
        errorvault.append(file)
        errorfile = open("errors.txt", "a")
        errorfile.write(f"Jumped: {file}\n")
        errorfile.close()
        continue

    except Exception as e:
        _log("E", f"Caught error in Miner: {e}")
        shutil.rmtree(actual_output)
        errorvault.append(file)
        errorfile = open("errors.txt", "a")
        errorfile.write(f"Especial error {e}: {file}\n")
        errorfile.close()
        continue


