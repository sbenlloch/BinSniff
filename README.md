# 🧩 BinSniff
![Python package](https://github.com/sg1o/BinSniff/actions/workflows/python-app.yml/badge.svg)
![Python 3.10](https://img.shields.io/badge/Python-3.10-3776AB?logo=python&logoColor=white)
![Python 3.11](https://img.shields.io/badge/Python-3.11-3776AB?logo=python&logoColor=white)
![Tested on Ubuntu Latest](https://img.shields.io/badge/Tested%20on-Ubuntu%20Latest-E95420?logo=ubuntu&logoColor=white)

🔎🔍 **BinSniff**: An insightful characteristic extractor for binary files

This repository is part of a larger project aimed at simplifying machine learning in low-level security by automating dataset creation.

## 💡 What is BinSniff?

BinSniff is a nimble tool designed for extracting informative features from binary files. With BinSniff, you can analyze binary files and identify crucial characteristics, such as file format, headers, imported functions, assembly of functions, VEX code of functions, and mnemonics statistics.

## ⚙️ Installation

BinSniff has been tested on Ubuntu 22.04 LTS. Follow these simple steps to install:

1. Clone the repository.
2. Run the setup.py installation script with `pip install -e .`.

## 🚀 Usage

To utilize BinSniff, navigate to the directory where you've stored the files. Then, invoke the `binsniff` command with the necessary options.

Here's an example:

```bash
$ binsniff -b /path/to/binary.exe -o /path/to/output
```

The `-b` flag indicates the path to the binary file to be analyzed, and `-o` specifies where to store the output JSON file.

Additional flags include:

- `-j` or `--json-name`: Set a custom name for the output JSON file. Defaults to `features.json`.
- `--harcode`: Pass a json file to convert to a dictionary and hardcode specific values into the output JSON file.

## ⛏️ Miner

A utility named `miner.py` is included within the `tools` directory. It allows you to extract features from multiple binaries within a directory.

## 📚 Features

BinSniff can extract a plethora of informative features:

- **strings**: ASCII and Unicode strings within the binary file.
- **sections**: Detailed information about the binary file's sections.
- **imports**: Functions imported by the binary file.
- **headers**: Headers within the binary file.
- **assembly**: Assembly of functions in the binary file.
- **vex**: VEX code of functions within the binary file.
- **mnemonics**: Mnemonics statistics in the binary file.

BinSniff supports ELF and PE file formats for feature extraction.

## 🤝 Contributing

Bug reports and feature requests are welcome! Please [open an issue](https://github.com/sg1o/binsniff/issues). If you're interested in contributing directly to BinSniff's development, kindly **fork the repository** and submit a pull request.

## 📄 License

BinSniff is licensed under the [GPLv3 License](https://github.com/sg1o/binsniff/blob/main/LICENSE).

## ⚠️ Warning

🚧 Please note, this repository is a prototype and forms part of a master's thesis work. It is under active development, so you might encounter bugs and incomplete features. We highly appreciate your patience and encourage you to report any issues or suggest improvements.
