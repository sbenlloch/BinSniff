# BinSniff
![Python package](https://github.com/sg1o/BinSniff/actions/workflows/python-app.yml/badge.svg)
![Python 3.10](https://img.shields.io/badge/Python-3.10-3776AB?logo=python&logoColor=white)
![Python 3.11](https://img.shields.io/badge/Python-3.11-3776AB?logo=python&logoColor=white)
![Tested on Ubuntu Latest](https://img.shields.io/badge/Tested%20on-Ubuntu%20Latest-E95420?logo=ubuntu&logoColor=white)

Characteristic extractor for binaries

This repo is included in a big project to automatize dataset creation to make ML more easy in low level security.

# BinSniff

BinSniff is a program designed for extracting features from binary files.
It is a lightweight and easy-to-use tool that can help you analyze binary files
and identify important characteristics such as file format, headers, function calls, and more.

## Installation

BinSniff can be installed on Linux, macOS or Windows using WSL.
To install it, simply clone the repo and run septup.pu installation.
```
pip install -e .
```

## Usage

To use BinSniff, open a terminal or command prompt and navigate to the directory where you extracted the files.
Then, run the `binsniff` command followed by the path to the binary file you want to analyze. For example:

```
$ binsniff /path/to/binary.exe
```


BinSniff will extract the default features from the binary file and display them in the terminal.
You can also specify which features you want to extract by using the `--features`
option followed by a comma-separated list of feature names. For example:

```
$ binsniff /path/to/binary.exe --features=format,headers,functions
```

This will extract the file format, headers, and function calls from the binary file.

## Features

BinSniff supports a variety of features, including: (CHANGE TO REALISTIC FEATURES)

- **format**: The file format of the binary file (ELF, PE, Mach-O, etc.).
- **headers**: The headers of the binary file (DOS header, PE header, etc.).
- **imports**: The imported functions of the binary file.
- **exports**: The exported functions of the binary file.
- **functions**: The function calls of the binary file.
- **strings**: The ASCII and Unicode strings of the binary file.
- **sections**: The sections of the binary file.

## Contributing

If you find a bug or have a feature request, please [open an issue](https://github.com/sg1o/binsniff/issues).
If you would like to contribute to the development of BinSniff, please **fork the repository** and submit a pull request.

## License

BinSniff is licensed under the [GPLv3 License](https://github.com/sg1o/binsniff/blob/main/LICENSE).
