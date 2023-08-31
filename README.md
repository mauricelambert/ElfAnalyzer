# ElfAnalyzer

## Description

This module parses and analyzes ELF file for Forensic and investigations.

Parses:
 - ELF identification
 - ELF headers
 - Program headers
 - ELF sections
 - ELF symbols tables
 - Comment section
 - Note sections
 - Dynamic section

## Requirements

This package require:
 - python3
 - python3 Standard Library

## Installation

```bash
python3 -m pip install ElfAnalyzer
```

```bash
git clone "https://github.com/mauricelambert/ElfAnalyzer.git"
cd "ElfAnalyzer"
python3 -m pip install .
```

## Usages

### Command line

```bash
ElfAnalyzer              # Using CLI package executable
python3 -m ElfAnalyzer   # Using python module
python3 ElfAnalyzer.pyz  # Using python executable
ElfAnalyzer.exe          # Using python Windows executable

./ElfAnalyzer.pyz ./local/ElfFile
ElfAnalyzer.exe -u https://github.com/mauricelambert/FastRC4/releases/download/v0.0.1/librc4.so
./ElfAnalyzer.pyz -v ./local/ElfFile
python3 ElfAnalyzer.pyz -c ./local/ElfFile
```

### Python script

```python
from ElfAnalyzer import *

file = open("./local/ElfFile", "rb")
elfindent, elf_headers, programs_headers, elf_sections, symbols_tables, comments, note_sections, notes, dynamics, sections = parse_elffile(file)
cli(elfindent, elf_headers, programs_headers, elf_sections, symbols_tables, comments, notes, dynamics, sections)
file.close()
```

## Links

 - [Pypi](https://pypi.org/project/ElfAnalyzer)
 - [Github](https://github.com/user/ElfAnalyzer)
 - [Documentation](https://mauricelambert.github.io/info/python/security/ElfAnalyzer.html)
 - [Python executable](https://mauricelambert.github.io/info/python/security/ElfAnalyzer.pyz)
 - [Python Windows executable](https://mauricelambert.github.io/info/python/security/ElfAnalyzer.exe)

## License

Licensed under the [GPL, version 3](https://www.gnu.org/licenses/).
