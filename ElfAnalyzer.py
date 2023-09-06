#!/usr/bin/env python3
# -*- coding: utf-8 -*-

###################
#    This module parses and analyzes ELF file for Forensic and
#    investigations.
#    Copyright (C) 2023  ElfAnalyzer

#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.

#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.

#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <https://www.gnu.org/licenses/>.
###################

"""
This module parses and analyzes ELF file for Forensic and
investigations.
"""

__version__ = "0.0.3"
__author__ = "Maurice Lambert"
__author_email__ = "mauricelambert434@gmail.com"
__maintainer__ = "Maurice Lambert"
__maintainer_email__ = "mauricelambert434@gmail.com"
__description__ = """
This module parses and analyzes ELF file for Forensic and
investigations.
"""
__url__ = "https://github.com/mauricelambert/ElfAnalyzer"

# __all__ = []

__license__ = "GPL-3.0 License"
__copyright__ = """
ElfAnalyzer  Copyright (C) 2023  Maurice Lambert
This program comes with ABSOLUTELY NO WARRANTY.
This is free software, and you are welcome to redistribute it
under certain conditions.
"""
copyright = __copyright__
license = __license__

print(copyright)

from ctypes import (
    Structure,
    c_bool,
    c_wchar,
    c_byte,
    c_ubyte,
    c_short,
    c_ushort,
    c_int,
    c_uint,
    c_long,
    c_ulong,
    c_longlong,
    c_size_t,
    c_ssize_t,
    c_float,
    c_double,
    c_longdouble,
    c_char_p,
    c_wchar_p,
    c_void_p,
    c_uint16,
    c_int32,
    c_ulonglong,
    c_int8,
    c_uint8,
    c_int16,
    c_uint32,
    c_int64,
    c_uint64,
    c_char,
    _SimpleCData,
    sizeof as _sizeof,
)
from typing import TypeVar, Union, Any, Iterable, List, Tuple
from sys import argv, executable, exit, stderr
from urllib.request import urlopen
from dataclasses import dataclass
from _io import _BufferedIOBase
from functools import partial
from string import printable
from os.path import getsize
from inspect import isclass
from _ctypes import Array
from io import BytesIO
from enum import Enum

Section = TypeVar("Section")

try:
    from EntropyAnalysis import charts_chunks_file_entropy, Section
    from matplotlib import pyplot
except ImportError:
    entropy_charts_import = False
else:
    entropy_charts_import = True

_CData = tuple(x for x in c_char.mro() if x.__name__ == "_CData")[0]
printable = printable[:-5].encode()

_issubclass = issubclass


def issubclass(test: Any, *args):
    """
    This function checks if the tested elements is a
    subclass of comparator.
    """

    if isclass(test):
        return _issubclass(test, *args)
    return False


@dataclass
class Field:
    """
    This class implements
    """

    value: Any
    information: str
    usage: str = None
    description: str = None


class FileString(str):
    """
    This class implements strings with positions
    (_start_position_ and _end_position_ attributes).
    """

    pass


class FileBytes(bytes):
    """
    This class implements bytes with positions
    (_start_position_ and _end_position_ attributes).
    """

    pass


class Data:
    """
    This class helps you to print a title for a "CLI section".
    """

    verbose: bool = False
    no_color: bool = False

    def __init__(
        self,
        name: str,
        start_position: int,
        end_position: int,
        data: bytes,
        information: str,
        format: bool = True,
    ):
        self.name = name
        self.start_position = start_position
        self.end_position = end_position
        self.data = data
        self.information = information
        self.format = format

    def vprint(self) -> None:
        """
        This method prints verbose data.
        """

        if self.verbose:
            self.print()

    def print(self) -> None:
        """
        This method prints the data.
        """

        if self.no_color:
            print(self)
            return None

        print(
            "\x1b[38;2;183;121;227m"
            + self.name.ljust(25)
            + "\x1b[38;2;255;240;175m"
            + f"{self.start_position:0>8x}-{self.end_position:0>8x}".ljust(20)
            + "\x1b[38;2;255;208;11m"
            + (
                (
                    self.data.hex().ljust(40)
                    + "\x1b[38;2;212;171;242m"
                    + "".join(
                        chr(x) if x in printable else "." for x in self.data
                    ).ljust(20)
                )
                if len(self.data) <= 20
                else "\x1b[38;2;212;171;242m"
                + "".join(
                    chr(x) if x in printable else "." for x in self.data
                ).ljust(40)
            )
            + "\x1b[38;2;201;247;87m"
            + (
                self.information.replace("_", " ").title()
                if self.format
                else self.information
            )
            + "\x1b[39m"
        )

    def __str__(self):
        return (
            self.name.ljust(25)
            + f"{self.start_position:0>8x}-{self.end_position:0>8x}".ljust(20)
            + (
                (
                    self.data.hex().ljust(40)
                    + "".join(
                        chr(x) if x in printable else "." for x in self.data
                    ).ljust(20)
                )
                if len(self.data) <= 20
                else "".join(
                    chr(x) if x in printable else "." for x in self.data
                ).ljust(20)
            )
            + (self.information if self.format else self.information)
        )


class Title:
    """
    This class helps you to print a title for a "CLI section".
    """

    def __init__(self, value: str):
        self.value = value

    def print(self) -> None:
        """
        This method prints the title.
        """

        if Data.no_color:
            print("\n" + str(self) + "\n")
            return None

        print(
            "\n\x1b[48;2;50;50;50m\x1b[38;2;175;241;11m"
            + str(self)
            + "\x1b[49m\x1b[39m\n"
        )

    def __str__(self):
        return f"{' ' + self.value + ' ':*^139}"


class _DynamicType(int):
    """
    This class is an integer type with usage
    and description attributes.
    """

    def __new__(cls, value: int, usage: str, description: str):
        self = int.__new__(cls, value)
        self.usage = usage
        self.description = description
        return self


class _DynamicFlags(int):
    """
    This class is an integer type with description attribut.
    """

    def __new__(cls, value: int, description: str):
        self = int.__new__(cls, value)
        self.description = description
        return self


class DataToCClass:
    """
    This class implements methods to get ctypes from data.
    """

    order: str = "little"

    def data_to_bytes(
        type: type, data: Union[bytes, int, str]
    ) -> _SimpleCData:
        """
        This method converts bytes, int or str to ctypes (c_char, c_char_p).
        """

        if isinstance(data, int):
            data = data.to_bytes()
        elif isinstance(data, str):
            data = data.encode("latin-1")

        return type(data[::-1] if DataToCClass.order == "little" else data)

    def data_to_int(type: type, data: Union[bytes, int, None]) -> _SimpleCData:
        """
        This method converts bytes, int or None to ctypes
        (c_bool, c_byte, c_ubyte, c_short, c_ushort, c_int,
        c_uint, c_long, c_ulong, c_longlong, c_ulonglong,
        c_size_t, c_ssize_t, c_void_p, c_int8, c_int16,
        c_int32, c_int64, c_uint8, c_uint16, c_uint32,
        c_uint64).
        """

        if isinstance(data, bytes):
            data = int.from_bytes(
                data[::-1] if DataToCClass.order == "little" else data
            )

        return type(data)

    def data_to_str(
        type: type, data: Union[bytes, str], encoding: str = "utf-8"
    ) -> _SimpleCData:
        """
        This method converts bytes or str to ctypes (c_wchar, c_wchar_p).
        """

        if isinstance(data, bytes):
            data = data.decode(encoding)

        return type(data)

    def data_to_float(type: type, data: Union[bytes, float]) -> _SimpleCData:
        """
        This method converts bytes or float to ctypes
        (c_float, c_double, c_longdouble).
        """

        if isinstance(data, bytes):
            data = float.fromhex(
                (data[::-1] if DataToCClass.order == "little" else data).hex()
            )

        return type(data)


data_to_ctypes = {
    c_bool: partial(DataToCClass.data_to_int, c_bool),
    c_char: partial(DataToCClass.data_to_bytes, c_char),
    c_wchar: partial(DataToCClass.data_to_str, c_wchar),
    c_byte: partial(DataToCClass.data_to_int, c_byte),
    c_int8: partial(DataToCClass.data_to_int, c_int8),
    c_ubyte: partial(DataToCClass.data_to_int, c_ubyte),
    c_uint8: partial(DataToCClass.data_to_int, c_uint8),
    c_short: partial(DataToCClass.data_to_int, c_short),
    c_int16: partial(DataToCClass.data_to_int, c_int16),
    c_ushort: partial(DataToCClass.data_to_int, c_ushort),
    c_uint16: partial(DataToCClass.data_to_int, c_uint16),
    c_int: partial(DataToCClass.data_to_int, c_int),
    c_int32: partial(DataToCClass.data_to_int, c_int32),
    c_uint: partial(DataToCClass.data_to_int, c_uint),
    c_uint32: partial(DataToCClass.data_to_int, c_uint32),
    c_long: partial(DataToCClass.data_to_int, c_long),
    c_ulong: partial(DataToCClass.data_to_int, c_ulong),
    c_longlong: partial(DataToCClass.data_to_int, c_longlong),
    c_int64: partial(DataToCClass.data_to_int, c_int64),
    c_ulonglong: partial(DataToCClass.data_to_int, c_ulonglong),
    c_uint64: partial(DataToCClass.data_to_int, c_uint64),
    c_size_t: partial(DataToCClass.data_to_int, c_size_t),
    c_ssize_t: partial(DataToCClass.data_to_int, c_ssize_t),
    c_float: partial(DataToCClass.data_to_float, c_float),
    c_double: partial(DataToCClass.data_to_float, c_double),
    c_longdouble: partial(DataToCClass.data_to_float, c_longdouble),
    c_char_p: partial(DataToCClass.data_to_bytes, c_char_p),
    c_wchar_p: partial(DataToCClass.data_to_str, c_wchar),
    c_void_p: partial(DataToCClass.data_to_int, c_void_p),
}


class BaseStructure:
    """
    This class implements the Structure base (methods).
    """

    def __init__(self, data: Union[bytes, _BufferedIOBase]) -> None:
        self._source = b""
        if isinstance(data, bytes):
            data = BytesIO(data)

        for attribute_name, attribute_value in self.__annotations__.items():
            start_position = data.tell()

            if issubclass(attribute_value, Array):
                cClass = self.array_to_cclass(attribute_value)
                cClass_size = sizeof(cClass)
                used_data = data.read(sizeof(attribute_value))
                self._source += used_data
                value = attribute_value(
                    *(
                        data_to_ctypes[cClass](
                            used_data[x * cClass_size : (x + 1) * cClass_size]
                        )
                        for x in range(attribute_value._length_)
                    )
                )
                setattr(self, attribute_name, value)
            elif issubclass(attribute_value, BaseStructure):
                used_data = data.read(sizeof(attribute_value))
                self._source += used_data
                value = attribute_value(used_data)
                setattr(self, attribute_name, value)
            else:
                cClass = self.class_to_cclass(attribute_value)
                used_data = data.read(sizeof(cClass))
                value = data_to_ctypes[cClass](used_data)
                self._source += used_data
                setattr(self, attribute_name, value)

            value._data_ = used_data
            value._start_position_ = start_position
            value._end_position_ = data.tell()

    @classmethod
    def array_to_cclass(cls, array: Array) -> type:
        """
        This method returns the inherited ctype.
        """

        return cls.class_to_cclass(array._type_)

    @staticmethod
    def class_to_cclass(cls: type) -> type:
        """
        This method returns the inherited ctype.
        """

        precedent_class = None
        for element in cls.mro():
            if element is _SimpleCData:
                return precedent_class
            precedent_class = element

    @classmethod
    def __sizeof__(cls) -> int:
        """
        This method returns the octet size to build the instance.
        """

        counter = 0
        for value in cls.__annotations__.values():
            counter += sizeof(value)

        return counter

    def __repr__(self):
        return self.__class__.__name__ + "(" + repr(self._source) + ")"

    def __str__(self):
        return (
            self.__class__.__name__
            + "("
            + ", ".join(
                f"{attr}="
                + (
                    (
                        getattr(self, attr).__class__.__name__
                        + f"({getattr(self, attr).value})"
                    )
                    if isinstance(getattr(self, attr), Array)
                    else getattr(self, attr)
                )
                for attr in self.__annotations__
            )
            + ")"
        )


Structure = TypeVar("Structure")


def sizeof(object: Union[_CData, type]) -> int:
    """
    This function returns the size of this object.
    """

    if isinstance(object, _CData) or issubclass(object, _CData):
        return _sizeof(object)
    return object.__sizeof__()


def structure(cls: type) -> type:
    """
    This decorator helps to build C Structures.
    """

    def wrap(cls: type) -> type:
        """
        This function builds the C Structure class.
        """

        return type(
            cls.__name__,
            (cls, BaseStructure),
            {"__annotations__": cls.__annotations__},
        )

    return wrap(cls)


class Elf32_Addr(c_uint32):
    pass


class Elf32_Half(c_uint16):
    pass


class Elf32_Section(c_uint16):
    pass


class Elf32_Versym(c_uint16):
    pass


class Elf32_Off(c_uint32):
    pass


class Elf32_Sword(c_int32):
    pass


class Elf32_Word(c_uint32):
    pass


class Elf32_Sxword(c_int64):
    pass


class Elf32_Xword(c_uint64):
    pass


class Elf64_Addr(c_uint64):
    pass


class Elf64_Half(c_uint16):
    pass


class Elf64_Section(c_uint16):
    pass


class Elf64_Versym(c_uint16):
    pass


class Elf64_Off(c_uint64):
    pass


class Elf64_Sword(c_int32):
    pass


class Elf64_Word(c_uint32):
    pass


class Elf64_Sxword(c_int64):
    pass


class Elf64_Xword(c_uint64):
    pass


class ELfIdentClass(Enum):
    INVALID = 0
    OBJECT_32_BITS = 1
    OBJECT_64_BITS = 2


class ELfIdentData(Enum):
    INVALID = 0
    LITTLE_ENDIAN = 1
    BIG_ENDIAN = 2


class ELfIdentVersion(Enum):
    INVALID = 0
    CURRENT = 1


class ELfIdentOS(Enum):
    SYSV = NONE = 0
    HPUX = 1
    NETBSD = 2
    LINUX = 3
    SOLARIS = 6
    AIX = 7
    IRIX = 8
    FREEBSD = 9
    TRU64 = 10
    MODESTO = 11
    OPENBSD = 12
    OPENVMS = 13
    NSK = 14
    AROS = 15
    ARM = 97
    MSP = 255


class ElfType(Enum):
    NO_FILE_TYPE = 0
    RELOCATABLE = 1
    EXECUTABLE = 2
    SHARED_OBJECT = 3
    CORE = 4
    OS_SPECIFIC_LOOS = 0xFE00
    OS_SPECIFIC_HIOS = 0xFEFF
    PROCESSOR_SPECIFIC_LOPROC = 0xFF00
    PROCESSOR_SPECIFIC_HIPROC = 0xFFFF


class ElfMachine(Enum):
    NO_MACHINE = 0
    ATAT_WE_32100 = 1
    SPARC = 2
    INTEL_80386 = 3
    MOTOROLA_68000 = 4
    MOTOROLA_88000 = 5
    INTEL_80860 = 7
    MIPS_I = 8
    IBM_SYSTEM370 = 9
    MIPS_RS3000 = 10
    PA_RISC = 15
    FUJITSU_VPP500 = 17
    SPARC32PLUS = 18
    INTEL_80960 = 19
    POWERPC = 20
    POWERPC64 = 21
    IBM_SYSTEM390 = 22
    NEC_V800 = 36
    FUJITSU_FR20 = 37
    TRW_RH32 = 38
    MOTOROLA_RCE = 39
    ARM = 40
    DIGITAL_ALPHA = 41
    HITACHI_SH = 42
    SPARC_V9 = 43
    SIEMENS_TRICORE = 44
    ARC = 45
    HITACHI_H8_300 = 46
    HITACHI_H8_300H = 47
    HITACHI_H8S = 48
    HITACHI_H8_500 = 49
    INTEL_IA_64 = 50
    STANFORD_MIPS_X = 51
    MOTOROLA_COLDFIRE = 52
    MOTOROLA_68HC12 = 53
    FUJITSU_MMA = 54
    SIEMENS_PCP = 55
    SONY_NCPU_RISC = 56
    DENSO_NDR1 = 57
    MOTOROLA_STARCORE = 58
    TOYOTA_ME16 = 59
    ST100 = 60
    TINYJ = 61
    AMD_X86_64 = 62
    SONY_PDSP = 63
    PDP10 = 64
    PDP11 = 65
    SIEMENS_FX66 = 66
    ST9PLUS = 67
    ST7 = 68
    MOTOROLA_68HC16 = 69
    MOTOROLA_68HC11 = 70
    MOTOROLA_68HC08 = 71
    MOTOROLA_68HC05 = 72
    SILICON_SVX = 73
    ST19 = 74
    DIGITAL_VAX = 75
    AXIS_CRIS = 76
    INFINEON_JAVELIN = 77
    LSI_DSP64_FIREPATH = 78
    LSI_DSP16_ZSP = 79
    DONALD_KNUTH_MMIX = 80
    HARVARD_HUANY = 81
    SITERA_PRISM = 82
    ATMEL_AVR = 83
    FUJITSU_FR30 = 84
    MITSUBISHI_D10V = 85
    MITSUBISHI_D30V = 86
    NEC_V850 = 87
    MITSUBISHI_M32R = 88
    MATSUSHITA_MN10300 = 89
    MATSUSHITA_MN10200 = 90
    PICOJAVA = 91
    OPENRISC = 92
    ARC_A5 = 93
    TENSILICA_XTENSA = 94
    ALPHAMOSAIC_VIDEOCORE = 95
    TMM_GPP = 96
    NS32K = 97
    TPC = 98
    TREBIA_SNP1K = 99
    ST200 = 100


ElfVersion = ELfIdentVersion


class SpecialSectionIndexes(Enum):
    SHN_UNDEF = 0
    SHN_LOPROC = SHN_LORESERVE = 0xFF00
    SHN_HIPROC = 0xFF1F
    SHN_LOOS = 0xFF20
    SHN_HIOS = 0xFF3F
    SHN_ABS = 0xFFF1
    SHN_COMMON = 0xFFF2
    SHN_HIRESERVE = SHN_XINDEX = 0xFFFF


class ProgramHeaderType(Enum):
    PT_NULL = 0
    PT_LOAD = 1
    PT_DYNAMIC = 2
    PT_INTERP = 3
    PT_NOTE = 4
    PT_SHLIB = 5
    PT_PHDR = 6
    PT_TLS = 7
    PT_NUM = 8
    PT_LOOS = 0x60000000
    PT_GNU_EH_FRAME = 0x6474E550
    PT_GNU_STACK = 0x6474E551
    PT_GNU_RELRO = 0x6474E552
    PT_HIOS = 0x6FFFFFFF
    PT_LOPROC = 0x70000000
    PT_HIPROC = 0x7FFFFFFF


class ProgramHeaderFlags(Enum):
    PF_EXECUTE = 1
    PF_WRITE = 2
    PF_READ = 3
    PF_MASKOS = 0x0FF00000
    PF_MASKPROC = 0xF0000000


class SectionHeaderType(Enum):
    SHT_NULL = 0
    SHT_PROGBITS = 1
    SHT_SYMTAB = 2
    SHT_STRTAB = 3
    SHT_RELA = 4
    SHT_HASH = 5
    SHT_DYNAMIC = 6
    SHT_NOTE = 7
    SHT_NOBITS = 8
    SHT_REL = 9
    SHT_SHLIB = 10
    SHT_DYNSYM = 11
    SHT_INIT_ARRAY = 14
    SHT_FINI_ARRAY = 15
    SHT_PREINIT_ARRAY = 16
    SHT_GROUP = 17
    SHT_SYMTAB_SHNDX = 18
    SHT_NUM = 19
    SHT_FILTER = 0x7FFFFFF
    SHT_LOOS = 0x60000000
    SHT_HIOS = 0x6FFFFFFF
    SHT_VERSYM2 = 0x6FFFFFF0
    SHT_GNU_ATTRIBUTES = 0x6FFFFFF5
    SHT_GNU_HASH = 0x6FFFFFF6
    SHT_GNU_LIBLIST = 0x6FFFFFF7
    SHT_CHECKSUM = 0x6FFFFFF8
    SHT_VERDEF = 0x6FFFFFFD
    SHT_VERNEED = 0x6FFFFFFE
    SHT_VERSYM1 = 0x6FFFFFFF
    SHT_LOPROC = 0x70000000
    SHT_AUXILIARY = 0x7FFFFFFD
    SHT_HIPROC = 0x7FFFFFFF
    SHT_LOUSER = 0x80000000
    SHT_HIUSER = 0xFFFFFFFF


class SectionAttributeFlags(Enum):
    SHF_WRITE = 0x1
    SHF_ALLOC = 0x2
    SHF_EXECINSTR = 0x4
    SHF_MERGE = 0x10
    SHF_STRINGS = 0x20
    SHF_INFO_LINK = 0x40
    SHF_LINK_ORDER = 0x80
    SHF_OS_NONCONFORMING = 0x100
    SHF_GROUP = 0x200
    SHF_TLS = 0x400
    SHF_MASKOS = 0x0FF00000
    SHF_MASKPROC = 0xF0000000


class SectionGroupFlags(Enum):
    GRP_COMDAT = 0x1
    GRP_MASKOS = 0x0FF00000
    GRP_MASKPROC = 0xF0000000


class SymbolBinding(Enum):
    STB_LOCAL = 0
    STB_GLOBAL = 1
    STB_WEAK = 2
    STB_LOOS = 10
    STB_HIOS = 12
    STB_LOPROC = 13
    STB_HIPROC = 15


class SymbolType(Enum):
    STT_NOTYPE = 0
    STT_OBJECT = 1
    STT_FUNC = 2
    STT_SECTION = 3
    STT_FILE = 4
    STT_COMMON = 5
    STT_TLS = 6
    STT_RELC = 8
    STT_SRELC = 9
    STT_LOOS = 10
    STT_HIOS = 12
    STT_LOPROC = 13
    STT_HIPROC = 15


class SymbolVisibility(Enum):
    STV_DEFAULT = 0
    STV_INTERNAL = 1
    STV_HIDDEN = 2
    STV_PROTECTED = 3


class DynamicType(Enum):
    DT_NULL = _DynamicType(0, "ignored", "End of dynamic array")
    DT_NEEDED = _DynamicType(1, "value", "Needed library name offset")
    DT_PLTRELSZ = _DynamicType(2, "value", "Relocation entries size")
    DT_PLTGOT = _DynamicType(3, "pointer", "Address procedure linkage table")
    DT_HASH = _DynamicType(4, "pointer", "Address symbol hash table")
    DT_STRTAB = _DynamicType(5, "pointer", "Address string table (.dynstr)")
    DT_SYMTAB = _DynamicType(6, "pointer", "Address symbol table (.dynsym)")
    DT_RELA = _DynamicType(7, "pointer", "Address relocation table")
    DT_RELASZ = _DynamicType(8, "value", "Relocation table size")
    DT_RELAENT = _DynamicType(9, "value", "Relocation entry size")
    DT_STRSZ = _DynamicType(10, "value", "String table size")
    DT_SYMENT = _DynamicType(11, "value", "Symbol table entry size")
    DT_INIT = _DynamicType(12, "pointer", "Initialization function address")
    DT_FINI = _DynamicType(13, "pointer", "Termination function address")
    DT_SONAME = _DynamicType(14, "value", "Shared object name")
    DT_RPATH = _DynamicType(15, "value", "Library search path string")
    DT_SYMBOLIC = _DynamicType(16, "ignored", "Alters dynamic linker's symbol")
    DT_REL = _DynamicType(17, "pointer", "Address relocation table")
    DT_RELSZ = _DynamicType(18, "value", "Relocation table size")
    DT_RELENT = _DynamicType(19, "value", "Relocation entry size")
    DT_PLTREL = _DynamicType(20, "value", "Relocation entry type")
    DT_DEBUG = _DynamicType(21, "pointer", "Used for debugging")
    DT_TEXTREL = _DynamicType(
        22, "ignored", "No relocation on non-writable segment"
    )
    DT_JMPREL = _DynamicType(23, "pointer", "Procedure linkage table")
    DT_BIND_NOW = _DynamicType(24, "ignored", "Relocations before execution")
    DT_INIT_ARRAY = _DynamicType(
        25, "pointer", "Initialization functions pointers"
    )
    DT_FINI_ARRAY = _DynamicType(
        26, "pointer", "Termination functions pointers"
    )
    DT_INIT_ARRAYSZ = _DynamicType(
        27, "value", "Initialization functions number"
    )
    DT_FINI_ARRAYSZ = _DynamicType(28, "value", "Termination functions number")
    DT_RUNPATH = _DynamicType(29, "value", "Library search path")
    DT_FLAGS = _DynamicType(30, "value", "Flag values specific")
    DT_ENCODING = _DynamicType(
        32, "unspecified", "Values interpretation rules"
    )
    DT_PREINIT_ARRAY = _DynamicType(
        32, "pointer", "Pre-initialization functions"
    )
    DT_PREINIT_ARRAYSZ = _DynamicType(33, "value", "Pre-init functions size")
    DT_LOOS = _DynamicType(
        0x6000000D, "unspecified", "System-specific semantics"
    )
    DT_HIOS = _DynamicType(
        0x6FFFF000, "unspecified", "System-specific semantics"
    )
    DT_LOPROC = _DynamicType(
        0x70000000, "unspecified", "Processor-specific semantics"
    )
    DT_HIPROC = _DynamicType(
        0x7FFFFFFF, "unspecified", "Processor-specific semantics"
    )


class DynamicFlags(Enum):
    DF_ORIGIN = _DynamicFlags(0x1, "Load libraries using filepath")
    DF_SYMBOLIC = _DynamicFlags(0x2, "Link start with object itself")
    DF_TEXTREL = _DynamicFlags(0x4, "No relocation on non-writable segment")
    DF_BIND_NOW = _DynamicFlags(0x8, "Relocations before execution")
    DF_STATIC_TLS = _DynamicFlags(0x10, "This object can't be link")


@structure
class ElfIdent:
    ei_mag: c_char * 4
    ei_class: c_ubyte
    ei_data: c_ubyte
    ei_version: c_ubyte
    ei_osabi: c_ubyte
    ei_abiversion: c_ubyte
    ei_pad: c_char
    ei_nident: c_char * 6


@structure
class ElfHeader32:
    e_ident: ElfIdent
    e_type: Elf32_Half
    e_machine: Elf32_Half
    e_version: Elf32_Word
    e_entry: Elf32_Addr
    e_phoff: Elf32_Off
    e_shoff: Elf32_Off
    e_flags: Elf32_Word
    e_ehsize: Elf32_Half
    e_phentsize: Elf32_Half
    e_phnum: Elf32_Half
    e_shentsize: Elf32_Half
    e_shnum: Elf32_Half
    e_shstrndx: Elf32_Half


@structure
class ElfHeader64:
    e_ident: ElfIdent
    e_type: Elf64_Half
    e_machine: Elf64_Half
    e_version: Elf64_Word
    e_entry: Elf64_Addr
    e_phoff: Elf64_Off
    e_shoff: Elf64_Off
    e_flags: Elf64_Word
    e_ehsize: Elf64_Half
    e_phentsize: Elf64_Half
    e_phnum: Elf64_Half
    e_shentsize: Elf64_Half
    e_shnum: Elf64_Half
    e_shstrndx: Elf64_Half


@structure
class ProgramHeader32:
    p_type: Elf32_Word
    p_offset: Elf32_Off
    p_vaddr: Elf32_Addr
    p_paddr: Elf32_Addr
    p_filesz: Elf32_Word
    p_memsz: Elf32_Word
    p_flags: Elf32_Word
    p_align: Elf32_Word


@structure
class ProgramHeader64:
    p_type: Elf64_Word
    p_flags: Elf64_Word
    p_offset: Elf64_Off
    p_vaddr: Elf64_Addr
    p_paddr: Elf64_Addr
    p_filesz: Elf64_Xword
    p_memsz: Elf64_Xword
    p_align: Elf64_Xword


@structure
class SectionHeader32:
    sh_name: Elf32_Word
    sh_type: Elf32_Word
    sh_flags: Elf32_Word
    sh_addr: Elf32_Addr
    sh_offset: Elf32_Off
    sh_size: Elf32_Word
    sh_link: Elf32_Word
    sh_info: Elf32_Word
    sh_addralign: Elf32_Word
    sh_entsize: Elf32_Word


@structure
class SectionHeader64:
    sh_name: Elf64_Word
    sh_type: Elf64_Word
    sh_flags: Elf64_Xword
    sh_addr: Elf64_Addr
    sh_offset: Elf64_Off
    sh_size: Elf64_Xword
    sh_link: Elf64_Word
    sh_info: Elf64_Word
    sh_addralign: Elf64_Xword
    sh_entsize: Elf64_Xword


@structure
class SymbolTableEntry32:
    st_name: Elf32_Word
    st_value: Elf32_Addr
    st_size: Elf32_Word
    st_info: c_byte
    st_other: c_byte
    st_shndx: Elf32_Half


@structure
class SymbolTableEntry64:
    st_name: Elf64_Word
    st_info: c_byte
    st_other: c_byte
    st_shndx: Elf64_Half
    st_value: Elf64_Addr
    st_size: Elf32_Xword


@structure
class RelocationEntries32:
    r_offset: Elf32_Addr
    r_info: Elf32_Word


@structure
class RelocationEntriesAddend32:
    r_offset: Elf32_Addr
    r_info: Elf32_Word
    r_addend: Elf32_Sword


@structure
class RelocationEntries64:
    r_offset: Elf64_Addr
    r_info: Elf64_Xword


@structure
class RelocationEntriesAddend64:
    r_offset: Elf64_Addr
    r_info: Elf64_Xword
    r_addend: Elf32_Sxword


@structure
class Note32:
    name_size: Elf32_Word
    descriptor_size: Elf32_Word
    type: Elf32_Word


@structure
class Note64:
    name_size: Elf64_Word
    descriptor_size: Elf64_Word
    type: Elf64_Word


@structure
class Dynamic32:
    dynamic_tag: Elf32_Sword
    dynamic_value: Elf32_Word


@structure
class Dynamic64:
    dynamic_tag: Elf64_Sxword
    dynamic_value: Elf64_Xword


sections_description = {
    ".bss": "Uninitialized data",
    ".comment": "Version control information",
    ".data": "Initialized data",
    ".data1": "Initialized data",
    ".debug": "Symbolic debugging information",
    ".dynamic": "Dynamic linking information",
    ".dynstr": "Dynamic linking strings",
    ".dynsym": "Dynamic linking symbol table",
    ".fini": "Process termination code",
    ".fini_array": "Termination function pointers",
    ".got": "Global offset table",
    ".hash": "Symbol hash table",
    ".init": "Process initialization code",
    ".init_array": "Initialization function pointers",
    ".interp": "Program interpreter",
    ".line": "Line number for debugging",
    ".note": "Specific vendor information",
    ".plt": "Procedure linkage table",
    ".preinit_array": "Pre-initialization functions",
    ".rel": "Relocation information,",
    ".rodata": "Read-only data",
    ".rodata1": "Read-only data",
    ".shstrtab": "Section names",
    ".strtab": "Strings (symbol table)",
    ".symtab": "Symbol table",
    ".symtab_shndx": "Special symbol table",
    ".tbss": "Uninitialized thread-local data",
    ".tdata": "Initialized thread-local data",
    ".text": "Executable instruction",
}


def enum_from_value(value: _CData, enum_class: Enum) -> Field:
    """
    This function returns a Field with Enum name and value.
    """

    for constant in enum_class:
        if constant.value == value.value:
            return Field(
                value,
                constant.name,
                getattr(constant.value, "usage", None),
                getattr(constant.value, "description", None),
            )
    return Field(value, "UNDEFINED")


def enum_from_flags(value: _CData, enum_class: Enum) -> Iterable[Field]:
    """
    This function yields Fields with Enum name and value.
    """

    for constant in enum_class:
        if constant.value & value.value:
            yield Field(
                value,
                constant.name,
                getattr(constant.value, "usage", None),
                getattr(constant.value, "description", None),
            )


def parse_from_structure(file: _BufferedIOBase, structure: type) -> Structure:
    """
    This function reads file and parse readed data
    to Structure and returns it.
    """

    return structure(file.read(sizeof(structure)))


def read_until(file: _BufferedIOBase, end_data: bytes) -> bytes:
    """
    This function reads file until data end doesn't match the end_data params.
    """

    old_position = file.tell()
    data = file.read(1)
    position = file.tell()
    while not data.endswith(end_data) and old_position < position:
        old_position = position
        data += file.read(1)
        position = file.tell()

    return data


def read_string(file: _BufferedIOBase) -> c_char_p:
    """
    This function reads file a NULL terminating string from file position.
    """

    return c_char_p(read_until(file, b"\0"))


def get_padding_length(data_size: int, padding_to: int) -> int:
    """
    This function returns the padding length for this field.
    """

    padding_length = data_size % padding_to
    return padding_to - padding_length if padding_length else 0


def start_printable() -> None:
    """
    This function starts printing.
    """

    print(
        "\x1b[38;2;183;121;227m"
        + "Data name".ljust(25)
        + "\x1b[38;2;255;240;175m"
        + "Position".ljust(20)
        + "\x1b[38;2;255;208;11m"
        + "Data hexadecimal".ljust(40)
        + "\x1b[38;2;212;171;242m"
        + "Data".ljust(20)
        + "\x1b[38;2;201;247;87m"
        + "Information"
        + "\x1b[39m\n"
    )


def main() -> int:
    """
    This function runs the script from the command line.
    """

    url = False
    verbose = False
    no_color = False

    if "-u" in argv:
        argv.remove("-u")
        url = True

    if "-v" in argv:
        argv.remove("-v")
        verbose = True

    if "-c" in argv:
        argv.remove("-c")
        no_color = True

    if len(argv) != 2:
        print(
            f'USAGES: "{executable}" "{argv[0]}" [-c(no '
            "color)] [-v(verbose)] [-u(url)] ElfFile",
            file=stderr,
        )
        return 1

    file = (
        BytesIO(data := urlopen(argv[1]).read())
        if url
        else open(argv[1], "rb")
    )
    filesize = len(data) if url else getsize(argv[1])

    Data.verbose = verbose
    Data.no_color = no_color

    (
        elfindent,
        elf_headers,
        programs_headers,
        elf_sections,
        symbols_tables,
        comments,
        note_sections,
        notes,
        dynamics,
        sections,
    ) = parse_elffile(file)
    cli(
        elfindent,
        elf_headers,
        programs_headers,
        elf_sections,
        symbols_tables,
        comments,
        notes,
        dynamics,
        sections,
    )

    if entropy_charts_import:
        file.seek(0)
        charts_chunks_file_entropy(
            file,
            part_size=round(filesize / 100),
            sections=sections,
        )

    file.close()
    return 0


def cli(
    elf_ident: ElfIdent,
    elf_header: Union[ElfHeader32, ElfHeader64],
    elf_tables: List[Union[ProgramHeader32, ProgramHeader64]],
    elf_sections: List[Union[SectionHeader32, SectionHeader64]],
    symbols: List[Tuple[str, Union[SymbolTableEntry32, SymbolTableEntry64]]],
    comments: List[bytes],
    note_sections: List[Union[SectionHeader32, SectionHeader64]],
    dynamicStructures: List[Union[Dynamic32, Dynamic64]],
    sections: List[Section],
) -> None:
    """
    This function prints results in CLI.
    """

    Title("ELF identification").print()

    Data(
        "Magic bytes",
        elf_ident.ei_mag.value._start_position_,
        elf_ident.ei_mag.value._end_position_,
        elf_ident.ei_mag.value.value,
        elf_ident.ei_mag.information,
    ).print()

    Data(
        "ELF class",
        elf_ident.ei_class.value._start_position_,
        elf_ident.ei_class.value._end_position_,
        elf_ident.ei_class.value._data_,
        f"{elf_ident.ei_class.information} ({elf_ident.ei_class.value.value})",
    ).print()

    Data(
        "ELF data",
        elf_ident.ei_data.value._start_position_,
        elf_ident.ei_data.value._end_position_,
        elf_ident.ei_data.value._data_,
        f"{elf_ident.ei_data.information} ({elf_ident.ei_data.value.value})",
    ).print()

    Data(
        "ELF version",
        elf_ident.ei_version.value._start_position_,
        elf_ident.ei_version.value._end_position_,
        elf_ident.ei_version.value._data_,
        elf_ident.ei_version.information
        + f" ({elf_ident.ei_version.value.value})",
    ).print()

    Data(
        "ELF operating system",
        elf_ident.ei_osabi.value._start_position_,
        elf_ident.ei_osabi.value._end_position_,
        elf_ident.ei_osabi.value._data_,
        elf_ident.ei_osabi.information
        + f" ({elf_ident.ei_osabi.value.value})",
        False,
    ).print()

    Data(
        "ELF defined OS",
        elf_ident.ei_abiversion.value._start_position_,
        elf_ident.ei_abiversion.value._end_position_,
        elf_ident.ei_abiversion.value._data_,
        elf_ident.ei_abiversion.information
        + f" ({elf_ident.ei_abiversion.value.value})",
    ).print()

    Data(
        "ELF start padding",
        elf_ident.ei_pad.value._start_position_,
        elf_ident.ei_pad.value._end_position_,
        elf_ident.ei_pad.value._data_,
        elf_ident.ei_pad.information,
    ).vprint()

    Data(
        "ELF padding",
        elf_ident.ei_nident.value._start_position_,
        elf_ident.ei_nident.value._end_position_,
        elf_ident.ei_nident.value._data_,
        elf_ident.ei_nident.information,
    ).vprint()

    Title("ELF headers").print()

    Data(
        "ELF type",
        elf_header.e_type.value._start_position_,
        elf_header.e_type.value._end_position_,
        elf_header.e_type.value._data_,
        f"{elf_header.e_type.information} ({elf_header.e_type.value.value})",
    ).print()

    Data(
        "ELF machine",
        elf_header.e_machine.value._start_position_,
        elf_header.e_machine.value._end_position_,
        elf_header.e_machine.value._data_,
        elf_header.e_machine.information
        + f" ({elf_header.e_machine.value.value})",
        False,
    ).print()

    Data(
        "ELF version",
        elf_header.e_version.value._start_position_,
        elf_header.e_version.value._end_position_,
        elf_header.e_version.value._data_,
        elf_header.e_version.information
        + f" ({elf_header.e_version.value.value})",
    ).print()

    Data(
        "ELF entry point",
        elf_header.e_entry.value._start_position_,
        elf_header.e_entry.value._end_position_,
        elf_header.e_entry.value._data_,
        f"{elf_header.e_entry.information} ({elf_header.e_entry.value.value})",
    ).print()

    Data(
        "ELF header table offset",
        elf_header.e_phoff.value._start_position_,
        elf_header.e_phoff.value._end_position_,
        elf_header.e_phoff.value._data_,
        f"{elf_header.e_phoff.information} ({elf_header.e_phoff.value.value})",
    ).vprint()

    Data(
        "ELF section table offset",
        elf_header.e_shoff.value._start_position_,
        elf_header.e_shoff.value._end_position_,
        elf_header.e_shoff.value._data_,
        f"{elf_header.e_shoff.information} ({elf_header.e_shoff.value.value})",
    ).vprint()

    Data(
        "ELF processor specific",
        elf_header.e_flags.value._start_position_,
        elf_header.e_flags.value._end_position_,
        elf_header.e_flags.value._data_,
        f"{elf_header.e_flags.information} ({elf_header.e_flags.value.value})",
    ).print()

    Data(
        "ELF header's size",
        elf_header.e_ehsize.value._start_position_,
        elf_header.e_ehsize.value._end_position_,
        elf_header.e_ehsize.value._data_,
        elf_header.e_ehsize.information
        + f" ({elf_header.e_ehsize.value.value})",
        False,
    ).print()

    Data(
        "ELF entry header size",
        elf_header.e_phentsize.value._start_position_,
        elf_header.e_phentsize.value._end_position_,
        elf_header.e_phentsize.value._data_,
        elf_header.e_phentsize.information
        + f" ({elf_header.e_phentsize.value.value})",
    ).print()

    Data(
        "ELF header entry length",
        elf_header.e_phnum.value._start_position_,
        elf_header.e_phnum.value._end_position_,
        elf_header.e_phnum.value._data_,
        f"{elf_header.e_phnum.information} ({elf_header.e_phnum.value.value})",
    ).print()

    Data(
        "ELF entry section size",
        elf_header.e_shentsize.value._start_position_,
        elf_header.e_shentsize.value._end_position_,
        elf_header.e_shentsize.value._data_,
        elf_header.e_shentsize.information
        + f" ({elf_header.e_shentsize.value.value})",
    ).print()

    Data(
        "ELF section entry length",
        elf_header.e_shnum.value._start_position_,
        elf_header.e_shnum.value._end_position_,
        elf_header.e_shnum.value._data_,
        f"{elf_header.e_shnum.information} ({elf_header.e_shnum.value.value})",
    ).print()

    Data(
        "Section header table",
        elf_header.e_shstrndx.value._start_position_,
        elf_header.e_shstrndx.value._end_position_,
        elf_header.e_shstrndx.value._data_,
        elf_header.e_shstrndx.information
        + f" ({elf_header.e_shstrndx.value.value})",
    ).print()

    Title("ELF header table").print()

    for elf_table in elf_tables:
        Data(
            "Program header type",
            elf_table.p_type.value._start_position_,
            elf_table.p_type.value._end_position_,
            elf_table.p_type.value._data_,
            f"{elf_table.p_type.information} ({elf_table.p_type.value.value})",
            False,
        ).print()

        for flags in elf_table.flags:
            Data(
                "Program header flags",
                flags.value._start_position_,
                flags.value._end_position_,
                flags.value._data_,
                f"{flags.information} ({flags.value.value})",
                False,
            ).print()

        Data(
            "Program header address",
            elf_table.p_offset.value._start_position_,
            elf_table.p_offset.value._end_position_,
            elf_table.p_offset.value._data_,
            elf_table.p_offset.information
            + f" ({elf_table.p_offset.value.value})",
        ).print()

        Data(
            "Virtual address memory",
            elf_table.p_vaddr.value._start_position_,
            elf_table.p_vaddr.value._end_position_,
            elf_table.p_vaddr.value._data_,
            elf_table.p_vaddr.information
            + f" ({elf_table.p_vaddr.value.value})",
        ).vprint()

        Data(
            "Physical address",
            elf_table.p_paddr.value._start_position_,
            elf_table.p_paddr.value._end_position_,
            elf_table.p_paddr.value._data_,
            elf_table.p_paddr.information
            + f" ({elf_table.p_paddr.value.value})",
        ).vprint()

        Data(
            "Segment length file",
            elf_table.p_filesz.value._start_position_,
            elf_table.p_filesz.value._end_position_,
            elf_table.p_filesz.value._data_,
            elf_table.p_filesz.information
            + f" ({elf_table.p_filesz.value.value})",
        ).print()

        Data(
            "Segment length memory",
            elf_table.p_memsz.value._start_position_,
            elf_table.p_memsz.value._end_position_,
            elf_table.p_memsz.value._data_,
            elf_table.p_memsz.information
            + f" ({elf_table.p_memsz.value.value})",
        ).print()

        Data(
            "Segment alignment",
            elf_table.p_align.value._start_position_,
            elf_table.p_align.value._end_position_,
            elf_table.p_align.value._data_,
            elf_table.p_align.information
            + f" ({elf_table.p_align.value.value})",
        ).print()

    Title("ELF section table").print()

    for elf_section in elf_sections:
        Data(
            "Name: " + elf_section.name,
            elf_section.name._start_position_,
            elf_section.name._end_position_,
            elf_section.name._data_,
            sections_description.get(
                "." + elf_section.name.split(".")[1]
                if "." in elf_section.name
                else "",
                "Undefined section role.",
            ),
            False,
        ).print()

        Data(
            "Section name position",
            elf_section.sh_name.value._start_position_,
            elf_section.sh_name.value._end_position_,
            elf_section.sh_name.value._data_,
            elf_section.sh_name.information
            + f" ({elf_section.sh_name.value.value})",
        ).vprint()

        Data(
            "Section type",
            elf_section.sh_type.value._start_position_,
            elf_section.sh_type.value._end_position_,
            elf_section.sh_type.value._data_,
            elf_section.sh_type.information
            + f" ({elf_section.sh_type.value.value})",
            False,
        ).print()

        for flag in elf_section.flags:
            Data(
                "Section flags",
                flag.value._start_position_,
                flag.value._end_position_,
                flag.value._data_,
                f"{flag.information} ({flag.value.value})",
                False,
            ).print()

        Data(
            "Section memory address",
            elf_section.sh_addr.value._start_position_,
            elf_section.sh_addr.value._end_position_,
            elf_section.sh_addr.value._data_,
            elf_section.sh_addr.information
            + f" ({elf_section.sh_addr.value.value})",
        ).vprint()

        Data(
            "Section offset",
            elf_section.sh_offset.value._start_position_,
            elf_section.sh_offset.value._end_position_,
            elf_section.sh_offset.value._data_,
            elf_section.sh_offset.information
            + f" ({elf_section.sh_offset.value.value})",
        ).print()

        Data(
            "Section size",
            elf_section.sh_size.value._start_position_,
            elf_section.sh_size.value._end_position_,
            elf_section.sh_size.value._data_,
            elf_section.sh_size.information
            + f" ({elf_section.sh_size.value.value})",
        ).print()

        Data(
            "Section link",
            elf_section.sh_link.value._start_position_,
            elf_section.sh_link.value._end_position_,
            elf_section.sh_link.value._data_,
            elf_section.sh_link.information
            + f" ({elf_section.sh_link.value.value})",
        ).print()

        Data(
            "Section info",
            elf_section.sh_info.value._start_position_,
            elf_section.sh_info.value._end_position_,
            elf_section.sh_info.value._data_,
            elf_section.sh_info.information
            + f" ({elf_section.sh_info.value.value})",
        ).print()

        Data(
            "Section alignment",
            elf_section.sh_addralign.value._start_position_,
            elf_section.sh_addralign.value._end_position_,
            elf_section.sh_addralign.value._data_,
            elf_section.sh_addralign.information
            + f" ({elf_section.sh_addralign.value.value})",
        ).vprint()

        Data(
            "Symbol table entry size",
            elf_section.sh_entsize.value._start_position_,
            elf_section.sh_entsize.value._end_position_,
            elf_section.sh_entsize.value._data_,
            elf_section.sh_entsize.information
            + f" ({elf_section.sh_entsize.value.value})",
        ).print()

    precedent_name = ""

    for name, symbol in symbols:
        if name != precedent_name:
            Title("Symbol tables " + name).print()
            precedent_name = name

        Data(
            "Symbol value",
            symbol.st_value.value._start_position_,
            symbol.st_value.value._end_position_,
            symbol.st_value.value._data_,
            f"{symbol.st_value.information} ({symbol.st_value.value.value})",
            False,
        ).print()

        Data(
            "Associated sizes",
            symbol.st_size.value._start_position_,
            symbol.st_size.value._end_position_,
            symbol.st_size.value._data_,
            f"{symbol.st_size.information} ({symbol.st_size.value.value})",
            False,
        ).print()

        Data(
            "Section header index",
            symbol.st_shndx.value._start_position_,
            symbol.st_shndx.value._end_position_,
            symbol.st_shndx.value._data_,
            symbol.st_shndx.information
            + (" exported" if symbol.st_shndx.value.value else " imported")
            + " ("
            + (
                elf_sections[symbol.st_shndx.value.value].name
                if len(elf_sections) > symbol.st_shndx.value.value
                else str(symbol.st_shndx.value.value)
            )
            + ")",
            False,
        ).print()

        Data(
            "Symbol binding",
            symbol.st_info._start_position_,
            symbol.st_info._end_position_,
            symbol.st_info._data_,
            f"{symbol.st_bind.information} ({symbol.st_bind.value.value})",
            False,
        ).print()

        Data(
            "Symbol type",
            symbol.st_info._start_position_,
            symbol.st_info._end_position_,
            symbol.st_info._data_,
            f"{symbol.st_type.information} ({symbol.st_type.value.value})",
            False,
        ).print()

        Data(
            "Symbol visibility",
            symbol.st_other._start_position_,
            symbol.st_other._end_position_,
            symbol.st_other._data_,
            symbol.st_visibility.information
            + f" ({symbol.st_visibility.value.value})",
            False,
        ).print()

        Data(
            "Symbol name",
            symbol.name._start_position_,
            symbol.name._end_position_,
            symbol.name._data_,
            "Name: " + symbol.name,
            False,
        ).print()

    first = True
    for data in comments:
        if first:
            Title("Comment section").print()
            first = False

        Data(
            "Version control info",
            data._start_position_,
            data._end_position_,
            data,
            data.string,
            False,
        ).print()

    first = True
    for note in note_sections:
        if first:
            Title("Note sections").print()
            first = False

        Data(
            "Note name size",
            note.name_size._start_position_,
            note.name_size._end_position_,
            note.name_size._data_,
            f"Note name size ({note.name_size.value})",
            False,
        ).print()

        Data(
            "Descriptor size",
            note.descriptor_size._start_position_,
            note.descriptor_size._end_position_,
            note.descriptor_size._data_,
            f"Note descriptor size ({note.descriptor_size.value})",
            False,
        ).print()

        Data(
            "Note type",
            note.type._start_position_,
            note.type._end_position_,
            note.type._data_,
            f"Note type ({note.type.value})",
            False,
        ).print()

        Data(
            "Note name",
            note.name._start_position_,
            note.name._end_position_,
            note.name,
            note.name.string,
            False,
        ).print()

        Data(
            "Note descriptor",
            note.descriptor._start_position_,
            note.descriptor._end_position_,
            note.descriptor,
            "",
            False,
        ).print()

    first = True
    for dynamic in dynamicStructures:
        if first:
            Title("Dynamic section").print()
            first = False

        Data(
            f"Tag {dynamic.dynamic_tag.information}",
            dynamic.dynamic_tag._start_position_,
            dynamic.dynamic_tag._end_position_,
            dynamic.dynamic_tag.value._data_,
            str(dynamic.dynamic_tag.description),
            False,
        ).print()

        if dynamic.dynamic_tag.value.value != DynamicType.DT_FLAGS.value:
            Data(
                (
                    "Address"
                    if dynamic.dynamic_tag.usage == "pointer"
                    else "Value"
                ),
                dynamic.dynamic_value._start_position_,
                dynamic.dynamic_value._end_position_,
                dynamic.dynamic_value._data_,
                str(dynamic.dynamic_value.value),
                False,
            ).print()
        else:
            for flag in dynamic.dynamic_value.flags:
                Data(
                    "Flags " + str(flag.value.value),
                    flag._start_position_,
                    flag._end_position_,
                    flag.value._data_,
                    flag.description,
                    False,
                ).print()


def parse_elffile(
    file: _BufferedIOBase,
) -> Tuple[
    ElfIdent,
    Union[ElfHeader32, ElfHeader64],
    List[Union[ProgramHeader32, ProgramHeader64]],
    List[Union[SectionHeader32, SectionHeader64]],
    List[Tuple[str, Union[SymbolTableEntry32, SymbolTableEntry64]]],
    List[bytes],
    List[Union[SectionHeader32, SectionHeader64]],
    List[Union[Note32, Note64]],
    List[Union[Dynamic32, Dynamic64]],
    List[Section],
]:
    """
    This function parses ELF file.
    """

    elfindent, elf_classe = parse_elfidentification(file)
    elf_headers = parse_elfheaders(file, elf_classe)
    programs_headers = [*parse_programheaders(file, elf_headers, elf_classe)]
    (
        elf_sections,
        strtab_section,
        symtab_section,
        dynstr_section,
        dynsym_section,
        comment_section,
        dynamic_section,
        note_sections,
        sections,
    ) = parse_elfsections(file, elf_headers, elf_classe)
    symbols_tables = [
        *parse_elfsymbolstable(
            file,
            dynsym_section,
            dynstr_section,
            symtab_section,
            strtab_section,
            elf_classe,
        )
    ]
    comments = [*parse_elfcomment(file, comment_section)]
    notes = [*parse_elfnote(file, note_sections, elf_classe)]
    dynamics = [*parse_elfdynamic(file, dynamic_section, elf_classe)]
    return (
        elfindent,
        elf_headers,
        programs_headers,
        elf_sections,
        symbols_tables,
        comments,
        note_sections,
        notes,
        dynamics,
        sections,
    )


def parse_elfidentification(file: _BufferedIOBase) -> Tuple[ElfIdent, str]:
    """
    This function parses ELF identification headers.
    """

    elf_ident = parse_from_structure(file, ElfIdent)
    elf_ident.ei_mag = Field(
        elf_ident.ei_mag,
        "ELF magic bytes"
        if elf_ident.ei_mag.value == b"\x7fELF"
        else "Invalid magic bytes",
    )

    elf_ident.ei_class = enum_from_value(elf_ident.ei_class, ELfIdentClass)
    elf_classe = "64" if elf_ident.ei_class.value.value == 2 else "32"
    elf_ident.ei_data = enum_from_value(elf_ident.ei_data, ELfIdentData)

    DataToCClass.order = (
        "little" if elf_ident.ei_data.value.value == 1 else "big"
    )
    elf_ident.ei_version = enum_from_value(
        elf_ident.ei_version, ELfIdentVersion
    )
    elf_ident.ei_osabi = enum_from_value(elf_ident.ei_osabi, ELfIdentOS)

    elf_ident.ei_abiversion = Field(
        elf_ident.ei_abiversion,
        "OS specified" if elf_ident.ei_abiversion else "OS unspecified",
    )

    elf_ident.ei_pad = Field(elf_ident.ei_pad, "Start padding")
    elf_ident.ei_nident = Field(elf_ident.ei_nident, "Padding")

    return elf_ident, elf_classe


def parse_elfheaders(
    file: _BufferedIOBase, elf_classe: str
) -> Union[ElfHeader32, ElfHeader64]:
    """
    This function parses ELF headers.
    """

    file.seek(0)

    elf_header = parse_from_structure(
        file, globals()["ElfHeader" + elf_classe]
    )

    elf_header.e_type = enum_from_value(elf_header.e_type, ElfType)
    elf_header.e_machine = enum_from_value(elf_header.e_machine, ElfMachine)
    elf_header.e_version = enum_from_value(elf_header.e_version, ElfVersion)

    elf_header.e_entry = Field(
        elf_header.e_entry,
        "Entry point" if elf_header.e_entry else "No entry point",
    )

    elf_header.e_phoff = Field(
        elf_header.e_phoff,
        "Program header table offset"
        if elf_header.e_phoff
        else "No program header table",
    )

    elf_header.e_shoff = Field(
        elf_header.e_shoff,
        "Section table offset" if elf_header.e_shoff else "No header table",
    )

    elf_header.e_flags = Field(elf_header.e_flags, "Processor specific flags")
    elf_header.e_ehsize = Field(elf_header.e_ehsize, "ELF header's size")

    elf_header.e_phentsize = Field(
        elf_header.e_phentsize, "Entry header table size"
    )

    elf_header.e_phnum = Field(elf_header.e_phnum, "Header table entry number")

    elf_header.e_shentsize = Field(
        elf_header.e_shentsize, "Entry section header's size"
    )

    elf_header.e_shnum = Field(
        elf_header.e_shnum, "Section header entry number"
    )

    elf_header.e_shstrndx = Field(
        elf_header.e_shstrndx, "Section header table address"
    )

    return elf_header


def parse_programheaders(
    file: _BufferedIOBase,
    elf_header: Union[ElfHeader32, ElfHeader64],
    elf_classe: str,
) -> Iterable[Union[ProgramHeader32, ProgramHeader64]]:
    """
    This function parses program headers.
    """

    file.seek(elf_header.e_phoff.value.value)

    for _ in range(elf_header.e_phnum.value.value):
        elf_table = parse_from_structure(
            file, globals()["ProgramHeader" + elf_classe]
        )

        elf_table.p_type = enum_from_value(elf_table.p_type, ProgramHeaderType)
        elf_table.flags = [
            *enum_from_flags(elf_table.p_flags, ProgramHeaderFlags)
        ]

        elf_table.p_offset = Field(
            elf_table.p_offset, "Program header file position"
        )

        elf_table.p_vaddr = Field(
            elf_table.p_vaddr, "Program header virtual position"
        )

        elf_table.p_paddr = Field(
            elf_table.p_paddr, "Program header physical position"
        )

        elf_table.p_filesz = Field(
            elf_table.p_filesz, "Segment size in bytes in file image"
        )

        elf_table.p_memsz = Field(
            elf_table.p_memsz, "Segment size in bytes in memory image"
        )

        elf_table.p_align = Field(
            elf_table.p_align,
            "No segment alignment"
            if elf_table.p_align.value in (0, 1)
            else "Segment alignment",
        )

        yield elf_table


def parse_elfsections(
    file: _BufferedIOBase,
    elf_header: Union[ElfHeader32, ElfHeader64],
    elf_classe: str,
) -> Tuple[
    List[Union[SectionHeader32, SectionHeader64]],
    Union[SectionHeader32, SectionHeader64, None],
    Union[SectionHeader32, SectionHeader64, None],
    Union[SectionHeader32, SectionHeader64, None],
    Union[SectionHeader32, SectionHeader64, None],
    Union[SectionHeader32, SectionHeader64, None],
    Union[SectionHeader32, SectionHeader64, None],
    List[Union[SectionHeader32, SectionHeader64]],
    List[Section],
]:
    """
    This function parses ELK sections.
    """

    file.seek(elf_header.e_shoff.value.value)

    elf_sections = [
        parse_from_structure(file, globals()["SectionHeader" + elf_classe])
        for _ in range(elf_header.e_shnum.value.value)
    ]
    sections = []
    headers_names_table_address = elf_sections[
        elf_header.e_shstrndx.value.value
    ].sh_offset.value
    strtab_section = None
    symtab_section = None
    dynstr_section = None
    dynsym_section = None
    comment_section = None
    note_sections = []
    dynamic_section = None

    for elf_section in elf_sections:
        position = file.tell()
        file.seek(headers_names_table_address + elf_section.sh_name.value)
        name = read_string(file)
        elf_section.name = FileString(name.value.decode("latin-1"))
        elf_section.name._start_position_ = (
            headers_names_table_address + elf_section.sh_name.value
        )
        elf_section.name._end_position_ = file.tell()
        elf_section.name._data_ = name.value + b"\0"
        file.seek(position)

        if elf_section.name == ".strtab":
            strtab_section = elf_section

        if elf_section.name == ".symtab":
            symtab_section = elf_section

        if elf_section.name == ".dynstr":
            dynstr_section = elf_section

        if elf_section.name == ".dynsym":
            dynstr_section = elf_section

        if elf_section.name == ".comment":
            comment_section = elf_section

        if elf_section.name == ".dynamic":
            dynamic_section = elf_section

        if elf_section.name.startswith(".note"):
            note_sections.append(elf_section)

        if entropy_charts_import:
            sections.append(
                Section(
                    elf_section.name,
                    elf_section.sh_offset.value,
                    elf_section.sh_size.value,
                )
            )

        elf_section.sh_name = Field(
            elf_section.sh_name, "Section name position"
        )

        elf_section.sh_type = enum_from_value(
            elf_section.sh_type, SectionHeaderType
        )

        elf_section.flags = [
            *enum_from_flags(elf_section.sh_flags, SectionAttributeFlags)
        ]

        elf_section.sh_addr = Field(
            elf_section.sh_addr, "Section memory address"
        )

        elf_section.sh_offset = Field(
            elf_section.sh_offset, "Section file offset"
        )

        elf_section.sh_size = Field(
            elf_section.sh_size, "Section size in bytes"
        )

        elf_section.sh_link = Field(elf_section.sh_link, "Section link")
        elf_section.sh_info = Field(elf_section.sh_info, "Section info")

        elf_section.sh_addralign = Field(
            elf_section.sh_addralign,
            "Section without alignment"
            if elf_section.sh_addralign.value in (1, 0)
            else "Section alignment",
        )

        elf_section.sh_entsize = Field(
            elf_section.sh_entsize,
            "No section symbal table"
            if elf_section.sh_entsize.value == 0
            else "Symbol table entry size",
        )

    return (
        elf_sections,
        strtab_section,
        symtab_section,
        dynstr_section,
        dynsym_section,
        comment_section,
        dynamic_section,
        note_sections,
        sections,
    )


def parse_elfsymbolstable(
    file: _BufferedIOBase,
    dynsym_section: Union[ElfHeader32, ElfHeader64, None],
    dynstr_section: Union[ElfHeader32, ElfHeader64, None],
    symtab_section: Union[ElfHeader32, ElfHeader64, None],
    strtab_section: Union[ElfHeader32, ElfHeader64, None],
    elf_classe: str,
) -> Iterable[Tuple[str, Union[SymbolTableEntry32, SymbolTableEntry64]]]:
    """
    This function parses ELF symbols table.
    """

    for symbol_section, str_section in (
        (dynsym_section, dynstr_section),
        (symtab_section, strtab_section),
    ):
        if str_section is None or symbol_section is None:
            continue

        file.seek(str_section.sh_offset.value.value)
        data = BytesIO(file.read(str_section.sh_size.value.value))

        symboltable_structure = globals()["SymbolTableEntry" + elf_classe]
        symboltable_structure_size = sizeof(symboltable_structure)

        file.seek(symbol_section.sh_offset.value.value)
        size = symbol_section.sh_size.value.value

        for _ in range(size // symboltable_structure_size):
            symbol = parse_from_structure(file, symboltable_structure)
            symbol.st_value = Field(symbol.st_value, "Symbol table value")

            symbol.st_size = Field(symbol.st_size, "Symbol table size")

            symbol.st_shndx = enum_from_value(
                symbol.st_shndx, SpecialSectionIndexes
            )

            symbol.st_bind = enum_from_value(
                c_byte(symbol.st_info.value >> 4), SymbolBinding
            )

            symbol.st_type = enum_from_value(
                c_byte(symbol.st_info.value & 0xF), SymbolType
            )

            symbol.st_visibility = enum_from_value(
                c_byte(symbol.st_other.value & 0x3), SymbolVisibility
            )

            start_position = (
                data.seek(symbol.st_name.value)
                + str_section.sh_offset.value.value
            )
            symbol.st_name = read_string(data)
            symbol.name = FileString(symbol.st_name.value.decode("latin-1"))
            symbol.name._start_position_ = start_position
            symbol.name._end_position_ = (
                symbol.name._start_position_ + len(symbol.name) + 1
            )
            symbol.name._data_ = symbol.st_name.value + b"\0"

            yield symbol_section.name, symbol


def parse_elfcomment(
    file: _BufferedIOBase,
    comment_section: Union[SectionHeader32, SectionHeader64],
) -> Iterable[bytes]:
    """
    This function parses ELF comment section.
    """

    if comment_section:
        position = file.seek(comment_section.sh_offset.value.value)

        for data in file.read(comment_section.sh_size.value.value).split(
            b"\0"
        ):
            if data:
                data = FileBytes(data + b"\0")
                data._start_position_ = position
                data._end_position_ = position + len(data) + 1
                data.string = data.decode("latin-1")
                yield data
                position += len(data) + 1
            else:
                position += 1


def parse_elfnote(
    file: _BufferedIOBase,
    note_sections: List[Union[SectionHeader32, SectionHeader64]],
    elf_classe: str,
) -> Iterable[Union[Note32, Note64]]:
    """
    This function parses ELF note sections.
    """

    for note in note_sections:
        file.seek(note.sh_offset.value.value)
        note = parse_from_structure(file, globals()["Note" + elf_classe])

        position = file.tell()
        note.name = FileBytes(
            file.read(
                note.name_size.value
                + get_padding_length(note.name_size.value, 4)
            )
        )
        note.name.string = note.name.decode("latin-1")
        note.name._start_position_ = position
        note.name._end_position_ = file.tell()
        position = file.tell()
        note.descriptor = FileBytes(
            file.read(
                note.descriptor_size.value
                + get_padding_length(note.name_size.value, 4)
            )
        )
        note.descriptor._start_position_ = position
        note.descriptor._end_position_ = file.tell()

        yield note


def parse_elfdynamic(
    file: _BufferedIOBase,
    dynamic_section: Union[SectionHeader32, SectionHeader64, None],
    elf_classe: str,
) -> Iterable[Union[Dynamic32, Dynamic64]]:
    """
    This function parses ELF dynamic section.
    """

    if dynamic_section is None:
        return None

    file.seek(dynamic_section.sh_offset.value.value)

    d_tag = 1
    while d_tag:
        position = file.tell()
        dynamic = parse_from_structure(file, globals()["Dynamic" + elf_classe])
        dynamic.dynamic_tag = enum_from_value(dynamic.dynamic_tag, DynamicType)
        dynamic.dynamic_tag._start_position_ = position
        dynamic.dynamic_tag._end_position_ = position + sizeof(
            dynamic.dynamic_tag.value
        )

        if dynamic.dynamic_tag.value.value != DynamicType.DT_FLAGS.value:
            dynamic.dynamic_value._start_position_ = position + sizeof(
                dynamic.dynamic_tag.value
            )
            dynamic.dynamic_value._end_position_ = file.tell()
        else:
            dynamic.dynamic_value.flags = []
            for flag in enum_from_flags(dynamic.dynamic_value, DynamicFlags):
                flag._start_position_ = position + sizeof(
                    dynamic.dynamic_tag.value
                )
                flag._end_position_ = file.tell()
                dynamic.dynamic_value.flags.append(flag)

        d_tag = dynamic.dynamic_tag.value.value
        yield dynamic


if __name__ == "__main__":
    exit(main())
