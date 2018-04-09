#! /usr/bin/env python

import sys, os
from enum import Enum

################### HELPERS ###########################
def read_fields(f, fields):
  header={}
  for (flen, fname, ftype) in fields:
    header[fname]=ftype.from_bytes(f.read(flen), byteorder=endianness())
  return header

def endianness():
  return 'big'

def littleendian():
  return 'little'


######################################################################
### ELF header definition
######################################################################
class e_elfenum(Enum):
  
  @classmethod
  def from_bytes(cls, ba, byteorder='little'):
    return cls(int.from_bytes(ba, byteorder=byteorder))
  
class e_endian(e_elfenum):
  little = 1
  big = 2
  
  def __init__(self, endian):
    super().__init__()
    if 1==endian:
      global endianness
      endianness = littleendian
  
class e_type(e_elfenum):
  relocatable = 1
  executable = 2
  shared = 3
  core = 4

class e_class(Enum):
  bit32 = 1
  bit64 = 2
  
class e_machine(e_elfenum):
  anymachine = 0
  sparc = 2
  x86 = 3
  mips = 8
  powerpc = 0x14
  x390 = 0x16
  arm = 0x28
  superH = 0x2A
  ia_64 = 0x32
  x86_64 = 0x3E
  aarch64 = 0xB7
  risc_v = 0xF3

elf_fields32 = (
# not included :
# (4, "EI_MAG0", b'\x00'),  # 0x7F followed by ELF(45 4c 46) in ASCII; these four bytes constitute the magic number.
# (1, "EI_CLASS", b'\x00'),	#This byte is set to either 1 or 2 to signify 32- or 64-bit format, respectively.
#   ( 1, "EI_DATA", endianness,)      #This byte is set to either 1 or 2 to signify little or big endianness, respectively. This affects interpretation of multi-byte fields starting with offset 0x10.
   (1,	"EI_VERSION", int,)	  #Set to 1 for the original version of ELF.
  ,(1,	"EI_OSABI", int,)	    #Identifies the target operating system ABI.
  ,(1,	"EI_ABIVERSION", int,)	#Further specifies the ABI version. Its interpretation depends on the target ABI. Linux kernel (after at least 2.6) has no definition of it.[5] In that case, offset and size of EI_PAD are 8.
  ,(7,	"EI_PAD", int,)	      #currently unused
  ,(2,	"e_type", e_type,)	      #1, 2, 3, 4 specify whether the object is relocatable, executable, shared, or core, respectively.
  ,(2,	"e_machine", e_machine,)	  #Specifies target instruction set architecture. Some examples are:
  ,(4,	"e_version", int,)	  #Set to 1 for the original version of ELF.
  ,(4,	"e_entry", int,)	    #This is the memory address of the entry point from where the process starts executing. This field is either 32 or 64 bits long depending on the format defined earlier.
  ,(4,	"e_phoff", int,)	    #Points to the start of the program header table. It usually follows the file header immediately, making the offset 0x34 or 0x40 for 32- and 64-bit ELF executables, respectively.
  ,(4,	"e_shoff", int,)	    #Points to the start of the section header table.
  ,(4,	"e_flags", int,)	    #Interpretation of this field depends on the target architecture.
  ,(2,	"e_ehsize", int,)	    #Contains the size of this header, normally 64 Bytes for 64-bit and 52 Bytes for 32-bit format.
  ,(2,	"e_phentsize", int,)	#Contains the size of a program header table entry.
  ,(2,	"e_phnum", int,)	    #Contains the number of entries in the program header table.
  ,(2,	"e_shentsize", int,)	#Contains the size of a section header table entry.
  ,(2,	"e_shnum", int,)	    #Contains the number of entries in the section header table.
  ,(2,	"e_shstrndx", int,)	  #Contains index of the section header table entry that contains the section names.
)
elf_fields64 = (
   (1,	"EI_VERSION", int,)
  ,(1,	"EI_OSABI", int,)
  ,(1,	"EI_ABIVERSION", int,)
  ,(7,	"EI_PAD", int,)
  ,(2,	"e_type", e_type,)
  ,(2,	"e_machine", e_machine,)
  ,(4,	"e_version", int,)
  ,(8,	"e_entry", int,)
  ,(8,	"e_phoff", int,)
  ,(8,	"e_shoff", int,)
  ,(4,	"e_flags", int,)
  ,(2,	"e_ehsize", int,)
  ,(2,	"e_phentsize", int,)
  ,(2,	"e_phnum", int,)
  ,(2,	"e_shentsize", int,)
  ,(2,	"e_shnum", int,)
  ,(2,	"e_shstrndx", int,)
)

######################################################################
### program header definition
######################################################################

class e_pttype(e_elfenum):
  PT_NULL     = 0
  PT_LOAD     = 1
  PT_DYNAMIC  = 2
  PT_INTERP   = 3
  PT_NOTE     = 4
  PT_SHLIB    = 5
  PT_PHDR     = 6
  PT_LOOS     = 0x60000000
  PT_HIOS     = 0x6FFFFFFF
  PT_LOPROC   = 0x70000000
  PT_HIPROC   = 0x7FFFFFFF

class mybytes(bytes):
  
  @classmethod
  def from_bytes(cls, ba, byteorder='little'):
    return ba
  
program_fields32 = (
   (4, 	"p_type", e_pttype) #Identifies the type of the segment.
  ,(4,	"p_offset",	int)       #Offset of the segment in the file image.
  ,(4,	"p_vaddr",	int)       #Virtual address of the segment in memory.
  ,(4,	"p_paddr",	int)       #On systems where physical address is relevant, reserved for segment's physical address.
  ,(4,	"p_filesz",	int)       #Size in bytes of the segment in the file image. May be 0.
  ,(4,	"p_memsz",	int)       #Size in bytes of the segment in memory. May be 0.
  ,(4,  "flags",	  mybytes)         #Segment-dependent flags (position for 32-bit structure).
  ,(4,	"p_align",	int)       #0 and 1 specify no alignment. Otherwise should be a positive, integral power of 2, with p_vaddr equating p_offset modulus p_align.
)

program_fields64 = (
   (4, 	"p_type", e_pttype)
  ,(4,	"p_flags",	mybytes) 
  ,(8,	"p_offset",	int)   
  ,(8,	"p_vaddr",	int)   
  ,(8,	"p_paddr",	int)   
  ,(8,	"p_filesz",	int)   
  ,(8,	"p_memsz",	int)   
  ,(8,	"p_align",	int)   
)

######################################################################
### section header definition
######################################################################

class e_shtype(e_elfenum):
  SHT_NULL	        = 0           # Section header table entry unused
  SHT_PROGBITS      = 1           # 	Program data
  SHT_SYMTAB	      = 2           #  Symbol table
  SHT_STRTAB	      = 3           #  String table
  SHT_RELA	        = 4           # Relocation entries with addends
  SHT_HASH	        = 5           # Symbol hash table
  SHT_DYNAMIC	      = 6           # Dynamic linking information
  SHT_NOTE	        = 7           # Notes
  SHT_NOBITS        = 8           # Program space with no data (bss)
  SHT_REL	          = 9           # Relocation entries, no addends
  SHT_SHLIB	        = 0x0A        # Reserved
  SHT_DYNSYM	      = 0x0B        # Dynamic linker symbol table
  SHT_INIT_ARRAY	  = 0x0E        # Array of constructors
  SHT_FINI_ARRAY	  = 0x0F        # Array of destructors
  SHT_PREINIT_ARRAY	= 0x10        # Array of pre-constructors
  SHT_GROUP	        = 0x11        # Section group
  SHT_SYMTAB_SHNDX	= 0x12        # Extended section indeces
  SHT_NUM	          = 0x13        # Number of defined types.
  SHT_LOOS	        = 0x60000000  # Start OS-specific.

class e_shflags(e_elfenum):
  SHF_WRITE	              = 0x1	                #   Writable
  SHF_ALLOC	              = 0x2	                # 	Occupies memory during execution
  SHF_EXECINSTR	          = 0x4	                # 	Executable
  SHF_MERGE	              = 0x10	              # 	Might be merged
  SHF_STRINGS	            = 0x20	              # 	Contains nul-terminated strings
  SHF_INFO_LINK	          = 0x40	              # 	'sh_info' contains SHT index
  SHF_LINK_ORDER	        = 0x80	              # 	Preserve order after combining
  SHF_OS_NONCONFORMING	  = 0x100	              # 	Non-standard OS specific handling required
  SHF_GROUP	              = 0x200	              # 	Section is member of a group
  SHF_TLS	                = 0x400	              # 	Section hold thread-local data
  SHF_MASKOS	            = 0x0ff00000	        # 	OS-specific
  SHF_MASKPROC          	= 0xf0000000	        # 	Processor-specific
  SHF_ORDERED	            = 0x4000000	          # 	Special ordering requirement (Solaris)
  SHF_EXCLUDE	            = 0x8000000	          # 	Section is excluded unless referenced or allocated (Solaris)

class sec_types:
  @staticmethod
  def from_bytes(ba, byteorder='little'):
    fl = int.from_bytes(ba, byteorder=byteorder)
    try:
      return e_shtype(fl)
    except:
      pass
    return fl # return raw value if type unknow
    
class sec_flags:
  @staticmethod
  def from_bytes(ba, byteorder='little'):
    attributs = []
    fl = int.from_bytes(ba, byteorder=byteorder)
    for v in list(e_shflags):
      if (v.value&fl) > 0:
        attributs.append(v)
    return attributs
    
class string_table:
  strings={}
  
  @classmethod
  def from_bytes(cls, ba):
    cls=cls()
    cls.strings={}
    stridx = 0
    for idx in range(len(ba)):
      if ba[idx]==0:
        if stridx > 0 : # igore first string which is NULL
          cls.strings[stridx]=ba[stridx:idx].decode("utf-8") # no elf specification here ?
        stridx = idx + 1
    return cls
  
section_fileds32 = (
   (4,	"sh_name", int)	        # An offset to a string in the .shstrtab section that represents the name of this section
  ,(4,	"sh_type", sec_types)    # 	Identifies the type of this header.
  ,(4,	"sh_flags", sec_flags)  # 	Identifies the attributes of the section.
  ,(4,	"sh_addr", int)         #	Virtual address of the section in memory, for sections that are loaded.
  ,(4,	"sh_offset", int)       # 	Offset of the section in the file image.
  ,(4,	"sh_size", int)         # 	Size in bytes of the section in the file image. May be 0.
  ,(4,	"sh_link", int)         # 	Contains the section index of an associated section. This field is used for several purposes, depending on the type of section.
  ,(4,	"sh_info", int)         # 	Contains extra information about the section. This field is used for several purposes, depending on the type of section.
  ,(4,	"sh_addralign", int)    # 	Contains the required alignment of the section. This field must be a power of two.
  ,(4,	"sh_entsize", int)      # 	Contains the size, in bytes, of each entry, for sections that contain fixed-size entries. Otherwise, this field contains zero.
)
section_fileds64 = (
   (4,	"sh_name", int)	        
  ,(4,	"sh_type", sec_types)    
  ,(8,	"sh_flags", sec_flags)  
  ,(8,	"sh_addr", int)         
  ,(8,	"sh_offset", int)       
  ,(8,	"sh_size", int)         
  ,(4,	"sh_link", int)         
  ,(4,	"sh_info", int)         
  ,(8,	"sh_addralign", int)    
  ,(8,	"sh_entsize", int)      
)

######################################################################
### symbole table definition
######################################################################
class e_stbind(e_elfenum):
  STB_LOCAL         = 0
  STB_GLOBAL        = 1
  STB_WEAK          = 2
  STB_LOPROC        = 13
  STB_HIPROC        = 15

class e_sttype(e_elfenum):
  STT_NOTYPE        = 0
  STT_OBJECT        = 1
  STT_FUNC          = 2
  STT_SECTION       = 3
  STT_FILE          = 4
  STT_LOPROC        = 13
  STT_HIPROC        = 15

class e_stinfo:
  st_bind = None
  st_type = None
  
  @classmethod
  def from_bytes(cls, ba, byteorder='little'):
    cls=cls()
    cls.st_bind=e_stbind(ord(ba)>>4)
    cls.st_type=e_sttype(ord(ba)&0x0f)
    return cls

symbol_fields32 = (
   (4, "st_name",     int)
  ,(4, "st_value",    int)
  ,(4, "st_size",     int)
  ,(1, "st_info",     e_stinfo)
  ,(1,  "st_other",   int)
  ,(2,  "st_shndx",   int)
)


######################################################################
### do the magic
######################################################################
def parse_elf_header(f):
  ei_class=e_class(int.from_bytes(f.read(1), byteorder=endianness()))
  ei_endian=e_endian(int.from_bytes(f.read(1), byteorder=endianness()))
  file_fields = elf_fields32
  program_fields = program_fields32
  section_fields = section_fileds32
  sections={}
  if ei_class.name == "bit62":
    file_fields = elf_fields64
    program_fields = program_fields64
    section_fields = section_fileds64
  elf_header=read_fields(f, file_fields)
  elf_header["ei_class"]=ei_class
  elf_header["ei_endian"]=ei_endian
  
  print("********** file header **********")
  print("%s"%elf_header)
  print("")

  p = elf_header["e_phoff"] 
  if p >0:
    program_headers={}
    for nprg in range(elf_header["e_phnum"]):
      f.seek(p+nprg*elf_header["e_phentsize"], 0) 
      program_headers[nprg]=read_fields(f, program_fields)

    print("********** program header **********")
    for n, p in program_headers.items():
      print("%s:%s"% (n,p))
    print("")

  p=elf_header["e_shoff"]
  if p>0:
    section_headers={}
    for nsec in range(elf_header["e_shnum"]):
      {}
      f.seek(p+nsec*elf_header["e_shentsize"], 0)
      section_header = read_fields(f, section_fields)
      if section_header["sh_type"] != e_shtype.SHT_NULL:
        section_headers[nsec]=section_header
        if e_shtype.SHT_STRTAB == section_header["sh_type"]:
          f.seek(section_header["sh_offset"], 0)
          section_header["string_table"]=string_table.from_bytes(f.read(section_header["sh_size"]))

    # populate strings in section header
    if elf_header["e_shstrndx"]>0:
      try:
        strs=section_headers[elf_header["e_shstrndx"]]["string_table"].strings
        for i, s in section_headers.items():
          if s["sh_name"] > 0:
            try:
              s["name"]=strs[s["sh_name"]]
              if ".strtab"==s["name"]:
                sections["STRINGS"]=s["string_table"].strings
              if ".symtab"==s["name"]:
                sections["SYMTAB"]=s
            except:
              print("*** ERROR: string %s not found" % s["sh_name"])
              # don"t fail
      except:
        print("*** ERROR: string table section not found")
        # don't fail here

    print("********** section header **********")
    for i,s in section_headers.items():
      print("%s:%s"%(i,s))
    print("")
    
    # populate symtables
    symbols={}
    i=0
    if "SYMTAB" in sections.keys():
      s=sections["SYMTAB"]
      f.seek(s["sh_offset"], 0)
      for idx in range(0, s["sh_size"], s["sh_entsize"]):
        symbol=read_fields(f, symbol_fields32)
        if idx > 0 and symbol["st_name"] > 0:
          try:
            symbol["name"]=sections["STRINGS"][symbol["st_name"]]
          except:
            symbol["name"]=""
        else:
          symbol["name"]=""
        symbols[i]=symbol
        i += 1
        
    print("********** symbols **********")
    print(" #:ADDRESS \tSIZE\tBIND    \tTYPE      \tSECTION \tNAME")
    for i, sym in symbols.items():
      print("%s:%08x\t%s\t%s\t%s\t%s\t%s"%(
        i, sym["st_value"], sym["st_size"], sym["st_info"].st_bind.name, sym["st_info"].st_type.name, sym["st_shndx"], sym["name"]
      ))
    print("")
    
def main():
  print("self.py: simple elf file parser, (c) 2018 by juju2013")
  if len(sys.argv)<2:
    print("  Usage: %s elf_binary"%sys.argv[0])
    exit(1)
  elf(sys.argv[1])

def elf(fname):
  with open(fname, "rb") as elff:
    if elff.read(4) != b'\x7fELF':
      print("%s is not a valid ELF file!" % sys.argv[1])
      exit(1)
      
    # parse headers
    print("")
    parse_elf_header(elff)

if __name__ == "__main__" :
  main()
else :
  print("from %s"%__name__)
