use core::fmt;
use core::mem;
use core::slice;

use {P32Le, P64Le, P32Be, P64Be, ToNative, Native, Primitive, ElfFile, U32Le, U32Be, U64Le, U64Be};
use header::{Header, Class, Data};
use zero::{read, read_array, read_str, read_strs_to_null, StrReaderIterator, Pod};
use symbol_table;
use dynamic::Dynamic;
use hash::HashTable;

pub fn parse_section_header<'a>(input: &'a [u8],
                                header: Header<'a>,
                                index: u16)
                                -> Result<SectionHeader<'a>, &'static str> {
    // Trying to get index 0 (SHN_UNDEF) is also probably an error, but it is a legitimate section.
    assert!(index < SHN_LORESERVE,
            "Attempt to get section for a reserved index");

    header.pt2.map(|pt2| {
        let start = (index as u64 * pt2.sh_entry_size() as u64 + pt2.sh_offset() as u64) as usize;
        let end = start + pt2.sh_entry_size() as usize;

        match (header.pt1.class(), header.pt1.data()) {
            (Class::ThirtyTwo, Data::LittleEndian) => {
                let header: &'a SectionHeader_<P32Le> = read(&input[start..end]);
                SectionHeader::Sh32Le(header)
            }
            (Class::ThirtyTwo, Data::BigEndian) => {
                let header: &'a SectionHeader_<P32Be> = read(&input[start..end]);
                SectionHeader::Sh32Be(header)
            }
            (Class::SixtyFour, Data::LittleEndian) => {
                let header: &'a SectionHeader_<P64Le> = read(&input[start..end]);
                SectionHeader::Sh64Le(header)
            }
            (Class::SixtyFour, Data::BigEndian) => {
                let header: &'a SectionHeader_<P64Be> = read(&input[start..end]);
                SectionHeader::Sh64Be(header)
            }
            _ => unreachable!(),
        }
    })
}

pub struct SectionIter<'b, 'a: 'b> {
    pub file: &'b ElfFile<'a>,
    pub next_index: u16,
}

impl<'b, 'a> Iterator for SectionIter<'b, 'a> {
    type Item = SectionHeader<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let count = self.file.header.pt2.map(|pt2| pt2.sh_count()).unwrap_or(0);
        if self.next_index >= count {
            return None;
        }

        let result = self.file.section_header(self.next_index);
        self.next_index += 1;
        result.ok()
    }
}

// Distinguished section indices.
pub const SHN_UNDEF: u16 = 0;
pub const SHN_LORESERVE: u16 = 0xff00;
pub const SHN_LOPROC: u16 = 0xff00;
pub const SHN_HIPROC: u16 = 0xff1f;
pub const SHN_LOOS: u16 = 0xff20;
pub const SHN_HIOS: u16 = 0xff3f;
pub const SHN_ABS: u16 = 0xfff1;
pub const SHN_COMMON: u16 = 0xfff2;
pub const SHN_XINDEX: u16 = 0xffff;
pub const SHN_HIRESERVE: u16 = 0xffff;

#[derive(Clone, Copy)]
pub enum SectionHeader<'a> {
    Sh32Le(&'a SectionHeader_<P32Le>),
    Sh32Be(&'a SectionHeader_<P32Be>),
    Sh64Le(&'a SectionHeader_<P64Le>),
    Sh64Be(&'a SectionHeader_<P64Be>),
}

macro_rules! getter {
    ($name: ident, $typ: ident) => {
        pub fn $name(&self) -> $typ {
            match *self {
                SectionHeader::Sh32Le(h) => h.$name.to_native() as $typ,
                SectionHeader::Sh32Be(h) => h.$name.to_native() as $typ,
                SectionHeader::Sh64Le(h) => h.$name.to_native() as $typ,
                SectionHeader::Sh64Be(h) => h.$name.to_native() as $typ,
            }
        }
    }
}

impl<'a> SectionHeader<'a> {
    // Note that this function is O(n) in the length of the name.
    pub fn get_name(&self, elf_file: &ElfFile<'a>) -> Result<&'a str, &'static str> {
        self.get_type().and_then(|typ| match typ {
            ShType::Null => Err("Attempt to get name of null section"),
            _ => elf_file.get_shstr(self.name()),
        })
    }

    pub fn get_type(&self) -> Result<ShType, &'static str> {
        self.type_().as_sh_type()
    }

    pub fn get_data(&self, elf_file: &ElfFile<'a>) -> Result<SectionData<'a>, &'static str> {
        macro_rules! array_data {
            ($data32le: ident, $data32be: ident, $data64le: ident, $data64be: ident) => {{
                let data = self.raw_data(elf_file);
                match (elf_file.header.pt1.class(), elf_file.header.pt1.data()) {
                    (Class::ThirtyTwo, Data::LittleEndian) => SectionData::$data32le(read_array(data)),
                    (Class::ThirtyTwo, Data::BigEndian) => SectionData::$data32be(read_array(data)),
                    (Class::SixtyFour, Data::LittleEndian) => SectionData::$data64le(read_array(data)),
                    (Class::SixtyFour, Data::BigEndian) => SectionData::$data64be(read_array(data)),
                    _ => unreachable!(),
                }
            }}
        }

        self.get_type().map(|typ| match typ {
            ShType::Null | ShType::NoBits => SectionData::Empty,
            ShType::ProgBits |
            ShType::ShLib |
            ShType::OsSpecific(_) |
            ShType::ProcessorSpecific(_) |
            ShType::User(_) => SectionData::Undefined(self.raw_data(elf_file)),
            ShType::SymTab => array_data!(SymbolTable32Le, SymbolTable32Be, SymbolTable64Le, SymbolTable64Be),
            ShType::DynSym => array_data!(DynSymbolTable32Le, DynSymbolTable32Be, DynSymbolTable64Le, DynSymbolTable64Be),
            ShType::StrTab => SectionData::StrArray(self.raw_data(elf_file)),
            ShType::InitArray | ShType::FiniArray | ShType::PreInitArray => {
                array_data!(FnArray32Le, FnArray32Be, FnArray64Le, FnArray32Be)
            }
            ShType::Rela => array_data!(Rela32Le, Rela32Be, Rela64Le, Rela64Be),
            ShType::Rel => array_data!(Rel32Le, Rel32Be, Rel64Le, Rel64Be),
            ShType::Dynamic => array_data!(Dynamic32Le, Dynamic32Be, Dynamic64Le, Dynamic64Be),
            ShType::Group => {
                let data = self.raw_data(elf_file);
                unsafe {
                    let flags: &'a u32 = mem::transmute(&data[0]);
                    let indicies: &'a [u32] = read_array(&data[4..]);
                    SectionData::Group {
                        flags: flags,
                        indicies: indicies,
                    }
                }
            }
            ShType::SymTabShIndex => {
                SectionData::SymTabShIndex(read_array(self.raw_data(elf_file)))
            }
            ShType::Note => {
                let data = self.raw_data(elf_file);
                match elf_file.header.pt1.class() {
                    Class::ThirtyTwo => unimplemented!(),
                    Class::SixtyFour => {
                        let header: &'a NoteHeader = read(&data[0..12]);
                        let index = &data[12..];
                        SectionData::Note64(header, index)
                    }
                    Class::None | Class::Other(_) => unreachable!(),
                }
            }
            ShType::Hash => {
                let data = self.raw_data(elf_file);
                SectionData::HashTable(read(&data[0..12]))
            }
        })
    }

    pub fn raw_data(&self, elf_file: &ElfFile<'a>) -> &'a [u8] {
        assert!(self.get_type().unwrap() != ShType::Null);
        &elf_file.input[self.offset() as usize..(self.offset() + self.size()) as usize]
    }

    getter!(flags, u64);
    getter!(name, u32);
    getter!(address, u64);
    getter!(offset, u64);
    getter!(size, u64);
    getter!(type_, ShType_);
}

impl<'a> fmt::Display for SectionHeader<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        macro_rules! sh_display {
            ($sh: ident) => {{
                try!(writeln!(f, "Section header:"));
                try!(writeln!(f, "    name:             {:?}", $sh.name));
                try!(writeln!(f, "    type:             {:?}", self.get_type()));
                try!(writeln!(f, "    flags:            {:?}", $sh.flags));
                try!(writeln!(f, "    address:          {:?}", $sh.address));
                try!(writeln!(f, "    offset:           {:?}", $sh.offset));
                try!(writeln!(f, "    size:             {:?}", $sh.size));
                try!(writeln!(f, "    link:             {:?}", $sh.link));
                try!(writeln!(f, "    align:            {:?}", $sh.align));
                try!(writeln!(f, "    entry size:       {:?}", $sh.entry_size));
                Ok(())
            }}
        }

        match *self {
            SectionHeader::Sh32Le(sh) => sh_display!(sh),
            SectionHeader::Sh32Be(sh) => sh_display!(sh),
            SectionHeader::Sh64Le(sh) => sh_display!(sh),
            SectionHeader::Sh64Be(sh) => sh_display!(sh),
        }
    }
}

#[derive(Debug)]
#[repr(C)]
pub struct SectionHeader_<P: Primitive> {
    name: P::u32,
    type_: ShType_<P>,
    flags: P::P,
    address: P::P,
    offset: P::P,
    size: P::P,
    link: P::u32,
    info: P::u32,
    align: P::P,
    entry_size: P::P,
}

unsafe impl<P: Primitive> Pod for SectionHeader_<P> {}

#[derive(Copy, Clone)]
pub struct ShType_<P: Primitive = Native>(P::u32);

impl<P: Primitive> ToNative for ShType_<P> {
    type Native = ShType_<Native>;
    fn to_native(&self) -> Self::Native {
        ShType_(self.0.to_native())
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum ShType {
    Null,
    ProgBits,
    SymTab,
    StrTab,
    Rela,
    Hash,
    Dynamic,
    Note,
    NoBits,
    Rel,
    ShLib,
    DynSym,
    InitArray,
    FiniArray,
    PreInitArray,
    Group,
    SymTabShIndex,
    OsSpecific(u32),
    ProcessorSpecific(u32),
    User(u32),
}

impl<P: Primitive> ShType_<P> {
    fn as_sh_type(&self) -> Result<ShType, &'static str> {
        match self.0.to_native() {
            0 => Ok(ShType::Null),
            1 => Ok(ShType::ProgBits),
            2 => Ok(ShType::SymTab),
            3 => Ok(ShType::StrTab),
            4 => Ok(ShType::Rela),
            5 => Ok(ShType::Hash),
            6 => Ok(ShType::Dynamic),
            7 => Ok(ShType::Note),
            8 => Ok(ShType::NoBits),
            9 => Ok(ShType::Rel),
            10 => Ok(ShType::ShLib),
            11 => Ok(ShType::DynSym),
            // sic.
            14 => Ok(ShType::InitArray),
            15 => Ok(ShType::FiniArray),
            16 => Ok(ShType::PreInitArray),
            17 => Ok(ShType::Group),
            18 => Ok(ShType::SymTabShIndex),
            st if st >= SHT_LOOS && st <= SHT_HIOS => Ok(ShType::OsSpecific(st)),
            st if st >= SHT_LOPROC && st <= SHT_HIPROC => Ok(ShType::ProcessorSpecific(st)),
            st if st >= SHT_LOUSER && st <= SHT_HIUSER => Ok(ShType::User(st)),
            _ => Err("Invalid sh type"),
        }
    }
}

impl<P: Primitive> fmt::Debug for ShType_<P> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.as_sh_type().fmt(f)
    }
}

pub enum SectionData<'a> {
    Empty,
    Undefined(&'a [u8]),
    Group {
        flags: &'a u32,
        indicies: &'a [u32],
    },
    StrArray(&'a [u8]),
    FnArray32Le(&'a [U32Le]),
    FnArray32Be(&'a [U32Be]),
    FnArray64Le(&'a [U64Le]),
    FnArray64Be(&'a [U64Be]),
    SymbolTable32Le(&'a [symbol_table::Entry32<P32Le>]),
    SymbolTable32Be(&'a [symbol_table::Entry32<P32Be>]),
    SymbolTable64Le(&'a [symbol_table::Entry64<P64Le>]),
    SymbolTable64Be(&'a [symbol_table::Entry64<P64Be>]),
    DynSymbolTable32Le(&'a [symbol_table::DynEntry32<P32Le>]),
    DynSymbolTable32Be(&'a [symbol_table::DynEntry32<P32Be>]),
    DynSymbolTable64Le(&'a [symbol_table::DynEntry64<P64Le>]),
    DynSymbolTable64Be(&'a [symbol_table::DynEntry64<P64Be>]),
    SymTabShIndex(&'a [u32]),
    // Note32 uses 4-byte words, which I'm not sure how to manage.
    // The pointer is to the start of the name field in the note.
    Note64(&'a NoteHeader, &'a [u8]),
    Rela32Le(&'a [Rela<P32Le>]),
    Rela32Be(&'a [Rela<P32Be>]),
    Rela64Le(&'a [Rela<P64Le>]),
    Rela64Be(&'a [Rela<P64Be>]),
    Rel32Le(&'a [Rel<P32Le>]),
    Rel32Be(&'a [Rel<P32Be>]),
    Rel64Le(&'a [Rel<P64Le>]),
    Rel64Be(&'a [Rel<P64Be>]),
    Dynamic32Le(&'a [Dynamic<P32Le>]),
    Dynamic32Be(&'a [Dynamic<P32Be>]),
    Dynamic64Le(&'a [Dynamic<P64Le>]),
    Dynamic64Be(&'a [Dynamic<P64Be>]),
    HashTable(&'a HashTable),
}

pub struct SectionStrings<'a> {
    inner: StrReaderIterator<'a>,
}

impl<'a> Iterator for SectionStrings<'a> {
    type Item = &'a str;

    #[inline]
    fn next(&mut self) -> Option<&'a str> {
        self.inner.next()
    }
}

impl<'a> SectionData<'a> {
    pub fn strings(&self) -> Result<SectionStrings<'a>, ()> {
        if let SectionData::StrArray(data) = *self {
            Ok(SectionStrings { inner: read_strs_to_null(data) })
        } else {
            Err(())
        }
    }
}

// Distinguished ShType values.
pub const SHT_LOOS: u32 = 0x60000000;
pub const SHT_HIOS: u32 = 0x6fffffff;
pub const SHT_LOPROC: u32 = 0x70000000;
pub const SHT_HIPROC: u32 = 0x7fffffff;
pub const SHT_LOUSER: u32 = 0x80000000;
pub const SHT_HIUSER: u32 = 0xffffffff;

// Flags (SectionHeader::flags)
pub const SHF_WRITE: u64 = 0x1;
pub const SHF_ALLOC: u64 = 0x2;
pub const SHF_EXECINSTR: u64 = 0x4;
pub const SHF_MERGE: u64 = 0x10;
pub const SHF_STRINGS: u64 = 0x20;
pub const SHF_INFO_LINK: u64 = 0x40;
pub const SHF_LINK_ORDER: u64 = 0x80;
pub const SHF_OS_NONCONFORMING: u64 = 0x100;
pub const SHF_GROUP: u64 = 0x200;
pub const SHF_TLS: u64 = 0x400;
pub const SHF_COMPRESSED: u64 = 0x800;
pub const SHF_MASKOS: u64 = 0x0ff00000;
pub const SHF_MASKPROC: u64 = 0xf0000000;

#[derive(Debug)]
#[repr(C)]
pub struct CompressionHeader64 {
    type_: CompressionType_,
    _reserved: u32,
    size: u64,
    align: u64,
}

#[derive(Debug)]
#[repr(C)]
pub struct CompressionHeader32 {
    type_: CompressionType_,
    size: u32,
    align: u32,
}

#[derive(Copy, Clone)]
pub struct CompressionType_(u32);

#[derive(Debug, PartialEq, Eq)]
pub enum CompressionType {
    Zlib,
    OsSpecific(u32),
    ProcessorSpecific(u32),
}

impl CompressionType_ {
    fn as_compression_type(&self) -> Result<CompressionType, &'static str> {
        match self.0 {
            1 => Ok(CompressionType::Zlib),
            ct if ct >= COMPRESS_LOOS && ct <= COMPRESS_HIOS => Ok(CompressionType::OsSpecific(ct)),
            ct if ct >= COMPRESS_LOPROC && ct <= COMPRESS_HIPROC => {
                Ok(CompressionType::ProcessorSpecific(ct))
            }
            _ => Err("Invalid compression type"),
        }
    }
}

impl fmt::Debug for CompressionType_ {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.as_compression_type().fmt(f)
    }
}

// Distinguished CompressionType values.
pub const COMPRESS_LOOS: u32 = 0x60000000;
pub const COMPRESS_HIOS: u32 = 0x6fffffff;
pub const COMPRESS_LOPROC: u32 = 0x70000000;
pub const COMPRESS_HIPROC: u32 = 0x7fffffff;

// Group flags
pub const GRP_COMDAT: u64 = 0x1;
pub const GRP_MASKOS: u64 = 0x0ff00000;
pub const GRP_MASKPROC: u64 = 0xf0000000;

#[derive(Debug)]
#[repr(C)]
pub struct Rela<P: Primitive> {
    offset: P::P,
    info: P::P,
    addend: P::P,
}

#[derive(Debug)]
#[repr(C)]
pub struct Rel<P: Primitive> {
    offset: P::P,
    info: P::P,
}

unsafe impl<P: Primitive> Pod for Rela<P> {}
unsafe impl<P: Primitive> Pod for Rel<P> {}

impl Rela<P32Le> {
    pub fn get_offset(&self) -> u32 {
        self.offset.to_native()
    }
    pub fn get_addend(&self) -> u32 {
        self.addend.to_native()
    }
    pub fn get_symbol_table_index(&self) -> u32 {
        self.info.to_native() >> 8
    }
    pub fn get_type(&self) -> u8 {
        self.info.to_native() as u8
    }
}

impl Rela<P32Be> {
    pub fn get_offset(&self) -> u32 {
        self.offset.to_native()
    }
    pub fn get_addend(&self) -> u32 {
        self.addend.to_native()
    }
    pub fn get_symbol_table_index(&self) -> u32 {
        self.info.to_native() >> 8
    }
    pub fn get_type(&self) -> u8 {
        self.info.to_native() as u8
    }
}

impl Rela<P64Le> {
    pub fn get_offset(&self) -> u64 {
        self.offset.to_native()
    }
    pub fn get_addend(&self) -> u64 {
        self.addend.to_native()
    }
    pub fn get_symbol_table_index(&self) -> u32 {
        (self.info.to_native() >> 32) as u32
    }
    pub fn get_type(&self) -> u32 {
        (self.info.to_native() & 0xffffffff) as u32
    }
}

impl Rela<P64Be> {
    pub fn get_offset(&self) -> u64 {
        self.offset.to_native()
    }
    pub fn get_addend(&self) -> u64 {
        self.addend.to_native()
    }
    pub fn get_symbol_table_index(&self) -> u32 {
        (self.info.to_native() >> 32) as u32
    }
    pub fn get_type(&self) -> u32 {
        (self.info.to_native() & 0xffffffff) as u32
    }
}

impl Rel<P32Le> {
    pub fn get_offset(&self) -> u32 {
        self.offset.to_native()
    }
    pub fn get_symbol_table_index(&self) -> u32 {
        self.info.to_native() >> 8
    }
    pub fn get_type(&self) -> u8 {
        self.info.to_native() as u8
    }
}

impl Rel<P32Be> {
    pub fn get_offset(&self) -> u32 {
        self.offset.to_native()
    }
    pub fn get_symbol_table_index(&self) -> u32 {
        self.info.to_native() >> 8
    }
    pub fn get_type(&self) -> u8 {
        self.info.to_native() as u8
    }
}

impl Rel<P64Le> {
    pub fn get_offset(&self) -> u64 {
        self.offset.to_native()
    }
    pub fn get_symbol_table_index(&self) -> u32 {
        (self.info.to_native() >> 32) as u32
    }
    pub fn get_type(&self) -> u32 {
        (self.info.to_native() & 0xffffffff) as u32
    }
}

impl Rel<P64Be> {
    pub fn get_offset(&self) -> u64 {
        self.offset.to_native()
    }
    pub fn get_symbol_table_index(&self) -> u32 {
        (self.info.to_native() >> 32) as u32
    }
    pub fn get_type(&self) -> u32 {
        (self.info.to_native() & 0xffffffff) as u32
    }
}

#[derive(Debug)]
#[repr(C)]
pub struct NoteHeader {
    name_size: u32,
    desc_size: u32,
    type_: u32,
}

unsafe impl Pod for NoteHeader {}

impl NoteHeader {
    pub fn type_(&self) -> u32 {
        self.type_
    }

    pub fn name<'a>(&'a self, input: &'a [u8]) -> &'a str {
        let result = read_str(input);
        // - 1 is due to null terminator
        assert!(result.len() == (self.name_size - 1) as usize);
        result
    }

    pub fn desc<'a>(&'a self, input: &'a [u8]) -> &'a [u8] {
        // Account for padding to the next u32.
        unsafe {
            let offset = (self.name_size + 3) & !0x3;
            let ptr = (&input[0] as *const u8).offset(offset as isize);
            slice::from_raw_parts(ptr, self.desc_size as usize)
        }
    }
}

pub fn sanity_check<'a>(header: SectionHeader<'a>, _file: &ElfFile<'a>) -> Result<(), &'static str> {
    if try!(header.get_type()) == ShType::Null {
        return Ok(());
    }
    // TODO
    Ok(())
}
