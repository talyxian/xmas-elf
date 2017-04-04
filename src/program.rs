use {ElfFile, P32Le, P64Le, P32Be, P64Be, Primitive, ToNative};
use zero::{read, read_array, Pod};
use header::{Class, Header, Data};
use dynamic::Dynamic;
use sections::NoteHeader;

use core::mem;
use core::fmt;


pub fn parse_program_header<'a>(input: &'a [u8],
                                header: Header<'a>,
                                index: u16)
                                -> Result<ProgramHeader<'a>, &'static str> {
    let pt2 = try!(header.pt2);
    assert!(index < pt2.ph_count() && pt2.ph_offset() > 0 && pt2.ph_entry_size() > 0);
    let start = pt2.ph_offset() as usize + index as usize * pt2.ph_entry_size() as usize;
    let end = start + pt2.ph_entry_size() as usize;

    match (header.pt1.class(), header.pt1.data()) {
        (Class::ThirtyTwo, Data::LittleEndian) => {
            let header: &'a ProgramHeader32<P32Le> = read(&input[start..end]);
            Ok(ProgramHeader::Ph32Le(header))
        }
        (Class::ThirtyTwo, Data::BigEndian) => {
            let header: &'a ProgramHeader32<P32Be> = read(&input[start..end]);
            Ok(ProgramHeader::Ph32Be(header))
        }
        (Class::SixtyFour, Data::LittleEndian) => {
            let header: &'a ProgramHeader64<P64Le> = read(&input[start..end]);
            Ok(ProgramHeader::Ph64Le(header))
        }
        (Class::SixtyFour, Data::BigEndian) => {
            let header: &'a ProgramHeader64<P64Be> = read(&input[start..end]);
            Ok(ProgramHeader::Ph64Be(header))
        }
        _ => unreachable!(),
    }
}

pub struct ProgramIter<'b, 'a: 'b> {
    pub file: &'b ElfFile<'a>,
    pub next_index: u16,
}

impl<'b, 'a> Iterator for ProgramIter<'b, 'a> {
    type Item = ProgramHeader<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let count = self.file.header.pt2.map(|pt2| pt2.ph_count()).unwrap_or(0);
        if self.next_index >= count {
            return None;
        }

        let result = self.file.program_header(self.next_index);
        self.next_index += 1;
        result.ok()
    }
}

#[derive(Copy, Clone, Debug)]
pub enum ProgramHeader<'a> {
    Ph32Le(&'a ProgramHeader32<P32Le>),
    Ph32Be(&'a ProgramHeader32<P32Be>),
    Ph64Le(&'a ProgramHeader64<P64Le>),
    Ph64Be(&'a ProgramHeader64<P64Be>),
}

#[derive(Clone, Debug)]
#[repr(C)]
pub struct ProgramHeader32<P: Primitive> {
    type_: Type_<P>,
    offset: P::u32,
    virtual_addr: P::u32,
    physical_addr: P::u32,
    file_size: P::u32,
    mem_size: P::u32,
    flags: P::u32,
    align: P::u32,
}


unsafe impl<P: Primitive> Pod for ProgramHeader32<P> {}

#[derive(Clone, Debug)]
#[repr(C)]
pub struct ProgramHeader64<P: Primitive> {
    type_: Type_<P>,
    flags: P::u32,
    offset: P::u64,
    virtual_addr: P::u64,
    physical_addr: P::u64,
    file_size: P::u64,
    mem_size: P::u64,
    align: P::u64,
}

unsafe impl<P: Primitive> Pod for ProgramHeader64<P> {}

macro_rules! ph_impl {
    ($ph: ident) => {
        impl<P: Primitive> $ph<P> {
            pub fn get_type(&self) -> Result<Type, &'static str> {
                self.type_.as_type()
            }

            pub fn get_data<'a>(&self, elf_file: &ElfFile<'a>) -> Result<SegmentData<'a>, &'static str> {
                self.get_type().map(|typ| match typ {
                    Type::Null => SegmentData::Empty,
                    Type::Load | Type::Interp | Type::ShLib | Type::Phdr | Type::Tls |
                    Type::OsSpecific(_) | Type::ProcessorSpecific(_) => {
                        SegmentData::Undefined(self.raw_data(elf_file))
                    }
                    Type::Dynamic => {
                        let data = self.raw_data(elf_file);
                        match (elf_file.header.pt1.class(), elf_file.header.pt1.data()) {
                            (Class::ThirtyTwo, Data::LittleEndian) => SegmentData::Dynamic32Le(read_array(data)),
                            (Class::ThirtyTwo, Data::BigEndian) => SegmentData::Dynamic32Be(read_array(data)),
                            (Class::SixtyFour, Data::LittleEndian) => SegmentData::Dynamic64Le(read_array(data)),
                            (Class::SixtyFour, Data::BigEndian) => SegmentData::Dynamic64Be(read_array(data)),
                            _ => unreachable!(),
                        }
                    }
                    Type::Note => {
                        let data = self.raw_data(elf_file);
                        match elf_file.header.pt1.class() {
                            Class::ThirtyTwo => unimplemented!(),
                            Class::SixtyFour => {
                                let header: &'a NoteHeader = read(&data[0..12]);
                                let index = &data[12..];
                                SegmentData::Note64(header, index)
                            }
                            Class::None | Class::Other(_) => unreachable!(),
                        }
                    }
                })
            }

            pub fn raw_data<'a>(&self, elf_file: &ElfFile<'a>) -> &'a [u8] {
                assert!(self.get_type().map(|typ| typ != Type::Null).unwrap_or(false));
                &elf_file.input[self.offset.to_native() as usize..(self.offset.to_native() + self.file_size.to_native()) as usize]
            }
        }

        impl<P: Primitive> fmt::Display for $ph<P> {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                try!(writeln!(f, "Program header:"));
                try!(writeln!(f, "    type:             {:?}", self.get_type()));
                try!(writeln!(f, "    flags:            {:?}", self.flags));
                try!(writeln!(f, "    offset:           {:?}", self.offset));
                try!(writeln!(f, "    virtual address:  {:?}", self.virtual_addr));
                try!(writeln!(f, "    physical address: {:?}", self.physical_addr));
                try!(writeln!(f, "    file size:        {:?}", self.file_size));
                try!(writeln!(f, "    memory size:      {:?}", self.mem_size));
                try!(writeln!(f, "    align:            {:?}", self.align));
                Ok(())
            }
        }
    }
}

ph_impl!(ProgramHeader32);
ph_impl!(ProgramHeader64);

macro_rules! getter {
    ($name: ident, $typ: ident) => {
        pub fn $name(&self) -> $typ {
            match *self {
                ProgramHeader::Ph32Le(h) => h.$name.to_native() as $typ,
                ProgramHeader::Ph32Be(h) => h.$name.to_native() as $typ,
                ProgramHeader::Ph64Le(h) => h.$name.to_native() as $typ,
                ProgramHeader::Ph64Be(h) => h.$name.to_native() as $typ,
            }
        }
    }
}

impl<'a> ProgramHeader<'a> {
    pub fn get_type(&self) -> Result<Type, &'static str> {
        match *self {
            ProgramHeader::Ph32Le(ph) => ph.get_type(),
            ProgramHeader::Ph32Be(ph) => ph.get_type(),
            ProgramHeader::Ph64Le(ph) => ph.get_type(),
            ProgramHeader::Ph64Be(ph) => ph.get_type(),
        }
    }

    pub fn get_data(&self, elf_file: &ElfFile<'a>) -> Result<SegmentData<'a>, &'static str> {
        match *self {
            ProgramHeader::Ph32Le(ph) => ph.get_data(elf_file),
            ProgramHeader::Ph32Be(ph) => ph.get_data(elf_file),
            ProgramHeader::Ph64Le(ph) => ph.get_data(elf_file),
            ProgramHeader::Ph64Be(ph) => ph.get_data(elf_file),
        }
    }

    getter!(align, u64);
    getter!(file_size, u64);
    getter!(mem_size, u64);
    getter!(offset, u64);
    getter!(physical_addr, u64);
    getter!(virtual_addr, u64);
    getter!(flags, u32);
}

impl<'a> fmt::Display for ProgramHeader<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            ProgramHeader::Ph32Le(ph) => ph.fmt(f),
            ProgramHeader::Ph32Be(ph) => ph.fmt(f),
            ProgramHeader::Ph64Le(ph) => ph.fmt(f),
            ProgramHeader::Ph64Be(ph) => ph.fmt(f),
        }
    }
}

#[derive(Copy, Clone)]
pub struct Type_<P: Primitive>(P::u32);

#[derive(Debug, Eq, PartialEq)]
pub enum Type {
    Null,
    Load,
    Dynamic,
    Interp,
    Note,
    ShLib,
    Phdr,
    Tls,
    OsSpecific(u32),
    ProcessorSpecific(u32),
}

impl<P: Primitive> Type_<P> {
    fn as_type(&self) -> Result<Type, &'static str> {
        match self.0.to_native() {
            0 => Ok(Type::Null),
            1 => Ok(Type::Load),
            2 => Ok(Type::Dynamic),
            3 => Ok(Type::Interp),
            4 => Ok(Type::Note),
            5 => Ok(Type::ShLib),
            6 => Ok(Type::Phdr),
            7 => Ok(Type::Tls),
            t if t >= TYPE_LOOS && t <= TYPE_HIOS => Ok(Type::OsSpecific(t)),
            t if t >= TYPE_LOPROC && t <= TYPE_HIPROC => Ok(Type::ProcessorSpecific(t)),
            _ => Err("Invalid type"),
        }
    }
}

impl<P: Primitive> fmt::Debug for Type_<P> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.as_type().fmt(f)
    }
}

pub enum SegmentData<'a> {
    Empty,
    Undefined(&'a [u8]),
    Dynamic32Le(&'a [Dynamic<P32Le>]),
    Dynamic32Be(&'a [Dynamic<P32Be>]),
    Dynamic64Le(&'a [Dynamic<P64Le>]),
    Dynamic64Be(&'a [Dynamic<P64Be>]),
    // Note32 uses 4-byte words, which I'm not sure how to manage.
    // The pointer is to the start of the name field in the note.
    Note64(&'a NoteHeader, &'a [u8]), /* TODO Interp and Phdr should probably be defined some how, but I can't find the details. */
}

pub const TYPE_LOOS: u32 = 0x60000000;
pub const TYPE_HIOS: u32 = 0x6fffffff;
pub const TYPE_LOPROC: u32 = 0x70000000;
pub const TYPE_HIPROC: u32 = 0x7fffffff;

pub const FLAG_X: u32 = 0x1;
pub const FLAG_W: u32 = 0x2;
pub const FLAG_R: u32 = 0x4;
pub const FLAG_MASKOS: u32 = 0x0ff00000;
pub const FLAG_MASKPROC: u32 = 0xf0000000;

pub fn sanity_check<'a>(ph: ProgramHeader<'a>, elf_file: &ElfFile<'a>) -> Result<(), &'static str> {
    let header = elf_file.header;
    match ph {
        ProgramHeader::Ph32Le(ph) => {
            check!(mem::size_of_val(ph) == try!(header.pt2).ph_entry_size() as usize,
                   "program header size mismatch");
            check!(((ph.offset.to_native() + ph.file_size.to_native()) as usize) < elf_file.input.len(),
                   "entry point out of range");
            check!(try!(ph.get_type()) != Type::ShLib, "Shouldn't use ShLib");
            if ph.align.to_native() > 1 {
                check!(ph.virtual_addr.to_native() % ph.align.to_native() == ph.offset.to_native() % ph.align.to_native(),
                       "Invalid combination of virtual_addr, offset, and align");
            }
        },
        ProgramHeader::Ph32Be(ph) => {
            check!(mem::size_of_val(ph) == try!(header.pt2).ph_entry_size() as usize,
                   "program header size mismatch");
            check!(((ph.offset.to_native() + ph.file_size.to_native()) as usize) < elf_file.input.len(),
                   "entry point out of range");
            check!(try!(ph.get_type()) != Type::ShLib, "Shouldn't use ShLib");
            if ph.align.to_native() > 1 {
                check!(ph.virtual_addr.to_native() % ph.align.to_native() == ph.offset.to_native() % ph.align.to_native(),
                       "Invalid combination of virtual_addr, offset, and align");
            }
        },
        ProgramHeader::Ph64Le(ph) => {
            check!(mem::size_of_val(ph) == try!(header.pt2).ph_entry_size() as usize,
                   "program header size mismatch");
            check!(((ph.offset.to_native() + ph.file_size.to_native()) as usize) < elf_file.input.len(),
                   "entry point out of range");
            check!(try!(ph.get_type()) != Type::ShLib, "Shouldn't use ShLib");
            if ph.align.to_native() > 1 {
                check!(ph.virtual_addr.to_native() % ph.align.to_native() == ph.offset.to_native() % ph.align.to_native(),
                       "Invalid combination of virtual_addr, offset, and align");
            }
        },
        ProgramHeader::Ph64Be(ph) => {
            check!(mem::size_of_val(ph) == try!(header.pt2).ph_entry_size() as usize,
                   "program header size mismatch");
            check!(((ph.offset.to_native() + ph.file_size.to_native()) as usize) < elf_file.input.len(),
                   "entry point out of range");
            check!(try!(ph.get_type()) != Type::ShLib, "Shouldn't use ShLib");
            if ph.align.to_native() > 1 {
                check!(ph.virtual_addr.to_native() % ph.align.to_native() == ph.offset.to_native() % ph.align.to_native(),
                       "Invalid combination of virtual_addr, offset, and align");
            }
        }
    }
    Ok(())
}
