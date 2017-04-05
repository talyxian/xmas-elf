use core::fmt;
use core::mem;

use {P32Le, P64Le, P32Be, P64Be, Primitive, Native, ToNative, ElfFile};
use zero::{read, Pod};


pub fn parse_header<'a>(input: &'a [u8]) -> Header<'a> {
    let size_pt1 = mem::size_of::<HeaderPt1>();
    let header_1: &'a HeaderPt1 = read(&input[..size_pt1]);
    assert!(header_1.magic == MAGIC);

    let header_2 = match (header_1.class(), header_1.data()) {
        (Class::ThirtyTwo, Data::LittleEndian) => {
            let header_2: &'a HeaderPt2_<P32Le> =
                read(&input[size_pt1..size_pt1 + mem::size_of::<HeaderPt2_<P32Le>>()]);
            Ok(HeaderPt2::Header32Le(header_2))
        }
        (Class::ThirtyTwo, Data::BigEndian) => {
            let header_2: &'a HeaderPt2_<P32Be> =
                read(&input[size_pt1..size_pt1 + mem::size_of::<HeaderPt2_<P32Be>>()]);
            Ok(HeaderPt2::Header32Be(header_2))
        }
        (Class::SixtyFour, Data::LittleEndian) => {
            let header_2: &'a HeaderPt2_<P64Le> =
                read(&input[size_pt1..size_pt1 + mem::size_of::<HeaderPt2_<P64Le>>()]);
            Ok(HeaderPt2::Header64Le(header_2))
        }
        (Class::SixtyFour, Data::BigEndian) => {
            let header_2: &'a HeaderPt2_<P64Be> =
                read(&input[size_pt1..size_pt1 + mem::size_of::<HeaderPt2_<P64Be>>()]);
            Ok(HeaderPt2::Header64Be(header_2))
        }
        (Class::None, _) | (Class::Other(_), _) => Err("Invalid ELF class"),
        (_, Data::None) | (_, Data::Other(_)) => Err("Invalid ELF datatype"),
    };
    Header {
        pt1: header_1,
        pt2: header_2,
    }
}

pub const MAGIC: [u8; 4] = [0x7f, 'E' as u8, 'L' as u8, 'F' as u8];

#[derive(Clone, Copy)]
pub struct Header<'a> {
    pub pt1: &'a HeaderPt1,
    pub pt2: Result<HeaderPt2<'a>, &'static str>,
}

// TODO add Header::section_count, because if sh_count = 0, then the real count is in the first section.

impl<'a> fmt::Display for Header<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        try!(writeln!(f, "ELF header:"));
        try!(writeln!(f, "    magic:            {:?}", self.pt1.magic));
        try!(writeln!(f, "    class:            {:?}", self.pt1.class));
        try!(writeln!(f, "    data:             {:?}", self.pt1.data));
        try!(writeln!(f, "    version:          {:?}", self.pt1.version));
        try!(writeln!(f, "    os abi:           {:?}", self.pt1.os_abi));
        try!(writeln!(f, "    abi version:      {:?}", self.pt1.abi_version));
        try!(writeln!(f, "    padding:          {:?}", self.pt1.padding));
        try!(self.pt2.ok().map_or(Ok(()), |pt2| write!(f, "{}", pt2)));
        Ok(())
    }
}

#[derive(Debug)]
#[repr(C)]
pub struct HeaderPt1 {
    pub magic: [u8; 4],
    pub class: Class_,
    pub data: Data_,
    pub version: Version_,
    pub os_abi: OsAbi_,
    // Often also just padding.
    pub abi_version: u8,
    pub padding: [u8; 7],
}

unsafe impl Pod for HeaderPt1 {}

impl HeaderPt1 {
    pub fn class(&self) -> Class {
        self.class.as_class()
    }

    pub fn data(&self) -> Data {
        self.data.as_data()
    }

    pub fn version(&self) -> Version {
        self.version.as_version()
    }

    pub fn os_abi(&self) -> OsAbi {
        self.os_abi.as_os_abi()
    }
}

#[derive(Clone, Copy)]
pub enum HeaderPt2<'a> {
    Header32Le(&'a HeaderPt2_<P32Le>),
    Header32Be(&'a HeaderPt2_<P32Be>),
    Header64Le(&'a HeaderPt2_<P64Le>),
    Header64Be(&'a HeaderPt2_<P64Be>),
}

macro_rules! getter {
    ($name: ident, $typ: ident) => {
        pub fn $name(&self) -> $typ {
            match *self {
                HeaderPt2::Header32Le(h) => (h.$name.to_native()) as $typ,
                HeaderPt2::Header32Be(h) => (h.$name.to_native()) as $typ,
                HeaderPt2::Header64Le(h) => (h.$name.to_native()) as $typ,
                HeaderPt2::Header64Be(h) => (h.$name.to_native()) as $typ,
            }
        }
    }
}

impl<'a> HeaderPt2<'a> {
    pub fn size(&self) -> usize {
        match *self {
            HeaderPt2::Header32Le(_) => mem::size_of::<HeaderPt2_<P32Le>>(),
            HeaderPt2::Header32Be(_) => mem::size_of::<HeaderPt2_<P32Be>>(),
            HeaderPt2::Header64Le(_) => mem::size_of::<HeaderPt2_<P64Le>>(),
            HeaderPt2::Header64Be(_) => mem::size_of::<HeaderPt2_<P64Be>>(),
        }
    }

    // TODO move to impl Header
    getter!(type_,  Type_);
    getter!(machine, Machine_);
    getter!(version, u32);
    getter!(header_size, u16);
    getter!(entry_point, u64);
    getter!(ph_offset, u64);
    getter!(sh_offset, u64);
    getter!(ph_entry_size, u16);
    getter!(ph_count, u16);
    getter!(sh_entry_size, u16);
    getter!(sh_count, u16);
    getter!(sh_str_index, u16);
}

impl<'a> fmt::Display for HeaderPt2<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            HeaderPt2::Header32Le(h) => write!(f, "{}", h),
            HeaderPt2::Header32Be(h) => write!(f, "{}", h),
            HeaderPt2::Header64Le(h) => write!(f, "{}", h),
            HeaderPt2::Header64Be(h) => write!(f, "{}", h),
        }
    }
}

#[derive(Debug)]
#[repr(C)]
pub struct HeaderPt2_<P: Primitive> {
    pub type_: Type_<P>,
    pub machine: Machine_<P>,
    pub version: P::u32,
    pub entry_point: P::P,
    pub ph_offset: P::P,
    pub sh_offset: P::P,
    pub flags: P::u32,
    pub header_size: P::u16,
    pub ph_entry_size: P::u16,
    pub ph_count: P::u16,
    pub sh_entry_size: P::u16,
    pub sh_count: P::u16,
    pub sh_str_index: P::u16,
}

unsafe impl<P: Primitive> Pod for HeaderPt2_<P> {}

impl<P: Primitive> fmt::Display for HeaderPt2_<P> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        try!(writeln!(f, "    type:             {:?}", self.type_));
        try!(writeln!(f, "    machine:          {:?}", self.machine));
        try!(writeln!(f, "    version:          {}", self.version));
        try!(writeln!(f, "    entry_point:      {}", self.entry_point));
        try!(writeln!(f, "    ph_offset:        {}", self.ph_offset));
        try!(writeln!(f, "    sh_offset:        {}", self.sh_offset));
        try!(writeln!(f, "    flags:            {}", self.flags));
        try!(writeln!(f, "    header_size:      {}", self.header_size));
        try!(writeln!(f, "    ph_entry_size:    {}", self.ph_entry_size));
        try!(writeln!(f, "    ph_count:         {}", self.ph_count));
        try!(writeln!(f, "    sh_entry_size:    {}", self.sh_entry_size));
        try!(writeln!(f, "    sh_count:         {}", self.sh_count));
        try!(writeln!(f, "    sh_str_index:     {}", self.sh_str_index));
        Ok(())
    }
}

#[derive(Clone, Copy)]
pub struct Class_(u8);

impl Class_ {
    pub fn as_class(self) -> Class {
        match self.0 {
            0 => Class::None,
            1 => Class::ThirtyTwo,
            2 => Class::SixtyFour,
            other => Class::Other(other),
        }
    }

    pub fn is_none(self) -> bool {
        self.0 == 0
    }
}

impl fmt::Debug for Class_ {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.as_class().fmt(f)
    }
}

#[derive(Debug)]
pub enum Class {
    None,
    ThirtyTwo,
    SixtyFour,
    Other(u8),
}

impl Class {
    pub fn is_none(&self) -> bool {
        if let Class::None = *self {
            true
        } else {
            false
        }
    }
}

#[derive(Clone, Copy)]
pub struct Data_(u8);

impl Data_ {
    pub fn as_data(self) -> Data {
        match self.0 {
            0 => Data::None,
            1 => Data::LittleEndian,
            2 => Data::BigEndian,
            other => Data::Other(other),
        }
    }

    pub fn is_none(self) -> bool {
        self.0 == 0
    }
}

impl fmt::Debug for Data_ {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.as_data().fmt(f)
    }
}

#[derive(Debug)]
pub enum Data {
    None,
    LittleEndian,
    BigEndian,
    Other(u8),
}

impl Data {
    pub fn is_none(&self) -> bool {
        if let Data::None = *self {
            true
        } else {
            false
        }
    }
}

#[derive(Clone, Copy)]
pub struct Version_(u8);

impl Version_ {
    pub fn as_version(self) -> Version {
        match self.0 {
            0 => Version::None,
            1 => Version::Current,
            other => Version::Other(other),
        }
    }

    pub fn is_none(self) -> bool {
        self.0 == 0
    }
}

impl fmt::Debug for Version_ {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.as_version().fmt(f)
    }
}

#[derive(Debug)]
pub enum Version {
    None,
    Current,
    Other(u8),
}

impl Version {
    pub fn is_none(&self) -> bool {
        if let Version::None = *self {
            true
        } else {
            false
        }
    }
}

#[derive(Clone, Copy)]
pub struct OsAbi_(u8);

impl OsAbi_ {
    pub fn as_os_abi(self) -> OsAbi {
        match self.0 {
            0x00 => OsAbi::SystemV,
            0x01 => OsAbi::HpUx,
            0x02 => OsAbi::NetBSD,
            0x03 => OsAbi::Linux,
            0x06 => OsAbi::Solaris,
            0x07 => OsAbi::Aix,
            0x08 => OsAbi::Irix,
            0x09 => OsAbi::FreeBSD,
            0x0C => OsAbi::OpenBSD,
            0x0D => OsAbi::OpenVMS,
            other => OsAbi::Other(other),
        }
    }
}

impl fmt::Debug for OsAbi_ {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.as_os_abi().fmt(f)
    }
}

#[derive(Debug)]
pub enum OsAbi {
    // or None
    SystemV,
    HpUx,
    NetBSD,
    Linux,
    Solaris,
    Aix,
    Irix,
    FreeBSD,
    OpenBSD,
    OpenVMS,
    Other(u8), // FIXME there are many, many more of these
}

#[derive(Clone, Copy)]
pub struct Type_<P: Primitive = Native>(pub P::u16);

impl<P: Primitive> Type_<P> {
    pub fn as_type(&self) -> Type {
        match self.0.to_native() as u16 {
            0 => Type::None,
            1 => Type::Relocatable,
            2 => Type::Executable,
            3 => Type::SharedObject,
            4 => Type::Core,
            x => Type::ProcessorSpecific(x),
        }
    }
}

impl<P: Primitive> ToNative for Type_<P> {
    type Native = Type_<Native>;
    fn to_native(&self) -> Self::Native {
        Type_(self.0.to_native())
    }
}

impl<P: Primitive> fmt::Debug for Type_<P> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.as_type().fmt(f)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Type {
    None,
    Relocatable,
    Executable,
    SharedObject,
    Core,
    ProcessorSpecific(u16), // TODO OsSpecific
}

#[derive(Clone, Copy)]
pub struct Machine_<P: Primitive = Native>(P::u16);

impl<P: Primitive> Machine_<P> {
    pub fn as_machine(&self) -> Machine {
        match self.0.to_native() {
            0x00 => Machine::None,
            0x02 => Machine::Sparc,
            0x03 => Machine::X86,
            0x08 => Machine::Mips,
            0x14 => Machine::PowerPC,
            0x28 => Machine::Arm,
            0x2A => Machine::SuperH,
            0x32 => Machine::Ia64,
            0x3E => Machine::X86_64,
            0xB7 => Machine::AArch64,
            other => Machine::Other(other),
        }
    }
}


impl<P: Primitive> ToNative for Machine_<P> {
    type Native = Machine_<Native>;
    fn to_native(&self) -> Self::Native {
        Machine_(self.0.to_native())
    }
}

impl<P: Primitive> fmt::Debug for Machine_<P> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.as_machine().fmt(f)
    }
}

#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy)]
pub enum Machine {
    None,
    Sparc,
    X86,
    Mips,
    PowerPC,
    Arm,
    SuperH,
    Ia64,
    X86_64,
    AArch64,
    Other(u16), // FIXME there are many, many more of these
}

// TODO any more constants that need to go in here?

pub fn sanity_check(file: &ElfFile) -> Result<(), &'static str> {
    check!(mem::size_of::<HeaderPt1>() == 16);
    check!(file.header.pt1.magic == MAGIC, "bad magic number");
    let pt2 = try!(file.header.pt2);
    check!(mem::size_of::<HeaderPt1>() + pt2.size() == pt2.header_size() as usize,
           "header_size does not match size of header");
    match (&file.header.pt1.class(), &file.header.pt2) {
        (&Class::None, _) => return Err("No class"),
        (&Class::ThirtyTwo, &Ok(HeaderPt2::Header32Le(_))) | 
        (&Class::ThirtyTwo, &Ok(HeaderPt2::Header32Be(_))) | 
        (&Class::SixtyFour, &Ok(HeaderPt2::Header64Le(_))) | 
        (&Class::SixtyFour, &Ok(HeaderPt2::Header64Be(_))) => {}
        _ => return Err("Mismatch between specified and actual class"),
    }
    check!(!file.header.pt1.version.is_none(), "no version");
    check!(!file.header.pt1.data.is_none(), "no data format");

    //check!(pt2.entry_point() < file.input.len() as u64,
    //       "entry point out of range");
    check!(pt2.ph_offset() + (pt2.ph_entry_size() as u64) * (pt2.ph_count() as u64) <=
           file.input.len() as u64,
           "program header table out of range");
    check!(pt2.sh_offset() + (pt2.sh_entry_size() as u64) * (pt2.sh_count() as u64) <=
           file.input.len() as u64,
           "section header table out of range");

    // TODO check that SectionHeader_ is the same size as sh_entry_size, depending on class

    Ok(())
}
