use core::fmt;
use {P32Le, P64Le, P32Be, P64Be, ToNative, Primitive};
use zero::Pod;

#[repr(C)]
pub struct Dynamic<P: Primitive> {
    tag: Tag_<P>,
    un: P::P,
}

unsafe impl<P: Primitive> Pod for Dynamic<P> {}

#[derive(Copy, Clone)]
pub struct Tag_<P: Primitive>(P::P);

#[derive(Debug, PartialEq, Eq)]
pub enum Tag<P: Primitive> {
    Null,
    Needed,
    PltRelSize,
    Pltgot,
    Hash,
    StrTab,
    SymTab,
    Rela,
    RelaSize,
    RelaEnt,
    StrSize,
    SymEnt,
    Init,
    Fini,
    SoName,
    RPath,
    Symbolic,
    Rel,
    RelSize,
    RelEnt,
    PltRel,
    Debug,
    TextRel,
    JmpRel,
    BindNow,
    InitArray,
    FiniArray,
    InitArraySize,
    FiniArraySize,
    RunPath,
    Flags,
    PreInitArray,
    PreInitArraySize,
    SymTabShIndex,
    OsSpecific(P::P),
    ProcessorSpecific(P::P),
}

macro_rules! impls {
    ($p: ident) => {
        impl Dynamic<$p> {
            pub fn get_tag(&self) -> Result<Tag<$p>, &'static str> {
                self.tag.as_tag()
            }

            pub fn get_val(&self) -> Result<<$p as Primitive>::P, &'static str> {
                match try!(self.get_tag()) {
                    Tag::Needed | Tag::PltRelSize | Tag::RelaSize | Tag::RelaEnt | Tag::StrSize |
                    Tag::SymEnt | Tag::SoName | Tag::RPath | Tag::RelSize | Tag::RelEnt | Tag::PltRel |
                    Tag::InitArraySize | Tag::FiniArraySize | Tag::RunPath | Tag::Flags |
                    Tag::PreInitArraySize | Tag::OsSpecific(_) | Tag::ProcessorSpecific(_) => Ok(self.un),
                    _ => Err("Invalid value"),
                }
            }

            pub fn get_ptr(&self) -> Result<<$p as Primitive>::P, &'static str> {
                match try!(self.get_tag()) {
                    Tag::Pltgot | Tag::Hash | Tag::StrTab | Tag::SymTab | Tag::Rela | Tag::Init | Tag::Fini |
                    Tag::Rel | Tag::Debug | Tag::JmpRel | Tag::InitArray | Tag::FiniArray |
                    Tag::PreInitArray | Tag::SymTabShIndex  | Tag::OsSpecific(_) | Tag::ProcessorSpecific(_)
                    => Ok(self.un),
                     _ => Err("Invalid ptr"),
                }
            }
        }

        impl Tag_<$p> {
            fn as_tag(&self) -> Result<Tag<$p>, &'static str> {
                match self.0.to_native() {
                    0 => Ok(Tag::Null),
                    1 => Ok(Tag::Needed),
                    2 => Ok(Tag::PltRelSize),
                    3 => Ok(Tag::Pltgot),
                    4 => Ok(Tag::Hash),
                    5 => Ok(Tag::StrTab),
                    6 => Ok(Tag::SymTab),
                    7 => Ok(Tag::Rela),
                    8 => Ok(Tag::RelaSize),
                    9 => Ok(Tag::RelaEnt),
                    10 => Ok(Tag::StrSize),
                    11 => Ok(Tag::SymEnt),
                    12 => Ok(Tag::Init),
                    13 => Ok(Tag::Fini),
                    14 => Ok(Tag::SoName),
                    15 => Ok(Tag::RPath),
                    16 => Ok(Tag::Symbolic),
                    17 => Ok(Tag::Rel),
                    18 => Ok(Tag::RelSize),
                    19 => Ok(Tag::RelEnt),
                    20 => Ok(Tag::PltRel),
                    21 => Ok(Tag::Debug),
                    22 => Ok(Tag::TextRel),
                    23 => Ok(Tag::JmpRel),
                    24 => Ok(Tag::BindNow),
                    25 => Ok(Tag::InitArray),
                    26 => Ok(Tag::FiniArray),
                    27 => Ok(Tag::InitArraySize),
                    28 => Ok(Tag::FiniArraySize),
                    29 => Ok(Tag::RunPath),
                    30 => Ok(Tag::Flags),
                    32 => Ok(Tag::PreInitArray),
                    33 => Ok(Tag::PreInitArraySize),
                    34 => Ok(Tag::SymTabShIndex),
                    t if t >= 0x6000000D && t <= 0x6fffffff => Ok(Tag::OsSpecific(self.0)),
                    t if t >= 0x70000000 && t <= 0x7fffffff => Ok(Tag::ProcessorSpecific(self.0)),
                    _ => Err("Invalid tag value"),
                }
            }
        }

        impl fmt::Debug for Tag_<$p> {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                self.as_tag().fmt(f)
            }
        }
    }
}

impls!(P32Le);
impls!(P32Be);
impls!(P64Le);
impls!(P64Be);
