pub trait ToNative {
    type Native;
    fn to_native(&self) -> Self::Native;
}

macro_rules! endian {
    ($name: ident, $native: ident, $from: path) => {
        #[derive(Copy, Clone)]
        pub struct $name($native);

        unsafe impl ::zero::Pod for $name {}

        impl ToNative for $name {
            type Native = $native;
            fn to_native(&self) -> Self::Native {
                $from(self.0)
            }
        }

        impl ::core::fmt::Display for $name {
            fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
                write!(f, "{:x}", self.to_native())
            }
        }

        impl ::core::fmt::Debug for $name {
            fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
                write!(f, "{:?}", self.to_native())
            }
        }
    }
}

endian!(U16Le, u16, u16::from_le);
endian!(U32Le, u32, u32::from_le);
endian!(U64Le, u64, u64::from_le);
endian!(I16Le, i16, i16::from_le);
endian!(I32Le, i32, i32::from_le);
endian!(I64Le, i64, i64::from_le);
endian!(U16Be, u16, u16::from_be);
endian!(U32Be, u32, u32::from_be);
endian!(U64Be, u64, u64::from_be);
endian!(I16Be, i16, i16::from_be);
endian!(I32Be, i32, i32::from_be);
endian!(I64Be, i64, i64::from_be);

macro_rules! native_dummy {
    ($name: ident) => {
        impl ToNative for $name {
            type Native = $name;
            fn to_native(&self) -> Self::Native { *self }
        }
    }
}

native_dummy!(u8);
native_dummy!(u16);
native_dummy!(u32);
native_dummy!(u64);
native_dummy!(i8);
native_dummy!(i16);
native_dummy!(i32);
native_dummy!(i64);

pub trait Primitive {
    type u8: ToNative<Native=u8> + ::core::fmt::Display + ::core::fmt::Debug + ::zero::Pod + Copy + Clone;
    type u16: ToNative<Native=u16> + ::core::fmt::Display + ::core::fmt::Debug + ::zero::Pod + Copy + Clone;
    type u32: ToNative<Native=u32> + ::core::fmt::Display + ::core::fmt::Debug + ::zero::Pod + Copy + Clone;
    type u64: ToNative<Native=u64> + ::core::fmt::Display + ::core::fmt::Debug + ::zero::Pod + Copy + Clone;
    type i8: ToNative<Native=i8> + ::core::fmt::Display + ::core::fmt::Debug + ::zero::Pod + Copy + Clone;
    type i16: ToNative<Native=i16> + ::core::fmt::Display + ::core::fmt::Debug + ::zero::Pod + Copy + Clone;
    type i32: ToNative<Native=i32> + ::core::fmt::Display + ::core::fmt::Debug + ::zero::Pod + Copy + Clone;
    type i64: ToNative<Native=i64> + ::core::fmt::Display + ::core::fmt::Debug + ::zero::Pod + Copy + Clone;
    type P: ToNative + ::core::fmt::Display + ::core::fmt::Debug + ::zero::Pod + Copy + Clone;
}

#[derive(Debug)]
pub struct Native;
impl Primitive for Native {
    type u8 = u8;
    type u16 = u16;
    type u32 = u32;
    type u64 = u64;
    type i8 = i8;
    type i16 = i16;
    type i32 = i32;
    type i64 = i64;
    type P = u32;
}

#[derive(Debug)]
pub struct P32Le;
impl Primitive for P32Le {
    type u8 = u8;
    type u16 = U16Le;
    type u32 = U32Le;
    type u64 = U64Le;
    type i8 = i8;
    type i16 = I16Le;
    type i32 = I32Le;
    type i64 = I64Le;
    type P = U32Le;
}

#[derive(Debug)]
pub struct P32Be;
impl Primitive for P32Be {
    type u8 = u8;
    type u16 = U16Be;
    type u32 = U32Be;
    type u64 = U64Be;
    type i8 = i8;
    type i16 = I16Be;
    type i32 = I32Be;
    type i64 = I64Be;
    type P = U32Be;
}

#[derive(Debug)]
pub struct P64Le;
impl Primitive for P64Le {
    type u8 = u8;
    type u16 = U16Le;
    type u32 = U32Le;
    type u64 = U64Le;
    type i8 = i8;
    type i16 = I16Le;
    type i32 = I32Le;
    type i64 = I64Le;
    type P = U64Le;
}

#[derive(Debug)]
pub struct P64Be;
impl Primitive for P64Be {
    type u8 = u8;
    type u16 = U16Be;
    type u32 = U32Be;
    type u64 = U64Be;
    type i8 = i8;
    type i16 = I16Be;
    type i32 = I32Be;
    type i64 = I64Be;
    type P = U64Be;
}
