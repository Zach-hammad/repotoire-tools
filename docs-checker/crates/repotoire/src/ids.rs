#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NodeId(pub u32);

#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct StringId(pub u32);

impl NodeId {
    #[inline]
    pub const fn from_raw(v: u32) -> Self {
        Self(v)
    }
    #[inline]
    pub const fn raw(self) -> u32 {
        self.0
    }
    #[inline]
    pub const fn as_usize(self) -> usize {
        self.0 as usize
    }
    #[inline]
    pub const fn to_le_bytes(self) -> [u8; 4] {
        self.0.to_le_bytes()
    }
    #[inline]
    pub const fn from_le_bytes(b: [u8; 4]) -> Self {
        Self(u32::from_le_bytes(b))
    }
}

impl StringId {
    #[inline]
    pub const fn from_raw(v: u32) -> Self {
        Self(v)
    }
    #[inline]
    pub const fn raw(self) -> u32 {
        self.0
    }
    #[inline]
    pub const fn as_usize(self) -> usize {
        self.0 as usize
    }
    #[inline]
    pub const fn to_le_bytes(self) -> [u8; 4] {
        self.0.to_le_bytes()
    }
    #[inline]
    pub const fn from_le_bytes(b: [u8; 4]) -> Self {
        Self(u32::from_le_bytes(b))
    }
}
