use crate::merkle::MerkleTree;
use crate::store::VecStore;
use digest::{Digest, FixedOutputDirty, Reset, Update};
use generic_array::GenericArray;
use std::fmt;
use typenum::Unsigned;

pub const SIZE: usize = 0x10;

pub const BINARY_ARITY: usize = 2;
pub const QUAD_ARITY: usize = 4;
pub const OCT_ARITY: usize = 8;

pub type Item = [u8; SIZE];

#[derive(Debug, Copy, Clone, Default)]
pub struct XOR128 {
    data: Item,
    i: usize,
}

impl FixedOutputDirty for XOR128 {
    type OutputSize = typenum::U16;

    fn finalize_into_dirty(&mut self, out: &mut GenericArray<u8, Self::OutputSize>) {
        out.copy_from_slice(&self.data)
    }
}

impl Update for XOR128 {
    fn update(&mut self, data: impl AsRef<[u8]>) {
        for x in data.as_ref() {
            self.data[self.i & (SIZE - 1)] ^= *x;
            self.i += 1;
        }
    }

    fn chain(mut self, data: impl AsRef<[u8]>) -> Self
    where
        Self: Sized,
    {
        digest::Update::update(&mut self, data);
        self
    }
}

impl Reset for XOR128 {
    fn reset(&mut self) {
        *self = Self::new();
    }
}

impl fmt::UpperHex for XOR128 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if f.alternate() {
            if let Err(e) = f.write_str("0x") {
                return Err(e);
            }
        }
        for b in self.data.as_ref() {
            if let Err(e) = write!(f, "{:02X}", b) {
                return Err(e);
            }
        }
        Ok(())
    }
}

pub fn get_vec_tree_from_slice<U: Unsigned>(
    leafs: usize,
) -> MerkleTree<XOR128, VecStore<typenum::U16>, U> {
    let mut x = Vec::with_capacity(leafs);
    for i in 0..leafs {
        x.push((i * 93).to_le_bytes());
    }
    MerkleTree::from_data(&x).expect("failed to create tree from slice")
}
