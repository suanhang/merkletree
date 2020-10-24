//! Hash infrastructure for items in Merkle Tree.

use digest::{Digest, Output};
use std::fmt;

pub trait ArrayLength: generic_array::ArrayLength<u8> {}

impl<A: generic_array::ArrayLength<u8>> ArrayLength for A {}

#[derive(Default, Clone)]
pub struct ArrayLengthMarker<N: generic_array::ArrayLength<u8>>(std::marker::PhantomData<*const N>);

impl<N: generic_array::ArrayLength<u8>> fmt::Debug for ArrayLengthMarker<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ArrayLengthMarker<{}>", N::to_usize())
    }
}

#[allow(unsafe_code)]
unsafe impl<N: generic_array::ArrayLength<u8>> Send for ArrayLengthMarker<N> {}
#[allow(unsafe_code)]
unsafe impl<N: generic_array::ArrayLength<u8>> Sync for ArrayLengthMarker<N> {}

/// MT leaf hash prefix
const LEAF: u8 = 0x00;

/// MT interior node hash prefix
const INTERIOR: u8 = 0x01;

/// A trait for hashing an arbitrary stream of bytes for calculating merkle tree
/// nodes.
///
/// T is a hash item must be of known size at compile time, globally ordered, with
/// default value as a neutral element of the hash space. Neutral element is
/// interpreted as 0 or nil and required for evaluation of merkle tree.
///
/// [`Algorithm`] breaks the [`Hasher`] contract at `finish()`, but that is intended.
/// This trait extends [`Hasher`] with `hash -> T` and `reset` state methods,
/// plus implements default behavior of evaluation of MT interior nodes.
pub trait Algorithm: Digest {
    /// Returns hash value for MT leaf (prefix 0x00).
    #[inline]
    fn leaf(&mut self, leaf: impl AsRef<[u8]>) -> Output<Self> {
        self.update(&[LEAF]);
        self.update(leaf.as_ref());
        self.finalize_reset()
    }

    /// Returns hash value for MT interior node (prefix 0x01).
    #[inline]
    fn node(
        &mut self,
        left: impl AsRef<[u8]>,
        right: impl AsRef<[u8]>,
        _height: usize,
    ) -> Output<Self> {
        self.update(&[INTERIOR]);
        self.update(left);
        self.update(right);
        self.finalize_reset()
    }

    /// Returns hash value for MT interior node (prefix 0x01).
    #[inline]
    fn multi_node(
        &mut self,
        nodes: impl Iterator<Item = impl AsRef<[u8]>>,
        _height: usize,
    ) -> Output<Self> {
        self.update(&[INTERIOR]);
        for node in nodes {
            self.update(node);
        }
        self.finalize_reset()
    }
}

impl<D: Digest> Algorithm for D {}
