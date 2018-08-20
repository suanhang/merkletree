#![cfg(test)]

use hash::*;
use merkle::log2_pow2;
use merkle::next_pow2;
use merkle::MerkleTree;
use std::fmt;
use std::hash::Hasher;
use std::iter::FromIterator;

const SIZE: usize = 0x10;

#[derive(Debug, Copy, Clone, Default, Eq, PartialEq, PartialOrd, Ord)]
struct Item([u8; SIZE]);

#[derive(Debug, Copy, Clone, Default)]
struct XOR128 {
    data: Item,
    i: usize,
}

impl AsRef<[u8]> for Item {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<Vec<u8>> for Item {
    fn from(val: Vec<u8>) -> Self {
        assert!(val.len() <= SIZE);
        let mut k = [0u8; SIZE];
        k.copy_from_slice(&val[..]);
        Item(k)
    }
}

impl XOR128 {
    fn new() -> XOR128 {
        XOR128 {
            data: Item([0; SIZE]),
            i: 0,
        }
    }
}

impl Hasher for XOR128 {
    fn write(&mut self, bytes: &[u8]) {
        for x in bytes {
            self.data.0[self.i & (SIZE - 1)] ^= *x;
            self.i += 1;
        }
    }

    fn finish(&self) -> u64 {
        unimplemented!()
    }
}

impl Algorithm<Item> for XOR128 {
    #[inline]
    fn hash(&mut self) -> Item {
        self.data
    }

    #[inline]
    fn reset(&mut self) {
        *self = XOR128::new();
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

#[test]
fn test_hasher_light() {
    let mut h = XOR128::new();
    "1234567812345678".hash(&mut h);
    h.reset();
    String::from("1234567812345678").hash(&mut h);
    assert_eq!(format!("{:#X}", h), "0x31323334353637383132333435363738");
    String::from("1234567812345678").hash(&mut h);
    assert_eq!(format!("{:#X}", h), "0x00000000000000000000000000000000");
    String::from("1234567812345678").hash(&mut h);
    assert_eq!(format!("{:#X}", h), "0x31323334353637383132333435363738");
}

#[test]
fn test_from_slice() {
    let x = [String::from("ars"), String::from("zxc")];
    let mt: MerkleTree<Item, XOR128> = MerkleTree::from_data(&x);
    assert_eq!(
        mt.as_vec(),
        [
            Item([0, 97, 114, 115, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            Item([0, 122, 120, 99, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            Item([1, 0, 27, 10, 16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
        ]
    );
    assert_eq!(mt.len(), 3);
    assert_eq!(mt.leafs(), 2);
    assert_eq!(mt.height(), 2);
    assert_eq!(
        mt.root(),
        Item([1, 0, 27, 10, 16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
    );
}

#[test]
fn test_from_iter() {
    let mut a = XOR128::new();
    let mt: MerkleTree<Item, XOR128> = MerkleTree::from_iter(["a", "b", "c"].iter().map(|x| {
        a.reset();
        x.hash(&mut a);
        a.hash()
    }));
    assert_eq!(mt.len(), 7);
    assert_eq!(mt.height(), 3);
}

#[test]
fn test_simple_tree() {
    let answer: Vec<Vec<Item>> = vec![
        vec![
            Item([0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            Item([0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            Item([1, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
        ],
        vec![
            Item([0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            Item([0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            Item([0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            Item([0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            Item([1, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            Item([1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            Item([1, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
        ],
        vec![
            Item([0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            Item([0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            Item([0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            Item([0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            Item([1, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            Item([1, 0, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            Item([1, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
        ],
        vec![
            Item([0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            Item([0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            Item([0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            Item([0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            Item([0, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            Item([0, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            Item([1, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            Item([1, 0, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            Item([1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            Item([1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            Item([1, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            Item([1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            Item([1, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
        ],
        vec![
            Item([0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            Item([0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            Item([0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            Item([0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            Item([0, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            Item([0, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            Item([1, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            Item([1, 0, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            Item([1, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            Item([1, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            Item([1, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            Item([1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            Item([1, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
        ],
        vec![
            Item([0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            Item([0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            Item([0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            Item([0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            Item([0, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            Item([0, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            Item([0, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            Item([0, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            Item([1, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            Item([1, 0, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            Item([1, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            Item([1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            Item([1, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            Item([1, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            Item([1, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
        ],
    ];
    for items in 2..8 {
        let mut a = XOR128::new();
        let mt: MerkleTree<Item, XOR128> = MerkleTree::from_iter(
            [1, 2, 3, 4, 5, 6, 7, 8]
                .iter()
                .map(|x| {
                    a.reset();
                    x.hash(&mut a);
                    a.hash()
                }).take(items),
        );

        assert_eq!(mt.leafs(), items);
        assert_eq!(mt.height(), log2_pow2(next_pow2(mt.len())));
        assert_eq!(mt.as_vec(), answer[items - 2].as_slice());
        // assert_eq!(mt[0], mt[0]);

        for i in 0..mt.leafs() {
            let p = mt.gen_proof(i);
            assert!(p.validate::<XOR128>());
        }
    }
}
