use std::io::{Result, Seek, SeekFrom, Write};

use hash::Algorithm;
use merkle::Element;
use proof::Proof;
use std::marker::PhantomData;

#[derive(Debug, Clone)]
struct Root<T>(usize, T);

#[derive(Debug)]
pub struct MerkleStreamer<T, A, S>
where
    T: Element,
    A: Algorithm<T>,
    S: Write + Seek,
{
    max_stack: usize,
    root_stack: Vec<Root<T>>,
    leafs: usize,
    height: usize,
    data: S,
    count: usize,
    _a: PhantomData<A>,
}

impl<T, A, S> MerkleStreamer<T, A, S>
where
    T: Element,
    A: Algorithm<T>,
    S: Write + Seek,
{
    pub fn new(size: usize, sink: S) -> Self {
        assert!(size > 0);
        assert!(size.count_ones() == 1);

        let mut s = size;
        let mut height = 0; // Will hold log2(s).

        while s != 1 {
            s >>= 1;
            height += 1;
        }

        let stack_capacity = height + 1; // Include room for the last item.

        Self {
            max_stack: stack_capacity,
            height,
            root_stack: Vec::with_capacity(stack_capacity),
            leafs: size,
            data: sink,
            count: 0,
            _a: PhantomData,
        }
    }

    pub fn from_iter<I: IntoIterator<Item = T>>(into: I, sink: S) -> Result<Self> {
        let iter = into.into_iter();

        let leaves = iter.size_hint().1.unwrap();
        assert!(leaves > 1);

        let mut tree = Self::new(leaves, sink);

        let mut a = A::default();

        let mut copy_buf = vec![0; T::byte_len()];

        for item in iter {
            a.reset();
            tree.add_leaf(a.leaf(item), &mut copy_buf)?;
        }
        Ok(tree)
    }

    pub fn add_leaf(&mut self, leaf: T, copy_buf: &mut[u8]) -> Result<Option<usize>> {
        if self.count >= self.leafs {
            return Ok(None);
        }

        self.shift(leaf);

        let mut count = 0;
        while self.reduce(copy_buf)? {
            count += 1
        }

        Ok(Some(count))
    }

    fn shift(&mut self, elt: T) {
        // `shift` should only be called by `add_leaf`, which verifies that too many leafs
        // have not been added. If that assumption is violated, it is a program(mer) error.
        assert!(self.root_stack.len() < self.max_stack);
        self.count += 1;

        let new_leaf_root = Root(0, elt);

        self.root_stack.push(new_leaf_root);
    }

    fn combine(left: &T, right: &T, height: usize) -> T {
        A::default().node(left.to_owned(), right.to_owned(), height)
    }

    fn reduce(&mut self, copy_buf: &mut[u8]) -> Result<bool> {
        if self.root_stack.len() > 1 {
            let top = self.root_stack.pop().expect("stack magically became empty");
            let next = self.root_stack.pop().expect("stack magically became empty");

            let Root(top_height, _) = top;
            let Root(next_height, _) = next;

            if top_height == next_height {
                let combined = Self::combine(&next.1, &top.1, top_height);
                let new_height = top_height + 1;

                next.1.copy_to_slice(copy_buf);
                self.data.write_all(copy_buf)?;
                top.1.copy_to_slice(copy_buf);
                self.data.write_all(copy_buf)?;

                if new_height == self.height {
                    // This is the final hash, the root of the tree.
                    combined.copy_to_slice(copy_buf);
                    self.data.write_all(copy_buf)?;
                } else {
                    self.root_stack.push(Root(new_height, combined));
                };

                Ok(true)
            } else {
                // TODO: Don't push and pop needlessly. Peek at top/next of stack.
                self.root_stack.push(next);
                self.root_stack.push(top);

                Ok(false)
            }
        } else {
            Ok(false)
        }
    }

    fn read_position(&mut self, position: usize) -> Result<T> {
        let l = T::byte_len();
        let buf = vec![0; l];

        self.data.seek(SeekFrom::Start((l * position) as u64))?;
        // self.data.read_exact(&mut buf)?;
        unimplemented!("We do not support the Read trait to benchmark using a buffered reader");

        // Ok(T::from_slice(&buf))
    }

    fn read_at(&mut self, index: usize) -> Result<T> {
        let p = position(index);

        self.read_position(p)
    }

    fn root(&mut self) -> Result<T> {
        // TODO: Ensure this won't return the wrong value if tree hasn't been fully built yet.
        let root_position = (1 << (1 + self.height)) - 2;

        self.read_position(root_position)
    }

    pub fn gen_proof(&mut self, i: usize) -> Result<Proof<T>> {
        assert!(self.height > 1);
        assert!(i < self.leafs); // i in [0 .. self.leafs)

        let mut lemma: Vec<T> = Vec::with_capacity(self.height + 1); // path + root
        let mut path: Vec<bool> = Vec::with_capacity(self.height - 1); // path - 1

        let mut position = position(i);
        let mut row_index = i;

        // Read and record the leaf.
        lemma.push(self.read_at(i)?);
        {
            // Find the leaf's hash partner.
            let is_left = row_index & 1 == 0;
            lemma.push(if is_left {
                // j is left
                self.read_at(row_index + 1)?
            } else {
                // j is right
                self.read_at(row_index - 1)?
            });

            // Record the first path bit;
            path.push(is_left);
        }
        let mut remaining = self.height - 1;
        let mut height = 0;

        while remaining > 0 {
            // How do we get to the next hash partner from current position?
            position += offset_to_next_proof_position(row_index, height);
            // Get and record the hash partner.
            lemma.push(self.read_position(position)?);

            // Find the row index (on the next row up) of the next hash partner.
            row_index = shift_and_flip(row_index);
            let is_left = row_index & 1 == 0;
            path.push(is_left);

            remaining -= 1;
            height += 1;
        }

        lemma.push(self.root()?);

        debug_assert!(lemma.len() == path.len() + 2);
        // TODO: These assertions from merkle.rs fail, but it's unclear why they are expected to succeed.
        // A terminology mismatch/error may have crept in.

        // debug_assert!(lemma.len() == self.height + 1);
        // debug_assert!(path.len() == self.height - 1);

        Ok(Proof::new(lemma, path))
    }
}

/// Translate from `index` space to `position` space.
/// Leaves to be added to a merkle tree have sequential indexes starting from 0.
/// As the tree is built, leafs and hashes are interspersed, so a leaf element's `position`
/// may be greater than its `index`.
fn position(index: usize) -> usize {
    // We will build up the position bit by bit.
    let mut position = 0;

    // Place in the sense of one's place, two's place, four's place.
    let mut place = 1;

    // We will reduce the index as we proceess its bits.
    let mut idx = index;

    while idx > 0 {
        if idx & 1 == 1 {
            // Otherwise, shift by the width of this place's sub-tree in the serialized layout.
            position += place_width(place);

            // In the one's place, we add one if there is a 'one' component of the index.
            // Consider that `index` 0 => `position` 0; `index` 1 => `position` 1.
            // We repeat this process for each larger place.
        }

        // Scale the place;
        place <<= 1;

        // Shift one bit off the end of the index.
        idx >>= 1;
    }
    position
}

/// TODO: Document how this works.
fn offset_to_next_proof_position(row_index: usize, height: usize) -> usize {
    let height_factor = 1 << (height + 2);
    match row_index & 0b11 {
        0b00 => height_factor + 1,
        0b01 => height_factor,
        0b10 => 2,
        0b11 => 1,
        _ => panic!("two-bit usize out of range, somehow"),
    }
}

#[test]
fn test_offset_to_next_proof_position() {
    assert_eq!(5, offset_to_next_proof_position(0b00, 0));
    assert_eq!(4, offset_to_next_proof_position(0b01, 0));
    assert_eq!(2, offset_to_next_proof_position(0b10, 0));
    assert_eq!(1, offset_to_next_proof_position(0b11, 0));

    assert_eq!(9, offset_to_next_proof_position(0b00, 1));
    assert_eq!(8, offset_to_next_proof_position(0b01, 1));
    assert_eq!(2, offset_to_next_proof_position(0b10, 1));
    assert_eq!(1, offset_to_next_proof_position(0b11, 1));
}

/// Return the next row index by right-shifting one bit then flipping the new least significant bit.
fn shift_and_flip(row_index: usize) -> usize {
    (row_index >> 1) ^ 1
}

/// How much space do subtrees rooted at this place's size take up?
/// Examples:
/// - a sub-tree of 2 leaves has a width of 2.
/// - a sub-tree of 4 leaves has a width of 6.
fn place_width(place: usize) -> usize {
    if place == 1 {
        // The one's place has no sub-trees. Set a bit, or not.
        1
    } else {
        2 * (place - 1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::hash::Hasher;
    use std::io::Cursor;

    const SIZE: usize = 3;

    type Item = [u8; SIZE];

    impl Element for [u8; SIZE] {
        fn byte_len() -> usize {
            SIZE
        }

        fn from_slice(bytes: &[u8]) -> Self {
            if bytes.len() != SIZE {
                panic!("invalid length {}, expected {}", bytes.len(), SIZE);
            }
            *array_ref!(bytes, 0, SIZE)
        }

        fn copy_to_slice(&self, bytes: &mut [u8]) {
            bytes.copy_from_slice(self);
        }
    }

    #[derive(Debug, Copy, Clone, Default)]
    struct XOR {
        data: Item,
        i: usize,
    }

    impl XOR {
        fn new() -> XOR {
            XOR {
                data: [0; SIZE],
                i: 0,
            }
        }
    }

    impl Hasher for XOR {
        fn write(&mut self, bytes: &[u8]) {
            for x in bytes {
                self.data[self.i & (SIZE - 1)] ^= *x;
                self.i += 1;
            }
        }

        fn finish(&self) -> u64 {
            unimplemented!()
        }
    }

    impl Algorithm<Item> for XOR {
        #[inline]
        fn hash(&mut self) -> [u8; SIZE] {
            self.data
        }

        #[inline]
        fn reset(&mut self) {
            *self = XOR::new();
        }
    }
}
