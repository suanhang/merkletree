use hash::{Algorithm, Hashable};
use proof::Proof;
use rayon::prelude::*;
use std::iter::FromIterator;
use std::marker::PhantomData;
use std::{fmt, ops};

/// Merkle Tree.
///
/// All leafs and nodes are stored in a linear array (vec).
///
/// A merkle tree is a tree in which every non-leaf node is the hash of its
/// children nodes. A diagram depicting how it works:
///
/// ```text
///         root = h1234 = h(h12 + h34)
///        /                           \
///  h12 = h(h1 + h2)            h34 = h(h3 + h4)
///   /            \              /            \
/// h1 = h(tx1)  h2 = h(tx2)    h3 = h(tx3)  h4 = h(tx4)
/// ```
///
/// In memory layout:
///
/// ```text
///     [h1 h2 h3 h4 h12 h34 root]
/// ```
///
/// Merkle root is always the last element in the array.
///
/// The number of inputs is not always a power of two which results in a
/// balanced tree structure as above.  In that case, parent nodes with no
/// children are also zero and parent nodes with only a single left node
/// are calculated by concatenating the left node with itself before hashing.
/// Since this function uses nodes that are pointers to the hashes, empty nodes
/// will be nil.
///
/// TODO: Ord
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct MerkleTree<T: Ord + Clone + AsRef<[u8]> + Sync + Send + fmt::Debug, A: Algorithm<T>> {
    data: Vec<T>,
    leafs: usize,
    height: usize,
    _a: PhantomData<A>,
}

impl<T: Ord + Clone + AsRef<[u8]> + Sync + Send + fmt::Debug + Default, A: Algorithm<T>>
    MerkleTree<T, A>
{
    /// Creates new merkle from a sequence of hashes.
    pub fn new<I: IntoIterator<Item = T>>(data: I) -> MerkleTree<T, A> {
        Self::from_iter(data)
    }

    /// Creates new merkle tree from a list of hashable objects.
    pub fn from_data<O: Hashable<A>, I: IntoIterator<Item = O>>(data: I) -> MerkleTree<T, A> {
        let mut a = A::default();
        Self::from_iter(data.into_iter().map(|x| {
            a.reset();
            x.hash(&mut a);
            a.hash()
        }))
    }

    #[inline]
    fn build(&mut self, parallel: bool) {
        if !parallel || self.leafs < 8 {
            self.build_serial();
        } else {
            self.build_par();
        }
    }

    fn build_par(&mut self) {
        let width = self.leafs;
        assert!(width >= 8);
        assert_eq!(
            next_pow2(width),
            self.leafs,
            "only powers of two supported atm"
        );

        let (source, target) = self.data.split_at_mut(width);

        // split the source data into 8 parts
        let l = source.len() / 2;
        let (s0123, s4567) = source.split_at_mut(l);

        let (s01, s23) = s0123.split_at_mut(l / 2);
        let (s45, s67) = s4567.split_at_mut(l / 2);

        let (s0, s1) = s01.split_at_mut(l / 4);
        let (s2, s3) = s23.split_at_mut(l / 4);
        let (s4, s5) = s45.split_at_mut(l / 4);
        let (s6, s7) = s67.split_at_mut(l / 4);

        // split the target data into 8 parts
        let l = target.len() / 2;
        let (t0123, t4567) = target.split_at_mut(l);

        let (t01, t23) = t0123.split_at_mut(l / 2);
        let (t45, t67) = t4567.split_at_mut(l / 2);

        let (t0, t1) = t01.split_at_mut(l / 4);
        let (t2, t3) = t23.split_at_mut(l / 4);
        let (t4, t5) = t45.split_at_mut(l / 4);
        let (t6, t7) = t67.split_at_mut(l / 4);

        // build the four subtrees
        rayon::scope(|s| {
            s.spawn(|_| {
                let a = A::default();
                build_tree(s0, t0, a);
            });
            s.spawn(|_| {
                let a = A::default();
                build_tree(s1, t1, a);
            });
            s.spawn(|_| {
                let a = A::default();
                build_tree(s2, t2, a);
            });
            s.spawn(|_| {
                let a = A::default();
                build_tree(s3, t3, a);
            });
            s.spawn(|_| {
                let a = A::default();
                build_tree(s4, t4, a);
            });
            s.spawn(|_| {
                let a = A::default();
                build_tree(s5, t5, a);
            });
            s.spawn(|_| {
                let a = A::default();
                build_tree(s6, t6, a);
            });
            s.spawn(|_| {
                let a = A::default();
                build_tree(s7, t7, a);
            });
        });

        // TODO: rearange memory, or adjust other methods

        // TODO: build the top tree
    }

    fn build_serial(&mut self) {
        let mut width = self.leafs;

        // build tree
        let mut i: usize = 0;
        let mut j: usize = width;
        let mut height: usize = 0;
        while width > 1 {
            // if there is odd num of elements, fill in to the even
            if width & 1 == 1 {
                let he = self.data[self.len() - 1].clone();
                self.data.push(he);
                width += 1;
                j += 1;
            }

            // elements are in [i..j] and they are even
            let mut a = A::default();
            let layer: Vec<_> = self.data[i..j]
                .chunks(2)
                .map(|v| {
                    a.reset();
                    a.node(v[0].clone(), v[1].clone(), height)
                })
                .collect();
            self.data.extend(layer);

            i += j - i;

            width >>= 1;
            j += width;
            height += 1;
        }
    }

    /// Generate merkle tree inclusion proof for leaf `i`
    #[inline]
    pub fn gen_proof(&self, i: usize) -> Proof<T> {
        assert!(i < self.leafs); // i in [0 .. self.leafs)

        let mut lemma: Vec<T> = Vec::with_capacity(self.height + 1); // path + root
        let mut path: Vec<bool> = Vec::with_capacity(self.height - 1); // path - 1

        let mut base = 0;
        let mut j = i;

        // level 1 width
        let mut width = self.leafs;
        if width & 1 == 1 {
            width += 1;
        }

        lemma.push(self.data[j].clone());
        while base + 1 < self.len() {
            lemma.push(if j & 1 == 0 {
                // j is left
                self.data[base + j + 1].clone()
            } else {
                // j is right
                self.data[base + j - 1].clone()
            });
            path.push(j & 1 == 0);

            base += width;
            width >>= 1;
            if width & 1 == 1 {
                width += 1;
            }
            j >>= 1;
        }

        // root is final
        lemma.push(self.root());
        Proof::new(lemma, path)
    }

    /// Returns merkle root
    #[inline]
    pub fn root(&self) -> T {
        self.data[self.data.len() - 1].clone()
    }

    /// Returns number of elements in the tree.
    #[inline]
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Returns `true` if the vector contains no elements.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Returns height of the tree
    #[inline]
    pub fn height(&self) -> usize {
        self.height
    }

    /// Returns original number of elements the tree was built upon.
    #[inline]
    pub fn leafs(&self) -> usize {
        self.leafs
    }

    /// Extracts a slice containing the entire vector.
    ///
    /// Equivalent to `&s[..]`.
    #[inline]
    pub fn as_slice(&self) -> &[T] {
        self
    }
}

fn build_tree<
    T: Ord + Clone + AsRef<[u8]> + Send + Sync + Default + fmt::Debug,
    A: Algorithm<T>,
>(
    source: &[T],
    target: &mut [T],
    mut a: A,
) {
    let mut width = source.len();
    // build tree
    let mut i: usize = 0;
    let mut j: usize = width;
    let mut height: usize = 0;

    // first round reading from source, second need to read from target

    while width > 1 {
        if width == source.len() {
            for (k, v) in source.chunks(2).enumerate() {
                a.reset();
                target[k] = a.node(v[0].clone(), v[1].clone(), height);
            }

            width >>= 1;
            height += 1;
            i = 0;
            j = width;
        } else {
            let (source, target) = target.split_at_mut(j);

            for (k, v) in source[i..].chunks(2).enumerate() {
                a.reset();
                target[k] = a.node(v[0].clone(), v[1].clone(), height);
            }

            i = j;
            width >>= 1;
            j += width;
            height += 1;
        }
    }
}

impl<T: Ord + Clone + AsRef<[u8]> + Send + fmt::Debug + Sync + Default, A: Algorithm<T>>
    FromParallelIterator<T> for MerkleTree<T, A>
{
    /// Creates new merkle tree from an iterator over hashable objects.
    fn from_par_iter<I: IntoParallelIterator<Item = T>>(into: I) -> Self {
        let iter = into.into_par_iter();
        let mut data: Vec<T> = match iter.opt_len() {
            Some(e) => {
                let pow = next_pow2(e);
                let size = 2 * pow - 1;
                Vec::with_capacity(size)
            }
            None => Vec::new(),
        };

        // leafs
        data.par_extend(iter.map(|item| {
            let mut a = A::default();
            a.leaf(item)
        }));

        let leafs = data.len();
        let pow = next_pow2(leafs);
        let size = 2 * pow - 1;

        assert!(leafs > 1);
        data.resize(size, Default::default());

        let mut mt: MerkleTree<T, A> = MerkleTree {
            data,
            leafs,
            height: log2_pow2(size + 1),
            _a: PhantomData,
        };

        mt.build(true);

        mt
    }
}

impl<T: Ord + Clone + AsRef<[u8]> + Send + fmt::Debug + Sync + Default, A: Algorithm<T>>
    FromIterator<T> for MerkleTree<T, A>
{
    /// Creates new merkle tree from an iterator over hashable objects.
    fn from_iter<I: IntoIterator<Item = T>>(into: I) -> Self {
        let iter = into.into_iter();
        let mut data: Vec<T> = match iter.size_hint().1 {
            Some(e) => {
                let pow = next_pow2(e);
                let size = 2 * pow - 1;
                Vec::with_capacity(size)
            }
            None => Vec::new(),
        };

        // leafs
        let mut a = A::default();
        data.extend(iter.map(|item| {
            a.reset();
            a.leaf(item)
        }));

        let leafs = data.len();
        let pow = next_pow2(leafs);
        let size = 2 * pow - 1;

        assert!(leafs > 1);

        let mut mt: MerkleTree<T, A> = MerkleTree {
            data,
            leafs,
            height: log2_pow2(size + 1),
            _a: PhantomData,
        };

        mt.build(false);
        mt
    }
}

impl<T: Ord + Clone + AsRef<[u8]> + Send + fmt::Debug + Sync, A: Algorithm<T>> ops::Deref
    for MerkleTree<T, A>
{
    type Target = [T];

    fn deref(&self) -> &[T] {
        self.data.deref()
    }
}

/// `next_pow2` returns next highest power of two from a given number if
/// it is not already a power of two.
///
/// [](http://locklessinc.com/articles/next_pow2/)
/// [](https://stackoverflow.com/questions/466204/rounding-up-to-next-power-of-2/466242#466242)
pub fn next_pow2(mut n: usize) -> usize {
    n -= 1;
    n |= n >> 1;
    n |= n >> 2;
    n |= n >> 4;
    n |= n >> 8;
    n |= n >> 16;
    n |= n >> 32;
    n + 1
}

/// find power of 2 of a number which is power of 2
pub fn log2_pow2(n: usize) -> usize {
    n.trailing_zeros() as usize
}
