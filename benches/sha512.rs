//! cargo bench --features "bench" --verbose
#![cfg(feature = "bench")]
#![feature(test)]

extern crate test;

use anyhow::Result;
use digest::Digest;
use merkletree::forward_digest_impl;
use merkletree::hash::Algorithm;
use merkletree::merkle::{FromIndexedParallelIterator, MerkleTree};
use merkletree::store::{DiskStore, VecStore};
use rand::prelude::*;
use rand::thread_rng;
use rayon::prelude::*;
use sha2::Sha512;
use test::Bencher;

impl Algorithm for ASha512 {}

type Hash512 = digest::Output<Sha512>;

#[derive(Default, Clone)]
struct ASha512(Sha512);

forward_digest_impl!(ASha512, Sha512);

impl std::ops::Deref for ASha512 {
    type Target = Sha512;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::ops::DerefMut for ASha512 {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

fn tree_5() -> impl Iterator<Item = Result<Hash512>> {
    ["one", "two", "three", "four"].iter().map(|x| {
        let mut a = Sha512::new();
        a.update(&x[..]);
        Ok(a.finalize())
    })
}

fn tree_160_par() -> impl IndexedParallelIterator<Item = Hash512> {
    let mut values = vec![[0u8; 256]; 160];

    let mut rng = thread_rng();
    for i in 0..values.len() {
        rng.fill(&mut values[i]);
    }

    values.into_par_iter().map(|x| {
        let mut a = Sha512::new();
        a.update(&x[..]);
        a.finalize()
    })
}

fn tree_160() -> impl Iterator<Item = Result<Hash512>> {
    let mut values = vec![[0u8; 256]; 160];

    let mut rng = thread_rng();
    for i in 0..values.len() {
        rng.fill(&mut values[i]);
    }

    values.into_iter().map(|x| {
        let mut a = Sha512::new();
        a.update(&x[..]);
        Ok(a.finalize())
    })
}

fn tree_30000() -> impl Iterator<Item = Result<Hash512>> {
    let mut values = vec![[0u8; 256]; 30000];

    let mut rng = thread_rng();
    for i in 0..values.len() {
        rng.fill(&mut values[i]);
    }

    values.into_iter().map(|x| {
        let mut a = Sha512::new();
        a.update(&x[..]);
        Ok(a.finalize())
    })
}

fn tree_30000_par() -> impl IndexedParallelIterator<Item = Hash512> {
    let mut values = vec![[0u8; 256]; 30000];

    let mut rng = thread_rng();
    for i in 0..values.len() {
        rng.fill(&mut values[i]);
    }

    values.into_par_iter().map(|x| {
        let mut a = Sha512::new();
        a.update(&x[..]);
        a.finalize()
    })
}

#[bench]
fn bench_crypto_sha512(b: &mut Bencher) {
    let mut h = [0u8; 64];
    b.iter(|| {
        let mut x = Sha512::new();
        x.update(&"12345"[..]);
        h.copy_from_slice(&x.finalize());
    });
}

#[bench]
fn bench_crypto_sha512_from_data_5(b: &mut Bencher) {
    b.iter(|| MerkleTree::<ASha512, VecStore<_>>::try_from_iter(tree_5()).unwrap());
}

#[bench]
fn bench_crypto_sha512_from_data_5_proof(b: &mut Bencher) {
    let tree: MerkleTree<ASha512, VecStore<_>> = MerkleTree::try_from_iter(tree_5()).unwrap();

    b.iter(|| {
        for i in 0..tree.len() {
            let proof = tree.gen_proof(i).unwrap();
            test::black_box(proof);
        }
    });
}

#[bench]
fn bench_crypto_sha512_from_data_5_proof_check(b: &mut Bencher) {
    let tree: MerkleTree<ASha512, VecStore<_>> = MerkleTree::try_from_iter(tree_5()).unwrap();

    let proofs = (0..tree.len())
        .map(|i| tree.gen_proof(i).unwrap())
        .collect::<Vec<_>>();

    b.iter(|| {
        for proof in &proofs {
            test::black_box(proof.validate::<ASha512>().unwrap());
        }
    });
}

#[bench]
fn bench_crypto_sha512_from_data_160_vec(b: &mut Bencher) {
    b.iter(|| MerkleTree::<ASha512, VecStore<_>>::try_from_iter(tree_160()).unwrap());
}

#[bench]
fn bench_crypto_sha512_from_data_160_mmap(b: &mut Bencher) {
    b.iter(|| MerkleTree::<ASha512, DiskStore<_>>::try_from_iter(tree_160()).unwrap());
}

#[bench]
fn bench_crypto_sha512_from_data_160_par(b: &mut Bencher) {
    b.iter(|| MerkleTree::<ASha512, VecStore<_>>::from_par_iter(tree_160_par()));
}

#[bench]
fn bench_crypto_sha512_from_data_30000_vec(b: &mut Bencher) {
    b.iter(|| MerkleTree::<ASha512, VecStore<_>>::try_from_iter(tree_30000()).unwrap());
}

#[bench]
fn bench_crypto_sha512_from_data_30000_mmap(b: &mut Bencher) {
    b.iter(|| MerkleTree::<ASha512, DiskStore<_>>::try_from_iter(tree_30000()).unwrap());
}

#[bench]
fn bench_crypto_sha512_from_data_30000_par(b: &mut Bencher) {
    b.iter(|| MerkleTree::<ASha512, VecStore<_>>::from_par_iter(tree_30000_par()));
}

#[bench]
fn bench_crypto_sha512_from_data_160_proof(b: &mut Bencher) {
    let tree: MerkleTree<ASha512, VecStore<_>> = MerkleTree::try_from_iter(tree_160()).unwrap();

    b.iter(|| {
        for i in 0..tree.len() {
            let proof = tree.gen_proof(i).unwrap();
            test::black_box(proof);
        }
    });
}

#[bench]
fn bench_crypto_sha512_from_data_160_proof_check(b: &mut Bencher) {
    let tree: MerkleTree<ASha512, VecStore<_>> = MerkleTree::try_from_iter(tree_160()).unwrap();
    let proofs = (0..tree.len())
        .map(|i| tree.gen_proof(i).unwrap())
        .collect::<Vec<_>>();

    b.iter(|| {
        for proof in &proofs {
            test::black_box(proof.validate::<ASha512>().unwrap());
        }
    });
}
