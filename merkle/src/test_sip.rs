#![cfg(test)]

use hash::{Algorithm, Hashable};
use merkle::log2_pow2;
use merkle::next_pow2;
use merkle::MerkleTree;
use std::collections::hash_map::DefaultHasher;
use std::hash::Hasher;
use std::iter::FromIterator;
use test_item::Item;

impl Algorithm<Item> for DefaultHasher {
    #[inline]
    fn hash(&mut self) -> Item {
        Item(self.finish())
    }

    #[inline]
    fn reset(&mut self) {
        *self = DefaultHasher::default()
    }
}

#[test]
fn test_simple_tree() {
    let answer: Vec<Vec<Item>> = vec![
        vec![
            Item(18161131233134742049),
            Item(15963407371316104707),
            Item(8061613778145084206),
        ],
        vec![
            Item(18161131233134742049),
            Item(15963407371316104707),
            Item(2838807777806232157),
            Item(2838807777806232157),
            Item(8061613778145084206),
            Item(8605533607343419251),
            Item(12698627859487956302),
        ],
        vec![
            Item(18161131233134742049),
            Item(15963407371316104707),
            Item(2838807777806232157),
            Item(4356248227606450052),
            Item(8061613778145084206),
            Item(6971098229507888078),
            Item(452397072384919190),
        ],
        vec![
            Item(18161131233134742049),
            Item(15963407371316104707),
            Item(2838807777806232157),
            Item(4356248227606450052),
            Item(5528330654215492654),
            Item(5528330654215492654),
            Item(8061613778145084206),
            Item(6971098229507888078),
            Item(7858164776785041459),
            Item(7858164776785041459),
            Item(452397072384919190),
            Item(13691461346724970593),
            Item(12928874197991182098),
        ],
        vec![
            Item(18161131233134742049),
            Item(15963407371316104707),
            Item(2838807777806232157),
            Item(4356248227606450052),
            Item(5528330654215492654),
            Item(11057097817362835984),
            Item(8061613778145084206),
            Item(6971098229507888078),
            Item(6554444691020019791),
            Item(6554444691020019791),
            Item(452397072384919190),
            Item(2290028692816887453),
            Item(151678167824896071),
        ],
        vec![
            Item(18161131233134742049),
            Item(15963407371316104707),
            Item(2838807777806232157),
            Item(4356248227606450052),
            Item(5528330654215492654),
            Item(11057097817362835984),
            Item(15750323574099240302),
            Item(15750323574099240302),
            Item(8061613778145084206),
            Item(6971098229507888078),
            Item(6554444691020019791),
            Item(13319587930734024288),
            Item(452397072384919190),
            Item(15756788945533226834),
            Item(8300325667420840753),
        ],
    ];
    for items in 2..8 {
        let mut a = DefaultHasher::new();
        let mt: MerkleTree<Item, DefaultHasher> = MerkleTree::from_iter(
            [1, 2, 3, 4, 5, 6, 7, 8]
                .iter()
                .map(|x| {
                    a.reset();
                    x.hash(&mut a);
                    a.hash()
                }).take(items),
        );

        println!("round {}", items);
        assert_eq!(mt.leafs(), items);
        assert_eq!(mt.height(), log2_pow2(next_pow2(mt.len())));
        assert_eq!(mt.as_vec(), answer[items - 2].as_slice());

        for i in 0..mt.leafs() {
            let p = mt.gen_proof(i);
            assert!(p.validate::<DefaultHasher>());
        }
    }
}
