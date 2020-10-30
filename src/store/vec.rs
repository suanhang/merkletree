use anyhow::Result;

use crate::hash::{ArrayLength, ArrayLengthMarker};
use crate::store::{Store, StoreConfig};
use generic_array::GenericArray;

#[derive(Debug, Clone, Default)]
pub struct VecStore<N: ArrayLength> {
    data: Vec<u8>,
    _n: ArrayLengthMarker<N>,
}

impl<N: ArrayLength> Store<N> for VecStore<N> {
    fn new_with_config(size: usize, _branches: usize, _config: StoreConfig) -> Result<Self> {
        Self::new(size)
    }

    fn new(size: usize) -> Result<Self> {
        Ok(VecStore {
            data: Vec::with_capacity(size * N::to_usize()),
            _n: Default::default(),
        })
    }

    fn write_at(&mut self, el: impl AsRef<[u8]>, index: usize) -> Result<()> {
        let start = index * N::to_usize();
        let end = start + N::to_usize();

        if end > self.data.len() {
            self.data.resize(end, 0);
        }

        self.data[start..end].copy_from_slice(&el.as_ref()[..N::to_usize()]);
        Ok(())
    }

    fn copy_from_slice(&mut self, buf: &[u8], start: usize) -> Result<()> {
        ensure!(
            buf.len() % N::to_usize() == 0,
            "buf size must be a multiple of {}",
            N::to_usize()
        );
        let len = buf.len();
        let start = start * N::to_usize();

        if self.data.len() < start + len {
            self.data.resize(start + len, 0);
        }

        self.data[start..start + len].copy_from_slice(buf);
        Ok(())
    }

    fn new_from_slice_with_config(
        size: usize,
        _branches: usize,
        data: &[u8],
        _config: StoreConfig,
    ) -> Result<Self> {
        Self::new_from_slice(size, &data)
    }

    fn new_from_slice(size: usize, data: &[u8]) -> Result<Self> {
        ensure!(
            data.len() % N::to_usize() == 0,
            "data size must be a multiple of {}",
            N::to_usize()
        );

        let mut v = data.to_vec();
        let size = size * N::to_usize();
        let additional = size - v.len();
        v.reserve(additional);

        Ok(VecStore {
            data: v,
            _n: Default::default(),
        })
    }

    fn new_from_disk(_size: usize, _branches: usize, _config: &StoreConfig) -> Result<Self> {
        unimplemented!("Cannot load a VecStore from disk");
    }

    fn read_at(&self, index: usize) -> Result<GenericArray<u8, N>> {
        let start = index * N::to_usize();
        let end = start + N::to_usize();
        let res: &GenericArray<u8, N> = self.data[start..end].into();

        Ok(res.clone())
    }

    fn read_into(&self, index: usize, buf: &mut [u8]) -> Result<()> {
        assert_eq!(buf.len(), N::to_usize());

        let start = index * N::to_usize();
        let end = start + N::to_usize();
        buf.copy_from_slice(&self.data[start..end]);

        Ok(())
    }

    fn read_range_into(&self, start: usize, end: usize, buf: &mut [u8]) -> Result<()> {
        let start = start * N::to_usize();
        let end = end * N::to_usize();

        let len = self.len() * N::to_usize();
        ensure!(start < len, "start out of range {} >= {}", start, len);
        ensure!(end <= len, "end out of range {} > {}", end, len);

        buf.copy_from_slice(&self.data[start..end]);

        Ok(())
    }

    fn len(&self) -> usize {
        self.data.len() / N::to_usize()
    }

    fn loaded_from_disk(&self) -> bool {
        false
    }

    fn compact(
        &mut self,
        _branches: usize,
        _config: StoreConfig,
        _store_version: u32,
    ) -> Result<bool> {
        self.data.shrink_to_fit();

        Ok(true)
    }

    fn delete(_config: StoreConfig) -> Result<()> {
        Ok(())
    }

    fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    fn push(&mut self, el: impl Into<GenericArray<u8, N>>) -> Result<()> {
        self.data.extend_from_slice(&el.into());

        Ok(())
    }
}
