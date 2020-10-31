use std::cell::UnsafeCell;
use std::sync::atomic::{AtomicUsize, Ordering};

use anyhow::Result;
use generic_array::GenericArray;

use crate::hash::{ArrayLength, ArrayLengthMarker};
use crate::store::{Store, StoreConfig};

#[derive(Debug, Default)]
pub struct VecStore<N: ArrayLength> {
    data: UnsafeCell<Vec<u8>>,
    len: AtomicUsize,
    _n: ArrayLengthMarker<N>,
}

unsafe impl<N: ArrayLength> Send for VecStore<N> {}
unsafe impl<N: ArrayLength> Sync for VecStore<N> {}

impl<N: ArrayLength> VecStore<N> {
    fn get_data_mut(&mut self) -> &mut Vec<u8> {
        // Safety: self is borrowed mutably
        unsafe { &mut *self.data.get() }
    }

    fn get_data(&self) -> &Vec<u8> {
        // Safety: self is borrowed
        unsafe { &*self.data.get() }
    }

    fn len_max(&self, other: usize) {
        let mut current = self.len.load(Ordering::SeqCst);
        loop {
            let updated = std::cmp::max(current, other);
            let inner = self
                .len
                .compare_and_swap(current, updated, Ordering::SeqCst);
            if inner == current {
                break;
            }
            current = inner;
        }
    }
}

impl<N: ArrayLength> Clone for VecStore<N> {
    fn clone(&self) -> Self {
        Self {
            data: UnsafeCell::new(unsafe { &*self.data.get() }.clone()),
            len: AtomicUsize::new(self.len.load(Ordering::SeqCst)),
            _n: Default::default(),
        }
    }
}

impl<N: ArrayLength> Store<N> for VecStore<N> {
    fn new_with_config(size: usize, _branches: usize, _config: StoreConfig) -> Result<Self> {
        Self::new(size)
    }

    fn new(size: usize) -> Result<Self> {
        Ok(VecStore {
            data: UnsafeCell::new(vec![0u8; size * N::to_usize()]),
            len: AtomicUsize::new(0),
            _n: Default::default(),
        })
    }

    fn write_at(&mut self, el: impl AsRef<[u8]>, index: usize) -> Result<()> {
        let start = index * N::to_usize();
        let end = start + N::to_usize();

        self.get_data_mut()[start..end].copy_from_slice(&el.as_ref()[..N::to_usize()]);
        self.len_max(index + 1);

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

        self.get_data_mut()[start..start + len].copy_from_slice(buf);
        self.len_max((start / N::to_usize()) + (buf.len() / N::to_usize()));
        Ok(())
    }

    unsafe fn copy_from_slice_unchecked(&self, buf: &[u8], start: usize) -> Result<()> {
        let len = buf.len();
        let start_bytes = start * N::to_usize();

        (&mut *self.data.get())[start_bytes..start_bytes + len].copy_from_slice(buf);
        self.len_max(start + buf.len() / N::to_usize());

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

        let mut store = Self::new(size)?;
        store.get_data_mut()[..data.len()].copy_from_slice(data);
        store
            .len
            .store(data.len() / N::to_usize(), Ordering::SeqCst);

        Ok(store)
    }

    fn new_from_disk(_size: usize, _branches: usize, _config: &StoreConfig) -> Result<Self> {
        unimplemented!("Cannot load a VecStore from disk");
    }

    fn read_at(&self, index: usize) -> Result<GenericArray<u8, N>> {
        let start = index * N::to_usize();
        let end = start + N::to_usize();
        let res: &GenericArray<u8, N> = self.get_data()[start..end].into();

        Ok(res.clone())
    }

    fn read_into(&self, index: usize, buf: &mut [u8]) -> Result<()> {
        assert_eq!(buf.len(), N::to_usize());

        let start = index * N::to_usize();
        let end = start + N::to_usize();
        buf.copy_from_slice(&self.get_data()[start..end]);

        Ok(())
    }

    fn read_range_into(&self, start: usize, end: usize, buf: &mut [u8]) -> Result<()> {
        let start = start * N::to_usize();
        let end = end * N::to_usize();

        let len = self.len() * N::to_usize();
        ensure!(start < len, "start out of range {} >= {}", start, len);
        ensure!(end <= len, "end out of range {} > {}", end, len);

        buf.copy_from_slice(&self.get_data()[start..end]);

        Ok(())
    }

    fn len(&self) -> usize {
        self.len.load(Ordering::SeqCst)
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
        self.get_data_mut().shrink_to_fit();

        Ok(true)
    }

    fn delete(_config: StoreConfig) -> Result<()> {
        Ok(())
    }

    fn is_empty(&self) -> bool {
        self.len.load(Ordering::SeqCst) == 0
    }

    fn push(&mut self, el: impl Into<GenericArray<u8, N>>) -> Result<()> {
        self.get_data_mut().extend_from_slice(&el.into());

        Ok(())
    }
}
