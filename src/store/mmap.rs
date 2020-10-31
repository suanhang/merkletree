use std::cell::UnsafeCell;
use std::fs::{File, OpenOptions};
use std::ops;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use anyhow::Result;
use generic_array::GenericArray;
use memmap::{MmapMut, MmapOptions};

use crate::hash::{ArrayLength, ArrayLengthMarker};
use crate::store::{Store, StoreConfig};

/// Store that saves the data on disk, and accesses it using memmap.
#[derive(Debug)]
pub struct MmapStore<N: ArrayLength> {
    path: PathBuf,
    map: MmapMut,
    data: UnsafeCell<&'static mut [u8]>, // not static, bound to the MmapMut
    file: File,
    len: AtomicUsize,
    store_size: usize,
    _n: ArrayLengthMarker<N>,
}

unsafe impl<N: ArrayLength> Sync for MmapStore<N> {}

impl<N: ArrayLength> MmapStore<N> {
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

    fn get_data_mut(&mut self) -> &mut [u8] {
        // Safety: self is borrowed mutably
        unsafe { &mut *self.data.get() }
    }

    fn get_data(&self) -> &[u8] {
        // Safety: self is borrowed
        unsafe { &*self.data.get() }
    }
}

impl<N: ArrayLength> ops::Deref for MmapStore<N> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.get_data()
    }
}

impl<N: ArrayLength> Store<N> for MmapStore<N> {
    fn new_with_config(size: usize, branches: usize, config: StoreConfig) -> Result<Self> {
        let data_path = StoreConfig::data_path(&config.path, &config.id);

        // If the specified file exists, load it from disk.
        if Path::new(&data_path).exists() {
            return Self::new_from_disk(size, branches, &config);
        }

        // Otherwise, create the file and allow it to be the on-disk store.
        let file = OpenOptions::new()
            .write(true)
            .read(true)
            .create_new(true)
            .open(&data_path)?;

        let store_size = N::to_usize() * size;
        file.set_len(store_size as u64)?;

        let mut map = unsafe { MmapOptions::new().private().map_mut(&file)? };
        let data = UnsafeCell::new(unsafe { std::mem::transmute(&mut map[..]) });

        Ok(MmapStore {
            path: data_path,
            map,
            data,
            file,
            len: AtomicUsize::new(0),
            store_size,
            _n: Default::default(),
        })
    }

    fn new(size: usize) -> Result<Self> {
        let store_size = N::to_usize() * size;

        let file = tempfile::NamedTempFile::new()?;
        file.as_file().set_len(store_size as u64)?;
        let (file, path) = file.into_parts();
        let mut map = unsafe { MmapOptions::new().private().map_mut(&file)? };
        let data = UnsafeCell::new(unsafe { std::mem::transmute(&mut map[..]) });

        Ok(MmapStore {
            path: path.keep()?,
            map,
            data,
            file,
            len: AtomicUsize::new(0),
            store_size,
            _n: Default::default(),
        })
    }

    fn new_from_disk(size: usize, _branches: usize, config: &StoreConfig) -> Result<Self> {
        let data_path = StoreConfig::data_path(&config.path, &config.id);

        let file = File::open(&data_path)?;
        let metadata = file.metadata()?;
        let store_size = metadata.len() as usize;

        // Sanity check.
        ensure!(
            store_size == size * N::to_usize(),
            "Invalid formatted file provided. Expected {} bytes, found {} bytes",
            size * N::to_usize(),
            store_size
        );

        let mut map = unsafe { MmapOptions::new().private().map_mut(&file)? };
        let data = UnsafeCell::new(unsafe { std::mem::transmute(&mut map[..]) });

        Ok(MmapStore {
            path: data_path,
            map,
            data,
            file,
            len: AtomicUsize::new(size),
            store_size,
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

        let map_start = start * N::to_usize();
        let map_end = map_start + buf.len();

        self.get_data_mut()[map_start..map_end].copy_from_slice(buf);
        self.len_max(start + (buf.len() / N::to_usize()));

        Ok(())
    }

    unsafe fn copy_from_slice_unchecked(&self, buf: &[u8], start: usize) -> Result<()> {
        let map_start = start * N::to_usize();
        let map_end = map_start + buf.len();

        (&mut *self.data.get())[map_start..map_end].copy_from_slice(buf);
        self.len_max(start + (buf.len() / N::to_usize()));

        Ok(())
    }

    fn new_from_slice_with_config(
        size: usize,
        branches: usize,
        data: &[u8],
        config: StoreConfig,
    ) -> Result<Self> {
        ensure!(
            data.len() % N::to_usize() == 0,
            "data size must be a multiple of {}",
            N::to_usize()
        );

        let mut store = Self::new_with_config(size, branches, config)?;

        // If the store was loaded from disk (based on the config
        // information, avoid re-populating the store at this point
        // since it can be assumed by the config that the data is
        // already correct).
        if !store.loaded_from_disk() {
            let len = data.len();

            store.map.as_mut()[0..len].copy_from_slice(data);
            store.len.store(len / N::to_usize(), Ordering::SeqCst);
        }

        Ok(store)
    }

    fn new_from_slice(size: usize, data: &[u8]) -> Result<Self> {
        ensure!(
            data.len() % N::to_usize() == 0,
            "data size must be a multiple of {}",
            N::to_usize()
        );

        let mut store = Self::new(size)?;

        let len = data.len();
        store.map.as_mut()[0..len].copy_from_slice(data);
        store.len.store(len / N::to_usize(), Ordering::SeqCst);

        Ok(store)
    }

    fn read_at(&self, index: usize) -> Result<GenericArray<u8, N>> {
        let start = index * N::to_usize();
        let end = start + N::to_usize();
        let len = self.len() * N::to_usize();

        ensure!(start < len, "start out of range {} >= {}", start, len);
        ensure!(end <= len, "end out of range {} > {}", end, len);

        let res: &GenericArray<u8, N> = self.get_data()[start..end].into();
        Ok(res.clone())
    }

    fn read_into(&self, index: usize, buf: &mut [u8]) -> Result<()> {
        let start = index * N::to_usize();
        let end = start + N::to_usize();
        let len = self.len() * N::to_usize();

        ensure!(start < len, "start out of range {} >= {}", start, len);
        ensure!(end <= len, "end out of range {} > {}", end, len);

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
        Ok(true)
        // let map = self.map.take();

        // Ok(map.is_some())
    }

    fn reinit(&mut self) -> Result<()> {
        // self.map = unsafe { Some(MmapMut::map_mut(&self.file)?) };
        // ensure!(self.map.is_some(), "Re-init mapping failed");

        Ok(())
    }

    fn delete(_config: StoreConfig) -> Result<()> {
        Ok(())
    }

    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn push(&mut self, el: impl Into<GenericArray<u8, N>>) -> Result<()> {
        let l = self.len();

        ensure!(
            (l + 1) * N::to_usize() <= self.get_data().len(),
            "not enough space"
        );

        self.write_at(el.into(), l)
    }
}
