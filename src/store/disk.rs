use std::fs::{remove_file, File, OpenOptions};
use std::io::{copy, Seek, SeekFrom};
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};

use anyhow::{Context, Result};
use generic_array::GenericArray;
use positioned_io::{RandomAccessFile, ReadAt, WriteAt};
use tempfile::tempfile;

use crate::hash::{ArrayLength, ArrayLengthMarker};
use crate::merkle::{get_merkle_tree_cache_size, get_merkle_tree_leafs};
use crate::store::{Store, StoreConfig, StoreConfigDataVersion};

/// The Disk-only store is used to reduce memory to the minimum at the
/// cost of build time performance. Most of its I/O logic is in the
/// `store_copy_from_slice` and `store_read_range` functions.
#[derive(Debug)]
pub struct DiskStore<N: ArrayLength> {
    len: AtomicUsize,
    file: RandomAccessFile,

    // This flag is useful only immediate after instantiation, which
    // is false if the store was newly initialized and true if the
    // store was loaded from already existing on-disk data.
    loaded_from_disk: bool,

    // We cache the `store.len()` call to avoid accessing disk unnecessarily.
    // Not to be confused with `len`, this saves the total size of the `store`
    // in bytes and the other one keeps track of used `E` slots in the `DiskStore`.
    store_size: usize,

    _n: ArrayLengthMarker<N>,
}

impl<N: ArrayLength> DiskStore<N> {
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

impl<N: ArrayLength> Store<N> for DiskStore<N> {
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
            .open(data_path)?;

        let store_size = N::to_usize() * size;
        file.set_len(store_size as u64)?;

        Ok(DiskStore {
            len: AtomicUsize::new(0),
            file: RandomAccessFile::try_new(file)?,
            loaded_from_disk: false,
            store_size,
            _n: Default::default(),
        })
    }

    fn new(size: usize) -> Result<Self> {
        let store_size = N::to_usize() * size;
        let file = tempfile()?;
        file.set_len(store_size as u64)?;

        Ok(DiskStore {
            len: AtomicUsize::new(0),
            file: RandomAccessFile::try_new(file)?,
            loaded_from_disk: false,
            store_size,
            _n: Default::default(),
        })
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

        let store = Self::new_with_config(size, branches, config)?;

        // If the store was loaded from disk (based on the config
        // information, avoid re-populating the store at this point
        // since it can be assumed by the config that the data is
        // already correct).
        if !store.loaded_from_disk {
            store.store_copy_from_slice(0, data)?;
            store
                .len
                .store(data.len() / N::to_usize(), Ordering::SeqCst);
        }

        Ok(store)
    }

    fn new_from_slice(size: usize, data: &[u8]) -> Result<Self> {
        ensure!(
            data.len() % N::to_usize() == 0,
            "data size must be a multiple of {}",
            N::to_usize()
        );

        let store = Self::new(size)?;
        store.store_copy_from_slice(0, data)?;
        store
            .len
            .store(data.len() / N::to_usize(), Ordering::SeqCst);

        Ok(store)
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

        Ok(DiskStore {
            len: AtomicUsize::new(size),
            file: RandomAccessFile::try_new(file)?,
            loaded_from_disk: true,
            store_size,
            _n: Default::default(),
        })
    }

    fn write_at(&mut self, el: impl AsRef<[u8]>, index: usize) -> Result<()> {
        self.store_copy_from_slice(index * N::to_usize(), el.as_ref())?;
        self.len_max(index + 1);
        Ok(())
    }

    fn copy_from_slice(&mut self, buf: &[u8], start: usize) -> Result<()> {
        ensure!(
            buf.len() % N::to_usize() == 0,
            "buf size must be a multiple of {}",
            N::to_usize()
        );
        unsafe {
            self.copy_from_slice_unchecked(buf, start)?;
        }

        Ok(())
    }

    unsafe fn copy_from_slice_unchecked(&self, buf: &[u8], start: usize) -> Result<()> {
        self.store_copy_from_slice(start * N::to_usize(), buf)?;
        self.len_max(start + buf.len() / N::to_usize());

        Ok(())
    }

    fn read_at(&self, index: usize) -> Result<GenericArray<u8, N>> {
        let start = index * N::to_usize();
        let end = start + N::to_usize();

        let len = Store::len(self) * N::to_usize();
        ensure!(start < len, "start out of range {} >= {}", start, len);
        ensure!(end <= len, "end out of range {} > {}", end, len);

        let mut out = GenericArray::default();
        self.store_read_into(start, end, &mut out)?;

        Ok(out)
    }

    fn read_into(&self, index: usize, buf: &mut [u8]) -> Result<()> {
        let start = index * N::to_usize();
        let end = start + N::to_usize();

        let len = Store::len(self) * N::to_usize();
        ensure!(start < len, "start out of range {} >= {}", start, len);
        ensure!(end <= len, "end out of range {} > {}", end, len);

        self.store_read_into(start, end, buf)
    }

    fn read_range_into(&self, start: usize, end: usize, buf: &mut [u8]) -> Result<()> {
        let start = start * N::to_usize();
        let end = end * N::to_usize();

        let len = Store::len(self) * N::to_usize();
        ensure!(start < len, "start out of range {} >= {}", start, len);
        ensure!(end <= len, "end out of range {} > {}", end, len);

        self.store_read_into(start, end, buf)
    }

    fn len(&self) -> usize {
        self.len.load(Ordering::SeqCst)
    }

    fn loaded_from_disk(&self) -> bool {
        self.loaded_from_disk
    }

    // Specifically, this method truncates an existing DiskStore and
    // formats the data in such a way that is compatible with future
    // access using LevelCacheStore::new_from_disk.
    fn compact(
        &mut self,
        branches: usize,
        config: StoreConfig,
        store_version: u32,
    ) -> Result<bool> {
        // Determine how many base layer leafs there are (and in bytes).
        let leafs = get_merkle_tree_leafs(Store::len(self), branches)?;
        let data_width = leafs * N::to_usize();

        // Calculate how large the cache should be (based on the
        // config.rows_to_discard param).
        let cache_size =
            get_merkle_tree_cache_size(leafs, branches, config.rows_to_discard)? * N::to_usize();

        // The file cannot be compacted if the specified configuration
        // requires either 1) nothing to be cached, or 2) everything
        // to be cached.  For #1, create a data store of leafs and do
        // not use that store as backing for the MT.  For #2, avoid
        // calling this method.  To resolve, provide a sane
        // configuration.
        ensure!(
            cache_size < Store::len(self) * N::to_usize() && cache_size != 0,
            "Cannot compact with this configuration"
        );

        let v1 = store_version == StoreConfigDataVersion::One as u32;
        let start: u64 = if v1 { data_width as u64 } else { 0 };

        // Calculate cache start and updated size with repect to the
        // data size.
        let cache_start = self.store_size - cache_size;

        // Seek the reader to the start of the cached data.
        let mut reader = OpenOptions::new()
            .read(true)
            .open(StoreConfig::data_path(&config.path, &config.id))?;
        reader.seek(SeekFrom::Start(cache_start as u64))?;

        // Make sure the store file is opened for read/write.
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(StoreConfig::data_path(&config.path, &config.id))?;

        // Seek the writer.
        file.seek(SeekFrom::Start(start))?;

        // Copy the data from the cached region to the writer.
        let written = copy(&mut reader, &mut file)?;
        ensure!(written == cache_size as u64, "Failed to copy all data");
        if v1 {
            // Truncate the data on-disk to be the base layer data
            // followed by the cached data.
            file.set_len((data_width + cache_size) as u64)?;
            // Adjust our length for internal consistency.
            self.len
                .store((data_width + cache_size) / N::to_usize(), Ordering::SeqCst);
        } else {
            // Truncate the data on-disk to be only the cached data.
            file.set_len(cache_size as u64)?;

            // Adjust our length to be the cached elements only for
            // internal consistency.
            self.len.store(cache_size / N::to_usize(), Ordering::SeqCst);
        }

        // Sync and sanity check that we match on disk (this can be
        // removed if needed).
        self.sync()?;
        let metadata = file.metadata()?;
        let store_size = metadata.len() as usize;
        ensure!(
            Store::len(self) * N::to_usize() == store_size,
            "Inconsistent metadata detected"
        );

        self.file = RandomAccessFile::try_new(file)?;

        Ok(true)
    }

    fn delete(config: StoreConfig) -> Result<()> {
        let path = StoreConfig::data_path(&config.path, &config.id);
        remove_file(&path).with_context(|| format!("Failed to delete {:?}", &path))
    }

    fn is_empty(&self) -> bool {
        Store::len(self) == 0
    }

    fn push(&mut self, el: impl Into<GenericArray<u8, N>>) -> Result<()> {
        let len = Store::len(self);
        ensure!(
            (len + 1) * N::to_usize() <= self.store_size(),
            "not enough space, len: {}, E size {}, store len {}",
            len,
            N::to_usize(),
            self.store_size()
        );

        self.write_at(el.into(), len)
    }

    fn sync(&self) -> Result<()> {
        self.file.sync_all().context("failed to sync file")
    }
}

impl<N: ArrayLength> DiskStore<N> {
    // 'store_range' must be the total number of elements in the store
    // (e.g. tree.len()).  Arity/branches is ignored since a
    // DiskStore's size is related only to the number of elements in
    // the tree.
    pub fn is_consistent(
        store_range: usize,
        _branches: usize,
        config: &StoreConfig,
    ) -> Result<bool> {
        let data_path = StoreConfig::data_path(&config.path, &config.id);

        let file = File::open(&data_path)?;
        let metadata = file.metadata()?;
        let store_size = metadata.len() as usize;

        Ok(store_size == store_range * N::to_usize())
    }

    pub fn store_size(&self) -> usize {
        self.store_size
    }

    pub fn store_read_into(&self, start: usize, end: usize, buf: &mut [u8]) -> Result<()> {
        self.file
            .read_exact_at(start as u64, buf)
            .with_context(|| {
                format!(
                    "failed to read {} bytes from file at offset {}",
                    end - start,
                    start
                )
            })?;

        Ok(())
    }

    pub fn store_copy_from_slice(&self, start: usize, slice: &[u8]) -> Result<()> {
        ensure!(
            start + slice.len() <= self.store_size,
            "Requested slice too large (max: {})",
            self.store_size
        );
        let file: &mut &RandomAccessFile = &mut &self.file;
        file.write_all_at(start as u64, slice)?;

        Ok(())
    }
}
