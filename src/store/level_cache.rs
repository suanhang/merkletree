use std::fmt;
use std::fs::{remove_file, File, OpenOptions};
use std::io::{copy, Read, Seek, SeekFrom};
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};

use anyhow::{Context, Result};
use generic_array::GenericArray;
use positioned_io::{RandomAccessFile, ReadAt, WriteAt};
use tempfile::tempfile;
use typenum::marker_traits::Unsigned;

use crate::hash::{Algorithm, ArrayLength, ArrayLengthMarker};
use crate::merkle::{
    get_merkle_tree_cache_size, get_merkle_tree_leafs, get_merkle_tree_len, log2_pow2, next_pow2,
};
use crate::store::{ExternalReader, Store, StoreConfig};

/// The LevelCacheStore is used to reduce the on-disk footprint even
/// further to the minimum at the cost of build time performance.
/// Each LevelCacheStore is created with a StoreConfig object which
/// contains the number of binary tree levels above the base that are
/// 'cached'.  This implementation has hard requirements about the on
/// disk file size based on that number of levels, so on-disk files
/// are tied, structurally to the configuration they were built with
/// and can only be accessed with the same number of levels.
pub struct LevelCacheStore<N: ArrayLength, R: Read + Send + Sync> {
    len: AtomicUsize,
    file: RandomAccessFile,

    // The number of base layer data items.
    data_width: usize,

    // The byte index of where the cached data begins.
    cache_index_start: usize,

    // This flag is useful only immediate after instantiation, which
    // is false if the store was newly initialized and true if the
    // store was loaded from already existing on-disk data.
    loaded_from_disk: bool,

    // We cache the on-disk file size to avoid accessing disk
    // unnecessarily.
    store_size: usize,

    // If provided, the store will use this method to access base
    // layer data.
    reader: Option<ExternalReader<R>>,

    _n: ArrayLengthMarker<N>,
}

impl<N: ArrayLength, R: Read + Send + Sync> LevelCacheStore<N, R> {
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

impl<N: ArrayLength, R: Read + Send + Sync> fmt::Debug for LevelCacheStore<N, R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LevelCacheStore")
            .field("len", &self.len.load(Ordering::SeqCst))
            .field("data_width", &self.data_width)
            .field("loaded_from_disk", &self.loaded_from_disk)
            .field("cache_index_start", &self.cache_index_start)
            .field("store_size", &self.store_size)
            .finish()
    }
}

impl<N: ArrayLength, R: Read + Send + Sync> LevelCacheStore<N, R> {
    /// Used for opening v2 compacted DiskStores.
    pub fn new_from_disk_with_reader(
        store_range: usize,
        branches: usize,
        config: &StoreConfig,
        reader: ExternalReader<R>,
    ) -> Result<Self> {
        let data_path = StoreConfig::data_path(&config.path, &config.id);

        let file = File::open(data_path)?;
        let metadata = file.metadata()?;
        let store_size = metadata.len() as usize;

        // The LevelCacheStore base data layer must already be a
        // massaged next pow2 (guaranteed if created with
        // DiskStore::compact, which is the only supported method at
        // the moment).
        let size = get_merkle_tree_leafs(store_range, branches)?;
        ensure!(
            size == next_pow2(size),
            "Inconsistent merkle tree row_count detected"
        );

        // Values below in bytes.
        // Convert store_range from an element count to bytes.
        let store_range = store_range * N::to_usize();

        // LevelCacheStore on disk file is only the cached data, so
        // the file size dictates the cache_size.  Calculate cache
        // start and the updated size with repect to the file size.
        let cache_size =
            get_merkle_tree_cache_size(size, branches, config.rows_to_discard)? * N::to_usize();
        let cache_index_start = store_range - cache_size;

        // Sanity checks that the StoreConfig rows_to_discard matches this
        // particular on-disk file.  Since an external reader *is*
        // set, we check to make sure that the data on disk is *only*
        // the cached element data.
        ensure!(
            store_size == cache_size,
            "Inconsistent store size detected with external reader ({} != {})",
            store_size,
            cache_size,
        );

        Ok(LevelCacheStore {
            len: AtomicUsize::new(store_range / N::to_usize()),
            file: RandomAccessFile::try_new(file)?,
            data_width: size,
            cache_index_start,
            store_size,
            loaded_from_disk: false,
            reader: Some(reader),
            _n: Default::default(),
        })
    }

    pub fn set_external_reader(&mut self, reader: ExternalReader<R>) -> Result<()> {
        self.reader = Some(reader);

        Ok(())
    }
}

impl<N: ArrayLength, R: Read + Send + Sync> Store<N> for LevelCacheStore<N, R> {
    fn new_with_config(size: usize, branches: usize, config: StoreConfig) -> Result<Self> {
        let data_path = StoreConfig::data_path(&config.path, &config.id);

        // If the specified file exists, load it from disk.  This is
        // the only supported usage of this call for this type of
        // Store.
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
        let leafs = get_merkle_tree_leafs(size, branches)?;

        ensure!(
            leafs == next_pow2(leafs),
            "Inconsistent merkle tree row_count detected"
        );

        // Calculate cache start and the updated size with repect to
        // the data size.
        let cache_size =
            get_merkle_tree_cache_size(leafs, branches, config.rows_to_discard)? * N::to_usize();
        let cache_index_start = store_size - cache_size;

        file.set_len(store_size as u64)?;

        Ok(LevelCacheStore {
            len: AtomicUsize::new(0),
            file: RandomAccessFile::try_new(file)?,
            data_width: leafs,
            cache_index_start,
            store_size,
            loaded_from_disk: false,
            reader: None,
            _n: Default::default(),
        })
    }

    fn new(size: usize) -> Result<Self> {
        let store_size = N::to_usize() * size;
        let file = tempfile()?;
        file.set_len(store_size as u64)?;

        Ok(LevelCacheStore {
            len: AtomicUsize::new(0),
            file: RandomAccessFile::try_new(file)?,
            data_width: size,
            cache_index_start: 0,
            store_size,
            loaded_from_disk: false,
            reader: None,
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

    // Used for opening v1 compacted DiskStores.
    fn new_from_disk(store_range: usize, branches: usize, config: &StoreConfig) -> Result<Self> {
        let data_path = StoreConfig::data_path(&config.path, &config.id);

        let file = File::open(data_path)?;
        let metadata = file.metadata()?;
        let store_size = metadata.len() as usize;

        // The LevelCacheStore base data layer must already be a
        // massaged next pow2 (guaranteed if created with
        // DiskStore::compact, which is the only supported method at
        // the moment).
        let size = get_merkle_tree_leafs(store_range, branches)?;
        ensure!(
            size == next_pow2(size),
            "Inconsistent merkle tree row_count detected"
        );

        // Values below in bytes.
        // Convert store_range from an element count to bytes.
        let store_range = store_range * N::to_usize();

        // Calculate cache start and the updated size with repect to
        // the data size.
        let cache_size =
            get_merkle_tree_cache_size(size, branches, config.rows_to_discard)? * N::to_usize();
        let cache_index_start = store_range - cache_size;

        // For a true v1 compatible store, this check should remain,
        // but since the store structure is identical otherwise this
        // method can be re-used to open v2 stores, so long as an
        // external_reader is set afterward.

        // Sanity checks that the StoreConfig rows_to_discard matches this
        // particular on-disk file.
        /*
        ensure!(
            store_size == size * N::to_usize() + cache_size,
            "Inconsistent store size detected"
        );
         */

        Ok(LevelCacheStore {
            len: AtomicUsize::new(store_range / N::to_usize()),
            file: RandomAccessFile::try_new(file)?,
            data_width: size,
            cache_index_start,
            loaded_from_disk: true,
            store_size,
            reader: None,
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
        self.store_copy_from_slice(start * N::to_usize(), buf)?;
        self.len_max(start + buf.len() / N::to_usize());

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

        let len = self.len() * N::to_usize();
        ensure!(start < len, "start out of range {} >= {}", start, len);
        ensure!(end <= len, "end out of range {} > {}", end, len);
        ensure!(
            start <= self.data_width * N::to_usize() || start >= self.cache_index_start,
            "out of bounds"
        );

        let mut out = GenericArray::default();
        self.store_read_into(start, end, &mut out)?;
        Ok(out)
    }

    fn read_into(&self, index: usize, buf: &mut [u8]) -> Result<()> {
        let start = index * N::to_usize();
        let end = start + N::to_usize();

        let len = self.len() * N::to_usize();
        ensure!(start < len, "start out of range {} >= {}", start, len);
        ensure!(end <= len, "end out of range {} > {}", end, len);
        ensure!(
            start <= self.data_width * N::to_usize() || start >= self.cache_index_start,
            "out of bounds"
        );

        self.store_read_into(start, end, buf)
    }

    fn read_range_into(&self, start: usize, end: usize, buf: &mut [u8]) -> Result<()> {
        let start = start * N::to_usize();
        let end = end * N::to_usize();

        let len = self.len() * N::to_usize();
        ensure!(start < len, "start out of range {} >= {}", start, len);
        ensure!(end <= len, "end out of range {} > {}", end, len);
        ensure!(
            start <= self.data_width * N::to_usize() || start >= self.cache_index_start,
            "out of bounds"
        );

        self.store_read_into(start, end, buf)
    }

    fn len(&self) -> usize {
        self.len.load(Ordering::SeqCst)
    }

    fn loaded_from_disk(&self) -> bool {
        self.loaded_from_disk
    }

    fn compact(
        &mut self,
        _branches: usize,
        _config: StoreConfig,
        _store_version: u32,
    ) -> Result<bool> {
        bail!("Cannot compact this type of Store");
    }

    fn delete(config: StoreConfig) -> Result<()> {
        let path = StoreConfig::data_path(&config.path, &config.id);
        remove_file(&path).with_context(|| format!("Failed to delete {:?}", &path))
    }

    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn push(&mut self, el: impl Into<GenericArray<u8, N>>) -> Result<()> {
        let len = self.len();
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

    // LevelCacheStore specific merkle-tree build.
    fn build<A: Algorithm, U: Unsigned>(
        &mut self,
        leafs: usize,
        row_count: usize,
        config: Option<StoreConfig>,
    ) -> Result<GenericArray<u8, N>> {
        let branches = U::to_usize();
        ensure!(
            next_pow2(branches) == branches,
            "branches MUST be a power of 2"
        );
        ensure!(Store::len(self) == leafs, "Inconsistent data");
        ensure!(leafs % 2 == 0, "Leafs must be a power of two");
        ensure!(
            config.is_some(),
            "LevelCacheStore build requires a valid config"
        );

        // Process one `level` at a time of `width` nodes. Each level has half the nodes
        // as the previous one; the first level, completely stored in `data`, has `leafs`
        // nodes. We guarantee an even number of nodes per `level`, duplicating the last
        // node if necessary.
        let mut level: usize = 0;
        let mut width = leafs;
        let mut level_node_index = 0;

        let config = config.unwrap();
        let shift = log2_pow2(branches);

        // Both in terms of elements, not bytes.
        let cache_size = get_merkle_tree_cache_size(leafs, branches, config.rows_to_discard)?;
        let cache_index_start = (get_merkle_tree_len(leafs, branches)?) - cache_size;

        while width > 1 {
            // Start reading at the beginning of the current level, and writing the next
            // level immediate after.  `level_node_index` keeps track of the current read
            // starts, and width is updated accordingly at each level so that we know where
            // to start writing.
            let (read_start, write_start) = if level == 0 {
                // Note that we previously asserted that data.len() == leafs.
                (0, Store::len(self))
            } else if level_node_index < cache_index_start {
                (0, width)
            } else {
                (
                    level_node_index - cache_index_start,
                    (level_node_index + width) - cache_index_start,
                )
            };

            self.process_layer::<A, U>(width, level, read_start, write_start)?;

            if level_node_index < cache_index_start {
                self.front_truncate(&config, width)?;
            }

            level_node_index += width;
            level += 1;
            width >>= shift; // width /= branches;

            // When the layer is complete, update the store length
            // since we know the backing file was updated outside of
            // the store interface.
            self.set_len(level_node_index);
        }

        // Account for the root element.
        self.set_len(Store::len(self) + 1);
        // Ensure every element is accounted for.
        ensure!(
            Store::len(self) == get_merkle_tree_len(leafs, branches)?,
            "Invalid merkle tree length"
        );

        ensure!(row_count == level + 1, "Invalid tree row_count");
        // The root isn't part of the previous loop so `row_count` is
        // missing one level.

        // Return the root.  Note that the offset is adjusted because
        // we've just built a store that says that it has the full
        // length of elements, when in fact only the cached portion is
        // on disk.
        self.read_at(self.len() - cache_index_start - 1)
    }
}

impl<N: ArrayLength, R: Read + Send + Sync> LevelCacheStore<N, R> {
    pub fn set_len(&mut self, len: usize) {
        self.len.store(len, Ordering::SeqCst)
    }

    // Remove 'len' elements from the front of the file.
    pub fn front_truncate(&mut self, config: &StoreConfig, len: usize) -> Result<()> {
        let metadata = self.file.metadata()?;
        let store_size = metadata.len();
        let len = (len * N::to_usize()) as u64;

        ensure!(store_size >= len, "Invalid truncation length");

        // Seek the reader past the length we want removed.
        let mut reader = OpenOptions::new()
            .read(true)
            .open(StoreConfig::data_path(&config.path, &config.id))?;
        reader.seek(SeekFrom::Start(len))?;

        // Make sure the store file is opened for read/write.
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(StoreConfig::data_path(&config.path, &config.id))?;
        // Seek the writer.
        file.seek(SeekFrom::Start(0))?;
        let written = copy(&mut reader, &mut file)?;
        ensure!(written == store_size - len, "Failed to copy all data");

        file.set_len(written)?;
        self.file = RandomAccessFile::try_new(file)?;

        Ok(())
    }

    pub fn store_size(&self) -> usize {
        self.store_size
    }

    // 'store_range' must be the total number of elements in the store (e.g. tree.len()).
    pub fn is_consistent_v1(
        store_range: usize,
        branches: usize,
        config: &StoreConfig,
    ) -> Result<bool> {
        let data_path = StoreConfig::data_path(&config.path, &config.id);

        let file = File::open(data_path)?;
        let metadata = file.metadata()?;
        let store_size = metadata.len() as usize;

        // The LevelCacheStore base data layer must already be a
        // massaged next pow2 (guaranteed if created with
        // DiskStore::compact, which is the only supported method at
        // the moment).
        let size = get_merkle_tree_leafs(store_range, branches)?;
        ensure!(
            size == next_pow2(size),
            "Inconsistent merkle tree row_count detected"
        );

        // Calculate cache start and the updated size with repect to
        // the data size.
        let cache_size =
            get_merkle_tree_cache_size(size, branches, config.rows_to_discard)? * N::to_usize();

        // Sanity checks that the StoreConfig rows_to_discard matches this
        // particular on-disk file.
        Ok(store_size == size * N::to_usize() + cache_size)
    }

    // Note that v2 is now the default compaction mode, so this isn't a versioned call.
    // 'store_range' must be the total number of elements in the store (e.g. tree.len()).
    pub fn is_consistent(
        store_range: usize,
        branches: usize,
        config: &StoreConfig,
    ) -> Result<bool> {
        let data_path = StoreConfig::data_path(&config.path, &config.id);

        let file = File::open(data_path)?;
        let metadata = file.metadata()?;
        let store_size = metadata.len() as usize;

        // The LevelCacheStore base data layer must already be a
        // massaged next pow2 (guaranteed if created with
        // DiskStore::compact, which is the only supported method at
        // the moment).
        let size = get_merkle_tree_leafs(store_range, branches)?;
        ensure!(
            size == next_pow2(size),
            "Inconsistent merkle tree row_count detected"
        );

        // LevelCacheStore on disk file is only the cached data, so
        // the file size dictates the cache_size.  Calculate cache
        // start and the updated size with repect to the file size.
        let cache_size =
            get_merkle_tree_cache_size(size, branches, config.rows_to_discard)? * N::to_usize();

        // Sanity checks that the StoreConfig rows_to_discard matches this
        // particular on-disk file.  Since an external reader *is*
        // set, we check to make sure that the data on disk is *only*
        // the cached element data.
        Ok(store_size == cache_size)
    }

    pub fn store_read_into(&self, start: usize, end: usize, buf: &mut [u8]) -> Result<()> {
        ensure!(
            start <= self.data_width * N::to_usize() || start >= self.cache_index_start,
            "Invalid read start"
        );

        // If an external reader was specified for the base layer, use it.
        if start < self.data_width * N::to_usize() && self.reader.is_some() {
            self.reader
                .as_ref()
                .unwrap()
                .read(start, end, buf)
                .with_context(|| {
                    format!(
                        "failed to read {} bytes from file at offset {}",
                        end - start,
                        start
                    )
                })?;
        } else {
            // Adjust read index if in the cached ranged to be shifted
            // over since the data stored is compacted.
            let adjusted_start = if start >= self.cache_index_start {
                if self.reader.is_none() {
                    // if v1
                    start - self.cache_index_start + (self.data_width * N::to_usize())
                } else {
                    start - self.cache_index_start
                }
            } else {
                start
            };

            self.file
                .read_exact_at(adjusted_start as u64, buf)
                .with_context(|| {
                    format!(
                        "failed to read {} bytes from file at offset {}",
                        end - start,
                        start
                    )
                })?;
        }

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
