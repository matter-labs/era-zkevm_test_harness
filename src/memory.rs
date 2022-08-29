use std::collections::HashMap;
use std::hash::{BuildHasherDefault, Hasher};
use zk_evm::abstractions::{Memory, MEMORY_CELLS_OTHER_PAGES};
use zk_evm::aux_structures::{MemoryPage, MemoryQuery};
use zk_evm::ethereum_types::U256;

#[derive(Debug)]
pub struct SimpleMemory {
    inner: Vec<HashMap<usize, U256, BuildHasherDefault<NoopHasher>>>,

    // the stack of return data pages
    return_data_pages: Vec<u32>,
    // the depth of the current recursion.
    // needed to keep track of the abandonded returndata pages
    depth_index: usize,
}

#[derive(Default)]
struct NoopHasher(u64);

impl Hasher for NoopHasher {
    fn write_usize(&mut self, value: usize) {
        self.0 = value as u64;
    }

    fn write(&mut self, _bytes: &[u8]) {
        unreachable!("internal hasher only handles usize type");
    }

    fn finish(&self) -> u64 {
        self.0
    }
}

impl SimpleMemory {
    pub fn new() -> Self {
        Self {
            inner: Default::default(),
            return_data_pages: vec![],
            depth_index: 0,
        }
    }

    fn ensure_page_exists(&mut self, page: usize) {
        if self.inner.len() <= page {
            self.inner.resize_with(page + 1, HashMap::default);
        }
    }

    fn clear_page(&mut self, page: u32) {
        if self.inner.len() <= page as usize {
            return;
        }

        self.inner[page as usize].clear();
        self.inner[page as usize].shrink_to_fit();
    }

    pub fn populate(&mut self, elements: Vec<(u32, Vec<U256>)>) -> Vec<(u32, usize)> {
        let mut results = vec![];
        for (page, values) in elements.into_iter() {
            // Resizing the pages array to fit the page.
            self.ensure_page_exists(page as usize);
            let len = values.len();
            assert!(len <= MEMORY_CELLS_OTHER_PAGES);
            self.inner[page as usize] = values.into_iter().enumerate().collect();
            results.push((page, len));
        }
        results
    }

    pub fn populate_page(&mut self, page: usize, elements: Vec<(usize, U256)>) {
        self.ensure_page_exists(page);
        elements.into_iter().for_each(|(offset, value)| {
            self.inner[page].insert(offset, value);
        })
    }
}

impl Memory for SimpleMemory {
    fn execute_partial_query(
        &mut self,
        _monotonic_cycle_counter: u32,
        mut query: MemoryQuery,
    ) -> MemoryQuery {
        self.ensure_page_exists(query.location.page.0 as usize);

        let entry = self.inner.get_mut(query.location.page.0 as usize).unwrap();
        if query.rw_flag {
            entry.insert(query.location.index.0 as usize, query.value);
        } else {
            query.value = *entry
                .get(&(query.location.index.0 as usize))
                .unwrap_or(&U256::zero());
        }

        query
    }

    fn start_frame(&mut self, new_returndata_page: MemoryPage) {
        // When a new frame starts we should check for all possibly outdated return data pages.
        while self.depth_index < self.return_data_pages.len() {
            let heap_page_to_remove = self.return_data_pages.pop().unwrap();
            let next_returndata_page = self.return_data_pages.last();

            let should_clear_page = next_returndata_page
                .map(|x| *x != heap_page_to_remove)
                .unwrap_or(true);

            if should_clear_page {
                self.clear_page(heap_page_to_remove as u32);
            }
        }
        assert!(self.depth_index == self.return_data_pages.len());

        self.return_data_pages.push(new_returndata_page.0);
        self.depth_index += 1;
    }

    fn finish_frame(&mut self, old_stack_page: MemoryPage, new_stack_page: MemoryPage) {
        if old_stack_page != new_stack_page {
            self.clear_page(old_stack_page.0)
        }

        self.depth_index -= 1;
    }
}

