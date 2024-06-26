use crate::witness::advancing_range::TupleFirst;

/// Used to store queries that will be used for the main VM witness generation.
/// This data structure internally sorts queries by main VM circuit instances.
#[derive(Clone, Debug)]
pub struct QueueForMainVm<T: TupleFirst> {
    cycles_per_vm_snapshot: usize,
    inner: Vec<Vec<T>>
}

impl<T: TupleFirst> QueueForMainVm<T> {
    pub fn new(cycles_per_vm_snapshot: usize) -> Self {
        Self {
            cycles_per_vm_snapshot,
            inner: Default::default()
        }
    }

    pub fn last(&self) -> Option<&T> {
        let last_batch = self.inner.last();
        if last_batch.is_none() {
            return None;
        }

        last_batch.unwrap().last()
    }

    pub fn from_iter<I: IntoIterator<Item = T>>(cycles_per_vm_snapshot: usize, iterator: I) -> Self {
       let mut _self = Self {
            cycles_per_vm_snapshot,
            inner: Default::default()
        };

        let mut iterator = iterator.into_iter();

        while let Some(element) = iterator.next() {
            _self.push(element);
        }

        _self
    }

    pub fn push(&mut self, val: T) {
        let cycle = val.first() as usize;
        let batch_index = cycle / self.cycles_per_vm_snapshot;

        while self.inner.len() <= batch_index {
            self.seal_last_batch();
            self.push_new_batch();
        }

        let batch = &mut self.inner[batch_index];
        batch.push(val);
    }

    pub fn into_batches(self) -> Vec<Vec<T>> {
        self.inner
    }

    pub fn get_batch(&self, batch_index: usize) -> Option<&Vec<T>> {
        self.inner.get(batch_index)
    }

    pub fn get_batch_mut(&mut self, batch_index: usize) -> Option<&mut Vec<T>> {
        if batch_index >= self.inner.len() {
            return None;
        }

        let batch = &mut self.inner[batch_index];
        Some(batch)
    }

    pub fn iter(&self) -> SplittedQueueIterator<T> {
        SplittedQueueIterator {
            queue: self,
            batch_index: 0,
            inner_index: 0
        }
    }

    fn push_new_batch(&mut self) {
        self.inner.push(Vec::with_capacity(self.cycles_per_vm_snapshot / 2));
    }

    fn seal_last_batch(&mut self) {
        let len = self.inner.len();
        if len == 0 {
            return;
        }

        self.inner[len - 1].shrink_to_fit();
    }
}

impl<T: TupleFirst> IntoIterator for QueueForMainVm<T> {
    type Item = T;
    type IntoIter = SplittedQueueIntoIter<T>;

    fn into_iter(self) -> SplittedQueueIntoIter<T> {
        SplittedQueueIntoIter { 
            queue: self,
            batch_index: 0
         }
    }
}

impl<T: TupleFirst> Extend<T> for QueueForMainVm<T> {
    #[inline]
    fn extend<I: IntoIterator<Item = T>>(&mut self, iter: I) {
        let mut iterator = iter.into_iter();

        while let Some(element) = iterator.next() {
            self.push(element);
        }
    }
}

pub struct SplittedQueueIterator<'a, T: TupleFirst> {
    queue: &'a QueueForMainVm<T>,
    batch_index: usize,
    inner_index: usize,
}

impl<'a, T: TupleFirst> Iterator for SplittedQueueIterator<'a, T> {
    type Item = &'a T;

    fn next(&mut self) -> Option<Self::Item> {
        let mut batch = self.queue.get_batch(self.batch_index);
        if batch.is_none() {
            return None;
        }

        if self.inner_index >= batch.unwrap().len(){
            self.batch_index += 1;
            self.inner_index = 0;
            batch = self.queue.get_batch(self.batch_index);
            if batch.is_none() {
                return None;
            }
        }
        
        batch.unwrap().get(self.inner_index)
    }
}

pub struct SplittedQueueIntoIter<T: TupleFirst> {
    queue: QueueForMainVm<T>,
    batch_index: usize
}

impl<T: TupleFirst> Iterator for SplittedQueueIntoIter<T> {
    type Item = T;

    fn next(&mut self) -> Option<Self::Item> {
        // TODO can be optimized
        let batch = self.queue.get_batch_mut(self.batch_index);
        if batch.is_none() {
            return None;
        }

        let mut batch = batch.unwrap();

        if batch.is_empty(){
            self.batch_index += 1;
            let next_batch = self.queue.get_batch_mut(self.batch_index);
            if next_batch.is_none() {
                return None;
            }
            batch = next_batch.unwrap();
        }

        let batch: &mut Vec<T> = batch;
        if batch.is_empty() {
            return None;
        }

        let result = batch.remove(0);
        Some(result)
    }
}

