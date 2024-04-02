use std::ops::Range;

/// Used for finding ranges in an array without having to iterate over the entire array every time.
pub struct AdvancingRange<'a, T: GetCycles> {
    data: &'a [T],
    start: usize,
    end: usize,
    previous_range: Range<u32>,
}

impl<'a, T: GetCycles> AdvancingRange<'a, T> {
    pub fn new(slice: &'a [T]) -> Self {
        Self {
            data: slice,
            start: 0,
            end: 0,
            previous_range: 0..0,
        }
    }

    /// Returns the range of the elements within the acceptable range, assuming
    /// the elements are in nondecreasing order.
    /// # Panics
    /// Panics if `acceptable_range`'s start or end is less than in the previous call.
    pub fn get_range(&mut self, acceptable_range: Range<u32>) -> Range<usize> {
        assert!(acceptable_range.start >= self.previous_range.start);
        assert!(acceptable_range.end >= self.previous_range.end);

        for x in self.data[self.start..].iter() {
            if x.cycles() < acceptable_range.start {
                self.start += 1;
            }
        }
        for x in self.data[self.end..].iter() {
            if x.cycles() < acceptable_range.end {
                self.end += 1;
            }
        }

        self.start..self.end
    }

    /// Returns a slice to the elements within the acceptable range, assuming
    /// the elements are in nondecreasing order.
    /// # Panics
    /// Panics if `acceptable_range`'s start or end is less than in the previous call.
    pub fn get_slice(&mut self, acceptable_range: Range<u32>) -> &[T] {
        &self.data[self.get_range(acceptable_range)]
    }
}

trait GetCycles {
    fn cycles(&self) -> u32;
}

impl GetCycles for u32 {
    fn cycles(&self) -> u32 {
        *self
    }
}

impl<T> GetCycles for (u32, T) {
    fn cycles(&self) -> u32 {
        self.0
    }
}
impl<T, U> GetCycles for (u32, T, U) {
    fn cycles(&self) -> u32 {
        self.0
    }
}
