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
        self.previous_range = acceptable_range.clone();

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

pub trait GetCycles {
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

#[cfg(test)]
mod test {
    use super::AdvancingRange;

    const EMPTY: &[u32] = &[];
    const INDICES: &[u32] = &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9];

    #[test]
    fn correct_usage() {
        let mut r = AdvancingRange::new(INDICES);
        assert_eq!(r.get_slice(0..0), EMPTY);
        assert_eq!(r.get_slice(1..5), &[1, 2, 3, 4]);
        assert_eq!(r.get_slice(6..11), &[6, 7, 8, 9]);
        assert_eq!(r.get_slice(7..11), &[7, 8, 9]);
        assert_eq!(r.get_slice(10..100), EMPTY);
        assert_eq!(r.get_range(10..100), 10..10);
    }

    #[test]
    #[should_panic]
    fn incorrect_usage() {
        let mut r = AdvancingRange::new(INDICES);
        r.get_slice(3..6);
        r.get_slice(1..7);
    }

    #[test]
    #[should_panic]
    fn incorrect_usage2() {
        let mut r = AdvancingRange::new(INDICES);
        r.get_slice(3..6);
        r.get_slice(3..5);
    }
}
