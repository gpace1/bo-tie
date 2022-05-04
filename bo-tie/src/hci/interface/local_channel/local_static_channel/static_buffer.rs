//! Statically allocated buffers
//!
//! Buffers in this module are statically allocated. The size of the buffer must be known at
//! compile time.

use std::fmt::{Display, Formatter};
use std::mem::{replace, transmute, MaybeUninit};
use std::ops::{Deref, DerefMut};

/// A linear buffer
///
/// Items in this buffer can be added or removed, but removing an item causes a swap with the last
/// item in the buffer.
pub struct LinearBuffer<const SIZE: usize, T> {
    buffer: [MaybeUninit<T>; SIZE],
    count: usize,
}

impl<T, const SIZE: usize> Deref for LinearBuffer<SIZE, T> {
    type Target = [T];

    fn deref(&self) -> &Self::Target {
        unsafe { transmute::<&[MaybeUninit<T>], &[T]>(&self.buffer[..self.count]) }
    }
}

impl<T, const SIZE: usize> DerefMut for LinearBuffer<SIZE, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { transmute::<&mut [MaybeUninit<T>], &mut [T]>(&mut self.buffer[..self.count]) }
    }
}

impl<T, const SIZE: usize> LinearBuffer<SIZE, T> {
    pub fn new() -> Self {
        let buffer = unsafe { MaybeUninit::uninit().assume_init() };

        let count = 0;

        Self { buffer, count }
    }

    /// Remove an item
    ///
    /// Removes an item from the buffer shifting everything past the index left by one.
    pub fn try_remove(&mut self, index: usize) -> Result<T, LinearBufferError> {
        if index < self.count {
            let v =
                unsafe { replace(&mut self.buffer[index], MaybeUninit::uninit()).assume_init() };

            if self.count != 1 {
                // shifting everything *past* the removed to the left by one
                unsafe {
                    let move_to = self.buffer.as_mut_ptr().add(index);

                    let move_from = self.buffer.as_ptr().add(index + 1);

                    // This is a copy of the raw *bytes*
                    // this leaves an uninitialized value at index `self.count - 1`
                    move_to.copy_from(move_from, self.count - (index + 1))
                }
            }

            self.count = self.count - 1;

            Ok(v)
        } else {
            if self.count == 0 {
                Err(LinearBufferError::BufferEmpty)
            } else {
                Err(LinearBufferError::IndexOutOfRange)
            }
        }
    }

    /// Insert an item
    ///
    /// Inserts an item into the buffer shifting everything past the index right by one
    pub fn try_insert(&mut self, t: T, at: usize) -> Result<(), LinearBufferError> {
        if at <= self.count {
            if self.count < SIZE {
                if at != self.count {
                    // shift everything *at and past* the insertion index to the right by one
                    unsafe {
                        let move_to = self.buffer.as_mut_ptr().add(at + 1);

                        let move_from = self.buffer.as_ptr().add(at);

                        // This is a copy of the raw *bytes*
                        // This leaves an uninitialized value to the insertion point
                        move_to.copy_from(move_from, self.count - at)
                    }
                }

                self.count += 1;

                self.buffer[at] = MaybeUninit::new(t);

                Ok(())
            } else {
                Err(LinearBufferError::BufferFull)
            }
        } else {
            Err(LinearBufferError::IndexOutOfRange)
        }
    }
}

impl<T, const SIZE: usize> Drop for LinearBuffer<SIZE, T> {
    fn drop(&mut self) {
        for is_init in self.buffer[..self.count].iter_mut() {
            unsafe { is_init.assume_init_drop() }
        }
    }
}

/// Error from a `LinearBuffer`
#[derive(Debug)]
pub enum LinearBufferError {
    BufferFull,
    BufferEmpty,
    IndexOutOfRange,
}

impl Display for LinearBufferError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            LinearBufferError::BufferFull => f.write_str("linear buffer full"),
            LinearBufferError::BufferEmpty => f.write_str("linear buffer empty"),
            LinearBufferError::IndexOutOfRange => f.write_str("index out of range"),
        }
    }
}

/// A queue buffer
///
/// This is a implementation of a buffer queue. Buffered items are added to the end and items are
/// removed from the front. For the fastest implementation, the size of buffer should be a power of
/// two.
///
/// # Note
/// The underlying implementation of a `QueueBuffer` is a circular buffer.
pub struct QueueBuffer<T, const SIZE: usize> {
    buffer: [MaybeUninit<T>; SIZE],
    start: usize,
    count: usize,
}

impl<T, const SIZE: usize> QueueBuffer<T, SIZE> {
    pub fn new() -> Self {
        let buffer = unsafe { MaybeUninit::uninit().assume_init() };

        let start = 0;

        let count = 0;

        Self {
            buffer,
            start,
            count,
        }
    }

    pub fn is_full(&self) -> bool {
        self.count == SIZE
    }

    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    pub fn try_push(&mut self, t: T) -> Result<(), QueueBufferError> {
        if self.count < SIZE {
            let next = (self.start + self.count) % SIZE;

            self.count += 1;

            self.buffer[next] = MaybeUninit::new(t);

            Ok(())
        } else {
            Err(QueueBufferError::BufferFull)
        }
    }

    pub fn try_remove(&mut self) -> Result<T, QueueBufferError> {
        if self.count != 0 {
            let ret = unsafe {
                replace(&mut self.buffer[self.start], MaybeUninit::uninit()).assume_init()
            };

            self.start = (self.start + 1) % SIZE;

            self.count -= 1;

            Ok(ret)
        } else {
            Err(QueueBufferError::BufferEmpty)
        }
    }
}

#[derive(Debug)]
pub enum QueueBufferError {
    BufferFull,
    BufferEmpty,
}

impl Display for QueueBufferError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            QueueBufferError::BufferFull => f.write_str("buffer is full"),
            QueueBufferError::BufferEmpty => f.write_str("buffer is empty"),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn linear_buffer_init() {
        let _: LinearBuffer<0, ()> = LinearBuffer::new();
    }

    #[test]
    fn linear_buffer_fill_and_remove() {
        const SIZE: usize = 5;

        let mut l: LinearBuffer<SIZE, usize> = LinearBuffer::new();

        for i in 0..SIZE {
            l.try_insert(i, i).unwrap();
        }

        for i in 0..SIZE {
            assert_eq!(i, l[i])
        }

        for i in 0..SIZE {
            assert_eq!(i, l.try_remove(0).unwrap())
        }

        for i in SIZE..(2 * SIZE) {
            l.try_insert(i, 0).unwrap();
        }

        for i in SIZE..(2 * SIZE) {
            assert_eq!(i, l.try_remove(l.len() - 1).unwrap())
        }
    }

    #[test]
    fn linear_buffer_overfill() {
        const SIZE: usize = 0;

        let mut l: LinearBuffer<SIZE, usize> = LinearBuffer::new();

        for _ in 0..SIZE {
            l.try_insert(0, 0).unwrap();
        }

        match l.try_insert(0, 0) {
            Err(LinearBufferError::BufferFull) => (),
            _ => panic!("Expected LinearBufferError::BufferFull"),
        }
    }

    #[test]
    fn liner_buffer_remove_from_empty() {
        let mut l: LinearBuffer<4, usize> = LinearBuffer::new();

        match l.try_remove(4) {
            Err(LinearBufferError::BufferEmpty) => (),
            _ => panic!("Expected LinearBufferError::BufferEmpty"),
        }
    }

    #[test]
    fn linear_buffer_index_out_of_bound() {
        let mut l: LinearBuffer<4, usize> = LinearBuffer::new();

        match l.try_insert(0, 2) {
            Err(LinearBufferError::IndexOutOfRange) => (),
            v => panic!(
                "Expected LinearBufferError::IndexOutOfRange, received {:?}",
                v
            ),
        }

        l.try_insert(0, 0).unwrap();

        match l.try_remove(2) {
            Err(LinearBufferError::IndexOutOfRange) => (),
            v => panic!(
                "Expected LinearBufferError::IndexOutOfRange, received {:?}",
                v
            ),
        }
    }

    #[test]
    fn queue_buffer_init() {
        let _: QueueBuffer<usize, 4> = QueueBuffer::new();
    }

    #[test]
    fn queue_buffer_add_remove() {
        const SIZE: usize = 4;

        let mut q: QueueBuffer<usize, SIZE> = QueueBuffer::new();

        for i in 0..SIZE {
            q.try_push(i).unwrap();
        }

        match q.try_push(0) {
            Err(QueueBufferError::BufferFull) => (),
            e => panic!("expected QueueBufferError::BufferFull, received {:?}", e),
        }

        for i in 0..SIZE {
            assert_eq!(i, q.try_remove().unwrap());
        }

        match q.try_remove() {
            Err(QueueBufferError::BufferEmpty) => (),
            e => panic!("expected QueueBufferError::BufferEmpty, received {:?}", e),
        }

        // internally moving the circle buffer `start` to the middle and then test if the circular
        // nature of the buffer works.

        for i in 0..(SIZE / 2) {
            q.try_push(i).unwrap();
        }

        for _ in 0..(SIZE / 2) {
            q.try_remove().unwrap();
        }

        for i in 0..SIZE {
            q.try_push(i).unwrap();
        }

        for i in 0..SIZE {
            assert_eq!(i, q.try_remove().unwrap())
        }
    }
}
