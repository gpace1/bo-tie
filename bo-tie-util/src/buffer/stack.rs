//! Statically allocated buffers
//!
//! Buffers in this module are statically allocated. The size of the buffer must be known at
//! compile time.

use core::fmt::{Debug, Display, Formatter};
use core::mem::{replace, transmute, MaybeUninit};
use core::ops::{Deref, DerefMut};
use core::ptr;

/// A linear buffer
///
/// Items in this buffer can be added or removed, but removing an item causes a swap with the last
/// item in the buffer.
pub struct LinearBuffer<const SIZE: usize, T> {
    buffer: [MaybeUninit<T>; SIZE],
    count: usize,
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
            let v = unsafe { replace(&mut self.buffer[index], MaybeUninit::uninit()).assume_init() };

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

    /// Try to push an item to the buffer
    pub fn try_push(&mut self, t: T) -> Result<(), LinearBufferError> {
        if self.count != SIZE {
            self.buffer[self.count].write(t);
            self.count += 1;
            Ok(())
        } else {
            Err(LinearBufferError::BufferFull)
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

    /// Get the length
    pub fn len(&self) -> usize {
        self.count
    }
}

impl<T: Clone, const SIZE: usize> Clone for LinearBuffer<SIZE, T> {
    fn clone(&self) -> Self {
        let mut buffer: [MaybeUninit<T>; SIZE] = unsafe { MaybeUninit::uninit().assume_init() };

        for (index, v) in self.deref().iter().enumerate() {
            buffer[index] = MaybeUninit::new(v.clone())
        }

        Self {
            buffer,
            count: self.count,
        }
    }
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

impl<T: Debug, const SIZE: usize> Debug for LinearBuffer<SIZE, T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.write_str("LinearBuffer")?;
        Debug::fmt(self.deref(), f)
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
    InsufficientCapacity,
    SizeTooSmall,
}

impl Display for LinearBufferError {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            LinearBufferError::BufferFull => f.write_str("linear buffer full"),
            LinearBufferError::BufferEmpty => f.write_str("linear buffer empty"),
            LinearBufferError::IndexOutOfRange => f.write_str("index out of range"),
            LinearBufferError::InsufficientCapacity => f.write_str("the capacity is too small"),
            LinearBufferError::SizeTooSmall => f.write_str("size of buffer is too small"),
        }
    }
}

/// A double ended linear buffer
///
/// This is a [`LinearBuffer`] where both the front and end of the list can be pushed to. A
/// `DeLinearBuffer` contains a finite reserve on both ends.
///
/// # Reserves
/// There is a front reserve and a back reserve in a `DeLinearBuffer`. When a `DeLinearBuffer` is
/// created these reserve sizes are fixed. Values cannot be added nor removed passed these reserve
/// limits. Elements can only be added to and from there respective reserves. Pushing to the back
/// is limited to the size of the back buffer, and consequently removing from the back can only be
/// done for elements *within the end reserve*. The same is true for the front reserve.
///
/// ## Adding/Removing
/// Adding and removing elements from a `DeLinearBuffer` is done by the traits [`TryExtend`],
/// [`TryRemove`], [`TryFrontExtend`], and [`TryFrontRemove`]. `TryExtend` and `TryRemove` can
/// add/take from the back reserve and `TryFrontExtend` and `TryFrontRemove` can take from the front
/// reserve.
///
/// [`TryExtend`]: crate::buffer::TryExtend
/// [`TryRemove`]: crate::buffer::TryRemove
/// [`TryFrontExtend`]: crate::buffer::TryFrontExtend
/// [`TryFrontRemove`]: crate::buffer::TryFrontRemove
pub struct DeLinearBuffer<const SIZE: usize, T> {
    buffer: [MaybeUninit<T>; SIZE],
    /// The size of the front reserve
    front: usize,
    /// Number of active elements in buffer
    count: usize,
    /// The starting point for accessing the linear buffer like a slice.
    start: usize,
}

impl<T, const SIZE: usize> DeLinearBuffer<SIZE, T> {
    /// Create a new `DeLinearBuffer`
    ///
    /// This creates a new `DeLinearBuffer` where `front_reserve` is the number of elements
    /// reserved at the front. The reserve at the end is just `SIZE - front_reserve`.
    ///
    /// # Panic
    /// `front_capacity` cannot be greater than `SIZE`.
    pub fn new(front_capacity: usize) -> Self {
        assert!(SIZE >= front_capacity);

        let buffer = unsafe { MaybeUninit::uninit().assume_init() };
        let count = 0;
        let start = front_capacity;
        let front = front_capacity;

        Self {
            buffer,
            front,
            count,
            start,
        }
    }

    /// Remove `how_many` elements from the front reserve
    ///
    /// Removes elements from the front reserve, returning a reference to those that were removed.
    fn try_remove_from_front(&mut self, how_many: usize) -> Result<&mut [MaybeUninit<T>], LinearBufferError> {
        let front_amount = self.front - self.start;

        let split_point = front_amount + how_many;

        if split_point < self.front {
            Err(LinearBufferError::SizeTooSmall)
        } else {
            self.count = self.count - how_many;
            self.start += how_many;

            let (_, back) = self.buffer.split_at_mut(split_point);

            Ok(back)
        }
    }

    /// Try to drop a number of elements from the start
    ///
    /// This drops elements from the start of the `DeLinearBuffer`.
    #[inline]
    fn try_drop_from_front(&mut self, how_many: usize) -> Result<(), LinearBufferError> {
        self.try_remove_from_front(how_many)?
            .iter_mut()
            .for_each(|elem| unsafe { elem.assume_init_drop() });

        Ok(())
    }

    /// Remove `how_many` elements from the back reserve
    ///
    /// Removes elements from the back reserve, returning a reference to those that were removed.
    fn try_remove_from_back(&mut self, how_many: usize) -> Result<&mut [MaybeUninit<T>], LinearBufferError> {
        let size = self.start + self.count;

        let split_point = size.checked_sub(how_many).ok_or(LinearBufferError::SizeTooSmall)?;

        if split_point < self.front {
            // the split point is outside of the back reserve
            Err(LinearBufferError::SizeTooSmall)
        } else {
            self.count = self.count - how_many;

            let (_, back) = self.buffer.split_at_mut(split_point);

            Ok(back)
        }
    }

    /// Try to drop a number of elements from the end
    ///
    /// This drops elements from the end of the `DeLinearBuffer`.
    #[inline]
    fn try_drop_from_back(&mut self, how_many: usize) -> Result<(), LinearBufferError> {
        self.try_remove_from_back(how_many)?
            .iter_mut()
            .for_each(|elem| unsafe { elem.assume_init_drop() });

        Ok(())
    }
}

impl<const SIZE: usize, T> Debug for DeLinearBuffer<SIZE, T>
where
    T: Debug,
{
    fn fmt(&self, f: &mut Formatter) -> core::fmt::Result {
        Debug::fmt(self.deref(), f)
    }
}

impl<const SIZE: usize> crate::buffer::Buffer for DeLinearBuffer<SIZE, u8> {
    fn with_capacity(front: usize, _back: usize) -> Self
    where
        Self: Sized,
    {
        Self::new(front)
    }

    fn clear_with_capacity(&mut self, front: usize, _back: usize) {
        *self = Self::new(front)
    }
}

impl<T, const SIZE: usize> Drop for DeLinearBuffer<SIZE, T> {
    fn drop(&mut self) {
        let start = self.start;
        let end = self.start + self.count;

        for is_init in self.buffer[start..end].iter_mut() {
            unsafe { is_init.assume_init_drop() }
        }
    }
}

impl<T, const SIZE: usize> Deref for DeLinearBuffer<SIZE, T> {
    type Target = [T];

    fn deref(&self) -> &Self::Target {
        let start = self.start;
        let end = self.start + self.count;

        unsafe { transmute::<&[MaybeUninit<T>], &[T]>(&self.buffer[start..end]) }
    }
}

impl<T, const SIZE: usize> DerefMut for DeLinearBuffer<SIZE, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        let start = self.start;
        let end = self.start + self.count;

        unsafe { transmute::<&mut [MaybeUninit<T>], &mut [T]>(&mut self.buffer[start..end]) }
    }
}

impl<const SIZE: usize, T> crate::buffer::TryExtend<T> for DeLinearBuffer<SIZE, T> {
    type Error = LinearBufferError;

    fn try_extend<I>(&mut self, iter: I) -> Result<(), Self::Error>
    where
        I: IntoIterator<Item = T>,
    {
        for (how_many, item) in iter.into_iter().enumerate() {
            if self.start + self.count < SIZE {
                self.buffer[self.start + self.count].write(item);
                self.count += 1;
            } else {
                self.try_drop_from_back(how_many)?;

                return Err(LinearBufferError::SizeTooSmall);
            }
        }

        Ok(())
    }
}

impl<const SIZE: usize, T> crate::buffer::TryRemove<T> for DeLinearBuffer<SIZE, T> {
    type Error = LinearBufferError;
    type RemoveIter<'a> = DeLinearBufferRemoveIter<'a, T> where Self: 'a,;

    fn try_remove(&mut self, how_many: usize) -> Result<Self::RemoveIter<'_>, Self::Error> {
        let removed = self.try_remove_from_back(how_many)?;

        Ok(DeLinearBufferRemoveIter(removed.iter_mut()))
    }
}

impl<const SIZE: usize, T> crate::buffer::TryFrontExtend<T> for DeLinearBuffer<SIZE, T> {
    type Error = LinearBufferError;

    fn try_front_extend<I>(&mut self, iter: I) -> Result<(), Self::Error>
    where
        I: IntoIterator<Item = T>,
    {
        for (how_many, item) in iter.into_iter().enumerate() {
            if self.start != 0 {
                self.start -= 1;
                self.count += 1;
                self.buffer[self.start].write(item);
            } else {
                self.try_drop_from_front(how_many)?;

                return Err(LinearBufferError::SizeTooSmall);
            }
        }

        Ok(())
    }
}

impl<const SIZE: usize, T> crate::buffer::TryFrontRemove<T> for DeLinearBuffer<SIZE, T> {
    type Error = LinearBufferError;
    type FrontRemoveIter<'a> = DeLinearBufferRemoveIter<'a, T> where Self: 'a,;

    fn try_front_remove(&mut self, how_many: usize) -> Result<Self::FrontRemoveIter<'_>, Self::Error> {
        let removed = self.try_remove_from_front(how_many)?;

        Ok(DeLinearBufferRemoveIter(removed.iter_mut()))
    }
}

/// An iterator over items removed from a `DeLinearBuffer`
pub struct DeLinearBufferRemoveIter<'a, T>(core::slice::IterMut<'a, MaybeUninit<T>>);

impl<T> Iterator for DeLinearBufferRemoveIter<'_, T> {
    type Item = T;

    fn next(&mut self) -> Option<Self::Item> {
        self.0
            .next()
            .map(|maybe| unsafe { replace(maybe, MaybeUninit::uninit()).assume_init() })
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

        Self { buffer, start, count }
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
            let ret = unsafe { replace(&mut self.buffer[self.start], MaybeUninit::uninit()).assume_init() };

            self.start = (self.start + 1) % SIZE;

            self.count -= 1;

            Ok(ret)
        } else {
            Err(QueueBufferError::BufferEmpty)
        }
    }

    pub fn empty(&mut self) {
        while self.count != 0 {
            unsafe { self.buffer[self.start].assume_init_drop() };

            self.start = (self.start + 1) % SIZE;

            self.count -= 1;
        }
    }
}

impl<T, const SIZE: usize> Drop for QueueBuffer<T, SIZE> {
    fn drop(&mut self) {
        self.empty()
    }
}

#[derive(Debug)]
pub enum QueueBufferError {
    BufferFull,
    BufferEmpty,
}

impl Display for QueueBufferError {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            QueueBufferError::BufferFull => f.write_str("buffer is full"),
            QueueBufferError::BufferEmpty => f.write_str("buffer is empty"),
        }
    }
}

/// Hotel style stack allocated memory
///
/// This is a simplistic hotel type memory allocation. A Hotel is a memory allocation scheme where
/// memory is 'reserved' for use. A holder of a reservation may use the memory how they wish, but
/// nothing else is allowed to access the memory. The memory allocation lasts as long as the
/// reservation to the allocation. Once the reservation is gone then the memory is deallocated.
///
/// The problem with stack allocated memory is that it either relies on the programmer or the
/// compiler (like rust) to ensure the lifetime of a reference does not outlive its source. A
/// `StackHotel` allocates memory on the stack and uses rust's lifetimes to ensure that a
/// `StackHotel` is never moved while any reservations exist. When [`take`](StackHotel::take)ing a
/// reserve from a `StackHotel` the created [`Reservation`] contains a lifetime back to the
/// `StackHotel`. Rust will ensure that a `StackHotel` cannot be moved so long as any `Reservation`
/// exists (a `StackHotel` is safe to move if no `Reservation` exists.
///
/// # Note
/// This is purpose built for module `local_stack`, so reservations are taken from a
/// `StackHotel` wrapped within a `Ref`.
///
/// # implementation
/// This is a growable doubly link list split between those that are taken and those that are free
/// to use. When a `StackHotel` is created the link list is empty. Once a buffer is
/// taken from the reserve the link list grows to one, and the buffer is referred to as 'reserved'.
/// The buffer is reserved until it is dropped where by it then becomes free to use. The link list
/// is split between a reserved part and a free part. The reserved part is at the front of the list
/// and the free part is at the back. Field `last` points to the last element in the list of the
/// reserved section. The link list grows when the list only contains reserved buffers. To grow, a
/// `StackHotel` uses a link from the `buffers` array and connects it to the end of the link list.
///
/// Field `buffers` contains the physical location of the links of the link list. A link list can
/// grow so long as there are unused links within `buffers`. The field `untouched` is the number of
/// links within `buffers` that can be used to grow the link list. Once every link in `buffers` is
/// used, trying to take a buffer from the reserve will cause it to return `None`.
pub struct StackHotel<T, const SIZE: usize> {
    inner: core::cell::UnsafeCell<StackLinkedListInner<T, SIZE>>,
}

impl<T, const SIZE: usize> StackHotel<T, SIZE> {
    /// Create a new `StackHotel`
    pub fn new() -> Self {
        let inner = core::cell::UnsafeCell::new(StackLinkedListInner::new());

        Self { inner }
    }

    fn get_inner(&self) -> &StackLinkedListInner<T, SIZE> {
        unsafe { &*self.inner.get() }
    }

    fn get_inner_mut(&mut self) -> &mut StackLinkedListInner<T, SIZE> {
        self.inner.get_mut()
    }

    unsafe fn get_inner_unsafe_mut(&self) -> &mut StackLinkedListInner<T, SIZE> {
        self.inner.get().as_mut().unwrap()
    }

    /// Get the index of the last buffer added to the link list
    ///
    /// # Panic (debug)
    /// This will panic if no buffer in field `buffers` is used.
    fn get_index_of_last(&self) -> usize {
        debug_assert_ne!(self.get_inner().untouched, SIZE);

        // untouched happens to always be the index of
        // the last element taken from field `buffers`
        self.get_inner().untouched
    }

    /// Set a waker to be called when the next buffer is freed
    pub fn set_waker(&self, waker: &core::task::Waker) {
        unsafe { self.get_inner_unsafe_mut().waker = Some(waker.clone()) }
    }
}

impl<T, const SIZE: usize> StackHotel<T, SIZE> {
    /// Get the next free buffer from `buffers`
    ///
    /// This is used to get the next buffer from `buffers`. If there is no more free buffers within
    /// `buffers` then `None` is returned, otherwise the number of untouched links is reduced by one
    /// and a mutable reference to the next `MaybeReserveLink` from `buffers` is returned.
    unsafe fn next(&self, init: T) -> Option<&mut MaybeReserveLink<T>> {
        self.get_inner().untouched.checked_sub(1).map(|next| {
            self.get_inner_unsafe_mut().untouched = next;

            self.get_inner_unsafe_mut().buffers[next].buffer.write(init);

            &mut self.get_inner_unsafe_mut().buffers[next]
        })
    }

    /// Init the list
    ///
    /// This method is called the first time a buffer is taken from the reserve. It may only be only
    /// called once per reserve.
    ///
    /// # Unsafe
    /// This may only be called once to initialize the the list.
    unsafe fn init_list(&self, init: T) -> UnsafeReservation<T, SIZE> {
        let first_buffer: *mut _ = self.next(init).expect("size of buffer reserve is zero");

        self.get_inner_unsafe_mut().start = first_buffer;
        self.get_inner_unsafe_mut().last = first_buffer;
        self.get_inner_unsafe_mut().end = first_buffer;

        let index = self.get_index_of_last();
        let reserve = ptr::NonNull::from(&*self);

        UnsafeReservation::new(index, reserve)
    }

    fn take_inner(&self, init: T) -> Option<UnsafeReservation<T, SIZE>> {
        unsafe {
            if self.get_inner().end.is_null() {
                Some(Self::init_list(self, init))
            } else {
                let link = if self.get_inner().end == self.get_inner().last {
                    let last = self.get_inner().last;

                    let link = self.next(init).map(|link| {
                        link.prev = last;

                        link as *mut _
                    })?;

                    last.as_mut().unwrap().next = link;

                    self.get_inner_unsafe_mut().last = link;
                    self.get_inner_unsafe_mut().end = link;

                    link
                } else {
                    // last is null when there is no reserved buffers
                    let next = match self.get_inner().last.as_ref() {
                        Some(last) => last.next,
                        None => self.get_inner().start,
                    };

                    self.get_inner_unsafe_mut().last = next;

                    next
                };

                let index = link.offset_from(self.get_inner().buffers.as_ptr()) as usize;

                let reserve = ptr::NonNull::from(self);

                Some(UnsafeReservation::new(index, reserve))
            }
        }
    }

    /// Take a reservation from a `StackHotel`
    ///
    /// A `Reservation` is returned to a new data location within the hotel if there is still
    /// unreserved locations.
    pub fn take(&self, init: T) -> Option<Reservation<'_, T, SIZE>> {
        self.take_inner(init).map(|ur| Reservation::new(ur, self))
    }

    /// Take an unsafe reservation from a `StackHotel` containing buffers
    ///
    /// This returns a reservation unless there is no more allocations available
    pub fn take_buffer(&self, front_capacity: usize) -> Option<BufferReservation<T, SIZE>>
    where
        T: crate::buffer::Buffer,
    {
        use crate::buffer::BufferExt;

        self.take_inner(T::with_front_capacity(front_capacity))
            .map(|ur| unsafe { BufferReservation::new(ur, self, front_capacity) })
    }
}

struct StackLinkedListInner<T, const SIZE: usize> {
    buffers: [MaybeReserveLink<T>; SIZE],
    start: *mut MaybeReserveLink<T>,
    last: *mut MaybeReserveLink<T>,
    end: *mut MaybeReserveLink<T>,
    untouched: usize,
    waker: Option<core::task::Waker>,
    _pp: core::marker::PhantomPinned,
}

impl<T, const SIZE: usize> StackLinkedListInner<T, SIZE> {
    fn new() -> Self {
        let buffers = [(); SIZE].map(|_| MaybeReserveLink::uninit());
        let start = ptr::null_mut();
        let last = ptr::null_mut();
        let end = ptr::null_mut();
        let untouched = SIZE;
        let waker = None;
        let _pp = core::marker::PhantomPinned;

        Self {
            buffers,
            start,
            last,
            end,
            untouched,
            waker,
            _pp,
        }
    }
}

/// A wrapper type to construct link list elements containing an uninitialized buffer
struct MaybeReserveLink<T> {
    buffer: MaybeUninit<T>,
    ref_count: core::cell::Cell<usize>,
    prev: *mut Self,
    next: *mut Self,
}

impl<T> MaybeReserveLink<T> {
    /// Uninitialized the link
    ///
    /// This creates a link that contains an uninitialized `T` and both `prev` and `next` are null.
    fn uninit() -> Self {
        Self {
            buffer: MaybeUninit::uninit(),
            ref_count: Default::default(),
            prev: ptr::null_mut(),
            next: ptr::null_mut(),
        }
    }
}

/// An unsafe reservation
///
/// This contains the information that points back to the hotel without any lifetime. As a result
/// the compiler cannot guarantee the the lifetime of an UnsafeReservation does not outlive the
/// `StackHotel` that created it.
///
/// # Reference Count
/// A `UnsafeReservation` is a counted reference, and cloning increases the reference count. The
/// clone must still follow the same lifetime requirements as the originating `UnsafeReservation`.
pub struct UnsafeReservation<T, const SIZE: usize> {
    index: usize,
    reserve: ptr::NonNull<StackHotel<T, SIZE>>,
}

impl<T, const SIZE: usize> UnsafeReservation<T, SIZE> {
    fn new(index: usize, reserve: ptr::NonNull<StackHotel<T, SIZE>>) -> Self {
        let mut this = Self { index, reserve };

        this.get_mut_link().ref_count.set(1);

        this
    }

    /// Rebind the `UnsafeReservation` to its [`StackHotel`]
    ///
    /// The caller must make sure that the lifetime is linked to the correct instance of the
    /// `StackHotel` that created this reservation.
    pub unsafe fn rebind<'a>(this: Self) -> Reservation<'a, T, SIZE> {
        let ur = this;
        let _pd = core::marker::PhantomData;

        Reservation { ur, _pd }
    }

    #[inline]
    fn get_reserve(&self) -> &StackHotel<T, SIZE> {
        unsafe { self.reserve.as_ref() }
    }

    #[inline]
    fn get_reserve_mut(&mut self) -> &mut StackHotel<T, SIZE> {
        unsafe { self.reserve.as_mut() }
    }

    #[inline]
    fn get_link(&self) -> &MaybeReserveLink<T> {
        &self.get_reserve().get_inner().buffers[self.index]
    }

    #[inline]
    fn get_mut_link(&mut self) -> &mut MaybeReserveLink<T> {
        let index = self.index;

        self.get_reserve_mut().get_inner_mut().buffers.get_mut(index).unwrap()
    }

    /// Move the current link to after the link pointed to by `last`
    ///
    /// This will move the link to the place after the link pointed to by member
    /// `StackHotel::last`.
    ///
    /// # Panic
    /// The last pointer must not be null
    unsafe fn move_to_after_last(&mut self) {
        let last = self.get_reserve_mut().get_inner_mut().last.as_mut().unwrap();

        self.get_mut_link().prev = last;

        self.get_mut_link().next = last.next;

        let this_link_ptr: *mut _ = self.get_mut_link();

        match last.next.as_mut() {
            Some(ptr) => ptr.prev = this_link_ptr,
            None => self.get_reserve_mut().get_inner_mut().end = this_link_ptr,
        };

        last.next = self.get_mut_link();
    }

    /// Drop operation for a link in the middle of the link list
    ///
    /// This does not drop the link from the list. Instead it moves the link from its current
    /// position in the 'reserved' portion of the list to the 'free' portion.
    unsafe fn drop_middle_of_link_list(&mut self) {
        if self.get_reserve().get_inner().last != self.get_mut_link() as *mut _ {
            // remove the link from its current position in the list

            self.get_mut_link().prev.as_mut().unwrap().next = self.get_mut_link().next;

            self.get_mut_link().next.as_mut().unwrap().prev = self.get_mut_link().prev;

            // put this link out of the reserved portion of the link list
            self.move_to_after_last()
        } else {
            // just put the last pointer to the previous link
            self.get_reserve_mut().get_inner_mut().last = self.get_mut_link().prev;
        }
    }

    /// Drop operation for a link at the beginning of the link list\
    ///
    /// This does not drop the link from the list. Instead it moves the link from its current
    /// position in the 'reserved' portion of the list to the 'free' portion.
    unsafe fn drop_front_of_link_list(&mut self) {
        if self.get_reserve().get_inner().last != self.get_mut_link() as *mut _ {
            // put the start pointer to the next item
            self.get_reserve_mut().get_inner_mut().start = self.get_link().next;

            self.get_mut_link().next.as_mut().unwrap().prev = ptr::null_mut();

            // put this link out of the reserved portion of the link list
            self.move_to_after_last()
        } else {
            // no more elements in the reserved part of the link list

            self.get_reserve_mut().get_inner_mut().last = ptr::null_mut();
        }
    }

    /// Drop operation for a link at the end of the link list
    ///
    /// When calling this method, `self.reserve.end` must point to the same location as this link.
    ///
    /// This does not drop the link from the list. Instead it moves the link from its current
    /// position in the 'reserved' portion of the list to the 'free' portion.
    unsafe fn drop_end_of_link_list(&mut self) {
        // just put the last pointer to the previous link
        self.get_reserve_mut().get_inner_mut().last = self.get_mut_link().prev;
    }

    /// Get a reference to the buffer
    fn get(&self) -> &T {
        unsafe { self.get_link().buffer.assume_init_ref() }
    }

    /// Get a mutable reference to the buffer
    fn get_mut(&mut self) -> &mut T {
        unsafe { self.get_mut_link().buffer.assume_init_mut() }
    }
}

impl<T, const SIZE: usize> Clone for UnsafeReservation<T, SIZE> {
    fn clone(&self) -> Self {
        let link = self.get_link();

        link.ref_count.set(link.ref_count.get() + 1);

        let index = self.index;
        let reserve = self.reserve;

        Self { index, reserve }
    }
}

impl<T, const SIZE: usize> Drop for UnsafeReservation<T, SIZE> {
    fn drop(&mut self) {
        unsafe {
            let link = self.get_mut_link();

            link.ref_count.set(link.ref_count.get() - 1);

            if link.ref_count.get() == 0 {
                link.buffer.assume_init_drop();

                match (link.prev.is_null(), link.next.is_null()) {
                    (false, false) => self.drop_middle_of_link_list(),
                    (true, false) => self.drop_front_of_link_list(),
                    (false, true) => self.drop_end_of_link_list(),
                    (true, true) => {
                        // This occurs when the link list only has one
                        // link in it (reserved by this `ReservedBuffer`)
                        self.get_reserve_mut().get_inner_mut().last = ptr::null_mut();
                    }
                }
            }
        }

        if let Some(waker) = self.get_reserve_mut().get_inner_mut().waker.take() {
            waker.wake()
        }
    }
}

/// A reservation from a `StackHotel`
pub struct Reservation<'a, T, const SIZE: usize> {
    ur: UnsafeReservation<T, SIZE>,
    _pd: core::marker::PhantomData<&'a StackHotel<T, SIZE>>,
}

impl<'a, T, const SIZE: usize> Reservation<'a, T, SIZE> {
    fn new(ur: UnsafeReservation<T, SIZE>, _: &'a StackHotel<T, SIZE>) -> Self {
        let _pd = core::marker::PhantomData;

        Self { ur, _pd }
    }

    /// Convert a `Reservation` into an `UnsafeReservation`
    pub unsafe fn to_unsafe(this: Self) -> UnsafeReservation<T, SIZE> {
        this.ur
    }
}

impl<T, const SIZE: usize> Debug for Reservation<'_, T, SIZE>
where
    T: Debug,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        Debug::fmt(self.deref(), f)
    }
}

impl<T, const SIZE: usize> Clone for Reservation<'_, T, SIZE> {
    fn clone(&self) -> Self {
        let ur = self.ur.clone();
        let _pd = core::marker::PhantomData;

        Self { ur, _pd }
    }
}

impl<T, const SIZE: usize> Deref for Reservation<'_, T, SIZE> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        self.ur.get()
    }
}

impl<T, const SIZE: usize> DerefMut for Reservation<'_, T, SIZE> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.ur.get_mut()
    }
}

/// A reserved buffer
///
/// This is returned by the method [`take_buffer`](StackHotel::take_buffer) of `StackHotel`
///
/// # Note
/// A `BufferReservation` can be converted into an `UnsafeBufferReservation` through methods
/// `from/into`. Although these methods are not unsafe, it does not mead that they make the
/// resulting `UnsafeBufferReservation` safe to use.
pub struct BufferReservation<'a, T, const SIZE: usize> {
    ubr: UnsafeBufferReservation<T, SIZE>,
    _pd: core::marker::PhantomData<&'a StackHotel<T, SIZE>>,
}

impl<'a, T, const SIZE: usize> BufferReservation<'a, T, SIZE> {
    /// Create a new `BufferReservation`
    ///
    /// This creates a new `BufferReservation` from the provided `link` and `reserve`.
    ///
    /// `link` must be a reference to an element of `reserve.buffers`. Undefined behaviour will
    /// occur if this is not the case and this method is called.
    ///
    /// # Safety
    /// This method assumes that input `link` points to a location that is unique to this
    /// `BufferReservation`. It is undefined behaviour if multiple `BufferReservation`s exist at the
    /// same time containing the same `link`.
    #[allow(unused_variables)]
    unsafe fn new(ur: UnsafeReservation<T, SIZE>, hotel: &'a StackHotel<T, SIZE>, front_capacity: usize) -> Self
    where
        T: crate::buffer::Buffer,
    {
        use crate::buffer::BufferExt;

        let ubr = UnsafeBufferReservation(ur);

        let _pd = core::marker::PhantomData;

        let mut ret = Self { ubr, _pd };

        ret.clear_with_front_capacity(front_capacity);

        ret
    }

    /// Convert a `BufferReservation` into an `UnsafeBufferReservation`
    pub unsafe fn to_unsafe(this: Self) -> UnsafeBufferReservation<T, SIZE> {
        this.ubr
    }
}

impl<T, const SIZE: usize> Debug for BufferReservation<'_, T, SIZE>
where
    T: Debug + Deref<Target = [u8]>,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        Debug::fmt(self.deref(), f)
    }
}

impl<T, const SIZE: usize> Clone for BufferReservation<'_, T, SIZE> {
    fn clone(&self) -> Self {
        let ubr = self.ubr.clone();

        let _pd = core::marker::PhantomData;

        BufferReservation { ubr, _pd }
    }
}

impl<T, const SIZE: usize> crate::buffer::Buffer for BufferReservation<'_, T, SIZE>
where
    T: crate::buffer::Buffer,
{
    fn with_capacity(_front: usize, _back: usize) -> Self
    where
        Self: Sized,
    {
        panic!("with_capacity cannot be called on a reserved buffer");
    }

    fn clear_with_capacity(&mut self, front: usize, back: usize) {
        self.ubr.clear_with_capacity(front, back)
    }
}

impl<T, const SIZE: usize> Deref for BufferReservation<'_, T, SIZE>
where
    T: Deref<Target = [u8]>,
{
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.ubr.deref()
    }
}

impl<T, const SIZE: usize> DerefMut for BufferReservation<'_, T, SIZE>
where
    T: DerefMut<Target = [u8]>,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.ubr.deref_mut()
    }
}

impl<T, A, const SIZE: usize> crate::buffer::TryExtend<A> for BufferReservation<'_, T, SIZE>
where
    T: crate::buffer::TryExtend<A>,
{
    type Error = T::Error;

    fn try_extend<I>(&mut self, iter: I) -> Result<(), Self::Error>
    where
        I: IntoIterator<Item = A>,
    {
        self.ubr.try_extend(iter)
    }
}

impl<T, A, const SIZE: usize> crate::buffer::TryRemove<A> for BufferReservation<'_, T, SIZE>
where
    T: crate::buffer::TryRemove<A>,
{
    type Error = T::Error;
    type RemoveIter<'a> = T::RemoveIter<'a> where Self: 'a;

    fn try_remove(&mut self, how_many: usize) -> Result<Self::RemoveIter<'_>, Self::Error> {
        self.ubr.try_remove(how_many)
    }
}

impl<T, A, const SIZE: usize> crate::buffer::TryFrontExtend<A> for BufferReservation<'_, T, SIZE>
where
    T: crate::buffer::TryFrontExtend<A>,
{
    type Error = T::Error;

    fn try_front_extend<I>(&mut self, iter: I) -> Result<(), Self::Error>
    where
        I: IntoIterator<Item = A>,
    {
        self.ubr.try_front_extend(iter)
    }
}

impl<T, A, const SIZE: usize> crate::buffer::TryFrontRemove<A> for BufferReservation<'_, T, SIZE>
where
    T: crate::buffer::TryFrontRemove<A>,
{
    type Error = T::Error;
    type FrontRemoveIter<'a> = T::FrontRemoveIter<'a> where Self: 'a;

    fn try_front_remove(&mut self, how_many: usize) -> Result<Self::FrontRemoveIter<'_>, Self::Error> {
        self.ubr.try_front_remove(how_many)
    }
}

/// An unsafe buffer reservation
///
/// This is a wrapper around an [`UnsafeReservation`] so that it can implement buffer related
/// traits.
#[repr(transparent)]
pub struct UnsafeBufferReservation<T, const SIZE: usize>(UnsafeReservation<T, SIZE>);

impl<T, const SIZE: usize> UnsafeBufferReservation<T, SIZE> {
    /// Rebind the `UnsafeBufferReservation` to its [`StackHotel`]
    ///
    /// The caller must make sure that the lifetime is linked to the correct instance of the
    /// `StackHotel` that created this reservation.
    pub unsafe fn rebind<'a>(this: Self) -> BufferReservation<'a, T, SIZE> {
        let ubr = this;
        let _pd = core::marker::PhantomData;

        BufferReservation { ubr, _pd }
    }
}

impl<T, const SIZE: usize> Clone for UnsafeBufferReservation<T, SIZE> {
    fn clone(&self) -> Self {
        UnsafeBufferReservation(self.0.clone())
    }
}

impl<T, const SIZE: usize> crate::buffer::Buffer for UnsafeBufferReservation<T, SIZE>
where
    T: crate::buffer::Buffer,
{
    fn with_capacity(_front: usize, _back: usize) -> Self
    where
        Self: Sized,
    {
        panic!("with_capacity cannot be called on a reserved buffer");
    }

    fn clear_with_capacity(&mut self, front: usize, back: usize) {
        unsafe {
            self.0
                .get_mut_link()
                .buffer
                .assume_init_mut()
                .clear_with_capacity(front, back)
        }
    }
}

impl<T, const SIZE: usize> Deref for UnsafeBufferReservation<T, SIZE>
where
    T: Deref<Target = [u8]>,
{
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.0.get().deref()
    }
}

impl<T, const SIZE: usize> DerefMut for UnsafeBufferReservation<T, SIZE>
where
    T: DerefMut<Target = [u8]>,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.0.get_mut().deref_mut()
    }
}

impl<T, A, const SIZE: usize> crate::buffer::TryExtend<A> for UnsafeBufferReservation<T, SIZE>
where
    T: crate::buffer::TryExtend<A>,
{
    type Error = T::Error;

    fn try_extend<I>(&mut self, iter: I) -> Result<(), Self::Error>
    where
        I: IntoIterator<Item = A>,
    {
        self.0.get_mut().try_extend(iter)
    }
}

impl<T, A, const SIZE: usize> crate::buffer::TryRemove<A> for UnsafeBufferReservation<T, SIZE>
where
    T: crate::buffer::TryRemove<A>,
{
    type Error = T::Error;
    type RemoveIter<'a> = T::RemoveIter<'a> where Self: 'a;

    fn try_remove(&mut self, how_many: usize) -> Result<Self::RemoveIter<'_>, Self::Error> {
        self.0.get_mut().try_remove(how_many)
    }
}

impl<T, A, const SIZE: usize> crate::buffer::TryFrontExtend<A> for UnsafeBufferReservation<T, SIZE>
where
    T: crate::buffer::TryFrontExtend<A>,
{
    type Error = T::Error;

    fn try_front_extend<I>(&mut self, iter: I) -> Result<(), Self::Error>
    where
        I: IntoIterator<Item = A>,
    {
        self.0.get_mut().try_front_extend(iter)
    }
}

impl<T, A, const SIZE: usize> crate::buffer::TryFrontRemove<A> for UnsafeBufferReservation<T, SIZE>
where
    T: crate::buffer::TryFrontRemove<A>,
{
    type Error = T::Error;
    type FrontRemoveIter<'a> = T::FrontRemoveIter<'a> where Self: 'a;

    fn try_front_remove(&mut self, how_many: usize) -> Result<Self::FrontRemoveIter<'_>, Self::Error> {
        self.0.get_mut().try_front_remove(how_many)
    }
}

/// Tests
///
/// # Note
/// Drops may be deliberately done with the method [`drop`](std::mem::drop) as it is easier to debug
/// an implementation of the trait `Drop` by doing this.
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
            v => panic!("Expected LinearBufferError::IndexOutOfRange, received {:?}", v),
        }

        l.try_insert(0, 0).unwrap();

        match l.try_remove(2) {
            Err(LinearBufferError::IndexOutOfRange) => (),
            v => panic!("Expected LinearBufferError::IndexOutOfRange, received {:?}", v),
        }
    }

    #[test]
    fn de_linear_buffer_init() {
        let _b = DeLinearBuffer::<10, u8>::new(5);
    }

    #[test]
    #[should_panic]
    fn de_linear_buffer_invalid_new() {
        let _b = DeLinearBuffer::<2, u8>::new(10);
    }

    #[test]
    fn de_linear_buffer_extend() {
        const BUFFER_SIZE: usize = 10;

        let mut buffer = DeLinearBuffer::<BUFFER_SIZE, u8>::new(5);

        let to_extend: &[u8] = &[5, 4, 3, 2, 1];

        buffer
            .try_extend(to_extend.iter().copied())
            .expect("failed to extend buffer");

        assert_eq!(to_extend, &*buffer)
    }

    #[test]
    fn de_linear_buffer_extend_front() {
        const BUFFER_SIZE: usize = 10;

        let mut buffer = DeLinearBuffer::<BUFFER_SIZE, u8>::new(5);

        let to_extend: &[u8] = &[5, 4, 3, 2, 1];

        buffer
            .try_rev_front_extend(to_extend.iter().copied())
            .expect("failed to extend buffer");

        assert_eq!(to_extend, &*buffer)
    }

    #[test]
    fn de_linear_buffer_extend_front_and_back() {
        const BUFFER_SIZE: usize = 10;

        let mut buffer = DeLinearBuffer::<BUFFER_SIZE, u8>::new(5);

        let to_extend: &[u8] = &[10, 9, 8, 7, 6, 5, 4, 3, 2, 1];

        let (to_extend_front, to_extend_back) = to_extend.split_at(5);

        buffer
            .try_extend(to_extend_back.iter().copied())
            .expect("failed to extend back of buffer");

        buffer
            .try_rev_front_extend(to_extend_front.iter().copied())
            .expect("failed to extend front of buffer");

        assert_eq!(to_extend, &*buffer)
    }

    #[test]
    fn de_linear_buffer_remove() {
        const BUFFER_SIZE: usize = 10;

        let mut buffer = DeLinearBuffer::<BUFFER_SIZE, u8>::new(5);

        let to_extend: &[u8] = &[5, 4, 3, 2, 1];

        buffer
            .try_extend(to_extend.iter().copied())
            .expect("failed to extend buffer");

        for (index, val) in buffer
            .try_remove(to_extend.len())
            .expect("failed to remove from buffer")
            .enumerate()
        {
            assert_eq!(to_extend[index], val)
        }
    }

    #[test]
    fn de_linear_buffer_remove_from_front() {
        const BUFFER_SIZE: usize = 10;

        let mut buffer = DeLinearBuffer::<BUFFER_SIZE, u8>::new(5);

        let to_extend: &[u8] = &[5, 4, 3, 2, 1];

        buffer
            .try_rev_front_extend(to_extend.iter().copied())
            .expect("failed to extend buffer");

        for (index, val) in buffer
            .try_front_remove(to_extend.len())
            .expect("failed to remove from front of buffer")
            .enumerate()
        {
            assert_eq!(to_extend[index], val)
        }
    }

    #[test]
    fn de_linear_buffer_remove_front_and_back() {
        const BUFFER_SIZE: usize = 10;

        let mut buffer = DeLinearBuffer::<BUFFER_SIZE, u8>::new(5);

        let to_extend: &[u8] = &[10, 9, 8, 7, 6, 5, 4, 3, 2, 1];

        let (to_extend_front, to_extend_back) = to_extend.split_at(5);

        buffer
            .try_extend(to_extend_back.iter().copied())
            .expect("failed to extend back of buffer");

        buffer
            .try_rev_front_extend(to_extend_front.iter().copied())
            .expect("failed to extend front of buffer");

        for (index, val) in buffer
            .try_front_remove(to_extend_front.len())
            .expect("failed to remove from front")
            .enumerate()
        {
            assert_eq!(to_extend_front[index], val)
        }

        for (index, val) in buffer
            .try_remove(to_extend_back.len())
            .expect("failed to remove from back")
            .enumerate()
        {
            assert_eq!(to_extend_back[index], val)
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

    /// A very unsafe way to create a `StackHotel` on the heap
    ///
    /// For testing a `StackHotel` needs to be created on the heap as the test threads do not
    /// have enough stack to allocate the type. This unsafely creates `StackHotel` of `usize`
    /// typed buffers on the stack.
    ///
    /// # Safety
    /// This creates a `HeapAllocatedStackHotel` from a zeroed dynamic allocation and then
    /// transforms it into a `StackHotel`. This is about as unsafely stupid as you can get
    /// without it being UB. The only check made
    unsafe fn inboxed_buffer_reserve<const SIZE: usize>() -> Box<StackHotel<usize, SIZE>> {
        use std::ptr::write;

        let layout = std::alloc::Layout::new::<StackHotel<usize, SIZE>>();

        let allocation = std::alloc::alloc(layout) as *mut StackHotel<usize, SIZE>;

        // uninit_boxed_buffer should be though of
        let mut uninit_boxed_buffer: Box<StackHotel<usize, SIZE>> = Box::from_raw(allocation);

        // The extensive use of the method std::ptr::write is to avoid
        // dropping an uninitialized value even when dropping would
        // still be fine.

        for buffer in &mut uninit_boxed_buffer.get_inner_mut().buffers {
            write(buffer, MaybeReserveLink::uninit());
        }

        write(&mut uninit_boxed_buffer.get_inner_mut().start, ptr::null_mut());

        write(&mut uninit_boxed_buffer.get_inner_mut().last, ptr::null_mut());

        write(&mut uninit_boxed_buffer.get_inner_mut().end, ptr::null_mut());

        write(&mut uninit_boxed_buffer.get_inner_mut().untouched, SIZE);

        write(&mut uninit_boxed_buffer.get_inner_mut().waker, None);

        write(
            &mut uninit_boxed_buffer.get_inner_mut()._pp,
            core::marker::PhantomPinned,
        );

        // memory should be fully initialized
        uninit_boxed_buffer
    }

    #[test]
    fn reserved_buffer_init() {
        const BUFFER_AMOUNT: usize = 15;

        let reserve_buffer = unsafe { inboxed_buffer_reserve::<BUFFER_AMOUNT>() };

        let mut reserved_holder = Vec::with_capacity(BUFFER_AMOUNT);

        for _ in 0..BUFFER_AMOUNT {
            let taken = reserve_buffer.take_buffer().expect("failed to take buffer");

            reserved_holder.push(taken);
        }

        assert!(reserve_buffer.take_buffer().is_none());

        reserved_holder.drain(..).for_each(|reserve| drop(reserve));

        for _ in 0..BUFFER_AMOUNT {
            let taken = reserve_buffer.take_buffer().expect("failed to take buffer");

            reserved_holder.push(taken);
        }
    }

    /// Randomly drop a number of elements from `vec`
    ///
    /// This randomly drops `how_many` number of elements from `vec`. After this method is called
    /// `vec` will contain `how_many` fewer elements.
    ///
    /// # Panic
    /// `how_many` cannot be larger than the size of `vec`,
    fn rand_drop_from<T>(vec: &mut Vec<T>, how_many: usize) {
        assert!(how_many <= vec.len(), "vec is too small");

        let mut drop_indexes = Vec::with_capacity(how_many);

        while drop_indexes.len() != how_many {
            let random = rand::random::<usize>() % vec.len();

            drop_indexes.push(random);

            drop_indexes.sort();

            drop_indexes.dedup();
        }

        for index in drop_indexes.into_iter().rev() {
            vec.swap_remove(index);
        }
    }

    #[test]
    fn reserved_buffer_take_and_drop() {
        const BUFFER_AMOUNT: usize = 512;

        let reserve_buffer = unsafe { inboxed_buffer_reserve::<BUFFER_AMOUNT>() };

        let mut reserved_holder = Vec::with_capacity(BUFFER_AMOUNT);

        for _ in 0..1024 {
            match reserve_buffer.take_buffer() {
                Some(reserved) => reserved_holder.push(reserved),
                None => rand_drop_from(&mut reserved_holder, 45),
            }
        }

        while reserved_holder.len() != reserved_holder.capacity() {
            reserved_holder.push(reserve_buffer.take_buffer().unwrap())
        }

        reserved_holder.into_iter().for_each(|reserve| drop(reserve))
    }

    #[test]
    fn reserved_buffer_grow() {
        const BUFFER_AMOUNT: usize = 32;

        let reserve_buffer = unsafe { inboxed_buffer_reserve::<BUFFER_AMOUNT>() };

        let mut reserved_holder = Vec::with_capacity(BUFFER_AMOUNT);

        for end in 0..BUFFER_AMOUNT {
            for _ in 0..end {
                let reserved = reserve_buffer.take_buffer().expect("failed to take buffer");

                reserved_holder.push(reserved);
            }

            assert_eq!(BUFFER_AMOUNT - end, reserve_buffer.get_inner().untouched);

            reserved_holder.drain(..).for_each(|reserve| drop(reserve));
        }
    }
}
