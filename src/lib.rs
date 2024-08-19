//! Parser and builder for packets formatted per [RFC 3550](https://tools.ietf.org/html/rfc3550), _A Transport
//! Protocol for Real-Time Applications_.
//!
//! Parse a packet
//! ```
//! use rtp_rs::*;
//! // let data = ...acquire UDP packet from the network etc...
//! # let data = &[
//! # 0x80u8, 0xe0u8, 0x27u8, 0x38u8, 0x64u8, 0xe4u8,
//! # 0x05u8, 0xa7u8, 0xa2u8, 0x42u8, 0xafu8, 0x01u8
//! # ];
//! if let Ok(rtp) = RtpReader::new(data) {
//!     println!("Sequence number {:?}", rtp.sequence_number());
//!     println!("Payload length {:?}", rtp.payload().len());
//! }
//! ```
//!
//! Build a packet
//! ```
//! use rtp_rs::*;
//!
//! let mut buffer = [0u8; 1024];
//! let payload = [0u8, 2, 5, 4, 6];
//! let result = RtpPacketBuilder::new()
//!     .payload_type(111)
//!     .ssrc(1337)
//!     .sequence(Seq::from(1234))
//!     .timestamp(666657)
//!     .padded(Pad::round_to(4))
//!     .marked(true)
//!     .payload(&payload)
//!     .build_into(&mut buffer);
//!
//! if let Ok(len) = result {
//!     println!("Packet: {:?}", &buffer[..len]);
//! }
//! ```
#![cfg_attr(feature = "std", doc = r#"

Building a packet with std enabled lets you skip the buffer;
    
```
use rtp_rs::*;

let payload = vec![0u8, 2, 5, 4, 6];
let result = RtpPacketBuilder::new()
    .payload_type(111)
    .ssrc(1337)
    .sequence(Seq::from(1234))
    .timestamp(666657)
    .padded(Pad::round_to(4))
    .marked(true)
    .payload(&payload)
    .build();
if let Ok(packet) = result {
    println!("Packet: {:?}", packet);
}
```"#)]

#![forbid(unsafe_code)]
#![deny(rust_2018_idioms, future_incompatible, missing_docs)]

#![cfg_attr(not(feature = "std"), no_std)]

/// 16 bit RTP sequence number value, as obtained from the `sequence_number()` method of RtpReader.
///
/// ```
/// use rtp_rs::*;
/// let seq = Seq::from(123);
/// ```
///
/// This type's behavior attempts to honour the expected wrap-around of sequence number values
/// from `0xffff` back to `0x0000`.
///
/// You can perform logic over sequences of RTP packets using this type and other helpers from this
/// crate,
/// ```
/// # use rtp_rs::*;
/// let start = Seq::from(0xfffe);
/// let end = Seq::from(0x0002);
/// // produces the Seq values 0xfffe, 0xffff, 0x0000, 0x0001:
/// for seq in (start..end).seq_iter() {
///     // ...inspect some RTP packet you've stored against this sequence number...
/// }
/// ```
///
/// ## Unsoundness
/// **Note** this type has implementations of `Ord` and `PartialOrd`, but those implementations
/// violate the requirement for transitivity which both traits document.
///
/// ```should_panic
/// # use rtp_rs::*;
/// let a = Seq::from(0);
/// let b = a + 0x7fff;
/// let c = b + 0x7fff;
/// assert!(a < b);
/// assert!(b < c);
/// assert!(a < c);  // Assertion fails, in violation of Ord/PartialOrd requirements
/// ```
/// A future release will potentially deprecate `Ord` / `PartialOrd` implementations for `Seq`, and
/// hopefully provide a mechanism for sequence number processing which is sound.
#[derive(PartialEq, Eq, Debug, Clone, Copy)]
pub struct Seq(u16);
impl Seq {
    /// Produce the sequence value which follows this one.
    ///
    /// Sequence numbers wrap back to `0x0000` after reaching the value `0xffff`
    pub fn next(self) -> Seq {
        Seq(self.0.wrapping_add(1))
    }

    /// Returns `true` if this sequence number value is immediately before the given one
    pub fn precedes(self, other: Seq) -> bool {
        self.next() == other
    }
}
impl From<Seq> for u16 {
    fn from(v: Seq) -> Self {
        v.0
    }
}
impl From<u16> for Seq {
    fn from(v: u16) -> Self {
        Seq(v)
    }
}

/// Implements wrapped subtraction such that for instance `Seq(0x0000) - Seq(0xffff)` results in
/// `1` (rather than `-65535`).
///
/// This is for symmetry with addition, where for example `Seq(0xffff) + 1` gives `Seq(0x0000)`
impl core::ops::Sub for Seq {
    type Output = i32;

    fn sub(self, rhs: Seq) -> Self::Output {
        let delta = i32::from(self.0) - i32::from(rhs.0);
        if delta < core::i16::MIN as i32 {
            core::u16::MAX as i32 + 1 + delta
        } else if delta > core::i16::MAX as i32 {
            delta - core::u16::MAX as i32 - 1
        } else {
            delta
        }
    }
}
impl PartialOrd for Seq {
    fn partial_cmp(&self, other: &Seq) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for Seq {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        (*self - *other).cmp(&0)
    }
}

impl core::ops::Add<u16> for Seq {
    type Output = Seq;

    fn add(self, rhs: u16) -> Self::Output {
        Seq(self.0.wrapping_add(rhs))
    }
}

/// Trait for types that can produce a `SeqIter`, with an implementation provided for `Range<Seq>`.
pub trait IntoSeqIterator {
    /// Produce an `Iterator` over sequence number values
    fn seq_iter(self) -> SeqIter;
}
impl IntoSeqIterator for core::ops::Range<Seq> {
    fn seq_iter(self) -> SeqIter {
        SeqIter(self.start, self.end)
    }
}

/// An `Iterator` which can produce values from the given start value to the given end value, inclusive.
///
/// Rather than using this directly, it is convenient to use a range like so,
/// ```
/// use rtp_rs::*;
/// use rtp_rs::IntoSeqIterator;
/// let here = 12.into();
/// let there = 22.into();
/// for seq in (here..there).seq_iter() {
///     println!("{:?}", seq);
/// }
/// ```
pub struct SeqIter(Seq, Seq);
impl Iterator for SeqIter {
    type Item = Seq;

    fn next(&mut self) -> Option<Self::Item> {
        if self.0 >= self.1 {
            None
        } else {
            let res = self.0;
            self.0 = self.0.next();
            Some(res)
        }
    }
}

mod reader;
pub use reader::*;

mod builder;
pub use builder::*;
