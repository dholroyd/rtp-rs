//! Parser for packets formatted per [RFC 3550](https://tools.ietf.org/html/rfc3550), _A Transport
//! Protocol for Real-Time Applications_.
//!
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

#![forbid(unsafe_code)]
#![deny(rust_2018_idioms, future_incompatible, missing_docs)]

use std::fmt;

/// Wrapper around a byte-slice of RTP data, providing accessor methods for the RTP header fields.
pub struct RtpReader<'a> {
    buf: &'a [u8],
}

/// Reasons for `RtpHeader::new()` to fail
#[derive(Debug)]
pub enum RtpHeaderError {
    /// Buffer too short to be valid RTP packet
    BufferTooShort(usize),
    /// Only RTP version 2 supported
    UnsupportedVersion(u8),
    /// RTP headers truncated before end of buffer
    HeadersTruncated {
        /// The amount of data which was expected to be present (which may vary depending on flags
        /// in the RTP header)
        header_len: usize,
        /// The actual amount of data that was available, which was found to be smaller than
        /// `header_len`
        buffer_len: usize,
    },
}

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
#[derive(PartialEq, Debug, Clone, Copy)]
pub struct Seq(u16);
impl Seq {
    /// Produce the sequence value which follows this one.
    ///
    /// Sequence numbers wrap back to `0x0000` after reaching the value `0xffff`
    pub fn next(&self) -> Seq {
        Seq(self.0.wrapping_add(1))
    }

    /// Returns `true` if this sequence number value is immediately before the given one
    pub fn precedes(&self, other: Seq) -> bool {
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
impl std::ops::Sub for Seq {
    type Output = i32;

    fn sub(self, rhs: Seq) -> Self::Output {
        let delta = i32::from(self.0) - i32::from(rhs.0);
        if delta < std::i16::MIN as i32 {
            std::u16::MAX as i32 + 1 + delta
        } else if delta > std::i16::MAX as i32 {
            delta - std::u16::MAX as i32 - 1
        } else {
            delta
        }
    }
}
impl PartialOrd for Seq {
    fn partial_cmp(&self, other: &Seq) -> Option<std::cmp::Ordering> {
        (*self - *other).partial_cmp(&0)
    }
}

impl std::ops::Add<u16> for Seq {
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
impl IntoSeqIterator for std::ops::Range<Seq> {
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

impl<'a> RtpReader<'a> {
    /// An RTP packet header is no fewer than 12 bytes long
    pub const MIN_HEADER_LEN: usize = 12;
    const EXTENSION_HEADER_LEN: usize = 4;

    /// Tries to construct a new `RtpHeader` instance, or an `RtpHeaderError` if the RTP data is
    /// malformed.
    ///
    /// In particular, if there is too little data in the given buffer, such that some later
    /// attempt to access an RTP header field would need to access bytes that are not available,
    /// then this method will fail up front, rather than allowing attempts to access any header
    /// field to fail later on.
    pub fn new(b: &'a [u8]) -> Result<RtpReader<'_>, RtpHeaderError> {
        if b.len() <= Self::MIN_HEADER_LEN {
            return Err(RtpHeaderError::BufferTooShort(b.len()));
        }
        let r = RtpReader { buf: b };
        if r.version() != 2 {
            return Err(RtpHeaderError::UnsupportedVersion(r.version()));
        }
        if r.extension_flag() {
            let extension_start = r.csrc_end() + Self::EXTENSION_HEADER_LEN;
            if extension_start > b.len() {
                return Err(RtpHeaderError::HeadersTruncated {
                    header_len: extension_start,
                    buffer_len: b.len(),
                });
            }
            let extension_end = extension_start + r.extension_len();
            if extension_end > b.len() {
                return Err(RtpHeaderError::HeadersTruncated {
                    header_len: extension_end,
                    buffer_len: b.len(),
                });
            }
        }
        if r.payload_offset() > b.len() {
            return Err(RtpHeaderError::HeadersTruncated {
                header_len: r.payload_offset(),
                buffer_len: b.len(),
            });
        }
        Ok(r)
    }

    /// Version field value (currently only version 2 is supported, so other values will not be
    /// seen from this release of `rtp-rs`.
    pub fn version(&self) -> u8 {
        (self.buf[0] & 0b1100_0000) >> 6
    }
    /// Flag indicating if padding is present at the end of the payload data.
    ///
    /// The `payload()` method should return the packet payload minus any padding, but that's not
    /// yet implemented.
    pub fn padding(&self) -> bool {
        (self.buf[0] & 0b0010_0000) != 0
    }
    fn extension_flag(&self) -> bool {
        (self.buf[0] & 0b0001_0000) != 0
    }
    /// A count of the number of CSRC fields present in the RTP headers - may be `0`.
    ///
    /// See [csrc()](#method.csrc).
    pub fn csrc_count(&self) -> u8 {
        self.buf[0] & 0b0000_1111
    }
    /// A 'marker', which may have some definition in the specific RTP profile in use
    pub fn mark(&self) -> bool {
        (self.buf[1] & 0b1000_0000) != 0
    }
    /// Indicates the type of content carried in this RTP packet.
    ///
    /// A few types-values are defined in the standard, but in many applications of RTP the value
    /// of this field needs to be agreed between sender and receiver by some mechanism outside of
    /// RTP itself.
    pub fn payload_type(&self) -> u8 {
        self.buf[1] & 0b0111_1111
    }
    /// The sequence number of this particular packet.
    ///
    /// Sequence numbers are 16 bits, and will wrap back to `0` after reaching the maximum 16-bit
    /// value of `65535`.
    ///
    /// Receivers can identify packet losses or reordering by inspecting the value of this field
    /// across a sequence of received packets.  The [`Seq`](struct.Seq.html) wrapper type helps
    /// calling code reason about sequence number problems in the face of any wraparound that might
    /// have legitimately happened.
    pub fn sequence_number(&self) -> Seq {
        Seq((self.buf[2] as u16) << 8 | (self.buf[3] as u16))
    }
    /// The timestamp of this packet, given in a timebase that relates to the particular
    /// `payload_type` in use.
    ///
    /// It is perfectly possible for successive packets in a sequence to have the same value, or
    /// to have values that differ by arbitrarily large amounts.
    ///
    /// Timestamps are 32 bits, and will wrap back to `0` after reaching the maximum 32 bit value
    /// of `4294967295`.
    pub fn timestamp(&self) -> u32 {
        (self.buf[4] as u32) << 24
            | (self.buf[5] as u32) << 16
            | (self.buf[6] as u32) << 8
            | (self.buf[7] as u32)
    }
    /// The _synchronisation source_ for this packet.  Many applications of RTP do not use this
    /// field.
    pub fn ssrc(&self) -> u32 {
        (self.buf[8] as u32) << 24
            | (self.buf[9] as u32) << 16
            | (self.buf[10] as u32) << 8
            | (self.buf[11] as u32)
    }
    /// A potentially empty list of _contributing sources_ for this packet.  Many applications of
    /// RTP do not use this field.
    pub fn csrc(&self) -> impl Iterator<Item = u32> + '_ {
        self.buf[Self::MIN_HEADER_LEN..]
            .chunks(4)
            .take(self.csrc_count() as usize)
            .map(|b| (b[0] as u32) << 24 | (b[1] as u32) << 16 | (b[2] as u32) << 8 | (b[3] as u32))
    }

    fn payload_offset(&self) -> usize {
        let offset = self.csrc_end();
        if self.extension_flag() {
            offset + Self::EXTENSION_HEADER_LEN + self.extension_len()
        } else {
            offset
        }
    }

    fn csrc_end(&self) -> usize {
        Self::MIN_HEADER_LEN + (4 * self.csrc_count()) as usize
    }

    /// Returns the puyload data of this RTP packet, excluding the packet's headers.
    ///
    /// ⚠ Warning: does not currently exclude any packet padding, for RTP streams that use the
    /// `padding` flag.
    pub fn payload(&self) -> &'a [u8] {
        &self.buf[self.payload_offset()..]
    }

    fn extension_len(&self) -> usize {
        let offset = self.csrc_end();
        // The 16 bit extension length header gives a length in 32 bit (4 byte) units; 0 is a
        // valid length.
        4 * ((self.buf[offset + 2] as usize) << 8 | (self.buf[offset + 3] as usize))
    }

    /// Returns details of the optional RTP header extension field.  If there is an extension,
    /// the first component of the resulting tuple is the extension id, and the second is a
    /// byte-slice for the extension data value, to be interpreted by the application.
    pub fn extension(&self) -> Option<(u16, &'a [u8])> {
        if self.extension_flag() {
            let offset = self.csrc_end();
            let id = (self.buf[offset] as u16) << 8 | (self.buf[offset + 1] as u16);
            let start = offset + 4;
            Some((id, &self.buf[start..start + self.extension_len()]))
        } else {
            None
        }
    }
}
impl<'a> fmt::Debug for RtpReader<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        f.debug_struct("RtpReader")
            .field("version", &self.version())
            .field("padding", &self.padding())
            .field("extension", &self.extension().map(|(id, _)| id))
            .field("csrc_count", &self.csrc_count())
            .field("mark", &self.mark())
            .field("payload_type", &self.payload_type())
            .field("sequence_number", &self.sequence_number())
            .field("timestamp", &self.timestamp())
            .field("ssrc", &self.ssrc())
            .field("payload_length", &self.payload().len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version() {
        let data = [
            0x80u8, 0xe0u8, 0x27u8, 0x38u8, 0x64u8, 0xe4u8, 0x05u8, 0xa7u8, 0xa2u8, 0x42u8, 0xafu8,
            0x01u8, 0x3cu8, 0x41u8, 0xa4u8, 0xa3u8, 0x5du8, 0x13u8, 0xf9u8, 0xcau8, 0x2cu8, 0x7eu8,
            0xa9u8, 0x77u8, 0xaau8, 0xdeu8, 0xf7u8, 0xcau8, 0xa4u8, 0x28u8, 0xfeu8, 0xdfu8, 0xc8u8,
            0x68u8, 0xf1u8, 0xd9u8, 0x4fu8, 0x69u8, 0x96u8, 0xa0u8, 0x57u8, 0xbau8, 0xfbu8, 0x07u8,
            0xc4u8, 0xc4u8, 0xd4u8, 0xfeu8, 0xf8u8, 0xc7u8, 0xb2u8, 0x0du8, 0x01u8, 0x12u8, 0x14u8,
            0x36u8, 0x69u8, 0x75u8, 0xf2u8, 0xb4u8, 0xb5u8, 0xf2u8, 0x54u8, 0x2eu8, 0xc2u8, 0x66u8,
            0x51u8, 0xebu8, 0x41u8, 0x80u8, 0x96u8, 0xceu8, 0x8eu8, 0x60u8, 0xb2u8, 0x44u8, 0xaeu8,
            0xe5u8, 0x43u8, 0xadu8, 0x7bu8, 0x48u8, 0x89u8, 0x44u8, 0xb0u8, 0x48u8, 0x67u8, 0x6au8,
            0x84u8, 0x7au8, 0x0au8, 0x8fu8, 0x71u8, 0x50u8, 0x69u8, 0xe6u8, 0xb1u8, 0x05u8, 0x40u8,
            0xb9u8, 0x8cu8, 0xafu8, 0x42u8, 0xcbu8, 0x58u8, 0x83u8, 0xcbu8, 0x32u8, 0x64u8, 0xd2u8,
            0x2au8, 0x7du8, 0x4eu8, 0xf5u8, 0xbcu8, 0x33u8, 0xfeu8, 0xb7u8, 0x0cu8, 0xe4u8, 0x8eu8,
            0x38u8, 0xbcu8, 0x3au8, 0x1eu8, 0xd2u8, 0x56u8, 0x13u8, 0x23u8, 0x47u8, 0xcfu8, 0x42u8,
            0xa9u8, 0xbbu8, 0xcfu8, 0x48u8, 0xf3u8, 0x11u8, 0xc7u8, 0xfdu8, 0x73u8, 0x2du8, 0xe1u8,
            0xeau8, 0x47u8, 0x5cu8, 0x5du8, 0x11u8, 0x96u8, 0x1eu8, 0xc4u8, 0x70u8, 0x32u8, 0x77u8,
            0xabu8, 0x31u8, 0x7au8, 0xb1u8, 0x22u8, 0x14u8, 0x8du8, 0x2bu8, 0xecu8, 0x3du8, 0x67u8,
            0x97u8, 0xa4u8, 0x40u8, 0x21u8, 0x1eu8, 0xceu8, 0xb0u8, 0x63u8, 0x01u8, 0x75u8, 0x77u8,
            0x03u8, 0x15u8, 0xcdu8, 0x35u8, 0xa1u8, 0x2fu8, 0x4bu8, 0xa0u8, 0xacu8, 0x8du8, 0xd7u8,
            0x78u8, 0x02u8, 0x23u8, 0xcbu8, 0xfdu8, 0x82u8, 0x4eu8, 0x0bu8, 0x79u8, 0x7fu8, 0x39u8,
            0x70u8, 0x26u8, 0x66u8, 0x37u8, 0xe9u8, 0x93u8, 0x91u8, 0x7bu8, 0xc4u8, 0x80u8, 0xa9u8,
            0x18u8, 0x23u8, 0xb3u8, 0xa1u8, 0x04u8, 0x72u8, 0x53u8, 0xa0u8, 0xb4u8, 0xffu8, 0x79u8,
            0x1fu8, 0x07u8, 0xe2u8, 0x5du8, 0x01u8, 0x7du8, 0x63u8, 0xc1u8, 0x16u8, 0x89u8, 0x23u8,
            0x4au8, 0x17u8, 0xbbu8, 0x6du8, 0x0du8, 0x81u8, 0x1au8, 0xbbu8, 0x94u8, 0x5bu8, 0xcbu8,
            0x2du8, 0xdeu8, 0x98u8, 0x40u8, 0x22u8, 0x62u8, 0x41u8, 0xc2u8, 0x9bu8, 0x95u8, 0x85u8,
            0x60u8, 0xf0u8, 0xdeu8, 0x6fu8, 0xeeu8, 0x93u8, 0xccu8, 0x15u8, 0x76u8, 0xfbu8, 0xf8u8,
            0x8au8, 0x1du8, 0xe1u8, 0x83u8, 0x12u8, 0xabu8, 0x25u8, 0x6au8, 0x7bu8, 0x89u8, 0xedu8,
            0x70u8, 0x4eu8, 0xcdu8, 0x1eu8, 0xa9u8, 0xfcu8, 0xa8u8, 0x22u8, 0x91u8, 0x5fu8, 0x50u8,
            0x68u8, 0x6au8, 0x35u8, 0xf7u8, 0xc1u8, 0x1eu8, 0x15u8, 0x37u8, 0xb4u8, 0x30u8, 0x62u8,
            0x56u8, 0x1eu8, 0x2eu8, 0xe0u8, 0x2du8, 0xa4u8, 0x1eu8, 0x75u8, 0x5bu8, 0xc7u8, 0xd0u8,
            0x5bu8, 0x9du8, 0xd0u8, 0x25u8, 0x76u8, 0xdfu8, 0xa7u8, 0x19u8, 0x12u8, 0x93u8, 0xf4u8,
            0xebu8, 0x02u8, 0xf2u8, 0x4au8, 0x13u8, 0xe9u8, 0x1cu8, 0x17u8, 0xccu8, 0x11u8, 0x87u8,
            0x9cu8, 0xa6u8, 0x40u8, 0x27u8, 0xb7u8, 0x2bu8, 0x9bu8, 0x6fu8, 0x23u8, 0x06u8, 0x2cu8,
            0xc6u8, 0x6eu8, 0xc1u8, 0x9au8, 0xbdu8, 0x59u8, 0x37u8, 0xe9u8, 0x9eu8, 0x76u8, 0xf6u8,
            0xc1u8, 0xbcu8, 0x81u8, 0x18u8, 0x60u8, 0xc9u8, 0x64u8, 0x0au8, 0xb3u8, 0x6eu8, 0xf3u8,
            0x6bu8, 0xb9u8, 0xd0u8, 0xf6u8, 0xe0u8, 0x9bu8, 0x91u8, 0xc1u8, 0x0fu8, 0x96u8, 0xefu8,
            0xbcu8, 0x5fu8, 0x8eu8, 0x86u8, 0x56u8, 0x5au8, 0xfcu8, 0x7au8, 0x8bu8, 0xddu8, 0x9au8,
            0x1cu8, 0xf6u8, 0xb4u8, 0x85u8, 0xf4u8, 0xb0u8,
        ];
        let header = RtpReader::new(&data).unwrap();
        assert_eq!(2, header.version());
        assert!(!header.padding());
        assert!(header.extension().is_none());
        assert_eq!(0, header.csrc_count());
        assert!(header.mark());
        assert_eq!(96, header.payload_type());
        assert_eq!(Seq(10040), header.sequence_number());
        assert_eq!(1_692_665_255, header.timestamp());
        assert_eq!(0xa242_af01, header.ssrc());
        assert_eq!(379, header.payload().len());
        format!("{:?}", header);
    }

    #[test]
    fn seq() {
        assert!(Seq(0).precedes(Seq(1)));
        assert!(Seq(0xffff).precedes(Seq(0)));
        assert!(Seq(0) < Seq(1));
        assert!(Seq(0xffff) < Seq(0));
        assert_eq!(-1, Seq(0) - Seq(1));
        assert_eq!(1, Seq(1) - Seq(0));
        assert_eq!(0, Seq(1) - Seq(1));
        assert_eq!(1, Seq(0) - Seq(0xffff));
        assert_eq!(-1, Seq(0xffff) - Seq(0));
        let mut it = (Seq(0xfffe)..Seq(1)).seq_iter();
        assert_eq!(Seq(0xfffe), it.next().unwrap());
        assert_eq!(Seq(0xffff), it.next().unwrap());
        assert_eq!(Seq(0x0000), it.next().unwrap());
        assert_eq!(None, it.next());
    }
}
