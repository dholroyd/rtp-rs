use crate::{RtpPacketBuilder, Seq};
use core::fmt;

/// Wrapper around a byte-slice of RTP data, providing accessor methods for the RTP header fields.
pub struct RtpReader<'a> {
    buf: &'a [u8],
}

/// Reasons for `RtpHeader::new()` to fail
#[derive(Debug)]
pub enum RtpReaderError {
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
    /// The padding header at the end of the packet, if present, specifies the number of padding
    /// bytes, including itself, and therefore cannot be less than `1`, or greater than the
    /// available space.
    PaddingLengthInvalid(u8),
}

impl<'a> RtpReader<'a> {
    /// An RTP packet header is no fewer than 12 bytes long
    pub const MIN_HEADER_LEN: usize = 12;
    const EXTENSION_HEADER_LEN: usize = 4;

    /// Tries to construct a new `RtpHeader` instance, or an `RtpReaderError` if the RTP data is
    /// malformed.
    ///
    /// In particular, if there is too little data in the given buffer, such that some later
    /// attempt to access an RTP header field would need to access bytes that are not available,
    /// then this method will fail up front, rather than allowing attempts to access any header
    /// field to fail later on.
    pub fn new(b: &'a [u8]) -> Result<RtpReader<'_>, RtpReaderError> {
        if b.len() < Self::MIN_HEADER_LEN {
            return Err(RtpReaderError::BufferTooShort(b.len()));
        }
        let r = RtpReader { buf: b };
        if r.version() != 2 {
            return Err(RtpReaderError::UnsupportedVersion(r.version()));
        }
        if r.extension_flag() {
            let extension_start = r.csrc_end() + Self::EXTENSION_HEADER_LEN;
            if extension_start > b.len() {
                return Err(RtpReaderError::HeadersTruncated {
                    header_len: extension_start,
                    buffer_len: b.len(),
                });
            }
            let extension_end = extension_start + r.extension_len();
            if extension_end > b.len() {
                return Err(RtpReaderError::HeadersTruncated {
                    header_len: extension_end,
                    buffer_len: b.len(),
                });
            }
        }
        if r.payload_offset() > b.len() {
            return Err(RtpReaderError::HeadersTruncated {
                header_len: r.payload_offset(),
                buffer_len: b.len(),
            });
        }
        if r.padding_flag() {
            let post_header_bytes = b.len() - r.payload_offset();
            // with 'padding' flag set, there must be at least a single byte after the headers to
            // hold the padding length
            if post_header_bytes == 0 {
                return Err(RtpReaderError::HeadersTruncated {
                    header_len: r.payload_offset(),
                    buffer_len: b.len() - 1,
                });
            }
            let pad_len = r.padding_len()?;

            if r.payload_offset() + pad_len as usize > b.len() {
                return Err(RtpReaderError::PaddingLengthInvalid(pad_len));
            }
        }
        Ok(r)
    }

    /// Version field value (currently only version 2 is supported, so other values will not be
    /// seen from this release of `rtp-rs`.
    pub fn version(&self) -> u8 {
        (self.buf[0] & 0b1100_0000) >> 6
    }

    /// Flag indicating if padding is present at the end of the payload data.
    fn padding_flag(&self) -> bool {
        (self.buf[0] & 0b0010_0000) != 0
    }
    /// Returns the size of the padding at the end of this packet, or `None` if the padding flag is
    /// not set in the packet header
    pub fn padding(&self) -> Option<u8> {
        if self.padding_flag() {
            Some(self.padding_len().unwrap())
        } else {
            None
        }
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

    /// Returns the offset of the payload for the packet
    pub fn payload_offset(&self) -> usize {
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

    /// Returns the payload data of this RTP packet, excluding the packet's headers and any
    /// optional trailing padding.
    pub fn payload(&self) -> &'a [u8] {
        let pad = if self.padding_flag() {
            // in Self::new(), we already checked this was Ok, and will not attempt an invalid
            // slice below,
            self.padding_len().unwrap() as usize
        } else {
            0
        };
        &self.buf[self.payload_offset()..self.buf.len() - pad]
    }

    fn extension_len(&self) -> usize {
        let offset = self.csrc_end();
        // The 16 bit extension length header gives a length in 32 bit (4 byte) units; 0 is a
        // valid length.
        4 * ((self.buf[offset + 2] as usize) << 8 | (self.buf[offset + 3] as usize))
    }

    // must only be used if padding() returns true
    fn padding_len(&self) -> Result<u8, RtpReaderError> {
        match self.buf[self.buf.len() - 1] {
            0 => Err(RtpReaderError::PaddingLengthInvalid(0)),
            l => Ok(l),
        }
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

    /// Create a `RtpPacketBuilder` from this packet.  **Note** that padding from the original
    /// packet will not be used by default, and must be defined on the resulting `RtpPacketBuilder`
    /// if required.
    ///
    /// The padding is not copied from the original since, while we do know how many padding bytes
    /// were present, we don't know if the intent was to round to 2 bytes, 4 bytes, etc.  Blindly
    /// copying the padding could result in an incorrect result _if_ the payload is subsequently
    /// changed for one with a different length.
    ///
    /// If you know your output packets don't need padding, there is nothing more to do, since
    /// that is the default for the resulting `RtpPacketBulder`.
    ///
    /// If you know you output packets need padding to 4 bytes, then you _must_ explicitly specify
    /// this using `builder.padded(Pad::round_to(4))` even if the source packet was already padded
    /// to a 4 byte boundary.
    pub fn create_builder(&self) -> RtpPacketBuilder<'a> {
        let mut builder = RtpPacketBuilder::new()
            .payload_type(self.payload_type())
            .marked(self.mark())
            .sequence(self.sequence_number())
            .ssrc(self.ssrc())
            .timestamp(self.timestamp())
            .payload(self.payload());

        if let Some(ext) = self.extension() {
            builder = builder.extension(ext.0, ext.1);
        }

        for csrc in self.csrc() {
            builder = builder.add_csrc(csrc);
        }

        builder
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

// When Rust 1.81 drops with Error in core, this feature gate can be removed.
#[cfg(feature = "std")]
impl std::error::Error for RtpReaderError {}

impl core::fmt::Display for RtpReaderError {
    #[cfg(feature = "std")]
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                RtpReaderError::BufferTooShort(b) => format!("buffer too short: {b}"),
                RtpReaderError::UnsupportedVersion(v) => format!("unsupported version: {v}"),
                RtpReaderError::HeadersTruncated {
                    header_len,
                    buffer_len,
                } => format!(
                    "headers truncated: header length: {header_len}; buffer length: {buffer_len}"
                ),
                RtpReaderError::PaddingLengthInvalid(p) => format!("padding length invalid: {p}"),
            }
        )
    }
    
    #[cfg(not(feature = "std"))]
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                RtpReaderError::BufferTooShort(_) => "buffer too short",
                RtpReaderError::UnsupportedVersion(_) => "unsupported version",
                RtpReaderError::HeadersTruncated  { header_len: _, buffer_len: _ } => "headers truncated",
                RtpReaderError::PaddingLengthInvalid(_) => "padding length invalid",
            }
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::IntoSeqIterator;

    const TEST_RTP_PACKET: [u8; 391] = [
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

    const TEST_RTP_PACKET_WITH_EXTENSION: [u8; 63] = [
        144u8, 111u8, 79u8, 252u8, 224u8, 94u8, 104u8, 203u8, 30u8, 112u8, 208u8, 191u8, 190u8,
        222u8, 0u8, 3u8, 34u8, 175u8, 185u8, 88u8, 49u8, 0u8, 171u8, 64u8, 48u8, 16u8, 219u8, 0u8,
        104u8, 9u8, 136u8, 90u8, 174u8, 145u8, 68u8, 165u8, 227u8, 178u8, 187u8, 68u8, 166u8, 66u8,
        235u8, 40u8, 171u8, 135u8, 30u8, 174u8, 130u8, 239u8, 205u8, 14u8, 211u8, 232u8, 65u8,
        67u8, 153u8, 120u8, 63u8, 17u8, 101u8, 55u8, 17u8,
    ];

    #[test]
    fn version() {
        let reader = RtpReader::new(&TEST_RTP_PACKET).unwrap();
        assert_eq!(2, reader.version());
        assert!(reader.padding().is_none());
        assert!(reader.extension().is_none());
        assert_eq!(0, reader.csrc_count());
        assert!(reader.mark());
        assert_eq!(96, reader.payload_type());
        assert_eq!(Seq(10040), reader.sequence_number());
        assert_eq!(1_692_665_255, reader.timestamp());
        assert_eq!(0xa242_af01, reader.ssrc());
        assert_eq!(379, reader.payload().len());
        format_args!("{:?}", reader);
    }

    #[test]
    fn padding() {
        let reader = RtpReader::new(&TEST_RTP_PACKET_WITH_EXTENSION).unwrap();
        assert_eq!(2, reader.version());
        assert!(reader.padding().is_none());
        assert!(reader.extension().is_some());
        assert_eq!(0, reader.csrc_count());
        assert_eq!(111, reader.payload_type());
    }

    #[test]
    fn padding_too_large() {
        // 'padding' header-flag is on, and padding length (255) in final byte is larger than the
        // buffer length. (Test data created by fuzzing.)
        let data = [
            0xa2, 0xa2, 0xa2, 0xa2, 0xa2, 0x90, 0x0, 0x0, 0x1, 0x0, 0xff, 0xa2, 0xa2, 0xa2, 0xa2,
            0x90, 0x0, 0x0, 0x0, 0x0, 0xff,
        ];
        assert!(RtpReader::new(&data).is_err());
    }

    #[test]
    fn builder_juggle() {
        let reader = RtpReader::new(&TEST_RTP_PACKET).unwrap();
        let mut buffer = [0u8; 1024];
        let buf_len = reader.create_builder().build_into(&mut buffer).unwrap();

        assert_eq!(&buffer[..buf_len], &TEST_RTP_PACKET[..]);
    }

    #[test]
    fn builder_juggle_extension() {
        let reader = RtpReader::new(&TEST_RTP_PACKET_WITH_EXTENSION).unwrap();
        let mut buffer = [0u8; 1024];
        let buf_len = reader.create_builder().build_into(&mut buffer).unwrap();
        assert_eq!(&buffer[..buf_len], &TEST_RTP_PACKET_WITH_EXTENSION[..]);
    }

    #[test]
    fn builder_juggle_clear_payload() {
        let new_payload = [0u8; 0];
        let reader = RtpReader::new(&TEST_RTP_PACKET_WITH_EXTENSION).unwrap();
        let mut buffer = [0u8; 1024];
        let buf_len = reader
            .create_builder()
            .payload(&new_payload)
            .build_into(&mut buffer)
            .unwrap();

        let expected = &TEST_RTP_PACKET_WITH_EXTENSION[0..(3 + 4) * 4];
        assert_eq!(&buffer[..buf_len], expected);
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
