use crate::Seq;

/// Reasons why `RtpPacketBuilder::build_info` fails
#[derive(Debug, Ord, PartialOrd, Eq, PartialEq)]
pub enum RtpPacketBuildError {
    /// The target buffer is too small for the RTP packet
    BufferTooSmall,

    /// The given payload type is invalid or not set
    PayloadTypeInvalid,

    /// The extension payload is too large
    ExtensionTooLarge,

    /// The extension payload hasn't been padded to a four byte boundary
    ExtensionMissingPadding,
}

/// A new packet build which collects the data which should be written as RTP packet
pub struct RtpPacketBuilder<'a> {
    padded: bool,
    marked: bool,
    payload_type: u8,

    extension: Option<(u16, &'a [u8])>,
    payload: Option<&'a [u8]>,

    sequence: Seq,
    timestamp: u32,

    ssrc: u32,
    csrcs: [u32; 15],
    csrc_count: u8
}

impl<'a> RtpPacketBuilder<'a> {
    /// Create a new RTP packet builder
    pub fn new() -> Self {
        RtpPacketBuilder {
            padded: false,
            marked: false,
            /*
             * Setting it to an invalid value enforces the user to set the payload type.
             * This will cause the build method to fail if it hasn't been updated.
             */
            payload_type: 0xFF,

            extension: None,
            payload: None,

            sequence: Seq::from(0),
            timestamp: 0,

            ssrc: 0,
            csrcs: [0u32; 15],
            csrc_count: 0
        }
    }

    /// Set the payload type.
    /// The type must be in range of [0; 127],
    /// else `RtpPacketBuilder::build_info` will fail.
    pub fn payload_type(mut self, payload_type: u8) -> Self {
        self.payload_type = payload_type;
        self
    }

    /// Pad the packet to a four byte boundary
    pub fn padded(mut self) -> Self {
        self.padded = true;
        self
    }

    /// Set the marker bit in the RTP header
    pub fn marked(mut self, flag: bool) -> Self {
        self.marked = flag;
        self
    }

    /// Add a contributing source (csrc).
    /// If more than 15 contributing sources the rest will be discarded.
    pub fn add_csrc(mut self, csrc: u32) -> Self {
        if self.csrc_count == 15 {
            /* The limit of contributing sources is 15. Any more should be discarded. */
            self
        } else {
            self.csrcs[self.csrc_count as usize] = csrc;
            self.csrc_count = self.csrc_count + 1;
            self
        }
    }

    /// Set the sequence number
    pub fn sequence(mut self, seq: Seq) -> Self {
        self.sequence = seq;
        self
    }

    /// Set the source for this packet
    pub fn ssrc(mut self, ssrc: u32) -> Self {
        self.ssrc = ssrc;
        self
    }

    /// Set the timestamp
    pub fn timestamp(mut self, timestamp: u32) -> Self {
        self.timestamp = timestamp;
        self
    }

    /// Add a custom extension payload.
    /// The bytes should be aligned to a a four byte boundary,
    /// else `RtpPacketBuilder::build_info` will fail.
    pub fn extension(mut self, id: u16, payload: &'a [u8]) -> Self {
        self.extension = Some((id, payload));
        self
    }

    /// Set the payload of the packet
    pub fn payload(mut self, payload: &'a [u8]) -> Self {
        self.payload = Some(payload);
        self
    }

    /// Calculate the target length of the packet.
    /// This can be used to allocate a buffer for the `build_into` method.
    pub fn target_length(&self) -> usize {
        /* 12 is the length of the basic header */
        let mut length = 12usize;
        length += self.csrc_count as usize * 4;
        length += if let Some((_, ext)) = self.extension { ext.len() + 4 } else { 0 };
        length += if let Some(payload) = self.payload { payload.len() } else { 0 };
        if self.padded && (length & 0x3) != 0 {
            length += (!(length & 0x3) + 1) & 0x3;
        }
        length
    }

    /// Build the packet into the target buffer but ignore all validity checks.
    pub fn build_into_unchecked(&mut self, target: &mut [u8]) -> usize {
        let first_byte = &mut target[0];
        *first_byte = 2 << 6; /* The RTP packet version */
        if self.extension.is_some() {
            *first_byte |= 1 << 4; /* set the extension flag */
        }
        *first_byte |= self.csrc_count;

        target[1] = self.payload_type;
        if self.marked {
            target[1] |= 0x80;
        }

        target[ 2] = (self.sequence.0 >>    8) as u8;
        target[ 3] = (self.sequence.0 &  0xFF) as u8;

        target[ 4] = (self.timestamp >> 24) as u8;
        target[ 5] = (self.timestamp >> 16) as u8;
        target[ 6] = (self.timestamp >>  8) as u8;
        target[ 7] = (self.timestamp      ) as u8;

        target[ 8] = (self.ssrc >> 24) as u8;
        target[ 9] = (self.ssrc >> 16) as u8;
        target[10] = (self.ssrc >>  8) as u8;
        target[11] = (self.ssrc      ) as u8;

        let mut write_index = 12usize;
        for index in 0..self.csrc_count as usize {
            let csrc = self.csrcs[index];
            target[write_index + 0] = (csrc >> 24) as u8;
            target[write_index + 1] = (csrc >> 16) as u8;
            target[write_index + 2] = (csrc >>  8) as u8;
            target[write_index + 3] = (csrc      ) as u8;

            write_index = write_index + 4;
        }

        if let Some((id, payload)) = self.extension {
            target[write_index + 0] = (id >>    8) as u8;
            target[write_index + 1] = (id &  0xFF) as u8;

            let len = payload.len() / 4;
            target[write_index + 2] = (len >>    8) as u8;
            target[write_index + 3] = (len &  0xFF) as u8;

            write_index = write_index + 4;

            /* the target buffer has been ensured to hold that many bytes */
            target[write_index..(write_index + payload.len())].copy_from_slice(payload);
            write_index += payload.len();
        }

        if let Some(payload) = self.payload {
            /* the target buffer has been ensured to hold that many bytes */
            target[write_index..(write_index + payload.len())].copy_from_slice(payload);
            write_index += payload.len();
        }

        if self.padded && (write_index & 0x3) != 0 {
            target[0] |= 1 << 5;  /* set the padded flag */

            let padded_bytes = (!(write_index & 0x3) + 1) & 0x3;
            write_index += padded_bytes;
            target[write_index - 1] = padded_bytes as u8;
        }

        write_index
    }

    /// Build the RTP packet on the target buffer.
    /// The length of the final packet will be returned on success.
    pub fn build_into(&mut self, target: &mut [u8]) -> Result<usize, RtpPacketBuildError> {
        if target.len() < self.target_length() {
            return Err(RtpPacketBuildError::BufferTooSmall);
        }

        self.validate_content()?;
        Ok(self.build_into_unchecked(target))
    }


    /// Build the RTP packet.
    /// On success it returns a buffer containing the target packet.
    pub fn build(&mut self) -> Result<Vec<u8>, RtpPacketBuildError> {
        self.validate_content()?;

        let mut buffer = Vec::<u8>::new();
        buffer.resize(self.target_length(), 0);

        let length = self.build_into_unchecked(buffer.as_mut_slice());
        assert_eq!(length, buffer.len());

        Ok(buffer)
    }

    fn validate_content(&self) -> Result<(), RtpPacketBuildError> {
        if (self.payload_type & (!0x7F)) != 0 {
            return Err(RtpPacketBuildError::PayloadTypeInvalid);
        }

        if let Some((_, payload)) = self.extension {
            if payload.len() > 0xFFFF {
                return Err(RtpPacketBuildError::ExtensionTooLarge);
            }

            if (payload.len() & 0x3) != 0 {
                return Err(RtpPacketBuildError::ExtensionMissingPadding);
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::RtpPacketBuilder;

    #[test]
    fn test_padded() {
        let payload = vec![1u8];
        let packet = RtpPacketBuilder::new()
            .payload_type(1)
            .payload(&payload)
            .padded()
            .build().unwrap();

        assert_eq!(packet.len() & 0x03, 0);
    }

    #[test]
    fn test_not_padded() {
        let payload = vec![1u8];
        let packet = RtpPacketBuilder::new()
            .payload_type(1)
            .payload(&payload)
            .build().unwrap();

        assert_eq!(packet.len() & 0x03, 1);
    }

    #[test]
    fn test_would_run() {
        let extension = vec![1u8, 2, 3, 4];
        let mut builder = RtpPacketBuilder::new()
            .payload_type(12)
            .extension(1, &extension);

        let mut buffer = [0u8; 100];
        builder.build_into(&mut buffer).unwrap();
    }
}