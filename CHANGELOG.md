# ChangeLog

## 0.4.0
### Changed
 - `RtpReader::extension()` no longer returns the boolean flag indicating if an extension is present, and instead
   produces an `Option` which is `Some` when an extension header is present.  The `Option` contains a `(u16, &[u8])`
   tuple when an extension header is present, where the `u16` value is the extension header id, and the byte-slice is
   the extension header payload.
 - Should no longer panic if the RTP packet length is not sufficient to contain all 4 bytes of an extension header
   (where the extension header is flagged to be present) -- thanks to [@ts252](https://github.com/ts252) for spotting.
 - Extension header lengths where incorrectly calculated in earlier releases, which would have resulted in invalid RTP
   payload data being produced for any packets that actually had an extension (the extension length header is a count of
   32-bit values, not a count of 8-bit values as the previous implementation had assumed).
