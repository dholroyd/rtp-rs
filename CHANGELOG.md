# ChangeLog

## Unreleased
- Extracted RtpPacketBuilder::build and Errors to 'std' feature, which is on by default. 

### Changed
 - Switched to Rust 2021 edition.

### Added
 - `RtpPacketBuildError` and `RtpReaderError` now implement `std::error::Error`

## 0.6.0 - 2021-05-13
### Added
 - The `Seq` type now implements `Ord` (in addition to the `PartialOrd` implementation that was already available).
 - [@WolverinDEV](https://github.com/WolverinDEV) added an `RtpPacketBuilder` 🎊

### Changed
 - `RtpHeaderError` was renamed to `RtpReaderError` (the type relates to read-failures specifically, and we now
   have support for writing too)
 - `RtpHeader::padding()` now returns `Option<u8>`, rather than `bool`, exposing how many padding bytes are present as
   well as the fact that padding is in use.
 - We no longer reject RTP packets that contain headers but no payload

## 0.5.0 - 2019-09-29
### Fixed
 - Trailing padding-bytes, indicated by the `padding` flag in the RTP header, are now excluded from the data returned by
   the `payload()` method.
 - Since we now pay attention to padding data, `RtpReader::new()` will fail if the indicated padding length is
   nonsensical (less than one byte, or greater than the available space).
### Changed
 - `RtpHeaderError` gains a new `PaddingLengthInvalid` variant
 - The `Seq` methods `next()` and `precedes()` now both take `self` by value, which _clippy_ points out should be more
   efficient,
### Added
 - `csrc()` method to expose any CSRC header values that might be present (rarely used RTP feature).
 - API docs are now provided for all public items

## 0.4.0 - 2019-09-25
### Changed
 - `RtpReader::extension()` no longer returns the boolean flag indicating if an extension is present, and instead
   produces an `Option` which is `Some` when an extension header is present.  The `Option` contains a `(u16, &[u8])`
   tuple when an extension header is present, where the `u16` value is the extension header id, and the byte-slice is
   the extension header payload.
### Fixed
 - Should no longer panic if the RTP packet length is not sufficient to contain all 4 bytes of an extension header
   (where the extension header is flagged to be present) -- thanks to [@ts252](https://github.com/ts252) for spotting.
 - Extension header lengths where incorrectly calculated in earlier releases, which would have resulted in invalid RTP
   payload data being produced for any packets that actually had an extension (the extension length header is a count of
   32-bit values, not a count of 8-bit values as the previous implementation had assumed).
