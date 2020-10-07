# rtp-rs

[![crates.io version](https://img.shields.io/crates/v/rtp-rs.svg)](https://crates.io/crates/rtp-rs)
[![Documentation](https://docs.rs/rtp-rs/badge.svg)](https://docs.rs/rtp-rs)

[ChangeLog](https://github.com/dholroyd/rtp-rs/blob/master/CHANGELOG.md)

Rust reader and builder for Realtime Transport Protocol packet structure.

This crate provides efficient read access to the fields and payload of an RTP packet.
The provided type is just a wrapper around a `&[u8]` borrowed byte slice; It is zero-copy
and zero-allocation, with RTP header fields only being read if calling code actually uses
a given accessor method.

Does not support actually reading UDP from the network, or any kind or RTP session management
(i.e. no buffering to handle packet reordering, loss notification, pacing, etc.)

# Supported RTP syntax

- [x] reading
  - [x] all simple header fields
  - [x] extension header (if present, the `u16` identifier and `&[u8]`value are exposed without further interpretation)
- [x] building
  - [x] all simple header fields
  - [x] extension header
  - [x] padding to 4 bytes
  
