#![no_main]
#[macro_use] extern crate libfuzzer_sys;
extern crate rtp_rs;

fuzz_target!(|data: &[u8]| {
    if let Ok(header) = rtp_rs::RtpReader::new(data) {
        let b = header.create_builder();
        let len = b.target_length();
        let mut out = vec![0u8; len];
        b.build_into(&mut out[..]).expect("build_into() failed");
        // check that the buffer we get back from the builder matches the buffer we started from,
        assert_eq!(&data[..len], &out[..]);
    }
});
