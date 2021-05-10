#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(header) = rtp_rs::RtpReader::new(data) {
        format!("{:?}", header);
        let b = header.create_builder();
        let len = b.target_length();
        let mut out = vec![0u8; len];
        b.build_into(&mut out[..]).expect("build_into() failed");
        if let Some(padding) = header.padding() {
            let padding = padding as usize;
            assert_eq!(data[0] & 0b1101_1111, out[0]);
            assert_eq!(&data[1..data.len()-padding], &out[1..len]);
        } else {
            assert_eq!(&data[..len], &out[..]);
        }
    }
});
