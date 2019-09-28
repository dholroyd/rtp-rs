#![no_main]
#[macro_use] extern crate libfuzzer_sys;
extern crate rtp_rs;

fuzz_target!(|data: &[u8]| {
    if let Ok(header) = rtp_rs::RtpReader::new(data) {
        let _ = header.version();
        let _ = header.padding();
        if let Some(ext) = header.extension() {
            let _ = ext.0;
            let _ = ext.1;
        }
        let _ = header.csrc_count();
        let _ = header.mark();
        let _ = header.payload_type();
        let _ = header.sequence_number();
        let _ = header.timestamp();
        let _ = header.ssrc();
        let _ = header.payload().len();
        let _ = header.extension();
        for _ in header.csrc() {
        }
    }
});
