use once_cell::sync::Lazy;
use serial::prelude::*;
use std::io::{Read, Write};
use std::sync::RwLock;
use std::time::Duration;

use rmodbus::{
    generate_ascii_frame, guess_request_frame_len, parse_ascii_frame,
    server::{context::ModbusContext, storage::ModbusStorageFull, ModbusFrame},
    ModbusFrameBuf, ModbusProto,
};

// pub for README example
pub static CONTEXT: Lazy<RwLock<ModbusStorageFull>> = Lazy::new(<_>::default);


pub fn asciiserver(unit: u8, port: &str) {
    let mut port = serial::open(port).unwrap();
    port.reconfigure(&|settings| {
        (settings.set_baud_rate(serial::Baud19200).unwrap());
        settings.set_char_size(serial::Bits8);
        settings.set_parity(serial::ParityNone);
        settings.set_stop_bits(serial::Stop1);
        settings.set_flow_control(serial::FlowNone);
        Ok(())
    })
    .unwrap();
    port.set_timeout(Duration::from_secs(3600)).unwrap();
    loop {
        let mut asciibuf = [0; 1024];
        let rd = port.read(&mut asciibuf).unwrap();
        if rd > 0 {
            println!("got frame len {}", rd);
            println!(
                "{}",
                guess_request_frame_len(&asciibuf, ModbusProto::Ascii).unwrap()
            );
            let mut buf: ModbusFrameBuf = [0; 256];
            let result = parse_ascii_frame(&asciibuf, rd, &mut buf, 0);
            if result.is_err() {
                println!("unable to decode");
                continue;
            }
            println!("parsed {} bytes", result.unwrap());
            let mut response = Vec::new();
            let mut frame = ModbusFrame::new(unit, &buf, ModbusProto::Ascii, &mut response);
            if frame.parse().is_err() {
                println!("server error");
                continue;
            }
            if frame.processing_required {
                let result = if frame.readonly {
                    frame.process_read(&*CONTEXT.read().unwrap())
                } else {
                    frame.process_write(&mut *CONTEXT.write().unwrap())
                };
                if result.is_err() {
                    println!("frame processing error");
                    continue;
                }
            }
            if frame.response_required {
                frame.finalize_response().unwrap();
                println!("{:x?}", response);
                let mut response_ascii = Vec::new();
                generate_ascii_frame(&response, &mut response_ascii).unwrap();
                println!("{:x?}", response_ascii);
                port.write_all(response_ascii.as_slice()).unwrap();
            }
        }
    }
}

fn main() {

    CONTEXT.write().unwrap().set_input(0, 1234).unwrap();
    CONTEXT.write().unwrap().set_input(1, 5678).unwrap();

    let args: Vec<String> = std::env::args().collect();
    let use_rtu = args.len() > 1;
    if use_rtu {
        let serial_port = args[1].clone();
        asciiserver(1, &serial_port);
    }else {
        println!("cannot start ASCII server without serial port argument");
    }
}
