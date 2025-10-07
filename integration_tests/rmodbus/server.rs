use once_cell::sync::Lazy;
use serial::prelude::*;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::RwLock;
use std::thread;
use std::time::Duration;
use rmodbus::{
    server::{context::ModbusContext, storage::ModbusStorageFull, ModbusFrame},
    ModbusFrameBuf, ModbusProto,
};

// pub for README example
pub static CONTEXT: Lazy<RwLock<ModbusStorageFull>> = Lazy::new(<_>::default);

pub fn tcpserver(unit: u8, listen: &str) {
    let listener = TcpListener::bind(listen).unwrap();
    println!("listening started, ready to accept");
    for stream in listener.incoming() {
        thread::spawn(move || {
            println!("client connected");
            let mut stream = stream.unwrap();
            loop {
                let mut buf: ModbusFrameBuf = [0; 256];
                let mut response = Vec::new(); // for nostd use FixedVec with alloc [u8;256]
                if stream.read(&mut buf).unwrap_or(0) == 0 {
                    return;
                }
                let mut frame = ModbusFrame::new(unit, &buf, ModbusProto::TcpUdp, &mut response);
                if frame.parse().is_err() {
                    println!("server error");
                    return;
                }
                if frame.processing_required {
                    let result = if frame.readonly {
                        frame.process_read(&*CONTEXT.read().unwrap())
                    } else {
                        frame.process_write(&mut *CONTEXT.write().unwrap())
                    };
                    if result.is_err() {
                        println!("frame processing error");
                        return;
                    }
                }
                if frame.response_required {
                    frame.finalize_response().unwrap();
                    println!("{:x?}", response.as_slice());
                    if stream.write(response.as_slice()).is_err() {
                        return;
                    }
                }
            }
        });
    }
}


pub fn rtuserver(unit: u8, port: &str) {
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
        let mut buf: ModbusFrameBuf = [0; 256];
        if port.read(&mut buf).unwrap() > 0 {
            println!("got frame");
            let mut response = Vec::new();
            let mut frame = ModbusFrame::new(unit, &buf, ModbusProto::Rtu, &mut response);
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
                port.write_all(response.as_slice()).unwrap();
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
        thread::spawn(move || {
            rtuserver(1, &serial_port);
        });
    }
    tcpserver(1, "127.0.0.1:5502");
}
