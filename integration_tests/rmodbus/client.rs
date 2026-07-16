use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;
use rmodbus::{
    client::ModbusRequest, ModbusProto, parse_ascii_frame, generate_ascii_frame,
};

enum Transport {
    Tcp(TcpStream),
    Serial(serial2::SerialPort),
}

impl Transport {
    fn write_all(&mut self, buf: &[u8]) -> std::io::Result<()> {
        match self {
            Transport::Tcp(s) => s.write_all(buf),
            Transport::Serial(p) => p.write_all(buf),
        }
    }

    fn read_exact(&mut self, buf: &mut [u8]) -> std::io::Result<()> {
        match self {
            Transport::Tcp(s) => s.read_exact(buf),
            Transport::Serial(p) => p.read_exact(buf),
        }
    }

    fn read_response(&mut self, proto: ModbusProto) -> std::io::Result<Vec<u8>> {
        match proto {
            ModbusProto::TcpUdp => {
                let mut mbap = [0u8; 6];
                self.read_exact(&mut mbap)?;
                let length = u16::from_be_bytes([mbap[4], mbap[5]]) as usize;
                let mut payload = vec![0u8; length];
                self.read_exact(&mut payload)?;
                let mut frame = mbap.to_vec();
                frame.extend(payload);
                Ok(frame)
            }
            ModbusProto::Rtu => {
                let mut header = [0u8; 3];
                self.read_exact(&mut header)?;
                let fc = header[1];
                let mut frame = header.to_vec();

                let remaining = match fc {
                    0x01 | 0x02 | 0x03 | 0x04 => {
                        let byte_count = header[2] as usize;
                        byte_count + 2 // data + CRC
                    }
                    _ => {
                        if (fc & 0x80) != 0 {
                            2 // exception code + CRC
                        } else {
                            5 // write echo fields + CRC (already read 3 bytes, total 8 bytes)
                        }
                    }
                };

                let mut rest = vec![0u8; remaining];
                self.read_exact(&mut rest)?;
                frame.extend(rest);
                Ok(frame)
            }
            ModbusProto::Ascii => {
                let mut frame = Vec::new();
                let mut buf = [0u8; 1];
                loop {
                    self.read_exact(&mut buf)?;
                    frame.push(buf[0]);
                    if buf[0] == b'\n' {
                        break;
                    }
                }
                Ok(frame)
            }
        }
    }
}

fn send_and_receive(
    transport: &mut Transport,
    proto: ModbusProto,
    req_bin: &[u8],
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let actual_resp = if proto == ModbusProto::Ascii {
        let mut ascii_req = Vec::new();
        generate_ascii_frame(req_bin, &mut ascii_req).map_err(|e| format!("{:?}", e))?;
        transport.write_all(&ascii_req)?;

        let ascii_resp = transport.read_response(proto)?;
        let mut binary_resp = [0u8; 1024];
        let bytes_parsed = parse_ascii_frame(&ascii_resp, ascii_resp.len(), &mut binary_resp, 0)
            .map_err(|e| format!("{:?}", e))?;
        binary_resp[..bytes_parsed as usize].to_vec()
    } else {
        transport.write_all(req_bin)?;
        transport.read_response(proto)?
    };
    Ok(actual_resp)
}

fn send_and_check(
    transport: &mut Transport,
    proto: ModbusProto,
    req_bin: &[u8],
    mreq: &ModbusRequest,
) -> Result<(), Box<dyn std::error::Error>> {
    let resp_bin = send_and_receive(transport, proto, req_bin)?;
    mreq.parse_ok(&resp_bin).map_err(|e| format!("{:?}", e))?;
    Ok(())
}

fn run_tests(transport: &mut Transport, proto: ModbusProto) -> Result<(), Box<dyn std::error::Error>> {
    let mut mreq = ModbusRequest::new(1, proto);

    println!("1. Testing Read/Write Coils...");
    // Write single coil
    {
        let mut req = Vec::new();
        mreq.generate_set_coil(0, true, &mut req).map_err(|e| format!("{:?}", e))?;
        send_and_check(transport, proto, &req, &mreq)?;

        let mut req = Vec::new();
        mreq.generate_get_coils(0, 1, &mut req).map_err(|e| format!("{:?}", e))?;
        let resp = send_and_receive(transport, proto, &req)?;
        let mut coils = Vec::new();
        mreq.parse_bool(&resp, &mut coils).map_err(|e| format!("{:?}", e))?;
        assert_eq!(coils, vec![true]);
    }

    // Write multiple coils
    {
        let mut req = Vec::new();
        mreq.generate_set_coils_bulk(5, &[true, false, true, true], &mut req).map_err(|e| format!("{:?}", e))?;
        send_and_check(transport, proto, &req, &mreq)?;

        let mut req = Vec::new();
        mreq.generate_get_coils(5, 4, &mut req).map_err(|e| format!("{:?}", e))?;
        let resp = send_and_receive(transport, proto, &req)?;
        let mut coils = Vec::new();
        mreq.parse_bool(&resp, &mut coils).map_err(|e| format!("{:?}", e))?;
        assert_eq!(coils, vec![true, false, true, true]);
    }

    println!("2. Testing Read Discrete Inputs...");
    {
        let mut req = Vec::new();
        mreq.generate_get_discretes(0, 4, &mut req).map_err(|e| format!("{:?}", e))?;
        let resp = send_and_receive(transport, proto, &req)?;
        let mut inputs = Vec::new();
        mreq.parse_bool(&resp, &mut inputs).map_err(|e| format!("{:?}", e))?;
        assert_eq!(inputs, vec![true, false, true, false]);
    }

    println!("3. Testing Holding Registers...");
    // Write single register
    {
        let mut req = Vec::new();
        mreq.generate_set_holding(10, 42, &mut req).map_err(|e| format!("{:?}", e))?;
        send_and_check(transport, proto, &req, &mreq)?;

        let mut req = Vec::new();
        mreq.generate_get_holdings(10, 1, &mut req).map_err(|e| format!("{:?}", e))?;
        let resp = send_and_receive(transport, proto, &req)?;
        let mut regs = Vec::new();
        mreq.parse_u16(&resp, &mut regs).map_err(|e| format!("{:?}", e))?;
        assert_eq!(regs, vec![42]);
    }

    // Write multiple registers
    {
        let mut req = Vec::new();
        mreq.generate_set_holdings_bulk(20, &[100, 200, 300], &mut req).map_err(|e| format!("{:?}", e))?;
        send_and_check(transport, proto, &req, &mreq)?;

        let mut req = Vec::new();
        mreq.generate_get_holdings(20, 3, &mut req).map_err(|e| format!("{:?}", e))?;
        let resp = send_and_receive(transport, proto, &req)?;
        let mut regs = Vec::new();
        mreq.parse_u16(&resp, &mut regs).map_err(|e| format!("{:?}", e))?;
        assert_eq!(regs, vec![100, 200, 300]);
    }

    println!("4. Testing Input Registers...");
    {
        let mut req = Vec::new();
        mreq.generate_get_inputs(0, 2, &mut req).map_err(|e| format!("{:?}", e))?;
        let resp = send_and_receive(transport, proto, &req)?;
        let mut regs = Vec::new();
        mreq.parse_u16(&resp, &mut regs).map_err(|e| format!("{:?}", e))?;
        assert_eq!(regs, vec![1234, 5678]);
    }

    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("Usage: client <tcp|rtu-over-tcp|rtu|ascii> <address/serial_port>");
        std::process::exit(1);
    }

    let mode = &args[1];
    let path_or_addr = &args[2];

    let (mut transport, proto) = match mode.as_str() {
        "tcp" => {
            let stream = TcpStream::connect(path_or_addr)?;
            stream.set_read_timeout(Some(Duration::from_secs(5)))?;
            (Transport::Tcp(stream), ModbusProto::TcpUdp)
        }
        "rtu-over-tcp" => {
            let stream = TcpStream::connect(path_or_addr)?;
            stream.set_read_timeout(Some(Duration::from_secs(5)))?;
            (Transport::Tcp(stream), ModbusProto::Rtu)
        }
        "rtu" => {
            let mut port = serial2::SerialPort::open(path_or_addr, |mut settings: serial2::Settings| {
                settings.set_raw();
                settings.set_baud_rate(19200)?;
                settings.set_char_size(serial2::CharSize::Bits8);
                settings.set_parity(serial2::Parity::None);
                settings.set_stop_bits(serial2::StopBits::One);
                settings.set_flow_control(serial2::FlowControl::None);
                Ok(settings)
            })?;
            port.set_read_timeout(Duration::from_secs(5))?;
            (Transport::Serial(port), ModbusProto::Rtu)
        }
        "ascii" => {
            let mut port = serial2::SerialPort::open(path_or_addr, |mut settings: serial2::Settings| {
                settings.set_raw();
                settings.set_baud_rate(19200)?;
                settings.set_char_size(serial2::CharSize::Bits8);
                settings.set_parity(serial2::Parity::None);
                settings.set_stop_bits(serial2::StopBits::One);
                settings.set_flow_control(serial2::FlowControl::None);
                Ok(settings)
            })?;
            port.set_read_timeout(Duration::from_secs(5))?;
            (Transport::Serial(port), ModbusProto::Ascii)
        }
        _ => {
            eprintln!("Invalid mode: {}", mode);
            std::process::exit(1);
        }
    };

    run_tests(&mut transport, proto)?;
    println!("ALL TESTS PASSED");
    Ok(())
}
