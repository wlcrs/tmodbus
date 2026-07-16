use std::error::Error;
use std::net::SocketAddr;
use tokio_modbus::client::{Reader, Writer};
use tokio_modbus::prelude::*;

async fn run_tests<C>(ctx: &mut C) -> Result<(), Box<dyn Error>>
where
    C: Reader + Writer,
{
    println!("1. Testing Read/Write Coils...");
    // Write single coil
    ctx.write_single_coil(0, true).await?.unwrap();
    let val = ctx.read_coils(0, 1).await?.unwrap();
    assert_eq!(val, vec![true]);

    ctx.write_single_coil(0, false).await?.unwrap();
    let val = ctx.read_coils(0, 1).await?.unwrap();
    assert_eq!(val, vec![false]);

    // Write multiple coils
    ctx.write_multiple_coils(5, &[true, false, true, true]).await?.unwrap();
    let vals = ctx.read_coils(5, 4).await?.unwrap();
    assert_eq!(vals, vec![true, false, true, true]);

    println!("2. Testing Read Discrete Inputs...");
    let discrete = ctx.read_discrete_inputs(0, 4).await?.unwrap();
    assert_eq!(discrete, vec![true, false, true, false]);

    println!("3. Testing Holding Registers...");
    println!("  - Write Single Register...");
    ctx.write_single_register(10, 42).await?.unwrap();
    println!("  - Read Single Register...");
    let val = ctx.read_holding_registers(10, 1).await?.unwrap();
    assert_eq!(val, vec![42]);

    println!("  - Write Multiple Registers...");
    ctx.write_multiple_registers(20, &[100, 200, 300]).await?.unwrap();
    println!("  - Read Multiple Registers...");
    let vals = ctx.read_holding_registers(20, 3).await?.unwrap();
    assert_eq!(vals, vec![100, 200, 300]);

    println!("4. Testing Input Registers...");
    println!("  - Read Input Registers...");
    let inputs = ctx.read_input_registers(0, 2).await?.unwrap();
    assert_eq!(inputs, vec![1234, 5678]);

    println!("5. Testing Mask Write Register...");
    println!("  - Write Single Register...");
    ctx.write_single_register(30, 0x0012).await?.unwrap();
    println!("  - Mask Write Register...");
    ctx.masked_write_register(30, 0x00F0, 0x000C).await?.unwrap();
    println!("  - Read Holding Register...");
    let val = ctx.read_holding_registers(30, 1).await?.unwrap();
    assert_eq!(val, vec![0x001C]);

    println!("6. Testing Read/Write Multiple Registers...");
    println!("  - Read/Write Multiple Registers...");
    let read_vals = ctx.read_write_multiple_registers(20, 3, 40, &[999, 888]).await?.unwrap();
    assert_eq!(read_vals, vec![100, 200, 300]);
    println!("  - Read Holding Registers...");
    let written_vals = ctx.read_holding_registers(40, 2).await?.unwrap();
    assert_eq!(written_vals, vec![999, 888]);

    println!("7. Testing Read Device Identification...");
    let response = ctx.read_device_identification(ReadCode::Basic, 0).await?.unwrap();
    assert_eq!(response.read_code, ReadCode::Basic);
    assert_eq!(response.conformity_level, ConformityLevel::BasicIdentificationStreamOnly);
    assert_eq!(response.more_follows, false);
    assert_eq!(response.next_object_id, 0);
    assert_eq!(response.device_id_objects.len(), 3);
    assert_eq!(response.device_id_objects[0].id, 0);
    assert_eq!(response.device_id_objects[0].value_as_str().unwrap(), "wlcrs");
    assert_eq!(response.device_id_objects[1].id, 1);
    assert_eq!(response.device_id_objects[1].value_as_str().unwrap(), "TMB");
    assert_eq!(response.device_id_objects[2].id, 2);
    assert_eq!(response.device_id_objects[2].value_as_str().unwrap(), "1.0");

    println!("All tests passed successfully!");
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("Usage: tokio-client <protocol> <addr/port>");
        std::process::exit(1);
    }

    let protocol = &args[1];
    let conn_arg = &args[2];

    match protocol.as_str() {
        "tcp" => {
            let socket_addr: SocketAddr = conn_arg.parse()?;
            println!("Connecting via TCP to {}...", socket_addr);
            let mut ctx = tcp::connect_slave(socket_addr, Slave(1)).await?;
            run_tests(&mut ctx).await?;
        }
        "rtu-over-tcp" => {
            let socket_addr: SocketAddr = conn_arg.parse()?;
            println!("Connecting via RTU-over-TCP to {}...", socket_addr);
            let stream = tokio::net::TcpStream::connect(socket_addr).await?;
            let mut ctx = rtu::attach_slave(stream, Slave(1));
            run_tests(&mut ctx).await?;
        }
        "rtu" => {
            println!("Connecting via RTU to {}...", conn_arg);
            let builder = tokio_serial::new(conn_arg, 19200);
            let port = tokio_serial::SerialStream::open(&builder)?;
            let mut ctx = rtu::attach_slave(port, Slave(1));
            run_tests(&mut ctx).await?;
        }
        _ => {
            eprintln!("Unknown protocol: {}", protocol);
            std::process::exit(1);
        }
    }

    Ok(())
}
