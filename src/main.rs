use tun_rs::DeviceBuilder;
pub mod parser;
use parser::{parser, Packet};

fn main() {



    let dev = DeviceBuilder::new()
        .name("tun0")
        .ipv4("10.0.0.12", 24, None)
        .mtu(1500)
        .build_sync()
        .unwrap();

    let mut buf = [0; 65535];
    loop {
        match dev.recv(&mut buf) {
            Ok(len) => {
                println!("Received packet");
                let packet = parser(&buf);

                match packet {
                    Packet::IPv4(h) => {
                        println!("--- IPv4 Packet ---");
                        println!("Version: {}", h.version);
                        println!("IHL: {}", h.ihl);
                        println!("TOS: {}", h.tos);
                        println!("Total Length: {}", h.total_length);
                        println!("Identification: {}", h.identification);
                        println!("Flags: {}", h.flags);
                        println!("Fragment Offset: {}", h.fragment_offset);
                        println!("TTL: {}", h.ttl);
                        println!("Protocol: {}", h.protocol);
                        println!("Header Checksum: {}", h.header_checksum);
                        println!("Source: {}.{}.{}.{}",
                            h.source[0], h.source[1], h.source[2], h.source[3]);
                        println!("Destination: {}.{}.{}.{}",
                            h.destination[0], h.destination[1], h.destination[2], h.destination[3]);
                        println!("-------------------");
                    }

                    Packet::IPv6(h) => {
                        println!("--- IPv6 Packet ---");
                        println!("Version: {}", h.version);
                        println!("Traffic Class: {}", h.traffic_class);
                        println!("Flow Label: {}", h.flow_label);
                        println!("Payload Length: {}", h.payload_length);
                        println!("Next Header: {}", h.next_header);
                        println!("Hop Limit: {}", h.hop_limit);

                        print!("Source: ");
                        for (i, byte) in h.source.iter().enumerate() {
                            print!("{:02x}", byte);
                            if i % 2 == 1 && i != 15 {
                                print!(":");
                            }
                        }
                        println!();

                        print!("Destination: ");
                        for (i, byte) in h.destination.iter().enumerate() {
                            print!("{:02x}", byte);
                            if i % 2 == 1 && i != 15 {
                                print!(":");
                            }
                        }
                        println!();

                        println!("-------------------");
                    }

                    Packet::Unknown => {
                        println!("Unknown packet");
                    }
                }
            }
            Err(e) => {
                eprintln!("recv error: {}", e);
                continue; // keep running
            }
        }
    }
}
