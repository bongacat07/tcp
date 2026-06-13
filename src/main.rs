use tcp::protocol::ACK;
use tcp::protocol::RST;
use tun_rs::DeviceBuilder;
use tun_rs::InterruptEvent;
use rand::Rng;
use std::time::Duration;
use std::io::ErrorKind;
use tcp::{
    parser, tcp_parser, ip_checksum, tcp_checksum, create_packet,check_flags,print_ipv4,print_ipv6,print_tcp,send_ack,send_fin,send_rst,
    Packet, Ipv4Packet, Ipv6Header, TCPPacket,
    TCPState, Ipv4Header, Ipv4HeaderFields, TCPHeader,TCB,ConnectionKey
};
use std::collections::HashMap;
use std::collections::HashSet;




/*
 * This is just me creating a TUN device. To greatly simplify things
 * this is the interface "through" which I "recieve" or "send" raw IP packets
 */
fn main() {
    let dev = DeviceBuilder::new()
        .name("tun0") //name
        .ipv4("10.0.0.12", 24, None) //Ip address
        .mtu(1500)
        .build_sync()
        .unwrap();

    dev.set_nonblocking(true).unwrap();
    let event = InterruptEvent::new().unwrap();
    let mut buf = [0u8; 65535];
    let mut connections: HashMap<ConnectionKey, TCB> = HashMap::new();
    let mut listener: HashSet<u16> = HashSet::new();
    listener.insert(8080);

    loop {
         match dev.recv_intr_timeout(&mut buf, &event, Some(Duration::from_millis(100)))  {
            Ok(len) => {
                let packet = parser(&buf[..len]);

                match packet {
                    Packet::IPv4(h) => {
                        print_ipv4(&h);

                        if h.header.fields.protocol != 6 {
                            continue;
                        }

                        let packet = tcp_parser(&h.payload);

                        if let Some(tcp) = packet {
                            print_tcp(&tcp);



                            let key = ConnectionKey{
                                src_ip: h.header.fields.source,
                                src_port: tcp.header.src_port,
                                dst_ip:h.header.fields.destination,
                                dst_port:tcp.header.dst_port

                            };


                            if let Some(tcb) = connections.get_mut(&key) {
                                let flags = tcp.header.flags;

                                if check_flags(&flags,RST){
                                    connections.remove(&key);
                                    println!("RST received, connection aborted");
                                    continue;
                                }

                                match tcb.state {
                                    TCPState::SynReceived => {
                                        if check_flags(&flags, ACK) {


                                            if tcp.header.ack_num == tcb.snd_nxt {
                                                tcb.state = TCPState::Established;
                                                tcb.snd_una = tcp.header.ack_num;

                                                println!("Handshake complete");
                                            } else {
                                                println!("Invalid ACK");
                                                send_rst(&dev, &h.header.fields, &tcp.header);
                                                continue;
                                            }


                                        }
                                        else {
                                                send_rst(&dev, &h.header.fields, &tcp.header);
                                                connections.remove(&key);
                                                continue;
                                            }
                                    }
                                        TCPState::SynSent     => { println!("SynSent: TODO"); continue; }
                                        TCPState::Established => {
                                            if flags & 0x02 != 0 {
                                                println!("Duplicate SYN in Established");
                                                send_rst(&dev, &h.header.fields, &tcp.header);
                                                connections.remove(&key);
                                                continue;
                                            }

                                            if flags & 0x18 == 0x18 {

                                            }
                                            if flags & 0x01 != 0 {
                                                if tcp.header.seq_num == tcb.rcv_nxt {
                                                    println!("Fin Recieved");
                                                    tcb.rcv_nxt+=1;
                                                    send_ack(&dev, &h.header.fields, &tcp.header, tcb.snd_nxt, tcb.rcv_nxt);
                                                    tcb.state = TCPState::CloseWait;
                                                }
                                            }
                                        }
                                        TCPState::FinWait1    => { println!("FinWait1: TODO"); continue; }
                                        TCPState::FinWait2    => { println!("FinWait2: TODO"); continue; }
                                        TCPState::CloseWait   => {
                                            send_fin(&dev, &h.header.fields, &tcp.header, tcb.snd_nxt, tcb.rcv_nxt);
                                            tcb.snd_nxt += 1;
                                            tcb.state = TCPState::LastAck;


                                        }
                                        TCPState::Closing     => { println!("Closing: TODO"); continue; }
                                        TCPState::LastAck => {
                                            if (flags & 0x10) != 0 && (flags & 0x02) == 0 {
                                                if tcp.header.ack_num == tcb.snd_nxt {
                                                    println!("Last ACK received, connection closed");
                                                    connections.remove(&key);
                                                } else {
                                                    println!("Invalid ACK");
                                                    send_rst(&dev, &h.header.fields, &tcp.header);
                                                }
                                            }
                                        }
                                        TCPState::TimeWait    => { println!("TimeWait: TODO"); continue; }
                                        TCPState::Closed      => { connections.remove(&key); continue; }
                                }
                            }
                            else{
                                if !listener.contains(&tcp.header.dst_port){
                                    let recv_ip = &h.header.fields;
                                    let recv_tcp = &tcp.header;
                                    send_rst(&dev, &h.header.fields, &tcp.header);
                                    continue;
                                }
                                let flags = tcp.header.flags;
                                if (flags & 0x02) != 0 && (flags & 0x10) == 0 {
                                    let recv_ip = &h.header.fields;
                                    let recv_tcp = &tcp.header;
                                    let iss: u32 = rand::random();
                                    let mut tcp_packet = TCPPacket {
                                        header: TCPHeader {
                                            src_port: recv_tcp.dst_port,
                                            dst_port: recv_tcp.src_port,
                                            seq_num: iss,
                                            ack_num: recv_tcp.seq_num + 1,
                                            data_offset: 5,
                                            flags: 0x12,
                                            window: 64240,
                                            checksum: 0,
                                            urgent_ptr: 0,
                                        },
                                        payload: vec![],
                                    };

                                    let ip_fields = Ipv4HeaderFields {
                                        version: 4,
                                        ihl: 5,
                                        tos: 0,
                                        total_length: 40,
                                        identification: 0,
                                        flags: 0,
                                        fragment_offset: 0,
                                        ttl: 64,
                                        protocol: 6,
                                        source: recv_ip.destination,
                                        destination: recv_ip.source,
                                    };

                                    let ip_chk = ip_checksum(&ip_fields);
                                    let tcp_chk = tcp_checksum(
                                        recv_ip.destination,
                                        recv_ip.source,
                                        &tcp_packet,
                                    );
                                    tcp_packet.header.checksum = tcp_chk;

                                    let ip_header = Ipv4Header {
                                        fields: ip_fields,
                                        header_checksum: ip_chk,
                                    };
                                    connections.insert(
                                     key,
                                        TCB {
                                            state: TCPState::SynReceived,

                                            iss,
                                            snd_una: iss,
                                            snd_nxt: iss + 1,

                                            irs: tcp.header.seq_num,
                                            rcv_nxt: tcp.header.seq_num + 1,
                                        }
                                    );
                                    let packet = create_packet(&tcp_packet, &ip_header);
                                    dev.send(&packet);


                                    println!("SYN received, SYN-ACK sent");
                                }
                                else {
                                    send_rst(&dev, &h.header.fields, &tcp.header);
                                }
                            }



                        }
                    }

                    Packet::IPv6(h) => {
                        print_ipv6(&h);
                    }

                    Packet::Unknown => {
                        println!("Unknown packet");
                    }
                }
            }
            Err(e) if e.kind() == ErrorKind::TimedOut => {
                println!("100 ms passed, no packet arrived");

            }
                    Err(e) if e.kind() == ErrorKind::Interrupted => {

                                break;
                            }
            Err(e) => {
                eprintln!("recv error: {}", e);
            }
        }
    }
}
