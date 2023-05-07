use pnet::datalink::interfaces;
use pnet::packet::icmp::echo_request::MutableEchoRequestPacket;
use pnet::packet::icmp::{IcmpPacket, IcmpTypes};
use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet};
use pnet::packet::tcp::{TcpPacket, MutableTcpPacket, TcpFlags, TcpOption};
use pnet::packet::udp::{MutableUdpPacket, UdpPacket};
use pnet::packet::{MutablePacket, Packet};
use pnet::transport::TransportSender;
use pnet::transport::{icmp_packet_iter, transport_channel, TransportChannelType::Layer3};
use pnet::util;
use rand::Rng;
use std::net::ToSocketAddrs;
use std::net::{IpAddr, Ipv4Addr};
use std::process::exit;
use std::time::Duration;

static IPV4_HEADER_LEN: usize = 21;
static ICMP_HEADER_LEN: usize = 8;
static ICMP_PAYLOAD_LEN: usize = 32;

fn create_icmp_packet<'a>(
    buf_ip: &'a mut [u8],
    buf_icmp: &'a mut [u8],
    dest: Ipv4Addr,
    ttl: u8,
    sequence_number: u16,
) -> (MutableIpv4Packet<'a>, u16) {
    let mut ipv4_packet = MutableIpv4Packet::new(buf_ip).expect("Error creating ipv4 packet");
    ipv4_packet.set_version(4);
    ipv4_packet.set_header_length(IPV4_HEADER_LEN as u8);
    ipv4_packet.set_total_length((IPV4_HEADER_LEN + ICMP_HEADER_LEN + ICMP_PAYLOAD_LEN) as u16);
    ipv4_packet.set_ttl(ttl);
    ipv4_packet.set_next_level_protocol(IpNextHeaderProtocols::Icmp);
    ipv4_packet.set_destination(dest);

    let mut icmp_packet =
        MutableEchoRequestPacket::new(buf_icmp).expect("Error creating icmp packet");
    icmp_packet.set_icmp_type(IcmpTypes::EchoRequest);
    icmp_packet.set_sequence_number(sequence_number);
    let checksum = util::checksum(&icmp_packet.packet_mut(), 1);
    icmp_packet.set_checksum(checksum);
    ipv4_packet.set_payload(icmp_packet.packet_mut());

    (ipv4_packet, checksum)
}

fn create_udp_packet<'a>(
    buf_ip: &'a mut [u8],
    buf_udp: &'a mut [u8],
    src: Ipv4Addr, // For checksum
    dest: Ipv4Addr,
    ttl: u8,
    payload: &[u8],
    dest_port: u16,
) -> (MutableIpv4Packet<'a>, u16) {
    let mut ipv4_packet = MutableIpv4Packet::new(buf_ip).expect("Error creating ipv4 packet");
    ipv4_packet.set_version(4);
    ipv4_packet.set_header_length(IPV4_HEADER_LEN as u8);
    ipv4_packet.set_total_length((IPV4_HEADER_LEN + ICMP_HEADER_LEN + ICMP_PAYLOAD_LEN) as u16);
    ipv4_packet.set_ttl(ttl);
    ipv4_packet.set_next_level_protocol(IpNextHeaderProtocols::Udp);
    ipv4_packet.set_destination(dest);

    let mut rng = rand::thread_rng();

    let mut udp_packet: MutableUdpPacket = MutableUdpPacket::new(buf_udp).expect("Error creating UDP packet");
    udp_packet.set_destination(465);
    udp_packet.set_source(rng.gen_range(30000..63000));
    udp_packet.set_length(32 + 8);
    udp_packet.set_payload(payload);
    let udp_checksum = pnet::packet::udp::ipv4_checksum(&udp_packet.to_immutable(), &src, &dest);
    udp_packet.set_checksum(udp_checksum);

    ipv4_packet.set_payload(udp_packet.packet_mut());

    (ipv4_packet, udp_checksum)
}

fn create_tcp_packet<'a>(
    buf_ip: &'a mut [u8],
    buf_tcp: &'a mut [u8],
    src: Ipv4Addr, // For checksum
    dest: Ipv4Addr,
    ttl: u8,
    // payload: &[u8],
    dest_port: u16,
) -> (MutableIpv4Packet<'a>, u16) {
    let mut ipv4_packet = MutableIpv4Packet::new(buf_ip).expect("Error creating ipv4 packet");
    ipv4_packet.set_version(4);
    ipv4_packet.set_header_length(IPV4_HEADER_LEN as u8);
    ipv4_packet.set_total_length((IPV4_HEADER_LEN + ICMP_HEADER_LEN + ICMP_PAYLOAD_LEN) as u16);
    ipv4_packet.set_ttl(ttl);
    ipv4_packet.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
    ipv4_packet.set_destination(dest);

    let mut rng = rand::thread_rng();

    let mut tcp_packet = MutableTcpPacket::new(buf_tcp).expect("Error creating TCP packet");
    tcp_packet.set_destination(443);
    tcp_packet.set_source(rng.gen_range(30000..63000));
    // tcp_packet.set_payload(payload);
    tcp_packet.set_flags(TcpFlags::SYN);
    tcp_packet.set_data_offset(40);
    let tcp_checksum = pnet::packet::tcp::ipv4_checksum(&tcp_packet.to_immutable(), &src, &dest);
    tcp_packet.set_checksum(tcp_checksum);

    ipv4_packet.set_payload(tcp_packet.packet_mut());

    (ipv4_packet, tcp_checksum)
}

fn send_icmp_probe(ttl: u8, _: Ipv4Addr, dst_ip: Ipv4Addr, tx: &mut TransportSender) -> u16 {
    let mut buf_ip = [0u8; 60];
    let mut buf_icmp = [0u8; 40];

    let (icmp_packet, icmp_checksum) = create_icmp_packet(
        &mut buf_ip,
        &mut buf_icmp,
        dst_ip.into(),
        ttl,
        1,
    );

    tx.send_to(icmp_packet, dst_ip.into()).unwrap();

    icmp_checksum
}

fn send_udp_probe(ttl: u8, src_ip: Ipv4Addr, dst_ip: Ipv4Addr, tx: &mut TransportSender) -> u16 {
    let mut buf_ip = [0u8; 60];
    let mut buf_udp = [0u8; 40];
    let mut udp_payload = [0u8; 32];

    rand::thread_rng().fill(&mut udp_payload);

    let target_port = 80u16;

    let (udp_packet, udp_checksum) = create_udp_packet(
        &mut buf_ip,
        &mut buf_udp,
        src_ip.into(),
        dst_ip.into(),
        ttl,
        udp_payload.as_slice(),
        target_port - 1 + ttl as u16,
    );

    tx.send_to(udp_packet, dst_ip.into()).unwrap();

    udp_checksum
}

fn send_tcp_probe(ttl: u8, src_ip: Ipv4Addr, dst_ip: Ipv4Addr, tx: &mut TransportSender) -> u16 {
    let mut buf_ip = [0u8; 60];
    let mut buf_tcp = [0u8; 40];
    // let mut tcp_payload = [0u8; 32];

    // rand::thread_rng().fill(&mut tcp_payload);

    let target_port = 80u16;

    let (tcp_packet, tcp_checksum) = create_tcp_packet(
        &mut buf_ip,
        &mut buf_tcp,
        src_ip.into(),
        dst_ip.into(),
        ttl,
        // tcp_payload.as_slice(),
        target_port - 1 + ttl as u16,
    );

    tx.send_to(tcp_packet, dst_ip.into()).unwrap();

    tcp_checksum
}

fn get_transport_sender(probe_type: TracerouteProbeType) -> TransportSender {
    let protocol = Layer3(match probe_type {
        TracerouteProbeType::UDP => IpNextHeaderProtocols::Udp,
        TracerouteProbeType::TCP => IpNextHeaderProtocols::Tcp,
        TracerouteProbeType::ICMP => IpNextHeaderProtocols::Icmp,
    });
    let (mut tx, _) = transport_channel(2 << 15, protocol)
        .map_err(|err| format!("Error opening the channel: {}", err))
        .unwrap();
    tx
}

fn get_src_ip(tx: &TransportSender) -> Ipv4Addr {
    let addr = nix::sys::socket::getsockname::<nix::sys::socket::SockaddrStorage>(tx.socket.fd);
    let ip = addr.unwrap().as_sockaddr_in().unwrap().ip();

    let mut src_ip = "0.0.0.0".parse::<Ipv4Addr>().unwrap();

    if ip != 0 {
        src_ip = Ipv4Addr::from(ip);
    } else {
        let all_interfaces = interfaces();
        let default_interface = all_interfaces
            .iter()
            .find(|e| e.is_up() && !e.is_loopback() && !e.ips.is_empty())
            .unwrap();
        default_interface.ips.to_owned().iter_mut().for_each(|ip| {
            if ip.is_ipv4() {
                src_ip = ip.to_string().split("/").collect::<Vec<&str>>()[0]
                    .parse::<Ipv4Addr>()
                    .unwrap();
            }
        });
    }

    src_ip
}

#[derive(Clone, Copy)]
pub enum TracerouteProbeType {
    UDP,
    ICMP,
    TCP,
}

pub struct Params {
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    tx: TransportSender,
}

fn traceroute(dest: IpAddr, probe_type: TracerouteProbeType) -> Vec<Option<Ipv4Addr>> {
    let timeout = std::time::Duration::from_millis(500);
    // dest

    let (_, mut rx) = transport_channel(2 << 15, Layer3(IpNextHeaderProtocols::Icmp))
        .map_err(|err| format!("Error opening the channel: {}", err))
        .unwrap();

    let mut tx = get_transport_sender(probe_type);
    let src_ip = get_src_ip(&tx);
    let dst_ip = dest.to_string().parse::<Ipv4Addr>().unwrap();
    // let params = Params {
    //     src_ip,
    //     dst_ip,
    //     tx,
    // };

    let mut rx = icmp_packet_iter(&mut rx);

    let mut done = false;
    for ttl in 1..30 {
        if done {
            break;
        }

        let n_retransmissions = 3;
        for i in 0..n_retransmissions - 1 {

            let last_checksum = match probe_type {
                TracerouteProbeType::UDP => send_udp_probe(ttl, src_ip, dst_ip, &mut tx),
                TracerouteProbeType::TCP => send_tcp_probe(ttl, src_ip, dst_ip, &mut tx),
                TracerouteProbeType::ICMP => send_icmp_probe(ttl, src_ip, dst_ip, &mut tx),
            };
            
            match rx.next_with_timeout(timeout).unwrap() {
                Some((packet, ip)) => {
                    // packet.
                    let mut payload = Vec::from(packet.payload());
                    payload.drain(0..16);

                    let icmp_packet = IcmpPacket::new(payload.as_slice()).unwrap();
                    let mut icmp_payload = Vec::from(icmp_packet.payload());
                    icmp_payload.drain(0..4);
                    let ip_packet = Ipv4Packet::new(icmp_payload.as_slice());
                    if let Some(ip_packet) = ip_packet {
                        let inner_payload = Vec::from(ip_packet.payload());

                        let inner_packet_checksum = match probe_type {
                            TracerouteProbeType::UDP => {
                                let mut checksum = 0u16;
                                let p = UdpPacket::new(inner_payload.as_slice());
                                if let Some(p) = p {
                                    checksum = p.get_checksum();
                                }
                                checksum
                            }
                            TracerouteProbeType::TCP => {
                                let mut checksum = 0u16;
                                let p = TcpPacket::new(inner_payload.as_slice());
                                if let Some(p) = p {
                                    checksum = p.get_checksum();
                                }
                                checksum
                            }
                            TracerouteProbeType::ICMP => {
                                let mut checksum = 0u16;
                                let p = IcmpPacket::new(inner_payload.as_slice());
                                if let Some(p) = p {
                                    checksum = p.get_checksum();
                                }
                                checksum
                            }
                        };
                        // println!("IP: {:#?}", ip);

                        if inner_packet_checksum == last_checksum || ip.to_string() == dest.to_string() {
                            println!("{} - {:#?}", ttl, ip);
                            if ip.to_string() == dest.to_string() {
                                done = true;
                            }
                            break;
                        }
                    }
                }
                None => {
                    println!("{} - *.*.*.*", ttl);
                }
            }
        }
    }
    vec![]
}

fn main() {
    let addrs_iter = "bohemiajazzcafe.com:80".to_socket_addrs();
    if addrs_iter.is_err() {
        println!("Could not find address.");
        exit(1);
    }
    let mut addrs_iter = addrs_iter.unwrap();

    // // println!("{:#?}", addrs_iter.next());
    match addrs_iter.next() {
        Some(addr) => {
            println!("Address found: {}", addr.ip());
            traceroute(addr.ip(), TracerouteProbeType::UDP);
        }
        None => {
            println!("Unexpected.");
        }
    }
    // for interface in pnet::datalink::interfaces() {
    //     println!("interface ips: ");
    //     for ip in interface.ips {
    //         println!("\t ip: {}", ip);
    //     }
    //     // println!("{}", interface.ips);
    // }
    // ping("127.0.0.1".parse::<Ipv4Addr>().unwrap());
}
