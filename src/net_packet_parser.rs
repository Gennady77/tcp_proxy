use core::fmt;
use std::{fmt::Display, net::{Ipv4Addr, Ipv6Addr}, time::{SystemTime, UNIX_EPOCH}};

use etherparse::{IpHeaders, IpNumber, NetSlice, PacketBuilder, PacketBuilderStep, SlicedPacket, TcpHeader, TcpOptionElement, TcpOptions, TransportSlice, err::io};
use rand::Rng;
use tracing::{debug, error};

pub type RawIpPacket = Vec<u8>;

pub enum NetPacket {
    Ipv4(Ipv4Packet),
    Ipv6(Ipv6Packet),
    Arp(ArpPacket),
    Unknown,
}

pub enum TransportPacket {
    Tcp(TcpPacket),
    Icmpv4(Icmpv4Packet),
    Icmpv6(Icmpv6Packet),
    Udp(UdpPacket),
    Unknown,
}

pub enum Packet {
    Ipv4Tcp(Ipv4TcpPacket),
    Ipv6Tcp(Ipv6TcpPacket),
    Unknown,
}

#[derive(Clone)]
pub struct Ipv4Packet {
    pub version: u8,
    pub ihl: u8,
    pub protocol: IpNumber,
    pub source_address: Ipv4Addr,
    pub destination_address: Ipv4Addr,
}

pub struct Ipv6Packet {
    pub source_addr: Ipv6Addr,
    pub destination_addr: Ipv6Addr,
}

pub struct ArpPacket {}

#[derive(Clone, Copy)]
pub struct TcpFlags {
    pub syn: bool,
    pub psh: bool,
    pub ack: bool,
    pub fin: bool,
    pub rst: bool
}

#[derive(Clone, Copy)]
pub struct TcpPacketOptions {
    pub mss: u16,
    pub window_scale: u8,
    pub selective_ack_permitted: bool,
    pub timestamp: (u32, u32),
}

impl Display for TcpPacketOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "mss {}, ws {}, sack {}, tstmp ({},{})",
            self.mss,
            self.window_scale,
            self.selective_ack_permitted,
            self.timestamp.0,
            self.timestamp.1,
        )
    }
}

#[derive(Clone)]
pub struct TcpPacket{
    pub source_port: u16,
    pub destination_port: u16,
    pub sequence_number: u32,
    pub acknowledgment_number: u32,
    pub ack: bool,
    pub psh: bool,
    pub rst: bool,
    pub syn: bool,
    pub fin: bool,
    pub window_size: u16,
    pub payload: Vec<u8>,
    pub options: TcpPacketOptions,
    pub flags: TcpFlags,
}

impl<'a> Display for TcpPacket {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "seqNum {}, ackNum {}, ack {}, psh {}, rst {}, syn {}, fin {}, wnd {}, payloadLen {}, options: [{}], payload {:?}",
            self.sequence_number,
            self.acknowledgment_number,
            self.ack,
            self.psh,
            self.rst,
            self.syn,
            self.fin,
            self.window_size,
            self.payload.len(),
            self.options,
            self.payload.get(..7).unwrap_or(&[])
        )
    }
}

pub struct Icmpv4Packet {}

pub struct Icmpv6Packet {}

pub struct UdpPacket {
    pub payload: Vec<u8>
}

pub trait IpTcpPacket {
    fn build_ip_packet(&self) -> PacketBuilderStep<IpHeaders>;
    fn source_socket_addr(&self) -> String;
    fn destination_socket_addr(&self) -> String;
    fn sequence_number(&self) -> u32;
    fn source_port(&self) -> u16;
    fn destination_port(&self) -> u16;
    fn acknowledgment_number(&self) -> u32;
    fn window_size(&self) -> u16;
    fn get_raw_handshake_response(&self, seq_num: u32, wnd_scl: u8) -> Result<(RawIpPacket, u32), std::io::Error> {
        let curr_timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u32;

        let options = vec![
            TcpOptionElement::MaximumSegmentSize(self.options().mss),
            TcpOptionElement::WindowScale(wnd_scl),
            TcpOptionElement::Timestamp(curr_timestamp, self.options().timestamp.0)
        ];

        let ack = self.sequence_number().wrapping_add(1);

        let builder = self.build_ip_packet()
            .tcp(
                self.destination_port(),
                self.source_port(),
                seq_num,
                65535
            )
            .syn()
            .ack(ack);

        let builder_with_options = builder.options(options.as_slice()).map_err(|e| {
            std::io::Error::new(std::io::ErrorKind::Other, e)
        })?;

        let mut buffer = Vec::<u8>::with_capacity(builder_with_options.size(0));
        let payload = Vec::<u8>::new();

        builder_with_options.write(&mut buffer, &payload).unwrap();

        Ok((buffer, ack))
    }
    fn get_ack_response(&self, seq_num: u32, ack_num: u32, win_size: u32, wnd_scl: u8) -> Result<(RawIpPacket, u32), std::io::Error> {
        let curr_timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u32;

        let options = vec![
            TcpOptionElement::MaximumSegmentSize(self.options().mss),
            TcpOptionElement::WindowScale(0),
            TcpOptionElement::Timestamp(curr_timestamp, self.options().timestamp.0)
        ];

        let builder = self.build_ip_packet()
            .tcp(
                self.destination_port(),
                self.source_port(),
                self.acknowledgment_number(),
                (win_size >> wnd_scl) as u16,
            )
            .ack(ack_num);

        let builder_with_options = builder.options(options.as_slice()).map_err(|e| {
            std::io::Error::new(std::io::ErrorKind::Other, e)
        })?;

        let mut buffer = Vec::<u8>::with_capacity(builder_with_options.size(0));
        let payload = Vec::<u8>::new();

        builder_with_options.write(&mut buffer, &payload).unwrap();

        Ok((buffer, ack_num))
    }
    fn get_ack_data_response(&self,
        payload: Vec<u8>,
        win_size: u16,
        seq_num: u32,
        ack_num: u32,
        mss: u16,
        wnd_scl: u8,
        psh: bool,
    ) -> Result<RawIpPacket, std::io::Error> {
        let curr_timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u32;

        let options = vec![
            TcpOptionElement::MaximumSegmentSize(mss),
            TcpOptionElement::WindowScale(wnd_scl),
            TcpOptionElement::Timestamp(curr_timestamp, self.options().timestamp.0)
        ];

        let mut builder = self.build_ip_packet()
            .tcp(
                self.destination_port(),
                self.source_port(),
                seq_num,
                win_size,
            )
            .ack(ack_num);

        if psh {
            builder = builder.psh();
        }

        let builder_with_options = builder.options(options.as_slice()).map_err(|e| {
            std::io::Error::new(std::io::ErrorKind::Other, e)
        })?;

        let mut buffer = Vec::<u8>::with_capacity(builder_with_options.size(payload.len()));

        builder_with_options.write(&mut buffer, &payload).map_err(|e| {
            std::io::Error::new(std::io::ErrorKind::Other, e)
        })?;

        Ok(buffer)
    }
    fn syn(&self) -> bool;
    fn ack(&self) -> bool;
    fn psh(&self) -> bool;
    fn rst(&self) -> bool;
    fn fin(&self) -> bool;
    fn options(&self) -> TcpPacketOptions;
    fn payload(&self) -> Vec<u8>;
    fn tcp(&self) -> TcpPacket;
}

#[derive(Clone)]
pub struct Ipv4TcpPacket {
    pub ip: Ipv4Packet,
    pub tcp: TcpPacket,
}

impl IpTcpPacket for Ipv4TcpPacket {
    fn build_ip_packet(&self) -> PacketBuilderStep<IpHeaders> {
        PacketBuilder::
        ipv4(
            self.ip.destination_address.octets(),
            self.ip.source_address.octets(),
            64
        )
    }
    fn source_socket_addr(&self) -> String {
        format!("{}:{}", self.ip.source_address, self.tcp.source_port)
    }
    fn destination_socket_addr(&self) -> String {
        format!("{}:{}", self.ip.destination_address, self.tcp.destination_port)
    }
    fn sequence_number(&self) -> u32 {
        self.tcp.sequence_number
    }
    fn acknowledgment_number(&self) -> u32 {
        self.tcp.acknowledgment_number
    }
    fn source_port(&self) -> u16 {
        self.tcp.source_port
    }
    fn destination_port(&self) -> u16 {
        self.tcp.destination_port
    }
    fn window_size(&self) -> u16 {
        self.tcp.window_size
    }
    fn syn(&self) -> bool {
        self.tcp.syn
    }
    fn ack(&self) -> bool {
        self.tcp.ack
    }
    fn psh(&self) -> bool {
        self.tcp.psh
    }
    fn rst(&self) -> bool {
        self.tcp.rst
    }
    fn fin(&self) -> bool {
        self.tcp.fin
    }
    fn payload(&self) -> Vec<u8> {
        self.tcp.payload.clone()
    }
    fn options(&self) -> TcpPacketOptions {
        self.tcp.options
    }
    fn tcp(&self) -> TcpPacket {
        self.tcp.clone()
    }
}

impl<'a> Display for Ipv4TcpPacket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "version {}, ihl {}, protocol {}, source {}, dest {}, {}",
            self.ip.version,
            self.ip.ihl,
            self.ip.protocol.keyword_str().unwrap_or("unknown"),
            self.source_socket_addr(),
            self.destination_socket_addr(),
            self.tcp
        )
    }
}

pub struct Ipv6TcpPacket {
    pub ip: Ipv6Packet,
    pub tcp: TcpPacket
}

impl<'a> IpTcpPacket for Ipv6TcpPacket {
    fn build_ip_packet(&self) -> PacketBuilderStep<IpHeaders> {
        PacketBuilder::
        ipv6(
            self.ip.destination_addr.octets(),
            self.ip.source_addr.octets(),
            64
        )
    }
    fn destination_socket_addr(&self) -> String {
        format!("[{}]:{}", self.ip.destination_addr, self.tcp.destination_port)
    }
    fn source_socket_addr(&self) -> String {
        format!("[{}]:{}", self.ip.source_addr, self.tcp.source_port)
    }
    fn sequence_number(&self) -> u32 {
        self.tcp.sequence_number
    }
    fn acknowledgment_number(&self) -> u32 {
        self.tcp.acknowledgment_number
    }
    fn source_port(&self) -> u16 {
        self.tcp.source_port
    }
    fn window_size(&self) -> u16 {
        self.tcp.window_size
    }
    fn destination_port(&self) -> u16 {
        self.tcp.destination_port
    }
    fn syn(&self) -> bool {
        self.tcp.syn
    }
    fn ack(&self) -> bool {
        self.tcp.ack
    }
    fn psh(&self) -> bool {
        self.tcp.psh
    }
    fn rst(&self) -> bool {
        self.tcp.rst
    }
    fn fin(&self) -> bool {
        self.tcp.fin
    }
    fn options(&self) -> TcpPacketOptions {
        self.tcp.options
    }
    fn payload(&self) -> Vec<u8> {
        self.tcp.payload.clone()
    }
    fn tcp(&self) -> TcpPacket {
        self.tcp.clone()
    }
}

impl Display for Ipv6TcpPacket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "source {}, dest {}, {}",
            self.source_socket_addr(),
            self.destination_socket_addr(),
            self.tcp
        )
    }
}

pub fn net_packet_parser(raw_ip_packet: &[u8]) -> Option<Packet> {
    match SlicedPacket::from_ip(&raw_ip_packet) {
        Ok(sliced_packet) => {
            let net_packet: NetPacket = match &sliced_packet.net {
                Some(NetSlice::Ipv4(ipv4_slice )) => {
                    NetPacket::Ipv4(Ipv4Packet {
                        version: ipv4_slice.header().version(),
                        ihl: ipv4_slice.header().ihl(),
                        protocol: ipv4_slice.header().protocol(),
                        source_address: ipv4_slice.header().source_addr(),
                        destination_address: ipv4_slice.header().destination_addr()
                    })
                },
                Some(NetSlice::Ipv6(ipv6_slice)) => {
                    NetPacket::Ipv6(Ipv6Packet {
                        source_addr: ipv6_slice.header().source_addr(),
                        destination_addr: ipv6_slice.header().destination_addr(),
                    })
                },
                Some(NetSlice::Arp(_arp_slice)) => NetPacket::Arp(ArpPacket {}),
                None => NetPacket::Unknown,
            };

            let transport_packet: TransportPacket = match &sliced_packet.transport {
                Some(TransportSlice::Tcp(tcp_slice)) => {
                    let mut tcp_options = TcpPacketOptions {
                        mss: 0,
                        window_scale: 0,
                        selective_ack_permitted: false,
                        timestamp: (0,0)
                    };
                    let tcp_options_iterator = tcp_slice.options_iterator();

                    for option_result in tcp_options_iterator {
                        match option_result {
                            Ok(option) => match option {
                                TcpOptionElement::MaximumSegmentSize(mss) => {
                                    tcp_options.mss = mss;
                                },
                                TcpOptionElement::WindowScale(scale) => {
                                    tcp_options.window_scale = scale;
                                },
                                TcpOptionElement::SelectiveAcknowledgementPermitted => {
                                    tcp_options.selective_ack_permitted = true;
                                }
                                TcpOptionElement::Timestamp(ts, ts_echo) => {
                                    tcp_options.timestamp = (ts, ts_echo);
                                },
                                TcpOptionElement::Noop => {},
                                _ => error!("Other option: {:?}", option)
                            }
                            Err(e) => {
                                error!("Error parsing option: {}", e);
                            }
                        }
                    }

                    TransportPacket::Tcp(TcpPacket {
                        source_port: tcp_slice.source_port(),
                        destination_port: tcp_slice.destination_port(),
                        sequence_number: tcp_slice.sequence_number(),
                        acknowledgment_number: tcp_slice.acknowledgment_number(),
                        ack: tcp_slice.ack(),
                        psh: tcp_slice.psh(),
                        rst: tcp_slice.rst(),
                        syn: tcp_slice.syn(),
                        fin: tcp_slice.fin(),
                        window_size: tcp_slice.window_size(),
                        options: tcp_options,
                        payload: tcp_slice.payload().to_vec(),
                        flags: TcpFlags {
                            ack: tcp_slice.ack(),
                            psh: tcp_slice.psh(),
                            rst: tcp_slice.rst(),
                            syn: tcp_slice.syn(),
                            fin: tcp_slice.fin(),
                        },
                    })
                },
                Some(TransportSlice::Icmpv4(_icmpv4_slice)) => {
                    TransportPacket::Icmpv4(Icmpv4Packet {})
                },
                Some(TransportSlice::Icmpv6(_icmpv6_slice)) => {
                    TransportPacket::Icmpv6(Icmpv6Packet {})
                },
                Some(TransportSlice::Udp(udp_slice)) => {
                    TransportPacket::Udp(UdpPacket {
                        payload: udp_slice.payload().to_vec()
                    })
                },
                None => TransportPacket::Unknown
            };

            let packet = match (net_packet, transport_packet) {
                (NetPacket::Ipv4(ipv4_packet), TransportPacket::Tcp(tcp_packet)) => 
                    Packet::Ipv4Tcp(Ipv4TcpPacket {
                        ip: ipv4_packet,
                        tcp: tcp_packet,
                    }),
                (NetPacket::Ipv4(ipv4_packet), TransportPacket::Udp(udp_packet)) => {
                    debug!("================ ipv4/udp packet");

                    Packet::Unknown
                }
                (NetPacket::Ipv6(ipv6_packet), TransportPacket::Tcp(tcp_packet)) => 
                    Packet::Ipv6Tcp(Ipv6TcpPacket {
                        ip: ipv6_packet,
                        tcp: tcp_packet
                    }),
                _ => Packet::Unknown,
            };

            return Some(packet);
        }
        Err(e) => {
            error!("[net_packet_parser] failed to slice packet: {}", e);

            return None;
        },
    }
}