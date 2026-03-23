use dashmap::DashMap;
use tokio::{io::{AsyncReadExt, AsyncWriteExt}, net::{TcpStream, UdpSocket}, sync::Mutex, time::timeout};
use tracing::{debug, error, warn};
use std::{collections::{BTreeMap, HashMap, VecDeque}, error::Error, fmt::Display, net::{IpAddr, SocketAddr}, time::Duration};
use rand::Rng;
use std::sync::Arc;

use crate::net_packet_parser::{IpTcpPacket, Packet, RawIpPacket, TcpFlags, TcpPacket, net_packet_parser};

#[derive(Clone, Copy)]
enum TcpState {
    Close,
    Listen,
    SynReceived,
    Established,
}

impl Display for TcpState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TcpState::Close => write!(f, "Close"),
            TcpState::Listen => write!(f, "Listen"),
            TcpState::SynReceived => write!(f, "SynReceived"),
            TcpState::Established => write!(f, "Established"),
        }
    }
}

#[derive(Clone)]
enum TcpEvent {
    OpenPassive,
    DataArrives,
    SegmentArrives(TcpFlags),
    RstArrives,
    Unknown,
}

impl Display for TcpEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TcpEvent::OpenPassive => write!(f, "OpenPassive"),
            TcpEvent::DataArrives => write!(f, "DataArrives"),
            TcpEvent::RstArrives => write!(f, "RstArrives"),
            TcpEvent::SegmentArrives(flags) => write!(f, "SegmentArrives(syn={}, psh={}, ack={}, fin={}, rst={})", flags.syn, flags.psh, flags.ack, flags.fin, flags.rst),
            TcpEvent::Unknown => write!(f, "Unknown"),
        }
    }
}

struct TcpConnection {
    stream: TcpStream,
}

struct TcpStateMachine {
    app_buffer: VecDeque<u8>,
    mss: u16,
    out_of_order_buffer: BTreeMap<u32, Vec<u8>>,
    rcv_next: u32,
    rcv_wnd: u32,
    rcv_wnd_scl: u8,
    snd_seq: u32,
    snd_seq_next: u32,
    snd_wnd: u16,
    snd_wnd_scl: u8,
    socket: Arc<UdpSocket>,
    socket_addr: SocketAddr,
    state: TcpState,
    stream: Option<TcpStream>,
}

impl TcpStateMachine {
    fn new(socket: Arc<UdpSocket>, socket_addr: SocketAddr) -> Self {
        let mut rng = rand::rng();

        Self {
            app_buffer: VecDeque::new(),
            mss: 1460,
            out_of_order_buffer: BTreeMap::new(),
            rcv_next: 0,
            rcv_wnd: 0,
            rcv_wnd_scl: 0,
            snd_seq: rng.next_u32(),
            snd_seq_next: rng.next_u32(),
            snd_wnd: 65535,
            snd_wnd_scl: 6,
            socket,
            socket_addr,
            state: TcpState::Close,
            stream: None,
        }
    }

    async fn init_stream(&mut self, dest_addr: String) -> Result<(), std::io::Error> {
        if self.stream.is_none() {
            let mut stream = TcpStream::connect(dest_addr.clone()).await?;

            tokio::spawn(async move {
                loop {
                    let mut buffer = [0u8; 65535];

                    match timeout(Duration::from_secs(5),  stream.read(&mut buffer)).await {
                        Ok(Ok(0)) => {
                            debug!("Server closed receiving data from {}", dest_addr);
                        },
                        Ok(Ok(n)) => {
                            debug!("Received data from destination {} {} bytes {:?}", dest_addr, n, buffer.to_vec().get(..6).unwrap_or(&[]));

                            self.write_all(buffer[..n].to_vec());
                        },
                        Ok(Err(error)) => {
                            error!("Failed to read response: {}", error);
                        },
                        Err(_) => {
                            warn!("Timeout waiting for data from {}, returning empty", dest_addr);
                        }
                    }
                }
            });

            self.stream = Some(stream);
        }
        Ok(())
    }

    async fn send_syn_ack_packet(&mut self, packet: Box<dyn IpTcpPacket + Send>) -> Result<(), std::io::Error> {
        debug!("===send_syn_ack_packet==== {}", packet.destination_socket_addr());

        self.rcv_wnd_scl = packet.options().window_scale;
        self.rcv_wnd = (packet.window_size() as u32) << packet.options().window_scale;

        let (syn_ack_packet, ack_num) = packet.get_raw_handshake_response(self.snd_seq, self.snd_wnd_scl)?;

        self.snd_seq_next = self.snd_seq.wrapping_add(1);
        self.rcv_next = ack_num;

        send_response(&syn_ack_packet, &self.socket, self.socket_addr).await?;

        Ok(())
    }

    fn get_rcv_wnd_size(&self, wnd_size: u16) -> u32 {
        (wnd_size as u32) << self.rcv_wnd_scl
    }

    async fn handle_data_in_established(&mut self, packet: Box<dyn IpTcpPacket + Send + Sync>) -> Result<(), std::io::Error> {
        let seq_num = packet.sequence_number();
        let data = packet.payload();
        self.rcv_wnd = self.get_rcv_wnd_size(packet.window_size());

        debug!("========== handle_data_in_established seq_num {}", seq_num);

        if seq_num == self.rcv_next {
            self.process_in_order_data(packet).await?;
        } else if seq_num > self.rcv_next {
            self.buffer_out_of_order_data(seq_num, data);
        } else {
            warn!("Duplicate unordered segment from the past (SEQ={} < rcv_nxt={})", seq_num, self.rcv_next);
        }

        Ok(())
    }

    async fn process_in_order_data(&mut self, packet: Box<dyn IpTcpPacket + Send + Sync>) -> Result<(), std::io::Error> {
        let data = packet.payload();
        let push_flag = packet.psh();

        debug!("===process_in_order_data==== {} {} psh {}", packet.destination_socket_addr(), self.app_buffer.len(), push_flag);

        self.app_buffer.extend(data.as_slice());
        self.rcv_next = self.rcv_next.wrapping_add(data.len() as u32);

        self.drain_out_of_order_buffer();

        if push_flag {
            self.send_ack(&packet).await?;
            self.push_to_application(packet).await?;
        }

        Ok(())
    }

    async fn write_all(&self, data: Vec<u8>) -> Result<(), std::io::Error> {
        while !data.is_empty() && self.snd_wnd > 0 {
            let send_size = (self.mss as u32)
                .min(self.rcv_wnd)
                .min(data.len() as u32) as usize;

            if send_size == 0 { break; }

            let send_data: Vec<u8> = data.drain(0..send_size).collect();

            let is_last = data.is_empty();

            let raw_packet = packet.get_ack_data_response(
                send_data.clone(),
                self.snd_wnd,
                self.snd_seq_next,
                self.rcv_next,
                self.mss,
                self.snd_wnd_scl,
                is_last,
            )?;

            send_response(&raw_packet, &self.socket, self.socket_addr).await?;

            self.snd_seq_next = self.snd_seq_next.wrapping_add(send_size as u32);
            self.rcv_wnd = self.rcv_wnd.saturating_sub(send_size as u32);
        }

        Ok(())
    }

    async fn push_to_application(&mut self, packet: Box<dyn IpTcpPacket + Send + Sync>) -> Result<(), std::io::Error> {
        let stream = self.stream.take().ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::NotConnected, "TcpStream not initialized")
        })?;

        let data = self.app_buffer.drain(..self.app_buffer.len()).collect();

        match transfer_to_destination(stream, data, packet.destination_socket_addr()).await {
            Ok((Some(mut raw_response), returned_stream)) => {
                while !raw_response.is_empty() && self.snd_wnd > 0 {
                    let send_size = (self.mss as u32)
                        .min(self.rcv_wnd)
                        .min(raw_response.len() as u32) as usize;

                    if send_size == 0 { break; }

                    let data: Vec<u8> = raw_response.drain(0..send_size).collect();

                    let is_last = raw_response.is_empty();

                    let raw_packet = packet.get_ack_data_response(
                        data.clone(),
                        self.snd_wnd,
                        self.snd_seq_next,
                        self.rcv_next,
                        self.mss,
                        self.snd_wnd_scl,
                        is_last,
                    )?;

                    send_response(&raw_packet, &self.socket, self.socket_addr).await?;

                    self.snd_seq_next = self.snd_seq_next.wrapping_add(send_size as u32);
                    self.rcv_wnd = self.rcv_wnd.saturating_sub(send_size as u32);
                }

                self.stream = Some(returned_stream);
            }
            Ok((None, returned_stream)) => {
                debug!("There no data to transfer to {} {}", packet.destination_socket_addr(), packet.sequence_number());

                self.stream = Some(returned_stream);
            },
            Err(e) => {
                return Err(e);
            }
        }

        Ok(())
    }

    async fn send_ack(&self, packet: &Box<dyn IpTcpPacket + Send + Sync>) -> Result<(), std::io::Error> {
        let win_size = (self.snd_wnd << self.snd_wnd_scl) as u32 - self.app_buffer.len() as u32;
        let (raw_request, _) = packet.get_ack_response(self.snd_seq_next, self.rcv_next, win_size, self.snd_wnd_scl)?;

        send_response(&raw_request, &self.socket, self.socket_addr).await?;

        Ok(())
    }

    fn drain_out_of_order_buffer(&mut self) {
        let mut next_seq = self.rcv_next;

        while let Some(data) = self.out_of_order_buffer.remove(&next_seq) {
            debug!("===drain_out_of_order_buffer==== {}", next_seq);
            self.app_buffer.extend(data.as_slice());
            next_seq = next_seq.wrapping_add(data.len() as u32);
        }

        if next_seq != self.rcv_next {
            self.rcv_next = next_seq;
        }
    }

    fn buffer_out_of_order_data(&mut self, seq_num: u32, data: Vec<u8>) {
        debug!("===buffer_out_of_order_data==== {}", seq_num);

        if !self.out_of_order_buffer.contains_key(&seq_num) {
            self.out_of_order_buffer.insert(seq_num, data);
        } else {
            warn!("Duplicate unordered segment SEQ={}", seq_num);
        }
    }

    async fn process_event(&mut self, packet: Box<dyn IpTcpPacket + Send + Sync>) -> Result<bool, std::io::Error> {
        let old_state = self.state;

        debug!("===process_event==== {} {}", packet.destination_socket_addr(), packet.sequence_number());

        let event = packet_to_event(packet.tcp());

        match (old_state, event.clone()) {
            (TcpState::Listen, TcpEvent::SegmentArrives(flags)) if flags.syn && !flags.ack => {
                self.mss = packet.options().mss.min(self.mss);
                self.rcv_wnd_scl = packet.options().window_scale;
                self.send_syn_ack_packet(packet).await?;
                self.state = TcpState::SynReceived;
            }
            (TcpState::SynReceived, TcpEvent::SegmentArrives(flags)) if !flags.syn && flags.ack => {
                self.rcv_next = packet.sequence_number();
                self.state = TcpState::Established;
            }
            (TcpState::Established, TcpEvent::DataArrives) => {
                self.handle_data_in_established(packet).await?;
            }
            (TcpState::Established, TcpEvent::SegmentArrives(flags)) if !flags.syn && flags.ack => {
                debug!("Data confirmation processing {} ack_num {}", packet.destination_socket_addr(), packet.acknowledgment_number());
            }
            (_, TcpEvent::RstArrives) => {
                debug!("process_event TcpEvent::RstArrives {} {}", packet.destination_socket_addr(), packet.sequence_number());

                self.state = TcpState::Close;

                self.stream.take();

                return Ok(true);
            },
            (_, TcpEvent::Unknown) => {
                debug!("++++++ process_event TcpEvent::Unknown");
            }
            _ => {
                error!("Invalid state/event combination event {}, state {}", event, old_state);
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "Invalid state/event combination"
                ));
            }
        };

        Ok(false)
    }
}

fn packet_to_event(packet: TcpPacket) -> TcpEvent {
    match packet {
        p if !p.payload.is_empty() => TcpEvent::DataArrives,
        p if p.flags.rst => TcpEvent::RstArrives,
        p if p.flags.fin => TcpEvent::SegmentArrives(p.flags),
        p if p.payload.is_empty() => TcpEvent::SegmentArrives(p.flags),
        _ => TcpEvent::Unknown,
    }
}

struct IpOverUdpServer {
    socket: Arc<UdpSocket>,
    tcp_connects: Arc<DashMap<IpAddr, TcpConnection>>,
    tcp_states: Arc<DashMap<IpAddr, Mutex<TcpStateMachine>>>
}

impl IpOverUdpServer {
    async fn new(bind_addr: &str) -> Result<Self, Box<dyn Error>> {
        let socket = UdpSocket::bind(bind_addr).await?;

        Ok(Self {
            socket: Arc::new(socket),
            tcp_states: Arc::new(DashMap::new()),
        })
    }

    async fn run(&mut self) -> Result<(), Box<dyn Error>>{
        loop {
            let mut buffer = [0u8; 65535];

            let socket_cloned = Arc::clone(&self.socket);

            match socket_cloned.recv_from(&mut buffer).await {
                Ok((n, socket_addr)) => {
                    debug!("===== Received {} from {}", n, socket_addr);

                    let raw_ip_packet = buffer[..n].to_vec();
                    let connects_cloned = Arc::clone(&self.tcp_states);
                    let socket_addr_cloned = socket_addr.clone();
                    let socket_cloned = Arc::clone(&self.socket);

                    tokio::spawn(async move {
                        let _ = handle_ip_packet(
                            raw_ip_packet,
                            socket_cloned,
                            connects_cloned,
                            socket_addr_cloned,
                        ).await;
                    });
                },
                Err(e) => {
                    error!("Recieve socket error: {}", e);
                }
            }
        }
    }
}

async fn handle_ip_packet<'a>(
    raw_ip_packet: Vec<u8>,
    socket: Arc<UdpSocket>,
    connects: Arc<DashMap<IpAddr, Mutex<TcpStateMachine>>>,
    socket_addr: SocketAddr
) -> Result<(), Box<dyn Error>> {
    match net_packet_parser(&raw_ip_packet) {
        Some(Packet::Ipv6Tcp(ip_v6_tcp_packet)) => {
            debug!("Received ipv6/tcp from udp {}", ip_v6_tcp_packet);

            let dest_addr = IpAddr::V6(ip_v6_tcp_packet.ip.destination_addr);
            let connects_cloned = Arc::clone(&connects);
            handle_ip_tcp_packet(
                Box::new(ip_v6_tcp_packet),
                socket,
                socket_addr,
                dest_addr,
                connects_cloned,
            ).await?;
        },
        Some(Packet::Ipv4Tcp(ip_tcp_packet)) => {
            debug!("Received ipv4/tcp from udp {}", ip_tcp_packet);

            let dest_addr = IpAddr::V4(ip_tcp_packet.ip.destination_address);
            let connects_cloned = Arc::clone(&connects);
            handle_ip_tcp_packet(
                Box::new(ip_tcp_packet),
                socket,
                socket_addr,
                dest_addr,
                connects_cloned,
            ).await?;
        },
        None => {
            warn!("Failed to parse packet");
        },
        _ => {
            warn!("Some unknown net/transport packet");
        }
    }

    Ok(())
}

async fn handle_ip_tcp_packet(
    packet: Box<dyn IpTcpPacket + Send + Sync>,
    socket: Arc<UdpSocket>,
    socket_addr: SocketAddr,
    dest_addr: IpAddr,
    connects: Arc<DashMap<IpAddr, Mutex<TcpStateMachine>>>,
) -> Result<(), Box<dyn Error>> {
    let d_addr = packet.destination_socket_addr();
    let seq_num = packet.sequence_number();

    debug!("===handle_ip_tcp_packet==== {} {}", d_addr.clone(), seq_num);

    let state_machine = connects.entry(dest_addr).or_insert_with(|| {
        debug!("===handle_ip_tcp_packet create new connection==== {} {}", d_addr.clone(), seq_num);
        let mut state = TcpStateMachine::new(socket, socket_addr);
        state.state = TcpState::Listen;
        Mutex::new(state)
    });

    debug!("===handle_ip_tcp_packet try to lock connection==== {} {}", d_addr.clone(), seq_num);

    let mut state_machine_guard = state_machine.lock().await;

    state_machine_guard.init_stream(d_addr.clone()).await?;

    debug!("===handle_ip_tcp_packet got lock connection==== {} {}", d_addr, seq_num);


    match state_machine_guard.process_event(packet).await {
        Ok(should_remove) => {
            if should_remove {
                drop(state_machine_guard);
                connects.remove(&dest_addr);
                debug!("Connection removed from map {}", dest_addr);
            }
        }
        Err(e) => {
            error!("Error processing event for {}: {}", dest_addr, e);
            drop(state_machine_guard);
            connects.remove(&dest_addr);
        }
    }

    debug!("===handle_ip_tcp_packet drop lock connection==== {} {}", d_addr, seq_num);

    Ok(())
}

async fn send_response(
    response_raw: &Vec<u8>,
    socket: &UdpSocket,
    addr: SocketAddr
) -> Result<(), std::io::Error> {
    debug!("===start send to socket==== {}", addr);

    if let Err(e) = socket.send_to(response_raw.as_slice(), addr).await {
        error!("Failed to send answer to udp socket: {}", e);

        return Err(std::io::Error::new(std::io::ErrorKind::Other, e.to_string()));
    }

    dump_raw_packet(response_raw, "+++++ Sent packet to socket");

    return Ok(())
}

fn dump_raw_packet(raw_packet: &RawIpPacket, prefix: &str) {
    match net_packet_parser(&raw_packet) {
        Some(Packet::Ipv4Tcp(parsed_response)) => {
            debug!("{} Ipv4Tcp packet {}", prefix, parsed_response);
        },
        Some(Packet::Ipv6Tcp(parsed_response)) => {
            debug!("{} Ipv6Tcp packet {}", prefix, parsed_response);
        },
        Some(Packet::Unknown) => {
            debug!("Unknown type of raw packet")
        }
        None => {
            debug!("Received response packet from server");
        }
    }
}

async fn transfer_to_destination<'a>(mut stream: TcpStream, payload: RawIpPacket, dest_addr: String) -> Result<(), std::io::Error> {
    stream.write_all(&payload).await?;

    debug!("Sent data to destination {} payload {}, {:?}...", dest_addr, payload.len(), payload.get(..7).unwrap_or(&[]));

    // loop {
    //     let mut buffer = [0u8; 65535];

    //     match timeout(Duration::from_secs(5),  stream.read(&mut buffer)).await {
    //         Ok(Ok(0)) => {
    //             debug!("Server closed receiving data from {}", dest_addr);
    //             return Ok((None, stream));
    //         },
    //         Ok(Ok(n)) => {
    //             debug!("Received data from destination {} {} bytes {:?}", dest_addr, n, buffer.to_vec().get(..6).unwrap_or(&[]));

    //             return Ok((Some(buffer[..n].to_vec()), stream));
    //         },
    //         Ok(Err(error)) => {
    //             error!("Failed to read response: {}", error);
    //             return Err(error);
    //         },
    //         Err(_) => {
    //             warn!("Timeout waiting for data from {}, returning empty", dest_addr);
    //             return Ok((None, stream));
    //         }
    //     }
    // }

    Ok(())
}

pub async fn handle_upd() -> Result<(), Box<dyn Error>> {
    let mut server = IpOverUdpServer::new("0.0.0.0:8090").await?;

    server.run().await?;

    Ok(())
}
