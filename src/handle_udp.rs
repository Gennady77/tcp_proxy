use dashmap::{DashMap, mapref::one::RefMut};
use tokio::{io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, copy}, net::{TcpStream, UdpSocket}, sync::{Mutex, mpsc::{Receiver, UnboundedReceiver, unbounded_channel}}, time::timeout};
use tracing::{debug, error, warn};
use std::{cmp::min, collections::{BTreeMap, HashMap, VecDeque}, error::Error, fmt::Display, net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4}, sync::mpsc::Sender, task::{Poll, Waker}, time::Duration};
use rand::Rng;
use std::sync::Arc;
use std::sync::Mutex as StdMutex;

use crate::net_packet_parser::{IpTcpPacket, Ipv4TcpPacket, Packet, RawIpPacket, TcpFlags, TcpPacket, get_ack_data_response, get_ack_response, get_handshake_response, net_packet_parser};

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

struct TcpConnect {
    stream: TcpStream,
}

struct ReadHalf<'a>(&'a mut Vec<u8>);
struct WriteHalf<'a>(&'a mut Vec<u8>);

impl<'a> AsyncRead for ReadHalf<'a>{
    fn poll_read(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let read_buffer = &mut this.0;

        if read_buffer.is_empty() {
            return Poll::Pending;
        }

        let available = read_buffer.len();
        let to_read = min(available, buf.remaining());

        let dst = buf.initialize_unfilled_to(to_read);
        dst.copy_from_slice(&read_buffer[..to_read]);
        buf.advance(to_read);

        read_buffer.drain(..to_read);

        Poll::Ready(Ok(()))
    }
}

impl<'a> AsyncWrite for WriteHalf<'a>{
    fn poll_write(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        let write_buffer = & mut this.0;

        let bytes_to_write = buf.len();

        write_buffer.extend_from_slice(buf);

        Poll::Ready(Ok(bytes_to_write))
    }

    fn poll_flush(self: std::pin::Pin<&mut Self>, _cx: &mut std::task::Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let write_buffer = &mut this.0;

        if write_buffer.is_empty() {
            Poll::Ready(Ok(()))
        } else {
            Poll::Pending
        }
    }

    fn poll_shutdown(self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<std::io::Result<()>> {
        match self.poll_flush(cx) {
            Poll::Ready(Ok(())) => {
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }
}

struct TcpStateMachine {
    app_buffer: VecDeque<u8>,
    destination_addr: Ipv4Addr,
    destination_port: u16,
    destination_socket_addr: SocketAddr,
    mss: u16,
    out_of_order_buffer: BTreeMap<u32, Vec<u8>>,
    rcv_ack: u32,
    rcv_seq: u32,
    rcv_timestamp: u32,
    rcv_wnd: u32,
    read_buffer: Vec<u8>,
    snd_ack: u32,
    snd_seq: u32,
    snd_wnd: u16,
    snd_wnd_scl: u8,
    socket: Arc<UdpSocket>,
    socket_addr: SocketAddr,
    source_addr: Ipv4Addr,
    source_port: u16,
    state: TcpState,
    wnd_scl: u8,
    wnd_size: u32,
    write_buffer: Vec<u8>,
}

impl TcpStateMachine {
    fn new(
        socket: Arc<UdpSocket>,
        socket_addr: SocketAddr,
        source_addr: Ipv4Addr,
        source_port: u16,
        destination_addr: Ipv4Addr,
        destination_port: u16,
    ) -> Self {
        let mut rng = rand::rng();

        let destination_socket_addr = SocketAddr::V4(
            SocketAddrV4::new(destination_addr, destination_port)
        );

        let sm = Self {
            app_buffer: VecDeque::new(),
            destination_addr,
            destination_port,
            destination_socket_addr,
            mss: 65535,
            out_of_order_buffer: BTreeMap::new(),
            rcv_ack: 0,
            rcv_seq: 0,
            rcv_timestamp: 0,
            rcv_wnd: 0,
            read_buffer: Vec::new(),
            snd_ack: 0,
            snd_seq: rng.next_u32(),
            snd_wnd: 65535,
            snd_wnd_scl: 6,
            socket,
            socket_addr,
            source_addr,
            source_port,
            state: TcpState::Close,
            wnd_scl: 0,
            wnd_size: 0,
            write_buffer: Vec::new(),
        };

        sm
    }

    fn is_closed(&self) -> bool {
        match self.state {
            TcpState::Close => true,
            _ => false
        }
    }

    fn split(&mut self) -> (ReadHalf<'_>, WriteHalf<'_>) {
        (ReadHalf(&mut self.read_buffer), WriteHalf(&mut self.write_buffer))
    }

    async fn send_syn_ack_packet(&self, packet: Ipv4TcpPacket) -> Result<(), std::io::Error> {
        debug!("===send_syn_ack_packet==== {}", packet.destination_socket_addr());

        let wnd_size = (self.wnd_size >> self.wnd_scl) as u16;

        let syn_ack_packet = get_handshake_response(
            self.snd_ack,
            self.source_addr,
            self.source_port,
            self.mss,
            self.snd_seq,
            self.destination_addr,
            self.destination_port,
            self.rcv_timestamp,
            self.wnd_scl,
            wnd_size,
        )?;

        send_response(&syn_ack_packet, &self.socket, self.socket_addr).await?;

        Ok(())
    }

    async fn handle_data_in_established(&mut self, packet: Ipv4TcpPacket) -> Result<(), std::io::Error> {
        let seq_num = packet.sequence_number();
        let data = packet.payload();

        debug!("========== handle_data_in_established seq_num {}", seq_num);

        if seq_num == self.snd_ack {
            self.process_in_order_data(packet).await?;
        } else if seq_num > self.snd_ack {
            self.buffer_out_of_order_data(seq_num, data);
        } else {
            warn!("Duplicate unordered segment from the past (SEQ={} < ack={})", seq_num, self.snd_ack);
        }

        Ok(())
    }

    async fn process_in_order_data(&mut self, packet: Ipv4TcpPacket) -> Result<(), std::io::Error> {
        let data = packet.payload();
        let push_flag = packet.psh();

        debug!("===process_in_order_data==== {} {} psh {}", packet.destination_socket_addr(), self.app_buffer.len(), push_flag);

        self.app_buffer.extend(data.as_slice());

        self.drain_out_of_order_buffer();

        if push_flag {
            self.send_ack().await?;

            let data_buff: Vec<u8> = self.app_buffer.drain(..self.app_buffer.len()).collect();

            self.read_buffer.extend(data_buff);
        }
        Ok(())
    }

    async fn send_ack(&self) -> Result<(), std::io::Error> {
        let wnd_size = (self.wnd_size >> self.wnd_scl) as u16;

        let raw_response = get_ack_response(
            self.snd_ack, 
            self.destination_addr,
            self.destination_port,
            self.snd_seq, 
            self.source_addr, 
            self.source_port,
            self.rcv_timestamp,
            wnd_size,
        )?;

        send_response(&raw_response, &self.socket, self.socket_addr).await?;

        Ok(())
    }

    fn drain_out_of_order_buffer(&mut self) {
        let mut next_seq = self.rcv_seq;

        while let Some(data) = self.out_of_order_buffer.remove(&next_seq) {
            debug!("===drain_out_of_order_buffer==== {}", next_seq);
            self.app_buffer.extend(data.as_slice());
            next_seq = next_seq.wrapping_add(data.len() as u32);
        }

        if next_seq != self.rcv_seq {
            self.rcv_seq = next_seq;
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

    async fn process_event(&mut self, packet: Ipv4TcpPacket) -> Result<(), std::io::Error> {
        let old_state = self.state;

        debug!("===process_event==== {} {}", packet.destination_socket_addr(), packet.sequence_number());

        let event = packet_to_event(packet.tcp());

        match (old_state, event.clone()) {
            (TcpState::Listen, TcpEvent::SegmentArrives(flags)) if flags.syn && !flags.ack => {
                self.mss = packet.options().mss.min(self.mss);
                self.wnd_scl = packet.options().window_scale;
                self.wnd_size = (65535) << self.wnd_scl;
                self.rcv_seq = packet.sequence_number();
                self.rcv_ack = packet.acknowledgment_number();
                self.rcv_wnd = (packet.window_size() << self.wnd_scl) as u32;
                self.rcv_timestamp = packet.options().timestamp.0;
                self.snd_ack = self.rcv_seq.wrapping_add(1);

                self.send_syn_ack_packet(packet).await?;

                self.snd_seq = self.snd_seq.wrapping_add(1);

                self.state = TcpState::SynReceived;
            }
            (TcpState::SynReceived, TcpEvent::SegmentArrives(flags)) if !flags.syn && flags.ack => {
                self.rcv_seq = packet.sequence_number();
                self.rcv_ack = packet.acknowledgment_number();
                self.rcv_wnd = (packet.window_size() << self.wnd_scl) as u32;
                self.rcv_timestamp = packet.options().timestamp.0;
                self.state = TcpState::Established;
            }
            (TcpState::Established, TcpEvent::DataArrives) => {
                self.rcv_seq = packet.sequence_number();
                self.rcv_ack = packet.acknowledgment_number();
                self.rcv_timestamp = packet.options().timestamp.0;
                self.snd_ack = self.rcv_seq.wrapping_add(packet.payload().len() as u32);
                self.wnd_size = self.wnd_size.wrapping_div(packet.payload().len() as u32);
                self.rcv_wnd = (packet.window_size() << self.wnd_scl) as u32;

                self.handle_data_in_established(packet).await?;
            }
            (TcpState::Established, TcpEvent::SegmentArrives(flags)) if !flags.syn && flags.ack => {
                debug!("Data confirmation processing {} ack_num {}", packet.destination_socket_addr(), packet.acknowledgment_number());
            }
            (_, TcpEvent::RstArrives) => {
                debug!("process_event TcpEvent::RstArrives {} {}", packet.destination_socket_addr(), packet.sequence_number());

                self.state = TcpState::Close;
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

        Ok(())
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
    tcp_states: HashMap<String, Arc<Mutex<TcpStateMachine>>>,
}

impl IpOverUdpServer {
    async fn new(bind_addr: &str) -> Result<Self, Box<dyn Error>> {
        let socket = UdpSocket::bind(bind_addr).await?;

        Ok(Self {
            socket: Arc::new(socket),
            tcp_states: HashMap::new(),
        })
    }

    async fn run(&mut self) -> Result<Arc<Mutex<TcpStateMachine>>, Box<dyn Error>>{
        loop {
            let mut buffer = [0u8; 65535];

            let socket_cloned = Arc::clone(&self.socket);

            match socket_cloned.recv_from(&mut buffer).await {
                Ok((n, socket_addr)) => {
                    debug!("===== Received {} from {}", n, socket_addr);

                    let raw_ip_packet = buffer[..n].to_vec();

                    match self.handle_ip_packet(raw_ip_packet, socket_addr).await {
                        Ok(Some(sm)) => {
                            return Ok(sm);
                        },
                        Ok(None) => continue,
                        Err(e) => {
                            error!("Handle ip packet error {e}");
                            continue;
                        }
                    };
                },
                Err(e) => {
                    error!("Recieve socket error: {}", e);
                }
            }
        }
    }

    async fn handle_ip_packet<'a>(
        &mut self,
        raw_ip_packet: Vec<u8>,
        socket_addr: SocketAddr
    ) -> Result<Option<Arc<Mutex<TcpStateMachine>>>, Box<dyn Error>> {
        match net_packet_parser(&raw_ip_packet) {
            Some(Packet::Ipv6Tcp(ip_v6_tcp_packet)) => {
                warn!("Received ipv6/tcp from udp {}", ip_v6_tcp_packet);
            },
            Some(Packet::Ipv4Tcp(ip_tcp_packet)) => {
                debug!("Received ipv4/tcp from udp {}", ip_tcp_packet);

                let state_machine = self.handle_ipv4_tcp_packet(
                    ip_tcp_packet,
                    socket_addr,
                ).await?;

                return Ok(state_machine);
            },
            None => {
                warn!("Failed to parse packet");
            },
            _ => {
                warn!("Some unknown net/transport packet");
            }
        }

        Ok(None)
    }

    async fn handle_ipv4_tcp_packet(
        &mut self,
        packet: Ipv4TcpPacket,
        socket_addr: SocketAddr,
    ) -> Result<Option<Arc<Mutex<TcpStateMachine>>>, std::io::Error> {
        let destination_socket_addr = packet.destination_socket_addr();
        let seq_num = packet.sequence_number();

        debug!("===handle_ip_tcp_packet==== {} {}", destination_socket_addr.clone(), seq_num);
        debug!("===handle_ip_tcp_packet==== syn {}, ack {}", packet.syn(), packet.ack());

        if packet.syn() && !packet.ack() {
            let socket = Arc::clone(&self.socket);
            let mut state_machine = TcpStateMachine::new(
                socket,
                socket_addr,
                packet.ip.source_address,
                packet.tcp.source_port,
                packet.ip.destination_address,
                packet.tcp.destination_port,
            );
            state_machine.state = TcpState::Listen;

            state_machine.process_event(packet).await?;

            let sm = Arc::new(Mutex::new(state_machine));

            start_sender(sm.clone());

            self.tcp_states.insert(destination_socket_addr.clone(), sm.clone());

            return Ok(Some(sm));
        }

        let state_machine = match self.tcp_states.get(&destination_socket_addr) {
            Some(val) => val.clone(),
            None => {
                return Ok(None);
            }
        };

        debug!("===handle_ip_tcp_packet try get lock state machine==== {} {}", destination_socket_addr.clone(), seq_num);

        // let mut state_machine_guard = state_machine.lock().await;

        debug!("===handle_ip_tcp_packet got lock state machine==== {} {}", destination_socket_addr.clone(), seq_num);

        let mut state_machine_guard = state_machine.lock().await;

        state_machine_guard.process_event(packet).await?;

        Ok(None)
    }
}

fn start_sender(state_machine: Arc<Mutex<TcpStateMachine>>) {

    let state_machine_clone = Arc::clone(&state_machine);

    tokio::spawn(async move {
        loop {
            let mut sm_guard = state_machine_clone.lock().await;

            while !sm_guard.write_buffer.is_empty() && sm_guard.rcv_wnd > 0 {

                let send_size = (sm_guard.mss as u32)
                    .min(sm_guard.rcv_wnd)
                    .min(sm_guard.write_buffer.len() as u32) as usize;

                if send_size == 0 { break; }

                let send_data: Vec<u8> = sm_guard.write_buffer.drain(0..send_size).collect();

                let is_last = sm_guard.write_buffer.is_empty();

                sm_guard.wnd_size = sm_guard.wnd_size.saturating_sub(send_size as u32);
                let win_size = (sm_guard.wnd_size >> sm_guard.wnd_scl) as u16;

                let raw_packet = get_ack_data_response(
                    sm_guard.snd_ack,
                    sm_guard.destination_addr,
                    sm_guard.destination_port,
                    send_data.clone(),
                    is_last,
                    sm_guard.snd_seq,
                    sm_guard.source_addr,
                    sm_guard.source_port,
                    sm_guard.rcv_timestamp,
                    win_size,
                ).unwrap();

                if let Err(e) = send_response(&raw_packet, &sm_guard.socket, sm_guard.socket_addr).await {
                    error!("Failed to send response {}", e);
                    continue;
                }

                sm_guard.snd_seq = sm_guard.snd_seq.wrapping_add(send_size as u32);
            }

            tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
        }
    });
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

pub async fn handle_upd() -> Result<(), Box<dyn Error>> {
    let mut server = IpOverUdpServer::new("0.0.0.0:8090").await?;

    loop {
        let state_maschine = server.run().await?;

        let state_maschine_clone = state_maschine.clone();

        tokio::spawn(async move {
            debug!("############### handle_upd thread try lock state_machine");
            let mut state_machine_guard = state_maschine_clone.lock().await;

            let addr = state_machine_guard.destination_socket_addr;

            debug!("############### handle_upd thread got lock state_machine {}", addr);

            match TcpStream::connect(addr).await {
                Ok(mut destination_connect) => {
                    let (mut read_destination, mut wright_destination) = destination_connect.split();
                    let (mut read_client, mut write_client) = state_machine_guard.split();

                    tokio::select! {
                        _ = copy(&mut read_client, &mut wright_destination) => {}
                        _ = copy(&mut read_destination, &mut write_client) => {}
                    }
                }
                Err(e) => {
                    error!("Connection error to target: {}", e);
                }
            }

            debug!("############### handle_upd thread drop lock state_machine {}", addr);
        });
    }
}
