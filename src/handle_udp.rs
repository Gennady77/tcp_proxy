use tokio::{io::{AsyncRead, AsyncWrite, copy}, net::{TcpStream, UdpSocket}, sync::{Mutex, mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel}}, time::sleep};
use tracing::{debug, error, warn};
use std::{cmp::min, collections::{BTreeMap, HashMap, VecDeque}, error::Error, fmt::Display, net::{Ipv4Addr, SocketAddr, SocketAddrV4}, task::{Poll, Waker}, time::Duration};
use rand::Rng;
use std::sync::Arc;

use crate::net_packet_parser::{IpTcpPacket, Ipv4TcpPacket, Packet, RawIpPacket, TcpFlags, TcpPacket, get_ack_data_response, get_ack_response, get_handshake_response, get_reset_response, net_packet_parser};

struct ReadHalf {
    buffer: Arc<Mutex<Vec<u8>>>,
    waker: Arc<Mutex<Option<Waker>>>,
}

struct WriteHalf(Arc<Mutex<Vec<u8>>>);

struct IpUdpStream {
    destination_socket_addr: SocketAddr,
    handle: TcpHandle,
    read_buffer: Arc<Mutex<Vec<u8>>>,
    read_waker: Arc<Mutex<Option<Waker>>>,
    write_buffer: Arc<Mutex<Vec<u8>>>,
}

impl IpUdpStream {
    fn new(
        destination_socket_addr: SocketAddr,
        handle: TcpHandle,
    ) -> Self {
        Self {
            destination_socket_addr,
            handle,
            read_buffer: Arc::new(Mutex::new(Vec::new())),
            read_waker: Arc::new(Mutex::new(None)),
            write_buffer: Arc::new(Mutex::new(Vec::new())),
        }

    }

    fn split(&self) -> (ReadHalf, WriteHalf) {
        let read_buffer = self.read_buffer.clone();
        let read_waker = self.read_waker.clone();
        let write_buffer = self.write_buffer.clone();

        let read_half = ReadHalf {
            buffer: read_buffer,
            waker: read_waker,
        };

        (read_half, WriteHalf(write_buffer))
    }
}

impl AsyncWrite for WriteHalf {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        let write_buffer = this.0.clone();

        match write_buffer.try_lock() {
            Ok(mut wb) => {
                let bytes_to_write = buf.len();

                debug!("AsyncWrite poll_write write_buffer extend. buf len {}", buf.len());

                wb.extend_from_slice(buf);

                Poll::Ready(Ok(bytes_to_write))
            },
            Err(_) => Poll::Pending
        }
    }

    fn poll_flush(self: std::pin::Pin<&mut Self>, _cx: &mut std::task::Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let write_buffer = this.0.clone();

        match write_buffer.try_lock() {
            Ok(wb) => {
                if wb.is_empty() {
                    Poll::Ready(Ok(()))
                } else {
                    Poll::Pending 
                }
            },
            Err(_) => Poll::Pending 
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

impl AsyncRead for ReadHalf {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let read_buffer = self.buffer.clone();
        let waker_clone = self.waker.clone();

        match read_buffer.try_lock() {
            Ok(mut rb) => {
                let mut waker = match waker_clone.try_lock() {
                    Ok(wk) => wk,
                    Err(_) => {
                        return Poll::Pending;
                    }
                };

                if rb.is_empty() {
                    *waker = Some(cx.waker().clone());
                    return Poll::Pending;
                }

                let available = rb.len();
                let to_read = min(available, buf.remaining());

                let dst = buf.initialize_unfilled_to(to_read);
                dst.copy_from_slice(&rb[..to_read]);
                buf.advance(to_read);

                rb.drain(..to_read);

                debug!("AsyncRead poll_read Poll::Ready(Ok(()))");

                Poll::Ready(Ok(()))
            },
            Err(_) => {
                let mut waker = match waker_clone.try_lock() {
                    Ok(wk) => wk,
                    Err(_) => {
                        return Poll::Pending;
                    }
                };

                *waker = Some(cx.waker().clone());
                Poll::Pending
            },
        }
    }
}

enum TcpCommand {
    Packet(Ipv4TcpPacket),
    Write(Vec<u8>),
}

enum TcpActorEvent {
    Data(Vec<u8>)
}

struct TcpHandle {
    cmd_tx: UnboundedSender<TcpCommand>,
}

impl TcpHandle {
    fn send_packet(&self, packet: Ipv4TcpPacket) -> Result<(), std::io::Error> {
        if let Err(e) = self.cmd_tx.send(TcpCommand::Packet(packet.clone())) {
            error!("Failed to send packet {}, {}: {}", packet.destination_socket_addr(), packet.sequence_number(), e);
        }

        Ok(())
    }

    fn write(&self, data: Vec<u8>) {
        let _ = self.cmd_tx.send(TcpCommand::Write(data));
    }
}

struct TcpActor {
    state: TcpStateMachine,
    cmd_rx: UnboundedReceiver<TcpCommand>,
    read_tx: UnboundedSender<TcpActorEvent>
}

impl TcpActor {
    fn new(
        socket: Arc<UdpSocket>,
        socket_addr: SocketAddr,
        source_addr: Ipv4Addr,
        source_port: u16,
        destination_addr: Ipv4Addr,
        destination_port: u16,
    ) -> (TcpHandle, UnboundedReceiver<TcpActorEvent>, Self) {
        let (cmd_tx, cmd_rx) = unbounded_channel();
        let (read_tx, read_rx) = unbounded_channel();

        let mut state = TcpStateMachine::new(
            socket,
            socket_addr,
            source_addr,
            source_port,
            destination_addr,
            destination_port,
        );

        state.state = TcpState::Listen;

        let actor = Self {
            state,
            cmd_rx,
            read_tx,
        };

        (TcpHandle { cmd_tx }, read_rx, actor )
    }

    async fn run(&mut self) -> Result<(), std::io::Error> {
        while let Some(cmd) = self.cmd_rx.recv().await {
            match cmd {
                TcpCommand::Packet(packet) => {
                    self.state.process_event(packet).await?;

                    if !self.state.read_buffer.is_empty() {
                        let data = std::mem::take(&mut self.state.read_buffer);
                        let _ = self.read_tx.send(TcpActorEvent::Data(data));
                    }
                }
                TcpCommand::Write(data) => {
                    debug!("TcpActor run TcpCommand::Write. data len {}", data.len());

                    self.state.try_send_data(data).await;
                }
            }
        }

        Ok(())
    }
}

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
    DataArrives,
    SegmentArrives(TcpFlags),
    RstArrives,
    Unknown,
}

impl Display for TcpEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TcpEvent::DataArrives => write!(f, "DataArrives"),
            TcpEvent::RstArrives => write!(f, "RstArrives"),
            TcpEvent::SegmentArrives(flags) => write!(f, "SegmentArrives(syn={}, psh={}, ack={}, fin={}, rst={})", flags.syn, flags.psh, flags.ack, flags.fin, flags.rst),
            TcpEvent::Unknown => write!(f, "Unknown"),
        }
    }
}

struct TcpStateMachine {
    app_buffer: VecDeque<u8>,
    destination_addr: Ipv4Addr,
    destination_port: u16,
    mss: u16,
    out_of_order_buffer: BTreeMap<u32, Vec<u8>>,
    rcv_ack: u32,
    rcv_seq: u32,
    rcv_seq_next: u32,
    rcv_timestamp: u32,
    rcv_wnd: u32,
    read_buffer: Vec<u8>,
    snd_ack: u32,
    snd_seq: u32,
    socket: Arc<UdpSocket>,
    socket_addr: SocketAddr,
    source_addr: Ipv4Addr,
    source_port: u16,
    state: TcpState,
    wnd_scl: u8,
    wnd_size: u32,
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

        let sm = Self {
            app_buffer: VecDeque::new(),
            destination_addr,
            destination_port,
            mss: 65535,
            out_of_order_buffer: BTreeMap::new(),
            rcv_ack: 0,
            rcv_seq: 0,
            rcv_seq_next: 0,
            rcv_timestamp: 0,
            rcv_wnd: 0,
            read_buffer: Vec::new(),
            snd_ack: 0,
            snd_seq: rng.next_u32(),
            socket,
            socket_addr,
            source_addr,
            source_port,
            state: TcpState::Close,
            wnd_scl: 0,
            wnd_size: 0,
        };

        sm
    }

    async fn send_syn_ack_packet(&self) -> Result<(), std::io::Error> {
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

        if seq_num == self.rcv_seq_next {
            self.process_in_order_data(packet).await?;
        } else if seq_num > self.rcv_seq_next {
            self.buffer_out_of_order_data(seq_num, data);
        } else {
            warn!("Duplicate unordered segment from the past {} (seq_num={} < rcv_seq_next={})", packet.destination_socket_addr(), seq_num, self.rcv_seq_next);
            self.send_ack().await?;
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
            self.source_addr, 
            self.source_port,
            self.snd_seq, 
            self.destination_addr,
            self.destination_port,
            self.rcv_timestamp,
            wnd_size,
        )?;

        send_response(&raw_response, &self.socket, self.socket_addr).await?;

        Ok(())
    }

    fn drain_out_of_order_buffer(&mut self) {
        let mut next_seq = self.rcv_seq;

        while let Some(data) = self.out_of_order_buffer.remove(&next_seq) {
            self.app_buffer.extend(data.as_slice());
            next_seq = next_seq.wrapping_add(data.len() as u32);
        }

        if next_seq != self.rcv_seq {
            self.rcv_seq = next_seq;
        }
    }

    fn buffer_out_of_order_data(&mut self, seq_num: u32, data: Vec<u8>) {
        if !self.out_of_order_buffer.contains_key(&seq_num) {
            self.out_of_order_buffer.insert(seq_num, data);
        } else {
            warn!("Duplicate unordered segment SEQ={}", seq_num);
        }
    }

    async fn process_event(&mut self, packet: Ipv4TcpPacket) -> Result<(), std::io::Error> {
        let old_state = self.state;

        let event = packet_to_event(packet.tcp());

        match (old_state, event.clone()) {
            (TcpState::Listen, TcpEvent::SegmentArrives(flags)) if flags.syn && !flags.ack => {
                self.mss = packet.options().mss.min(self.mss);
                self.wnd_scl = packet.options().window_scale;
                self.wnd_size = (65535) << self.wnd_scl;
                self.rcv_seq = packet.sequence_number();
                self.rcv_ack = packet.acknowledgment_number();
                self.rcv_wnd = (packet.window_size() as u32) << self.wnd_scl;
                self.rcv_timestamp = packet.options().timestamp.0;
                self.snd_ack = self.rcv_seq.wrapping_add(1);

                self.send_syn_ack_packet().await?;

                self.rcv_seq_next = self.rcv_seq.wrapping_add(1);
                self.snd_seq = self.snd_seq.wrapping_add(1);

                self.state = TcpState::SynReceived;
            }
            (TcpState::SynReceived, TcpEvent::SegmentArrives(flags)) if !flags.syn && flags.ack => {
                self.rcv_seq = packet.sequence_number();
                self.rcv_ack = packet.acknowledgment_number();
                self.rcv_wnd = (packet.window_size() as u32) << self.wnd_scl;
                self.rcv_timestamp = packet.options().timestamp.0;
                self.state = TcpState::Established;
            }
            (TcpState::Established, TcpEvent::DataArrives) => {
                self.rcv_seq = packet.sequence_number();
                self.rcv_ack = packet.acknowledgment_number();
                self.rcv_timestamp = packet.options().timestamp.0;
                self.snd_ack = self.rcv_seq.wrapping_add(packet.payload().len() as u32);
                self.wnd_size = self.wnd_size.wrapping_sub(packet.payload().len() as u32);
                self.rcv_wnd = (packet.window_size() as u32) << self.wnd_scl;

                self.handle_data_in_established(packet.clone()).await?;

                self.rcv_seq_next = self.rcv_seq.wrapping_add(packet.payload().len() as u32);
            }
            (TcpState::Established, TcpEvent::SegmentArrives(flags)) if !flags.syn && flags.ack => {
                self.rcv_seq = packet.sequence_number();
                self.rcv_ack = packet.acknowledgment_number();
                self.rcv_timestamp = packet.options().timestamp.0;

                debug!("Data confirmation processing {} ack_num {}", packet.destination_socket_addr(), packet.acknowledgment_number());
            }
            (_, TcpEvent::RstArrives) => {
                warn!("process_event TcpEvent::RstArrives {} {}", packet.destination_socket_addr(), packet.sequence_number());

                self.state = TcpState::Close;
            },
            (_, TcpEvent::Unknown) => {
                warn!("++++++ process_event TcpEvent::Unknown");
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

    async fn try_send_data(&mut self, mut data: Vec<u8>) {
        debug!("TcpStateMachine try_send_data. data len {}, rcv_win {}", data.len(), self.rcv_wnd);

        while !data.is_empty() && self.rcv_wnd > 0 {

            let send_size = (self.mss as u32)
                .min(self.rcv_wnd)
                .min(data.len() as u32) as usize;

            if send_size == 0 { break; }

            let send_data: Vec<u8> = data.drain(0..send_size).collect();

            let is_last = data.is_empty();

            let raw_packet = get_ack_data_response(
                self.snd_ack,
                self.source_addr,
                self.source_port,
                send_data.clone(),
                is_last,
                self.snd_seq,
                self.destination_addr,
                self.destination_port,
                self.rcv_timestamp,
                65535,
            ).unwrap();

            if let Err(e) = send_response(&raw_packet, &self.socket, self.socket_addr).await {
                error!("Failed to send response {}", e);
                continue;
            }

            self.snd_seq = self.snd_seq.wrapping_add(send_size as u32);
        }

        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
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
    conections: HashMap<(String, String), Arc<IpUdpStream>>,
}

impl IpOverUdpServer {
    async fn new(bind_addr: &str) -> Result<Self, Box<dyn Error>> {
        let socket = UdpSocket::bind(bind_addr).await?;

        Ok(Self {
            socket: Arc::new(socket),
            conections: HashMap::new(),
        })
    }

    async fn run(&mut self) -> Result<Arc<IpUdpStream>, Box<dyn Error>>{
        loop {
            let mut buffer = [0u8; 65535];

            let socket_cloned = Arc::clone(&self.socket);

            match socket_cloned.recv_from(&mut buffer).await {
                Ok((n, socket_addr)) => {
                    debug!("===== Received {} from {}", n, socket_addr);

                    let raw_ip_packet = buffer[..n].to_vec();

                    match self.handle_ip_packet(raw_ip_packet, socket_addr).await {
                        Ok(Some(stream)) => {
                            return Ok(stream);
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
    ) -> Result<Option<Arc<IpUdpStream>>, Box<dyn Error>> {
        match net_packet_parser(&raw_ip_packet) {
            Some(Packet::Ipv6Tcp(ip_v6_tcp_packet)) => {
                warn!("Received ipv6/tcp from udp {}", ip_v6_tcp_packet);
            },
            Some(Packet::Ipv4Tcp(ip_tcp_packet)) => {
                debug!("Received ipv4/tcp from udp {}", ip_tcp_packet);

                let stream = self.handle_ipv4_tcp_packet(
                    ip_tcp_packet,
                    socket_addr,
                ).await?;

                return Ok(stream);
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
    ) -> Result<Option<Arc<IpUdpStream>>, std::io::Error> {
        if packet.syn() && !packet.ack() {
            let socket = Arc::clone(&self.socket);

            let (handle, mut read_rx, mut actor) = TcpActor::new(
                socket,
                socket_addr,
                packet.ip.source_address,
                packet.tcp.source_port,
                packet.ip.destination_address,
                packet.tcp.destination_port,
            );

            let stream = Arc::new(
                IpUdpStream::new(
                SocketAddr::V4(SocketAddrV4::new(packet.ip.destination_address, packet.tcp.destination_port)),
                    handle,
                )
            );

            actor.state.process_event(packet.clone()).await?;

            tokio::spawn(async move {
                if let Err(e) = actor.run().await {
                    error!("Failed to raun actor {}", e);
                }
            });

            let stream_cloned = stream.clone();

            tokio::spawn(async move {
                loop {
                    match read_rx.recv().await {
                        Some(TcpActorEvent::Data(mut data)) => {
                            debug!("handle_ipv4_tcp_packet tokio::spawn read_rx.recv() TcpActorEvent::Data. data.len {}", data.len());

                            let mut rb = stream_cloned.read_buffer.lock().await;

                            rb.append(&mut data);

                            let waker_clone = stream_cloned.read_waker.clone();
                            let mut waker = waker_clone.lock().await;


                            if let Some(waker) = waker.take() {
                                waker.wake();
                            }
                        },
                        None => {
                            break;
                        }
                    }
                }
            });

            let stream_cloned = stream.clone();

            tokio::spawn(async move {
                loop {
                    let mut wb = stream_cloned.write_buffer.lock().await;

                    if !wb.is_empty() {
                        let write_len = wb.len();
                        let data = wb.drain(..write_len).collect();
                        stream_cloned.handle.write(data);
                    }

                    drop(wb);

                    sleep(Duration::from_millis(10)).await;
                }
            });

            let key = (packet.source_socket_addr(), packet.destination_socket_addr());

            self.conections.insert(key, stream.clone());

            return Ok(Some(stream.clone()));
        }

        let key = (packet.source_socket_addr(), packet.destination_socket_addr());

        let stream = match self.conections.get(&key) {
            Some(val) => val.clone(),
            None => {
                let mut rng = rand::rng();
                let socket = Arc::clone(&self.socket);
                let response_raw = get_reset_response(
                    packet.sequence_number(),
                    packet.ip.source_address,
                    packet.source_port(),
                    rng.next_u32(),
                    packet.ip.destination_address,
                    packet.destination_port(),
                    packet.options().timestamp.0,
                    65535,
                )?;
                send_response(&response_raw, &socket, socket_addr).await?;
                return Ok(None);
            }
        };

        stream.handle.send_packet(packet.clone())?;

        Ok(None)
    }
}

async fn send_response(
    response_raw: &Vec<u8>,
    socket: &UdpSocket,
    addr: SocketAddr
) -> Result<(), std::io::Error> {
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
    let mut server = IpOverUdpServer::new("0.0.0.0:8200").await?;

    loop {
        let client_stream = server.run().await?;

        debug!("Got new stream {}", client_stream.destination_socket_addr);

        tokio::spawn(async move {
            let addr = client_stream.destination_socket_addr;

            match TcpStream::connect(addr).await {
                Ok(mut destination_connect) => {
                    let (mut read_destination, mut write_destination) = destination_connect.split();
                    let (mut read_client, mut write_client) = client_stream.split();

                    tokio::select! {
                        _ = copy(&mut read_client, &mut write_destination) => {}
                        _ = copy(&mut read_destination, &mut write_client) => {}
                    }
                }
                Err(e) => {
                    error!("Connection error to target {} : {}", addr, e);
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr};

    use rand::Rng;
    use tokio::net::TcpListener;

    use crate::{handle_udp::IpOverUdpServer, net_packet_parser::{Ipv4Packet, Ipv4TcpPacket, TcpPacket}};

    #[tokio::test]
    async fn test_syn() {
        let mut rng = rand::rng();
        let mut client_server = IpOverUdpServer::new("127.0.0.1:0").await.unwrap();
        let destination_server = TcpListener::bind("127.0.0.1:0").await.unwrap();

        let client_addr = client_server.socket.local_addr().unwrap();

        let destination_addr = Ipv4Addr::new(127, 0, 0, 1);
        let destination_port = destination_server.local_addr().unwrap().port();
        let seq_num = rng.next_u32();
        let source_addr = Ipv4Addr::new(127, 0, 0, 1);
        let source_port = client_server.socket.local_addr().unwrap().port();

        let packet = Ipv4TcpPacket::syn_packet(
            destination_addr,
            destination_port,
            seq_num,
            source_addr,
            source_port,
            65535
        ).unwrap();

        let stream = client_server.handle_ipv4_tcp_packet(packet, client_addr).await;
    }
}
