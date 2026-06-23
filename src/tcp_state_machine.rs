use rand::Rng;
use std::{
    collections::{BTreeMap, VecDeque, btree_map::Entry}, fmt::Display, io, net::Ipv4Addr, time::{Duration, Instant}, u32
};
use tracing::{debug, error, warn};

use crate::{
    net_packet_parser::{
        IpTcpPacket, Ipv4TcpPacket, TcpFlags, TcpPacket, get_ack_data_response, get_ack_response,
        get_handshake_response, get_syn_response,
    }, utils::PacketHandler
};

#[derive(Clone, Copy, Debug)]
pub enum TcpState {
    Closed,
    Listen,
    SynSent,
    SynReceived,
    Established,
}

impl Display for TcpState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TcpState::Closed => write!(f, "Closed"),
            TcpState::Listen => write!(f, "Listen"),
            TcpState::SynSent => write!(f, "SynSent"),
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
            TcpEvent::SegmentArrives(flags) => write!(
                f,
                "SegmentArrives(syn={}, psh={}, ack={}, fin={}, rst={})",
                flags.syn, flags.psh, flags.ack, flags.fin, flags.rst
            ),
            TcpEvent::Unknown => write!(f, "Unknown"),
        }
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

struct PendingPacket {
    data: Vec<u8>,
    len: usize,
    retransmits: u8,
    send_at: Instant,
    seq: u32,
}

pub struct TcpStateMachine {
    app_buffer: Vec<u8>,
    destination_addr: Ipv4Addr,
    destination_port: u16,
    mss: u16,
    out_of_order_buffer: BTreeMap<u32, Ipv4TcpPacket>,
    prev_rcv_ack: u32,
    pub read_buffer: Vec<u8>,
    rcv_ack: u32,
    rcv_seq: u32,
    rcv_seq_next: u32,
    handler: PacketHandler,
    send_buffer: Vec<u8>,
    source_addr: Ipv4Addr,
    source_port: u16,
    ssthresh: u32,
    pub state: TcpState,
    wnd_scl: u8,
    // wnd_size: u32,
    cwnd: u32,
    dup_ack_count: u32,
    fast_retransmit_done: bool,
    flight_size: u32,
    rcv_timestamp: u32,
    rwnd: u32,
    smss: u16,
    snd_ack: u32,
    snd_seq: u32,
    snd_wnd_scl: u8,
    snd_wnd_size: u32,
    unacked_packets: BTreeMap<u32, PendingPacket>,
}

impl TcpStateMachine {
    pub fn new(
        source_addr: Ipv4Addr,
        source_port: u16,
        destination_addr: Ipv4Addr,
        destination_port: u16,
        handler: PacketHandler,
    ) -> Self {
        let mut rng = rand::rng();

        Self {
            app_buffer: Vec::new(),
            destination_addr,
            destination_port,
            mss: 65535,
            out_of_order_buffer: BTreeMap::new(),
            prev_rcv_ack: 0,
            read_buffer: Vec::new(),
            rcv_ack: 0,
            rcv_seq: 0,
            rcv_seq_next: 0,
            handler,
            send_buffer: Vec::new(),
            source_addr,
            source_port,
            ssthresh: u32::MAX,
            state: TcpState::Closed,
            wnd_scl: 0,
            // wnd_size: 0,
            cwnd: 0,
            dup_ack_count: 0,
            fast_retransmit_done: false,
            flight_size: 0,
            rcv_timestamp: 0,
            rwnd: 0,
            smss: 65535,
            snd_ack: 0,
            snd_seq: rng.next_u32(),
            snd_wnd_scl: 10,
            snd_wnd_size: 65535 << 10,
            unacked_packets: BTreeMap::new(),
        }
    }

    async fn send_syn_ack_packet(&self) -> Result<(), std::io::Error> {
        let wnd_size = (self.snd_wnd_size >> self.snd_wnd_scl) as u16;

        let raw_response = get_handshake_response(
            self.snd_ack,
            self.source_addr,
            self.source_port,
            self.mss,
            self.snd_seq,
            self.destination_addr,
            self.destination_port,
            self.rcv_timestamp,
            self.snd_wnd_scl,
            wnd_size,
        )?;

        (self.handler)(raw_response).await?;

        Ok(())
    }

    async fn handle_data_in_established(
        &mut self,
        packet: Ipv4TcpPacket,
    ) -> Result<(), std::io::Error> {
        let seq_num = packet.sequence_number();

        if seq_num == self.rcv_seq_next {
            self.process_in_order_data(packet).await?;
        } else if seq_num > self.rcv_seq_next {
            self.buffer_out_of_order_data(seq_num, packet);
        } else {
            warn!(
                "Duplicate unordered segment from the past {} (seq_num={} < rcv_seq_next={})",
                packet.destination_socket().to_string(),
                seq_num,
                self.rcv_seq_next
            );
            self.send_ack().await?;
        }

        Ok(())
    }

    async fn process_data(&mut self, packet: Ipv4TcpPacket) -> Result<(), std::io::Error> {
        let data = packet.payload();
        let push_flag = packet.psh();

        self.app_buffer.extend(data.as_slice());

        if push_flag {
            let data_buff: Vec<u8> = self.app_buffer.drain(..self.app_buffer.len()).collect();

            self.read_buffer.extend(data_buff);
        }
        Ok(())
    }

    async fn process_in_order_data(&mut self, packet: Ipv4TcpPacket) -> Result<(), std::io::Error> {
        let data = packet.payload();
        let push_flag = packet.psh();

        debug!(
            "===process_in_order_data==== {} {} psh {}",
            packet.destination_socket().to_string(),
            self.app_buffer.len(),
            push_flag
        );

        self.app_buffer.extend(data.as_slice());

        self.drain_out_of_order_buffer();

        self.send_ack().await?;

        if push_flag {
            let data_buff: Vec<u8> = self.app_buffer.drain(..self.app_buffer.len()).collect();

            self.read_buffer.extend(data_buff);
        }
        Ok(())
    }

    async fn send_syn(&mut self, mss: Option<u16>) -> Result<(), std::io::Error> {
        let mut rng = rand::rng();

        self.mss = mss.unwrap_or(1460);
        self.snd_seq = rng.next_u32();

        let raw_packet = get_syn_response(
            self.destination_addr,
            self.destination_port,
            self.mss,
            self.snd_seq,
            self.source_addr,
            self.source_port,
            self.snd_wnd_scl,
            (self.snd_wnd_size >> self.snd_wnd_scl) as u16,
        )?;

        (self.handler)(raw_packet).await?;

        self.state = TcpState::SynSent;

        Ok(())
    }

    async fn send_ack(&self) -> Result<(), std::io::Error> {
        let wnd_size = (self.snd_wnd_size >> self.snd_wnd_scl) as u16;

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

        (self.handler)(raw_response).await?;

        Ok(())
    }

    fn drain_out_of_order_buffer(&mut self) {
        let mut next_seq = self.rcv_seq;

        while let Some(data) = self.out_of_order_buffer.remove(&next_seq) {
            self.app_buffer.extend(data.payload().as_slice());
            next_seq = next_seq.wrapping_add(data.payload().len() as u32);
        }

        if next_seq != self.rcv_seq {
            self.rcv_seq = next_seq;
        }
    }

    fn buffer_out_of_order_data(&mut self, seq_num: u32, data: Ipv4TcpPacket) {
        match self.out_of_order_buffer.entry(seq_num) {
            Entry::Vacant(entry) => {
                entry.insert(data);
            }
            Entry::Occupied(_) => {
                warn!("Duplicate unordered segment SEQ={}", seq_num);
            }
        }
    }

    /// Инициализирует cwnd согласно RFC 5681 на основе SMSS
    fn init_cwnd(&mut self) {
        if self.smss > 2190 {
            self.cwnd = (2 * self.smss) as u32;
        } else if self.smss > 1095 && self.smss <= 2190 {
            self.cwnd = (3 * self.smss) as u32;
        } else {
            self.cwnd = (4 * self.smss) as u32;
        }
    }

    /// Вычисляет flight_size на основе unacked_packets
    /// flight_size = (seq_num + data.len()) самого нового элемента - seq_num самого старого элемента
    fn recalc_flight_size(&mut self) {
        if let Some((oldest_seq, _oldest_pkt)) = self.unacked_packets.iter().next() {
            if let Some((newest_seq, newest_pkt)) = self.unacked_packets.iter().next_back() {
                let oldest_seq = *oldest_seq;
                let newest_end = newest_seq.wrapping_add(newest_pkt.len as u32);
                self.flight_size = newest_end.wrapping_sub(oldest_seq);
            } else {
                self.flight_size = 0;
            }
        } else {
            self.flight_size = 0;
        }
    }

    /// Добавляет пакет в unacked_packets и пересчитывает flight_size
    fn add_to_unacked_packets(&mut self, seq: u32, data: Vec<u8>, len: usize) {
        self.unacked_packets.insert(seq, PendingPacket {
            data,
            len,
            retransmits: 0,
            send_at: Instant::now(),
            seq,
        });
        self.recalc_flight_size();
    }

    /// Удаляет подтвержденные пакеты из unacked_packets (seq < new_ack) и пересчитывает flight_size
    fn remove_acknowledged_packets(&mut self, new_ack: u32) {
        // Удаляем все пакеты с seq < new_ack
        while let Some((seq, _)) = self.unacked_packets.iter().next() {
            let seq = *seq;
            if seq < new_ack {
                self.unacked_packets.remove(&seq);
            } else {
                break;
            }
        }
        self.recalc_flight_size();
    }

    pub async fn process_event(&mut self, packet: Ipv4TcpPacket) -> Result<(), std::io::Error> {
        let old_state = self.state;

        let event = packet_to_event(packet.tcp());

        match (old_state, event.clone()) {
            (TcpState::Listen, TcpEvent::SegmentArrives(flags)) if flags.syn && !flags.ack => {
                self.mss = packet.options().mss.min(self.mss);
                self.wnd_scl = packet.options().window_scale;
                self.rcv_seq = packet.sequence_number();
                self.rcv_ack = packet.acknowledgment_number();

                self.smss = packet.options().mss;
                self.init_cwnd();

                self.rcv_timestamp = packet.options().timestamp.0;
                self.snd_ack = self.rcv_seq.wrapping_add(1);
                self.rwnd = (packet.window_size() as u32) << self.wnd_scl;

                self.send_syn_ack_packet().await?;

                self.rcv_seq_next = self.rcv_seq.wrapping_add(1);
                self.snd_seq = self.snd_seq.wrapping_add(1);

                self.state = TcpState::SynReceived;
            }
            (TcpState::SynSent, TcpEvent::SegmentArrives(flags)) if flags.syn && flags.ack => {
                // Process the SYN-ACK
                self.mss = packet.options().mss.min(self.mss);
                self.wnd_scl = packet.options().window_scale;
                self.rcv_seq = packet.sequence_number();
                self.rcv_timestamp = packet.options().timestamp.0;
                self.rwnd = (packet.window_size() as u32) << self.wnd_scl;
                self.smss = packet.options().mss;
                self.init_cwnd();

                // The ACK number in SYN-ACK points to our SYN sequence + 1
                // Our next sequence number should be the ACK number from SYN-ACK
                self.snd_ack = self.rcv_seq.wrapping_add(1);
                self.rcv_seq_next = self.rcv_seq.wrapping_add(1);

                // The server acknowledged our SYN, so our sequence number is incremented
                // snd_seq was already set when we sent SYN, just increment it
                self.snd_seq = self.snd_seq.wrapping_add(1);

                // Send ACK to complete the three-way handshake
                self.send_ack().await?;

                self.state = TcpState::Established;
            }
            (TcpState::SynReceived, TcpEvent::SegmentArrives(flags)) if !flags.syn && flags.ack => {
                self.rcv_seq = packet.sequence_number();

                if self.prev_rcv_ack == 0 {
                    self.prev_rcv_ack = packet.acknowledgment_number();
                } else {
                    self.prev_rcv_ack = self.rcv_ack;
                }

                self.rcv_ack = packet.acknowledgment_number();

                self.state = TcpState::Established;

                self.rcv_timestamp = packet.options().timestamp.0;

                // НЕ вызываем send_pending_data при ACK на SYN-ACK
            }
            (TcpState::Established, TcpEvent::DataArrives) => {
                self.rcv_timestamp = packet.options().timestamp.0;
                self.snd_wnd_size = self.snd_wnd_size.wrapping_sub(packet.payload().len() as u32);

                if packet.sequence_number() == self.rcv_seq_next {
                    self.rcv_seq = packet.sequence_number();
                    self.rwnd = (packet.window_size() as u32) << self.wnd_scl;
                    self.rcv_seq_next = self.rcv_seq.wrapping_add(packet.payload().len() as u32);
                    self.snd_ack = self.rcv_seq.wrapping_add(packet.payload().len() as u32);

                    self.process_data(packet.clone()).await?;

                    while let Some(data) = self.out_of_order_buffer.remove(&self.rcv_seq_next) {
                        self.rcv_seq = data.sequence_number();
                        self.rwnd = (data.window_size() as u32) << self.wnd_scl;
                        self.rcv_seq_next = self.rcv_seq.wrapping_add(data.payload().len() as u32);
                        self.snd_ack = self.rcv_seq.wrapping_add(data.payload().len() as u32);

                        self.process_data(data.clone()).await?;
                    }

                    self.send_ack().await?;

                } else if packet.sequence_number() > self.rcv_seq_next {
                    self.buffer_out_of_order_data(packet.sequence_number(), packet);

                    self.send_ack().await?;
                }
            }
            (TcpState::Established, TcpEvent::SegmentArrives(flags)) if !flags.syn && flags.ack => {
                self.rcv_seq = packet.sequence_number();

                if self.prev_rcv_ack == 0 {
                    self.prev_rcv_ack = packet.acknowledgment_number();
                } else {
                    self.prev_rcv_ack = self.rcv_ack;
                }

                let new_ack = packet.acknowledgment_number();

                self.rcv_timestamp = packet.options().timestamp.0;
                let n = new_ack - self.prev_rcv_ack;
                
                // Проверяем, это дублирующий ACK (new_ack == prev_rcv_ack)
                if n == 0 && self.prev_rcv_ack != 0 {
                    self.dup_ack_count += 1;
                    debug!("Duplicate ACK #{} received {} > {}", self.dup_ack_count, packet.source_socket(), packet.destination_socket());
                    
                    // Fast Retransmit после 3 дублирующих ACK
                    if self.dup_ack_count == 3 && !self.fast_retransmit_done {
                        self.fast_retransmit_done = true;

                        self.ssthresh = (self.flight_size / 2).max(2 * self.smss as u32);
                        self.cwnd = self.ssthresh + 3 * self.smss as u32;
                        
                        warn!("Fast Retransmit: ssthresh={}, cwnd={}", self.ssthresh, self.cwnd);
                        
                        // Находим первый неподтвержденный пакет и переотправляем его
                        if let Some((seq, pending_pkt)) = self.unacked_packets.iter().next() {
                            let seq = *seq;
                            
                            warn!("Fast Retransmit: retransmitting packet at seq={}", seq);
                            
                            let raw_packet = get_ack_data_response(
                                self.snd_ack,
                                self.source_addr,
                                self.source_port,
                                &pending_pkt.data,
                                false,
                                seq,
                                self.destination_addr,
                                self.destination_port,
                                self.rcv_timestamp,
                                65535,
                            ).unwrap();

                            if let Err(e) = (self.handler)(raw_packet).await {
                                error!("Failed to retransmit packet {}", e);
                            }
                        }
                    } else if self.dup_ack_count > 3 && self.fast_retransmit_done {
                        self.cwnd += self.smss as u32;
                        
                        // Во время Fast Recovery отправляем новые данные если позволяет окно
                        self.send_pending_data().await;
                    }
                } else if n > 0 {
                    // Новый ACK - сбрасываем счетчик дублирующих ACK
                    self.dup_ack_count = 0;
                    self.fast_retransmit_done = false;
                    
                    // Удаляем подтвержденные пакеты и пересчитываем flight_size
                    self.remove_acknowledged_packets(new_ack);
                    
                    // Увеличиваем cwnd только при получении ACK на данные (не SYN)
                    self.cwnd += n.min(self.smss as u32);
                    
                    // После получения ACK на данные, отправляем pending данные
                    self.send_pending_data().await;
                }
                
                self.rwnd = (packet.window_size() as u32) << self.wnd_scl;
                self.rcv_ack = new_ack;
            }
            (_, TcpEvent::RstArrives) => {
                warn!(
                    "process_event TcpEvent::RstArrives {} {}",
                    packet.destination_socket().to_string(),
                    packet.sequence_number()
                );

                self.read_buffer.clear();
                self.app_buffer.clear();

                self.state = TcpState::Closed;
            }
            (_, TcpEvent::Unknown) => {
                warn!("++++++ process_event TcpEvent::Unknown");
            }
            _ => {
                error!(
                    "Invalid state/event combination event {}, state {}",
                    event, old_state
                );
                return Err(std::io::Error::other(format!("Invalid state/event combination event {}, state {}", event, old_state)));
            }
        };

        Ok(())
    }

    async fn send_ack_data(&mut self, data: Vec<u8>, psh: bool) {
        let data_size = data.len();

        let raw_packet = get_ack_data_response(
            self.snd_ack,
            self.source_addr,
            self.source_port,
            &data,
            psh,
            self.snd_seq,
            self.destination_addr,
            self.destination_port,
            self.rcv_timestamp,
            65535,
        )
        .unwrap();

        if let Err(e) = (self.handler)(raw_packet).await {
            error!("Failed to send response {}", e);
            return;
        }

        self.add_to_unacked_packets(self.snd_seq, data, data_size);
        self.snd_seq = self.snd_seq.wrapping_add(data_size as u32);
    }

    async fn send_pending_data(&mut self) {
        loop {
            if self.send_buffer.is_empty() {
                return;
            }

            let available_window = self.cwnd.min(self.rwnd);
            if self.flight_size >= available_window {
                return;
            }

            let send_size = (self.smss as u32).min(available_window - self.flight_size).min(self.send_buffer.len() as u32) as usize;

            if send_size == 0 {
                return;
            }

            let send_data: Vec<u8> = self.send_buffer.drain(0..send_size).collect();

            let raw_packet = get_ack_data_response(
                self.snd_ack,
                self.source_addr,
                self.source_port,
                &send_data,
                self.send_buffer.len() == 0,
                self.snd_seq,
                self.destination_addr,
                self.destination_port,
                self.rcv_timestamp,
                65535,
            ).unwrap();

            if let Err(e) = (self.handler)(raw_packet).await {
                error!("Failed to send response {}", e);
                return;
            }

            self.add_to_unacked_packets(self.snd_seq, send_data, send_size);
            self.snd_seq = self.snd_seq.wrapping_add(send_size as u32);
        }
    }

    pub async fn try_send_data(&mut self, mut data: Vec<u8>) {
        self.send_buffer.append(&mut data);

        // Отправляем пакеты согласно Slow Start
        self.send_pending_data().await;
    }
}

#[cfg(test)]
mod tests {
    use std::{io::{Error, ErrorKind}, net::{Ipv4Addr, SocketAddrV4}, time::{SystemTime, UNIX_EPOCH}};

    use etherparse::{PacketBuilder, TcpOptionElement};
    use tokio::sync::{mpsc::{UnboundedReceiver, unbounded_channel}};

    use crate::{net_packet_parser::{IpTcpPacket, Ipv4TcpPacket, Packet, RawIpPacket, net_packet_parser}, tcp_state_machine::{TcpState, TcpStateMachine}};

    fn assert_state(actual: TcpState, expected: TcpState) {
        assert_eq!(
            std::mem::discriminant(&actual),
            std::mem::discriminant(&expected),
            "Ожидалось состояние {:?}, но получено {:?}",
            expected,
            actual
        );
    }

    struct Client {
        response_rx: UnboundedReceiver<Ipv4TcpPacket>,
        state: TcpStateMachine,
    }

    impl Client {
        fn new(
            destination_socket: SocketAddrV4,
            source_socket: SocketAddrV4,
        ) -> Self {
            let (tx, rx) = unbounded_channel::<Ipv4TcpPacket>();

            let state = TcpStateMachine::new(
                *source_socket.ip(),
                source_socket.port(),
                *destination_socket.ip(),
                destination_socket.port(),
                Box::new(move |raw_response| {
                    let tx = tx.clone();

                    Box::pin(async move {
                        if let Some(Packet::Ipv4Tcp(syn_ack_packet)) = net_packet_parser(raw_response.as_slice()) {
                            tx.send(syn_ack_packet).map_err(|e| Error::new(ErrorKind::Other, e))?;

                            Ok(())
                        } else {
                            panic!("syn_ack_packet should be ipv4");
                        }
                    })
                })
            );

            Client {
                response_rx: rx,
                state,
            }
        }

        async fn send_syn(&mut self, mss: Option<u16>) {
            self.state.send_syn(mss).await;
        }

        async fn send_data(&mut self, data: Vec<u8>) {
            self.state.try_send_data(data).await;
        }

        async fn accept_request(&mut self, packet: Ipv4TcpPacket) {
            self.state.process_event(packet.clone()).await.unwrap();
        }

        async fn get_response(&mut self) -> Vec<Ipv4TcpPacket> {
            let mut result: Vec<Ipv4TcpPacket> = Vec::new();


            while let Ok(packet) = self.response_rx.try_recv() {
                result.push(packet);
            }

            result
        }
    }

    struct Server {
        response_rx: UnboundedReceiver<Ipv4TcpPacket>,
        state: TcpStateMachine,
    }

    impl Server {
        fn new(
            destination_socket: SocketAddrV4,
            source_socket: SocketAddrV4,
        ) -> Self {
            let (tx, rx) = unbounded_channel::<Ipv4TcpPacket>();

            let mut state = TcpStateMachine::new(
                *source_socket.ip(),
                source_socket.port(),
                *destination_socket.ip(),
                destination_socket.port(),
                Box::new(move |raw_response| {
                    let tx = tx.clone();

                    Box::pin(async move {
                        if let Some(Packet::Ipv4Tcp(syn_ack_packet)) = net_packet_parser(raw_response.as_slice()) {
                            tx.send(syn_ack_packet).map_err(|e| Error::new(ErrorKind::Other, e))?;

                            Ok(())
                        } else {
                            panic!("syn_ack_packet should be ipv4");
                        }
                    })
                })
            );

            state.state = TcpState::Listen;

            let server = Server {
                response_rx: rx,
                state,
            };

            server
        }

        async fn accept_request(&mut self, packet: Ipv4TcpPacket) {
            self.state.process_event(packet.clone()).await.unwrap();
        }
        
        async fn get_response(&mut self) -> Vec<Ipv4TcpPacket> {
            let mut result: Vec<Ipv4TcpPacket> = Vec::new();


            while let Ok(packet) = self.response_rx.try_recv() {
                result.push(packet);
            }

            result
        }

        async fn send_data(&mut self, data: Vec<u8>) {
            self.state.try_send_data(data).await;
        }
    }

    pub fn get_syn_response(
        destination_addr: &Ipv4Addr,
        destination_port: u16,
        mss: u16,
        seq_num: u32,
        source_addr: &Ipv4Addr,
        source_port: u16,
        win_size: u16,
    ) -> Result<RawIpPacket, std::io::Error> {
        let curr_timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u32;

        let options = vec![
            TcpOptionElement::MaximumSegmentSize(mss),
            TcpOptionElement::Timestamp(curr_timestamp, 0),
        ];

        let builder = PacketBuilder::ipv4(source_addr.octets(), destination_addr.octets(), 64)
            .tcp(source_port, destination_port, seq_num, win_size)
            .syn();

        let builder_with_options = builder
            .options(options.as_slice())
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

        let payload = Vec::<u8>::new();

        let mut buffer = Vec::<u8>::with_capacity(builder_with_options.size(payload.len()));

        builder_with_options.write(&mut buffer, &payload).unwrap();

        Ok(buffer)
    }

    async fn assert_client_send_data(
        client: &mut Client,
        server: &mut Server,
    ) {
        let data = "123456789";

        client.send_data(data.as_bytes().to_vec()).await;

        let net_client_server = client.get_response().await;

        for client_data_packet in net_client_server {
            server.accept_request(client_data_packet.clone()).await;
            
            let mut net_server_client = server.get_response().await;

            let packet = net_server_client.remove(0);

            client.accept_request(packet.clone());

            let expect_ack_num = client_data_packet.sequence_number().wrapping_add(client_data_packet.payload().len() as u32);

            assert!(packet.ack());
            assert_eq!(packet.acknowledgment_number(), expect_ack_num);
            assert_eq!(packet.sequence_number(), client_data_packet.acknowledgment_number());
        }
    }

    #[tokio::test]
    async fn test() {
        let server_socket = SocketAddrV4::new(
            Ipv4Addr::new(127, 0, 0, 1),
            8000,
        );

        let client_socket = SocketAddrV4::new(
            Ipv4Addr::new(127, 0, 0, 1),
            8001,
        );

        let mut server = Server::new(
            client_socket,
            server_socket,
        );

        let mut client = Client::new(
            server_socket,
            client_socket
        );

        let mut net_server_client_tick = 0;
        let mut net_server_client: Vec<Ipv4TcpPacket> = Vec::new();
        let mut net_client_server: Vec<Ipv4TcpPacket> = Vec::new();

        // отправляем syn запрос на сервер. устанавливаем размер окна 3 байта для удобства тестирования
        client.send_syn(Some(3)).await;

        // пакет клиента уходит в сеть
        net_client_server.append(&mut client.get_response().await);

        assert!(net_client_server[0].syn());

        // пакет клиента доставлен на сервер. сервер отвечает syn-ack
        let packet = net_client_server.remove(0);
        server.accept_request(packet.clone()).await;

        // пакет syn-ack уходит в сеть
        net_server_client.append(&mut server.get_response().await);

        assert!(net_server_client[0].syn());
        assert!(net_server_client[0].ack());
        assert_eq!(net_server_client[0].acknowledgment_number(), packet.sequence_number().wrapping_add(1));

        // клиент принимает syn-ack и отвечает подтверждением ack
        client.accept_request(net_server_client.remove(0)).await;

        net_client_server.append(&mut client.get_response().await);

        server.accept_request(net_client_server.remove(0)).await;

        assert_state(server.state.state, TcpState::Established);

        assert_client_send_data(
            &mut client,
            &mut server,
        ).await;

        let server_data = "0123456789abcdefghjklmnopqr";

        // Сервер отправляет пакеты с данными в сеть
        server.send_data(server_data.as_bytes().to_vec()).await;

        net_server_client.append(&mut server.get_response().await);
        assert_eq!(server.state.cwnd, 12);
        assert_eq!(server.state.flight_size, 12);
        assert_eq!(net_server_client.len(), 4); // 012, 345, 678, 9ab

        net_server_client_tick = 0;

        // Клиент принимает первый пакет из сети и генерит ack
        client.accept_request(net_server_client[net_server_client_tick].clone()).await;
        net_client_server.append(&mut client.get_response().await);
        assert_eq!(String::from_utf8_lossy(client.state.app_buffer.as_slice()), "012");

        // запоминаем ack этого пакета
        let last_ack_in_order = net_client_server[0].acknowledgment_number();

        // сервер принимает ack на первый пакет
        server.accept_request(net_client_server.remove(0)).await;
        net_server_client.append(&mut server.get_response().await); // отправляет новые два пакета
        assert_eq!(server.state.cwnd, 15);
        assert_eq!(server.state.flight_size, 15);
        assert_eq!(net_server_client.len(), 6); // 012, 345, 678, 9ab, cde, fgh

        // Предположим второй пакет теряется в сети (345)
        net_server_client_tick = 2;

        // Клиент принимает третий пакет (678), но должен сгенерировать ack на первый пакет (1 dup ack)
        client.accept_request(net_server_client[net_server_client_tick].clone()).await;
        net_client_server.append(&mut client.get_response().await);
        assert_eq!(client.state.out_of_order_buffer.len(), 1); // 678
        assert_eq!(net_client_server.len(), 1);
        assert_eq!(net_client_server[0].acknowledgment_number(), last_ack_in_order);

        // сервер принимает первый dup ack
        server.accept_request(net_client_server.remove(0)).await;
        net_server_client.append(&mut server.get_response().await);
        assert_eq!(server.state.cwnd, 15);
        assert_eq!(server.state.flight_size, 15);
        assert_eq!(net_server_client.len(), 6); // 012, 345, 678, 9ab, cde, fgh

        net_server_client_tick = 3;

        // Клиент принимает четвертый пакет (9ab), но должен сгенерировать ack на первый пакет (2 dup ack)
        client.accept_request(net_server_client[net_server_client_tick].clone()).await;
        net_client_server.append(&mut client.get_response().await);
        assert_eq!(client.state.out_of_order_buffer.len(), 2); // 678, 9ab
        assert_eq!(net_client_server.len(), 1);
        assert_eq!(net_client_server[0].acknowledgment_number(), last_ack_in_order);

        // сервер принимает второй dup ack
        server.accept_request(net_client_server.remove(0)).await;
        net_server_client.append(&mut server.get_response().await);
        assert_eq!(server.state.cwnd, 15);
        assert_eq!(server.state.flight_size, 15, "При получении dup ack, flight_size не уеньшается");
        assert_eq!(net_server_client.len(), 6); // 012, 345, 678, 9ab, cde, fgh

        net_server_client_tick = 4;

        // Клиент принимает пятый пакет (cde), но должен сгенерировать ack на первый пакет (3 dup ack)
        client.accept_request(net_server_client[net_server_client_tick].clone()).await;
        net_client_server.append(&mut client.get_response().await);
        assert_eq!(client.state.out_of_order_buffer.len(), 3); // 678, 9ab, cde
        assert_eq!(net_client_server.len(), 1);
        assert_eq!(net_client_server[0].acknowledgment_number(), last_ack_in_order);

        // сервер принимает третий dup ack
        server.accept_request(net_client_server.remove(0)).await;
        net_server_client.append(&mut server.get_response().await);
        assert_eq!(net_server_client.last().unwrap().sequence_number(), net_server_client[1].sequence_number());
        assert_eq!(server.state.cwnd, 16);
        assert_eq!(server.state.flight_size, 15);
        assert_eq!(server.state.ssthresh, 7, "3 dup ack. Вычисляется ssthresh");
        assert_eq!(net_server_client.len(), 7); // 012, 345, 678, 9ab, cde, fgh, 345

        net_server_client_tick = 5;

        // клиент принимает шестой пакет (fgh) из сети в порядке очереди
        // let expected_next_ack = flying_packet.sequence_number().wrapping_add(flying_packet.payload().len() as u32);
        client.accept_request(net_server_client[net_server_client_tick].clone()).await;
        net_client_server.append(&mut client.get_response().await); // клиент снова отдает dup ack
        assert_eq!(client.state.out_of_order_buffer.len(), 4); // 678, 9ab, cde, fgh
        assert_eq!(net_client_server[0].acknowledgment_number(), last_ack_in_order);

        // сервер принимает четвертый dup ack
        server.accept_request(net_client_server.remove(0)).await;
        net_server_client.append(&mut server.get_response().await);
        assert_eq!(server.state.cwnd, 19);
        assert_eq!(server.state.flight_size, 19);
        assert_eq!(net_server_client.len(), 9); // 012, 345, 678, 9ab, cde, fgh, 345, jkl, m

        net_server_client_tick = 6;

        // клиент принимает ретранслированный пакет
        client.accept_request(net_server_client[net_server_client_tick].clone()).await;
        net_client_server.append(&mut client.get_response().await);
        assert_eq!(client.state.out_of_order_buffer.len(), 0); // клиент отдает ack всех ранее принятых пакетов
        assert_eq!(net_client_server.len(), 1);
        assert_eq!(net_client_server[0].acknowledgment_number(), net_server_client[net_server_client_tick - 1].sequence_number().wrapping_add(net_server_client[net_server_client_tick - 1].payload().len() as u32));

        // сервер принимает ack, что все ранее отрпавленные пакеты приняты
        server.accept_request(net_client_server.remove(0)).await;
        net_server_client.append(&mut server.get_response().await); // сервер продолжает слать данные
        assert_eq!(server.state.cwnd, 22);
        assert_eq!(server.state.flight_size, 9);
        assert_eq!(net_server_client.len(), 11); // 012, 345, 678, 9ab, cde, fgh, 345, jkl, m, nop, qr

        net_server_client_tick = 7;

        // Клиент принимает следующий пакет с данными (jkl)
        client.accept_request(net_server_client[net_server_client_tick].clone()).await;
        net_client_server.append(&mut client.get_response().await);

        server.accept_request(net_client_server.remove(0)).await;
        net_client_server.append(&mut client.get_response().await);
        assert_eq!(server.state.cwnd, 25);
        assert_eq!(server.state.flight_size, 6);
        assert_eq!(net_server_client.len(), 11); // 012, 345, 678, 9ab, cde, fgh, 345, jkl, m, nop, qr

        net_server_client_tick = 8;

        // Клиент принимает следующий пакет с данными (m)
        client.accept_request(net_server_client[net_server_client_tick].clone()).await;
        net_client_server.append(&mut client.get_response().await);

        server.accept_request(net_client_server.remove(0)).await;
        net_client_server.append(&mut client.get_response().await);
        assert_eq!(server.state.cwnd, 26);
        assert_eq!(server.state.flight_size, 5);
        assert_eq!(net_server_client.len(), 11); // 012, 345, 678, 9ab, cde, fgh, 345, jkl, m, nop, qr

        net_server_client_tick = 9;

        // Клиент принимает следующий пакет с данными (nop)
        client.accept_request(net_server_client[net_server_client_tick].clone()).await;
        net_client_server.append(&mut client.get_response().await);

        server.accept_request(net_client_server.remove(0)).await;
        net_client_server.append(&mut client.get_response().await);
        assert_eq!(server.state.cwnd, 29);
        assert_eq!(server.state.flight_size, 2);
        assert_eq!(net_server_client.len(), 11); // 012, 345, 678, 9ab, cde, fgh, 345, jkl, m, nop, qr

        net_server_client_tick = 10;

        // Клиент принимает следующий пакет с данными (qr)
        client.accept_request(net_server_client[net_server_client_tick].clone()).await;
        net_client_server.append(&mut client.get_response().await);

        server.accept_request(net_client_server.remove(0)).await;
        net_client_server.append(&mut client.get_response().await);
        assert_eq!(server.state.cwnd, 31);
        assert_eq!(server.state.flight_size, 0);
        assert_eq!(net_server_client.len(), 11); // 012, 345, 678, 9ab, cde, fgh, 345, jkl, m, nop, qr

        assert_eq!(String::from_utf8_lossy(client.state.read_buffer.as_slice()), server_data);
    }
}
