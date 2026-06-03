use rand::Rng;
use std::{
    collections::{BTreeMap, VecDeque, btree_map::Entry}, fmt::Display, io, net::Ipv4Addr, time::{Duration, Instant}, u32
};
use tracing::{debug, error, warn};

use crate::{
    net_packet_parser::{
        IpTcpPacket, Ipv4TcpPacket, TcpFlags, TcpPacket, get_ack_data_response, get_ack_response,
        get_handshake_response,
    },
    utils::PacketHandler,
};

#[derive(Clone, Copy)]
pub enum TcpState {
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
    app_buffer: VecDeque<u8>,
    destination_addr: Ipv4Addr,
    destination_port: u16,
    mss: u16,
    out_of_order_buffer: BTreeMap<u32, Vec<u8>>,
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
    wnd_size: u32,
    // Поля TCP состояния (бывшие SharedTcpState)
    cwnd: u32,
    flight_size: u32,
    rcv_timestamp: u32,
    rwnd: u32,
    smss: u16,
    snd_ack: u32,
    snd_seq: u32,
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
            app_buffer: VecDeque::new(),
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
            state: TcpState::Close,
            wnd_scl: 0,
            wnd_size: 0,
            cwnd: 0,
            flight_size: 0,
            rcv_timestamp: 0,
            rwnd: 0,
            smss: 65535,
            snd_ack: 0,
            snd_seq: rng.next_u32(),
            unacked_packets: BTreeMap::new(),
        }
    }

    async fn send_syn_ack_packet(&self) -> Result<(), std::io::Error> {
        let wnd_size = (self.wnd_size >> self.wnd_scl) as u16;

        let raw_response = get_handshake_response(
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

        (self.handler)(raw_response).await?;

        Ok(())
    }

    async fn handle_data_in_established(
        &mut self,
        packet: Ipv4TcpPacket,
    ) -> Result<(), std::io::Error> {
        let seq_num = packet.sequence_number();
        let data = packet.payload();

        if seq_num == self.rcv_seq_next {
            self.process_in_order_data(packet).await?;
        } else if seq_num > self.rcv_seq_next {
            self.buffer_out_of_order_data(seq_num, data);
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

        (self.handler)(raw_response).await?;

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
        match self.out_of_order_buffer.entry(seq_num) {
            Entry::Vacant(entry) => {
                entry.insert(data);
            }
            Entry::Occupied(_) => {
                warn!("Duplicate unordered segment SEQ={}", seq_num);
            }
        }
    }

    pub async fn process_event(&mut self, packet: Ipv4TcpPacket) -> Result<(), std::io::Error> {
        let old_state = self.state;

        let event = packet_to_event(packet.tcp());

        match (old_state, event.clone()) {
            (TcpState::Listen, TcpEvent::SegmentArrives(flags)) if flags.syn && !flags.ack => {
                self.mss = packet.options().mss.min(self.mss);
                self.wnd_scl = packet.options().window_scale;
                self.wnd_size = (65535) << self.wnd_scl;
                self.rcv_seq = packet.sequence_number();
                self.rcv_ack = packet.acknowledgment_number();

                self.smss = packet.options().mss;

                if self.smss > 2190 {
                    self.cwnd = (2 * self.smss) as u32;
                } else if self.smss > 1095 && self.smss <= 2190 {
                    self.cwnd = (3 * self.smss) as u32;
                } else {
                    self.cwnd = (4 * self.smss) as u32;
                }

                self.rcv_timestamp = packet.options().timestamp.0;
                self.snd_ack = self.rcv_seq.wrapping_add(1);
                self.rwnd = (packet.window_size() as u32) << self.wnd_scl;

                self.send_syn_ack_packet().await?;

                self.rcv_seq_next = self.rcv_seq.wrapping_add(1);
                self.snd_seq = self.snd_seq.wrapping_add(1);

                self.state = TcpState::SynReceived;
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
                self.rcv_seq = packet.sequence_number();
                // НЕ обновляем rcv_ack здесь - acknowledgment_number в пакете с данными
                // может быть старым. Обновление только в SegmentArrives
                self.wnd_size = self.wnd_size.wrapping_sub(packet.payload().len() as u32);

                self.snd_ack = self.rcv_seq.wrapping_add(packet.payload().len() as u32);
                self.rcv_timestamp = packet.options().timestamp.0;
                self.rwnd = (packet.window_size() as u32) << self.wnd_scl;

                self.handle_data_in_established(packet.clone()).await?;

                self.rcv_seq_next = self.rcv_seq.wrapping_add(packet.payload().len() as u32);
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
                // Увеличиваем cwnd только при получении ACK на данные (не SYN)
                self.cwnd += n.min(self.smss as u32);
                self.flight_size -= n;
                self.rwnd = (packet.window_size() as u32) << self.wnd_scl;
                self.rcv_ack = new_ack;

                // После получения ACK на данные, отправляем pending данные
                self.send_pending_data().await;
            }
            (_, TcpEvent::RstArrives) => {
                warn!(
                    "process_event TcpEvent::RstArrives {} {}",
                    packet.destination_socket().to_string(),
                    packet.sequence_number()
                );

                self.read_buffer.clear();
                self.app_buffer.clear();

                self.state = TcpState::Close;
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

        self.unacked_packets.insert(self.snd_seq, PendingPacket {
            data: data.clone(),
            len: data_size,
            retransmits: 0,
            send_at: Instant::now(),
            seq: self.snd_seq
        });

        self.flight_size += data_size as u32;
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
                false,
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

            self.unacked_packets.insert(self.snd_seq, PendingPacket {
                data: send_data.clone(),
                len: send_size,
                retransmits: 0,
                send_at: Instant::now(),
                seq: self.snd_seq
            });

            self.flight_size += send_size as u32;
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
    use std::{io::{Error, ErrorKind}, net::{Ipv4Addr, SocketAddrV4}, sync::Arc, time::{Duration, SystemTime, UNIX_EPOCH}};

    use etherparse::{PacketBuilder, TcpOptionElement};
    use rand::Rng;
    use tokio::sync::{Mutex, mpsc::{UnboundedReceiver, unbounded_channel}};

    use crate::{net_packet_parser::{IpTcpPacket, Ipv4TcpPacket, Packet, RawIpPacket, get_ack_data_response, get_ack_response, net_packet_parser}, tcp_state_machine::{TcpState, TcpStateMachine}};

    struct Client {
        ack_num: u32,
        mss: u16,
        seq_num: u32,
        server_timestamp: u32,
        socket: SocketAddrV4,
    }

    impl Client {
        fn new(
            mss: u16,
            socket: SocketAddrV4
        ) -> Self {
            let mut rng = rand::rng();

            Client {
                ack_num: 0,
                mss,
                seq_num: rng.next_u32(),
                server_timestamp: 0,
                socket,
            }
        }

        fn send_syn(&mut self, destination_socket: SocketAddrV4) -> Ipv4TcpPacket {
            let syn_packet = get_syn_response(
                destination_socket.ip(),
                destination_socket.port(),
                self.mss,
                self.seq_num,
                self.socket.ip(),
                self.socket.port(),
                65535,
            ).unwrap();

            if let Some(Packet::Ipv4Tcp(packet)) = net_packet_parser(syn_packet.as_slice()) {
                self.seq_num = self.seq_num.wrapping_add(1);

                return packet;
            } else {
                panic!("Packet should be ipv4");
            }
        }

        fn send_ack(&self, destination_socket: SocketAddrV4) -> Ipv4TcpPacket {
            let packet = get_ack_response(
                self.ack_num,
                *destination_socket.ip(),
                destination_socket.port(),
                self.seq_num,
                *self.socket.ip(),
                self.socket.port(),
                self.server_timestamp,
                65535,
            ).unwrap();

            if let Some(Packet::Ipv4Tcp(packet)) = net_packet_parser(packet.as_slice()) {
                return packet;
            } else {
                panic!("Packet should be ipv4");
            }
        }

        fn send_data_packet(&mut self, destination_socket: SocketAddrV4, mut data: Vec<u8>) -> Vec<Ipv4TcpPacket> {
            let mut result: Vec<Ipv4TcpPacket> = Vec::new();

            while !data.is_empty() {
                let send_size = self.mss as usize;
                let send_data: Vec<u8> = data.drain(0..send_size).collect();
                let is_last = data.is_empty();

                let data_packet = get_ack_data_response(
                    self.ack_num,
                    *destination_socket.ip(),
                    destination_socket.port(),
                    &send_data,
                    is_last,
                    self.seq_num,
                    *self.socket.ip(),
                    self.socket.port(),
                    self.server_timestamp,
                    65535,
                ).unwrap();

                self.seq_num = self.seq_num.wrapping_add(send_data.len() as u32);

                if let Some(Packet::Ipv4Tcp(packet)) = net_packet_parser(data_packet.as_slice()) {
                    result.push(packet);
                } else {
                    panic!("Packet should be ipv4");
                }
            }

            return result;
        }

        fn accept_packet(&mut self, packet: Ipv4TcpPacket) -> Ipv4TcpPacket {
            // SYN и FIN занимают 1 номер последовательности даже без payload
            let seq_increment = if packet.syn() { 1 } else { 0 };
            self.ack_num = packet.sequence_number().wrapping_add(packet.payload().len() as u32 + seq_increment);
            self.server_timestamp = packet.options().timestamp.0;

            let raw_packet = get_ack_response(
                self.ack_num,
                packet.ip.source_address,
                packet.tcp.source_port,
                self.seq_num,
                packet.ip.destination_address,
                packet.tcp.destination_port,
                packet.tcp.options.timestamp.0,
                65535,
            ).unwrap();

            if let Some(Packet::Ipv4Tcp(packet)) = net_packet_parser(raw_packet.as_slice()) {
                    return packet;
            } else {
                panic!("Packet should be ipv4");
            }
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
        destination_socket: SocketAddrV4,
        server: &mut Server,
    ) {
        let data = "123456789";

        let net_client_server_packets = client.send_data_packet(destination_socket, data.as_bytes().to_vec());

        for client_data_packet in net_client_server_packets {
            server.accept_request(client_data_packet.clone()).await;
            
            let mut net_server_client_packets = server.get_response().await;

            let packet = net_server_client_packets.remove(0);

            client.accept_packet(packet.clone());

            let expect_ack_num = client_data_packet.sequence_number().wrapping_add(client_data_packet.payload().len() as u32);

            assert!(packet.ack());
            assert_eq!(packet.acknowledgment_number(), expect_ack_num);
            assert_eq!(packet.sequence_number(), client_data_packet.acknowledgment_number());
        }
    }

    #[tokio::test]
    async fn test() {
        let source_socket = SocketAddrV4::new(
            Ipv4Addr::new(127, 0, 0, 1),
            8000,
        );

        let destination_socket = SocketAddrV4::new(
            Ipv4Addr::new(127, 0, 0, 1),
            8001,
        );

        let mut server = Server::new(
            destination_socket,
            source_socket,
        );

        let mss = 3;
        let mut client = Client::new(mss, source_socket);

        {
            let net_client_server_packet = client.send_syn(destination_socket);

            server.accept_request(net_client_server_packet).await;

            let mut net_server_client_packets = server.get_response().await;
        
            let packet = net_server_client_packets.remove(0);

            drop(net_server_client_packets);

            assert!(packet.syn());
            assert!(packet.ack());
            assert_eq!(packet.acknowledgment_number(), client.seq_num);

            let net_client_server_packet = client.accept_packet(packet);

            server.accept_request(net_client_server_packet).await;

            match server.state.state {
                TcpState::Established => {},
                _ => {
                    panic!("State of state machine should be established")
                }
            };
        }

        assert_client_send_data(
            &mut client,
            destination_socket,
            &mut server,
        ).await;

        let server_data = "0123456789abcdefghjklmnopqrzxcqwe493689zxcftg047"; // 48

        // Сервер отправляет пакеты с данными в сеть
        server.send_data(server_data.as_bytes().to_vec()).await;
        let mut net_serever_client_packets: Vec<Ipv4TcpPacket> = Vec::new();

        let client_server_packet = {
            let mut resp = server.get_response().await;
            net_serever_client_packets.append(&mut resp);

            // Проверка сколько пакетов в сети. По скольку ширина окна 3, то cwnd = 4
            assert_eq!(net_serever_client_packets.len(), 4);

            // Клиент принимает первый пакет из сети и генерит ack
            client.accept_packet(net_serever_client_packets.remove(0).clone())
        };

        // сервер принимает ack на первый пакет
        server.accept_request(client_server_packet).await;

        let mut resp = server.get_response().await;
        net_serever_client_packets.append(&mut resp);
        // Проверка сколько пакетов ы сети. cwnd увеличелось на 1. Теперь cwnd = 5
        assert_eq!(net_serever_client_packets.len(), 5);

        let mut resp = server.get_response().await;
        net_serever_client_packets.append(&mut resp);

        // Клиент принимает второй пакет из сети и генерит ack
        let client_server_packet = client.accept_packet(net_serever_client_packets.remove(0).clone());

        // сервер принимает ack на второй пакет
        server.accept_request(client_server_packet.clone()).await;

        let mut resp = server.get_response().await;

        // Сервер отдает пакеты в сеть
        net_serever_client_packets.append(&mut resp);
        // Проверка сколько пакетов ы сети. cwnd увеличелось на 1. Теперь cwnd = 6
        assert_eq!(net_serever_client_packets.len(), 6);

        // Предположим, что третий пакет потерялся. Отправляем дублирующий ack от второго пакета
        server.accept_request(client_server_packet.clone()).await;

        let resp = server.get_response().await;
        assert_eq!(resp.len(), 0);

        // Проиходит второй дублирующий пакет
        server.accept_request(client_server_packet.clone()).await;
        assert_eq!(resp.len(), 0);

        // Проиходит третий дублирующий пакет
        server.accept_request(client_server_packet.clone()).await;

    }
}
