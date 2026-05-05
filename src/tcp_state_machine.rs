use rand::Rng;
use std::{
    collections::{BTreeMap, VecDeque, btree_map::Entry},
    fmt::Display,
    net::Ipv4Addr,
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

pub struct TcpStateMachine {
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
    pub read_buffer: Vec<u8>,
    snd_ack: u32,
    snd_seq: u32,
    source_addr: Ipv4Addr,
    source_port: u16,
    pub state: TcpState,
    wnd_scl: u8,
    wnd_size: u32,
    handler: PacketHandler,
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
            rcv_ack: 0,
            rcv_seq: 0,
            rcv_seq_next: 0,
            rcv_timestamp: 0,
            rcv_wnd: 0,
            read_buffer: Vec::new(),
            snd_ack: 0,
            snd_seq: rng.next_u32(),
            source_addr,
            source_port,
            state: TcpState::Close,
            wnd_scl: 0,
            wnd_size: 0,
            handler,
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
                return Err(std::io::Error::other("Invalid state/event combination"));
            }
        };

        Ok(())
    }

    pub async fn try_send_data(&mut self, mut data: Vec<u8>) {
        debug!(
            "TcpStateMachine try_send_data. data len {}, rcv_win {}",
            data.len(),
            self.rcv_wnd
        );

        while !data.is_empty() && self.rcv_wnd > 0 {
            let send_size = (self.mss as u32).min(self.rcv_wnd).min(data.len() as u32) as usize;

            if send_size == 0 {
                break;
            }

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
            )
            .unwrap();

            if let Err(e) = (self.handler)(raw_packet).await {
                error!("Failed to send response {}", e);
                continue;
            }

            self.snd_seq = self.snd_seq.wrapping_add(send_size as u32);
        }

        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
    }
}
