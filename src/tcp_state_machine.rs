use rand::Rng;
use std::{
    collections::{BTreeMap, btree_map::Entry}, fmt::Display, net::Ipv4Addr, sync::{Arc, Mutex as StdMutex}, time::Instant, u32
};
use tokio::sync::Notify;
use tracing::{debug, error, warn};

use crate::{
    net_packet_parser::{
        IpTcpPacket, Ipv4TcpPacket, RawIpPacket, TcpFlags, TcpPacket, get_ack_data_response, get_ack_response, get_fin_response, get_handshake_response, get_syn_response
    }, tcp_stream::{ConnShared, new_conn_shared}, utils::PacketHandler
};

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum TcpState {
    Closed,
    Listen,
    SynSent,
    SynReceived,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
}

impl Display for TcpState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TcpState::Closed => write!(f, "Closed"),
            TcpState::Listen => write!(f, "Listen"),
            TcpState::SynSent => write!(f, "SynSent"),
            TcpState::SynReceived => write!(f, "SynReceived"),
            TcpState::Established => write!(f, "Established"),
            TcpState::FinWait1 => write!(f, "FIN-WAIT-1"),
            TcpState::FinWait2 => write!(f, "FIN-WAIT-2"),
            TcpState::CloseWait => write!(f, "CLOSE-WAIT"),
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

/// ВАЖНО: наличие payload имеет приоритет над флагами — сегмент с данными и FIN
/// трактуется как DataArrives, а не как SegmentArrives(fin).
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
    // --- Конфигурация соединения ---
    destination_addr: Ipv4Addr,
    destination_port: u16,
    source_addr: Ipv4Addr,
    source_port: u16,
    handler: PacketHandler,
    mss: u16,
    smss: u16,
    wnd_scl: u8,
    snd_wnd_scl: u8,

    // --- Состояние FSM ---
    state: TcpState,
    prev_rcv_ack: u32,

    // --- Приём (receive path) ---
    rcv_seq: u32,
    rcv_seq_next: u32,
    rcv_ack: u32,
    rcv_timestamp: u32,
    rwnd: u32,
    snd_wnd_size: u32,
    /// Приёмный буфер FSM: реассембляция in-order сегментов, флаш в ConnShared по PSH
    recv_buffer: Vec<u8>,
    out_of_order_buffer: BTreeMap<u32, Ipv4TcpPacket>,

    // --- Мост к AsyncRead/AsyncWrite-половинкам (см. tcp_stream.rs) ---
    shared: Arc<StdMutex<ConnShared>>,
    notify: Arc<Notify>,

    // --- Передача (send path) ---
    snd_seq: u32,
    snd_ack: u32,
    /// Очередь на отправку: драйвер перекачивает сюда данные из ConnShared,
    /// send_pending_data сегментирует очередь согласно cwnd/rwnd
    send_queue: Vec<u8>,
    unacked_packets: BTreeMap<u32, PendingPacket>,

    // --- Управление перегрузкой (RFC 5681) ---
    cwnd: u32,
    ssthresh: u32,
    flight_size: u32,
    dup_ack_count: u32,
    fast_retransmit_done: bool,
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

        let (shared, notify) = new_conn_shared();

        Self {
            // --- Конфигурация соединения ---
            destination_addr,
            destination_port,
            source_addr,
            source_port,
            handler,
            mss: 65535,
            smss: 65535,
            wnd_scl: 0,
            snd_wnd_scl: 10,

            // --- Состояние FSM ---
            state: TcpState::Closed,
            prev_rcv_ack: 0,

            // --- Приём (receive path) ---
            rcv_seq: 0,
            rcv_seq_next: 0,
            rcv_ack: 0,
            rcv_timestamp: 0,
            rwnd: 0,
            snd_wnd_size: 65535 << 10,
            recv_buffer: Vec::new(),
            out_of_order_buffer: BTreeMap::new(),

            // --- Мост к половинкам ---
            shared,
            notify,

            // --- Передача (send path) ---
            snd_seq: rng.next_u32(),
            snd_ack: 0,
            send_queue: Vec::new(),
            unacked_packets: BTreeMap::new(),

            // --- Управление перегрузкой (RFC 5681) ---
            cwnd: 0,
            ssthresh: u32::MAX,
            flight_size: 0,
            dup_ack_count: 0,
            fast_retransmit_done: false,
        }
    }

    /// FSM в состоянии Listen (пассивное открытие — входящее соединение).
    /// Заменяет внешнюю мутацию `state.state = TcpState::Listen`.
    pub fn new_listen(
        source_addr: Ipv4Addr,
        source_port: u16,
        destination_addr: Ipv4Addr,
        destination_port: u16,
        handler: PacketHandler,
    ) -> Self {
        let mut fsm = Self::new(source_addr, source_port, destination_addr, destination_port, handler);
        fsm.state = TcpState::Listen;
        fsm
    }

    /// Текущее состояние FSM.
    pub fn state(&self) -> TcpState {
        self.state
    }

    /// Read-половинка потока поверх приёмного буфера FSM.
    pub(crate) fn recv_half(&self) -> crate::tcp_stream::TcpRecvHalf {
        crate::tcp_stream::TcpRecvHalf::new(Arc::clone(&self.shared), Arc::clone(&self.notify))
    }

    /// Send-половинка потока поверх отправного буфера FSM.
    pub(crate) fn send_half(&self) -> crate::tcp_stream::TcpSendHalf {
        crate::tcp_stream::TcpSendHalf::new(Arc::clone(&self.shared), Arc::clone(&self.notify))
    }

    /// Уведомитель драйвера: пробуждение для pump_send.
    pub(crate) fn notify(&self) -> Arc<Notify> {
        Arc::clone(&self.notify)
    }

    /// Размер окна, анонсируемый в исходящих пакетах (учитывает window scale)
    fn advertised_window(&self) -> u16 {
        (self.snd_wnd_size >> self.snd_wnd_scl) as u16
    }

    async fn send_syn_ack_packet(&self) -> Result<(), std::io::Error> {
        let wnd_size = self.advertised_window();

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

    fn process_data(&mut self, packet: Ipv4TcpPacket) -> Result<(), std::io::Error> {
        let data = packet.payload();
        let push_flag = packet.psh();

        self.recv_buffer.extend(data.as_slice());

        // Флаш приёмного буфера в read-половинку по PSH (семантика сохранена
        // сознательно; непрерывный поток — отдельная задача, не в этом рефакторинге)
        if push_flag {
            self.flush_recv();
        }
        Ok(())
    }

    /// Выгружает приёмный буфер FSM в ConnShared и будит ждущего читателя.
    fn flush_recv(&mut self) {
        let data = std::mem::take(&mut self.recv_buffer);

        self.shared.lock().unwrap().push_recv(&data);
    }

    /// Обрабатывает сегмент, пришедший в порядке очереди: обновляет rcv-состояние
    /// и передаёт данные из сегмента в app_buffer (process_data).
    fn accept_in_order_segment(&mut self, packet: &Ipv4TcpPacket) -> Result<(), std::io::Error> {
        self.rcv_seq = packet.sequence_number();
        self.rwnd = (packet.window_size() as u32) << self.wnd_scl;
        self.rcv_seq_next = self.rcv_seq.wrapping_add(packet.payload().len() as u32);
        self.snd_ack = self.rcv_seq.wrapping_add(packet.payload().len() as u32);

        self.process_data(packet.clone())
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
            self.advertised_window(),
        )?;

        (self.handler)(raw_packet).await?;

        self.state = TcpState::SynSent;

        Ok(())
    }

    async fn send_ack(&self) -> Result<(), std::io::Error> {
        let wnd_size = self.advertised_window();

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

    /// Отправляет сырой пакет через handler: логирует ошибку и возвращает её
    /// вызывающему, который решает — пробросить или игнорировать.
    async fn send_raw(&self, raw_packet: RawIpPacket, context: &str) -> Result<(), std::io::Error> {
        if let Err(e) = (self.handler)(raw_packet).await {
            error!("Failed to send {} response {}", context, e);
            return Err(e);
        }

        Ok(())
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

    /// Обновляет prev_rcv_ack для отслеживания дублирующих ACK.
    /// Вызывается ДО присвоения self.rcv_ack нового значения.
    fn update_prev_rcv_ack(&mut self, new_ack: u32) {
        if self.prev_rcv_ack == 0 {
            self.prev_rcv_ack = new_ack;
        } else {
            self.prev_rcv_ack = self.rcv_ack;
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

    /// Диспетчер FSM: определяет событие из пакета и передаёт обработку
    /// хендлеру, соответствующему паре (состояние, событие).
    pub async fn process_event(&mut self, packet: Ipv4TcpPacket) -> Result<(), std::io::Error> {
        let old_state = self.state;

        let event = packet_to_event(packet.tcp());

        match (old_state, event.clone()) {
            (TcpState::Listen, TcpEvent::SegmentArrives(flags)) if flags.syn && !flags.ack => {
                self.handle_syn_in_listen(packet).await
            }
            (TcpState::SynSent, TcpEvent::SegmentArrives(flags)) if flags.syn && flags.ack => {
                self.handle_syn_ack_in_syn_sent(packet).await
            }
            (TcpState::SynReceived, TcpEvent::SegmentArrives(flags)) if !flags.syn && flags.ack => {
                self.handle_ack_in_syn_received(packet).await
            }
            (TcpState::Established, TcpEvent::DataArrives) => {
                self.handle_data_in_established(packet).await
            }
            (TcpState::FinWait1,  TcpEvent::SegmentArrives(flags)) if flags.ack => {
                self.handle_ack_in_fin_wait1(packet).await
            }
            (TcpState::Established, TcpEvent::SegmentArrives(flags)) if flags.fin => {
                self.handle_fin_in_established(packet).await
            }
            (TcpState::Established, TcpEvent::SegmentArrives(flags)) if !flags.syn && flags.ack => {
                self.handle_ack_in_established(packet).await
            }
            (_, TcpEvent::RstArrives) => self.handle_rst(packet).await,
            (_, TcpEvent::Unknown) => {
                warn!("++++++ process_event TcpEvent::Unknown");
                Ok(())
            }
            _ => {
                error!(
                    "Invalid state/event combination event {}, state {}",
                    event, old_state
                );
                Err(std::io::Error::other(format!("Invalid state/event combination event {}, state {}", event, old_state)))
            }
        }
    }

    /// Listen + SYN: инициализирует параметры соединения из опций клиента,
    /// отвечает SYN-ACK и переходит в SynReceived.
    async fn handle_syn_in_listen(&mut self, packet: Ipv4TcpPacket) -> Result<(), std::io::Error> {
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

        Ok(())
    }

    /// SynSent + SYN-ACK: завершает трёхстороннее рукопожатие со стороны
    /// активного открытия — обновляет параметры соединения и отправляет ACK.
    async fn handle_syn_ack_in_syn_sent(&mut self, packet: Ipv4TcpPacket) -> Result<(), std::io::Error> {
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

        Ok(())
    }

    /// SynReceived + ACK: ACK на наш SYN-ACK, соединение установлено.
    async fn handle_ack_in_syn_received(&mut self, packet: Ipv4TcpPacket) -> Result<(), std::io::Error> {
        self.rcv_seq = packet.sequence_number();
        self.update_prev_rcv_ack(packet.acknowledgment_number());

        self.rcv_ack = packet.acknowledgment_number();

        self.state = TcpState::Established;

        self.rcv_timestamp = packet.options().timestamp.0;

        // НЕ вызываем send_pending_data при ACK на SYN-ACK

        Ok(())
    }

    /// Established + данные: кладёт упорядоченные сегменты в app_buffer,
    /// неупорядоченные — в out_of_order_buffer, и отправляет ACK.
    async fn handle_data_in_established(&mut self, packet: Ipv4TcpPacket) -> Result<(), std::io::Error> {
        self.rcv_timestamp = packet.options().timestamp.0;
        self.snd_wnd_size = self.snd_wnd_size.wrapping_sub(packet.payload().len() as u32);

        if packet.sequence_number() == self.rcv_seq_next {
            self.accept_in_order_segment(&packet)?;

            // Вычитываем сегменты, ставшие упорядоченными после прихода этого пакета
            while let Some(data) = self.out_of_order_buffer.remove(&self.rcv_seq_next) {
                self.accept_in_order_segment(&data)?;
            }

            self.send_ack().await?;

        } else if packet.sequence_number() > self.rcv_seq_next {
            self.buffer_out_of_order_data(packet.sequence_number(), packet);

            self.send_ack().await?;
        }

        Ok(())
    }

    /// FinWait1 + ACK: наш FIN подтверждён, переходим в FinWait2.
    async fn handle_ack_in_fin_wait1(&mut self, packet: Ipv4TcpPacket) -> Result<(), std::io::Error> {
        self.rcv_seq = packet.sequence_number();
        self.rcv_ack = packet.acknowledgment_number();
        self.rcv_timestamp = packet.options().timestamp.0;

        self.state = TcpState::FinWait2;

        Ok(())
    }

    /// Established + FIN: удалённая сторона закрывает соединение.
    /// Подтверждаем FIN, сигнализируем EOF внешнему сокету, переходим в CloseWait.
    async fn handle_fin_in_established(&mut self, packet: Ipv4TcpPacket) -> Result<(), std::io::Error> {
        self.rcv_seq = packet.sequence_number();
        self.rcv_ack = packet.acknowledgment_number();
        self.rcv_timestamp = packet.options().timestamp.0;

        self.snd_ack = self.rcv_seq.wrapping_add(1);

        self.state = TcpState::CloseWait;

        // EOF на read-половинке: пир закрыл свою сторону
        self.set_recv_eof();

        self.send_ack().await?;

        Ok(())
    }

    /// Established + ACK: различает дублирующие и новые ACK и управляет
    /// congestion control (Fast Retransmit / Fast Recovery / рост cwnd).
    async fn handle_ack_in_established(&mut self, packet: Ipv4TcpPacket) -> Result<(), std::io::Error> {
        self.rcv_seq = packet.sequence_number();
        self.update_prev_rcv_ack(packet.acknowledgment_number());

        let new_ack = packet.acknowledgment_number();

        self.rcv_timestamp = packet.options().timestamp.0;
        let n = new_ack - self.prev_rcv_ack;

        // Проверяем, это дублирующий ACK (new_ack == prev_rcv_ack)
        if n == 0 && self.prev_rcv_ack != 0 {
            self.handle_duplicate_ack(&packet).await;
        } else if n > 0 {
            self.handle_new_ack(new_ack, n).await;
        }

        self.rwnd = (packet.window_size() as u32) << self.wnd_scl;
        self.rcv_ack = new_ack;

        Ok(())
    }

    /// Обработка дублирующего ACK: увеличивает счётчик, после 3 дублирующих ACK
    /// запускает Fast Retransmit, далее — Fast Recovery (раздувание cwnd).
    async fn handle_duplicate_ack(&mut self, packet: &Ipv4TcpPacket) {
        self.dup_ack_count += 1;
        debug!("Duplicate ACK #{} received {} > {}", self.dup_ack_count, packet.source_socket(), packet.destination_socket());

        // Fast Retransmit после 3 дублирующих ACK
        if self.dup_ack_count == 3 && !self.fast_retransmit_done {
            self.fast_retransmit_done = true;
            self.do_fast_retransmit(packet).await;
        } else if self.dup_ack_count > 3 && self.fast_retransmit_done {
            self.cwnd += self.smss as u32;

            // Во время Fast Recovery отправляем новые данные если позволяет окно
            self.send_pending_data().await;
        }
    }

    /// Fast Retransmit: уменьшает ssthresh вдвое, раздувает cwnd на 3 SMSS
    /// и переотправляет старший неподтверждённый пакет.
    async fn do_fast_retransmit(&mut self, packet: &Ipv4TcpPacket) {
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

            self.send_raw(raw_packet, "RETRANSMIT").await.ok();
        } else {
            warn!("Fast Retransmit {} > {}: retransmitting packet is not found. unacked_packets len {}", packet.source_socket(), packet.destination_socket(), self.unacked_packets.len());
        }
    }

    /// Обработка нового ACK: сбрасывает счётчик дублирующих ACK, удаляет
    /// подтверждённые пакеты, увеличивает cwnd на полученные байты
    /// и отправляет pending данные.
    async fn handle_new_ack(&mut self, new_ack: u32, n: u32) {
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

    /// RST: очищает буферы и переводит соединение в Closed.
    async fn handle_rst(&mut self, packet: Ipv4TcpPacket) -> Result<(), std::io::Error> {
        warn!(
            "process_event TcpEvent::RstArrives {} {}",
            packet.destination_socket().to_string(),
            packet.sequence_number()
        );

        self.recv_buffer.clear();

        // После RST соединение абортнуто: очередь ретрансмиссий больше не нужна
        self.unacked_packets.clear();
        self.recalc_flight_size();

        // Отправной путь тоже закрывается: накопленные, но не отправленные
        // данные после RST уходить не должны
        self.send_queue.clear();
        self.shared.lock().unwrap().take_send();

        // EOF на read-половинке: соединение абортнуто
        self.set_recv_eof();

        self.state = TcpState::Closed;

        Ok(())
    }

    async fn send_fin(&mut self) {
        let raw_packet = get_fin_response(
            self.snd_ack,
            self.destination_addr,
            self.destination_port,
            self.snd_seq,
            self.source_addr,
            self.source_port,
            self.rcv_timestamp,
            65535
        ).unwrap();

        if self.send_raw(raw_packet, "FIN").await.is_err() {
            return;
        }

        self.snd_seq = self.snd_seq.wrapping_add(1);
        self.state = TcpState::FinWait1;

        // FIN фактически ушёл в сеть — будим ждущий poll_shutdown
        self.shared.lock().unwrap().set_fin_sent();
    }

    /// Отправляет сегмент с данными, регистрирует его в unacked_packets
    /// и продвигает snd_seq.
    async fn send_data_segment(&mut self, data: Vec<u8>, psh: bool) -> Result<(), std::io::Error> {
        let data_size = data.len();

        // ВАЖНО: окно в сегментах с данными/FIN захардкожено 65535, а не advertised_window(),
        // т.к. snd_wnd_size уменьшается на размер принятых данных
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
        ).unwrap();

        self.send_raw(raw_packet, "DATA").await?;

        self.add_to_unacked_packets(self.snd_seq, data, data_size);
        self.snd_seq = self.snd_seq.wrapping_add(data_size as u32);

        Ok(())
    }

    async fn send_pending_data(&mut self) {
        // После RST соединение закрыто — отправлять данные нельзя (в т.ч. из-за гонки:
        // писатель мог забрать данные из send_buf до выставления recv_eof)
        if self.state == TcpState::Closed {
            return;
        }

        while !self.send_queue.is_empty() {
            let available_window = self.cwnd.min(self.rwnd);
            if self.flight_size >= available_window {
                return;
            }

            let send_size = (self.smss as u32).min(available_window - self.flight_size).min(self.send_queue.len() as u32) as usize;

            if send_size == 0 {
                return;
            }

            let send_data: Vec<u8> = self.send_queue.drain(0..send_size).collect();
            let psh = self.send_queue.is_empty();

            if self.send_data_segment(send_data, psh).await.is_err() {
                return;
            }
        }
    }

    /// Перекачивает данные, накопленные write-половинкой в ConnShared, в очередь
    /// на отправку и отправляет сегменты согласно cwnd/rwnd.
    /// Вызывается драйвером при пробуждении notify.
    pub async fn pump_send(&mut self) {
        // take_send забирает данные и будит ждущего писателя (освободилось место)
        let data = self.shared.lock().unwrap().take_send();

        if !data.is_empty() {
            self.send_queue.extend_from_slice(&data);
        }

        self.send_pending_data().await;

        // Shutdown write-половинки: после осушения очереди отправляем FIN
        if self.send_queue.is_empty() && self.shared.lock().unwrap().shutdown_pending() {
            self.close().await;
        }
    }

    /// Ставит EOF на read-половинку (FIN или RST от пира) и будит читателя.
    fn set_recv_eof(&mut self) {
        self.shared.lock().unwrap().set_recv_eof();
    }

    /// Закрытие соединения со стороны прокси: отправка FIN пиру.
    /// Полная машина закрытия (LastAck, TimeWait, повторные FIN) — вне скоупа.
    pub async fn close(&mut self) {
        match self.state {
            // Активное закрытие: Established/SynReceived → FinWait1
            TcpState::Established | TcpState::SynReceived => self.send_fin().await,
            // Пир уже закрыл свою сторону (EOF отдан читателю) — отвечаем FIN
            TcpState::CloseWait => self.send_fin().await,
            // Closed/SynSent/FinWait1/FinWait2 — закрытие уже идёт или завершено
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{io::{Error, ErrorKind}, net::{Ipv4Addr, SocketAddrV4}};

    use tokio::{io::{AsyncReadExt, AsyncWriteExt}, sync::{mpsc::{UnboundedReceiver, unbounded_channel}}};

    use crate::{net_packet_parser::{IpTcpPacket, Ipv4TcpPacket, Packet, net_packet_parser}, tcp_state_machine::{TcpState, TcpStateMachine}};

    fn assert_state(actual: TcpState, expected: TcpState) {
        assert_eq!(
            std::mem::discriminant(&actual),
            std::mem::discriminant(&expected),
            "Ожидалось состояние {:?}, но получено {:?}",
            expected,
            actual
        );
    }

    /// Тестовый пир (клиент или сервер) вокруг TcpStateMachine:
    /// перехватывает исходящие пакеты в response_rx.
    struct Peer {
        response_rx: UnboundedReceiver<Ipv4TcpPacket>,
        state: TcpStateMachine,
        /// Read-половинка потока: сюда FSM выгружает принятые данные
        recv: crate::tcp_stream::TcpRecvHalf,
        /// Write-половинка потока: данные отсюда драйвер (pump_send) забирает в FSM
        send: crate::tcp_stream::TcpSendHalf,
    }

    impl Peer {
        fn new(source_socket: SocketAddrV4, destination_socket: SocketAddrV4, listen: bool) -> Self {
            let (tx, rx) = unbounded_channel::<Ipv4TcpPacket>();

            let mut state = TcpStateMachine::new(
                *source_socket.ip(),
                source_socket.port(),
                *destination_socket.ip(),
                destination_socket.port(),
                Box::new(move |raw_response| {
                    let tx = tx.clone();

                    Box::pin(async move {
                        if let Some(Packet::Ipv4Tcp(packet)) = net_packet_parser(raw_response.as_slice()) {
                            tx.send(packet).map_err(|e| Error::new(ErrorKind::Other, e))?;

                            Ok(())
                        } else {
                            panic!("syn_ack_packet should be ipv4");
                        }
                    })
                })
            );

            let recv = state.recv_half();
            let send = state.send_half();

            if listen {
                state.state = TcpState::Listen;
            }

            Peer {
                response_rx: rx,
                state,
                recv,
                send,
            }
        }

        fn new_client(source_socket: SocketAddrV4, destination_socket: SocketAddrV4) -> Self {
            Self::new(source_socket, destination_socket, false)
        }

        fn new_server(source_socket: SocketAddrV4, destination_socket: SocketAddrV4) -> Self {
            Self::new(source_socket, destination_socket, true)
        }

        async fn send_syn(&mut self, mss: Option<u16>) {
            self.state.send_syn(mss).await;
        }

        async fn send_data(&mut self, data: Vec<u8>) {
            // Как в реальном прокси: write-половинка → драйвер (pump_send)
            self.send.write_all(&data).await.unwrap();
            self.state.pump_send().await;
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

        async fn close(&mut self) {
            self.state.send_fin().await;
        }
    }

    async fn assert_client_send_data(
        client: &mut Peer,
        server: &mut Peer,
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

        let mut server = Peer::new_server(
            server_socket,
            client_socket,
        );

        let mut client = Peer::new_client(
            client_socket,
            server_socket,
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
        // «012» пришёл без PSH — данные накапливаются в приёмном буфере FSM
        // и уйдут в recv-половинку при следующем флаше по PSH
        assert_eq!(String::from_utf8_lossy(client.state.recv_buffer.as_slice()), "012");

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
        net_server_client.append(&mut server.get_response().await);
        assert_eq!(server.state.cwnd, 25);
        assert_eq!(server.state.flight_size, 6);
        assert_eq!(net_server_client.len(), 11); // 012, 345, 678, 9ab, cde, fgh, 345, jkl, m, nop, qr

        net_server_client_tick = 8;

        // Клиент принимает следующий пакет с данными (m)
        client.accept_request(net_server_client[net_server_client_tick].clone()).await;
        net_client_server.append(&mut client.get_response().await);

        server.accept_request(net_client_server.remove(0)).await;
        net_server_client.append(&mut server.get_response().await);
        assert_eq!(server.state.cwnd, 26);
        assert_eq!(server.state.flight_size, 5);
        assert_eq!(net_server_client.len(), 11); // 012, 345, 678, 9ab, cde, fgh, 345, jkl, m, nop, qr

        net_server_client_tick = 9;

        // Клиент принимает следующий пакет с данными (nop)
        client.accept_request(net_server_client[net_server_client_tick].clone()).await;
        net_client_server.append(&mut client.get_response().await);

        server.accept_request(net_client_server.remove(0)).await;
        net_server_client.append(&mut server.get_response().await);
        assert_eq!(server.state.cwnd, 29);
        assert_eq!(server.state.flight_size, 2);
        assert_eq!(net_server_client.len(), 11); // 012, 345, 678, 9ab, cde, fgh, 345, jkl, m, nop, qr

        net_server_client_tick = 10;

        // Клиент принимает следующий пакет с данными (qr)
        client.accept_request(net_server_client[net_server_client_tick].clone()).await;
        net_client_server.append(&mut client.get_response().await);

        server.accept_request(net_client_server.remove(0)).await;
        net_server_client.append(&mut server.get_response().await);
        assert_eq!(server.state.cwnd, 31);
        assert_eq!(server.state.flight_size, 0);
        assert_eq!(net_server_client.len(), 11); // 012, 345, 678, 9ab, cde, fgh, 345, jkl, m, nop, qr

        // Все данные, отправленные сервером, дошли до recv-половинки клиента:
        // финальный сегмент «qr» идёт с PSH и флашит весь накопленный буфер
        let mut received = vec![0u8; server_data.len()];
        client.recv.read_exact(&mut received).await.unwrap();
        assert_eq!(String::from_utf8_lossy(received.as_slice()), server_data);

        server.close().await;
        net_server_client.append(&mut server.get_response().await);
        match server.state.state {
            TcpState::FinWait1 => {}
            _ => panic!("State should be TcpState::FinWait1. Current is {}", server.state.state)
        }

        net_server_client_tick = 11;

        client.accept_request(net_server_client[net_server_client_tick].clone()).await;
        match client.state.state {
            TcpState::CloseWait => {},
            _ => panic!("State should be TcpState::CloseWait. Current is {}", client.state.state)
        }
        net_client_server.append(&mut client.get_response().await);
        let packet = net_client_server.remove(0);
        assert_eq!(packet.acknowledgment_number(), net_server_client[net_server_client_tick].sequence_number().wrapping_add(1));

        server.accept_request(packet).await;
        match server.state.state {
            TcpState::FinWait2 => {},
            _ => panic!("State should be TcpState::FinWait2. Current is {}", server.state.state)
        }

    }
}
