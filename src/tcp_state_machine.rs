use rand::Rng;
use std::{
    collections::{BTreeMap, btree_map::Entry}, fmt::Display, net::Ipv4Addr, sync::{Arc, Mutex as StdMutex}, time::Duration, u32
};
use tokio::{sync::Notify, time::Instant};
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
    /// Кредит подтверждённых байт для CA: +SMSS на каждые cwnd подтверждённых байт
    bytes_acked: u32,
    /// Таймаут ретрансмиссии (RFC 6298): удваивается при каждой RTO-ретрансмиссии
    rto: Duration,
    /// Момент истечения явного таймера RTO (RFC 6298 §5.1–5.3);
    /// None — таймер не заведён (нет неподтверждённых данных)
    rto_deadline: Option<Instant>,
    /// Сглаженное RTT и его вариация (RFC 6298 §2); None — семплов ещё не было
    srtt: Option<Duration>,
    rttvar: Duration,
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
            bytes_acked: 0,
            rto: Duration::from_secs(1),
            rto_deadline: None,
            srtt: None,
            rttvar: Duration::ZERO,
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

    /// Добавляет пакет в unacked_packets и пересчитывает flight_size.
    /// Заводит таймер RTO, если тот не идёт (RFC 6298 §5.1): отправка данных
    /// при пустой очереди запускает таймер, повторные отправки не перезапускают.
    fn add_to_unacked_packets(&mut self, seq: u32, data: Vec<u8>, len: usize) {
        self.unacked_packets.insert(seq, PendingPacket {
            data,
            len,
            retransmits: 0,
            send_at: Instant::now(),
            seq,
        });
        if self.rto_deadline.is_none() {
            self.rto_deadline = Some(Instant::now() + self.rto);
        }
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

    /// Пересчёт оценок RTT и rto по семплу (RFC 6298 §2). Арифметика
    /// целочисленная (Duration делится нацело) — значения точны на микросекундах.
    /// Минимум 1s из §2.4 («MAY») не применяется: rto следует за оценкой RTT.
    fn update_rto(&mut self, sample: Duration) {
        match self.srtt {
            None => {
                self.srtt = Some(sample);
                self.rttvar = sample / 2;
            }
            Some(srtt) => {
                // rttvar — по старому srtt
                self.rttvar = self.rttvar / 4 * 3 + srtt.abs_diff(sample) / 4;
                self.srtt = Some(srtt / 8 * 7 + sample / 8);
            }
        }
        self.rto = self.srtt.unwrap() + Duration::from_millis(1).max(self.rttvar * 4);
    }

    /// Единственная точка работы таймера RTO: ожидает истечения дедлайна
    /// и ретранслирует голову очереди. Таймер не заведён — ожидает бесконечно
    /// (ветка select! в драйвере не должна крутиться вхолостую).
    pub async fn rto_tick(&mut self) -> bool {
        match self.rto_deadline {
            Some(deadline) => tokio::time::sleep_until(deadline).await,
            None => std::future::pending().await,
        }
        self.handle_rto_expired().await
    }

    /// Обработка сработавшего RTO (RFC 6298 §5): коллапс cwnd до SMSS,
    /// ретрансмиссия самого старого неподтверждённого пакета, экспоненциальный
    /// бэкофф rto и перезапуск таймера.
    async fn handle_rto_expired(&mut self) -> bool {
        if self.unacked_packets.is_empty() {
            // Таймер не должен был идти; на всякий случай останавливаем
            self.rto_deadline = None;
            return false;
        }

        let now = Instant::now();
        let (seq, data) = {
            let oldest = self.unacked_packets.values().next().unwrap();
            (oldest.seq, oldest.data.clone())
        };

        // Коллапс окна: медленный старт заново (в отличие от inflate Fast
        // Retransmit); активный Fast Recovery прерывается
        self.ssthresh = (self.flight_size / 2).max(2 * self.smss as u32);
        self.cwnd = self.smss as u32;
        self.bytes_acked = 0;
        self.fast_retransmit_done = false;
        self.dup_ack_count = 0;

        // Экспоненциальный бэкофф и перезапуск таймера с удвоенным rto
        self.rto *= 2;
        self.rto_deadline = Some(now + self.rto);

        let oldest = self.unacked_packets.get_mut(&seq).unwrap();
        oldest.retransmits += 1;
        oldest.send_at = now;

        warn!("RTO: retransmitting packet at seq={}, rto={:?}", seq, self.rto);

        let raw_packet = get_ack_data_response(
            self.snd_ack,
            self.source_addr,
            self.source_port,
            &data,
            false,
            seq,
            self.destination_addr,
            self.destination_port,
            self.rcv_timestamp,
            65535,
        ).unwrap();

        self.send_raw(raw_packet, "RTO").await.ok();

        true
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

        self.snd_ack = self.rcv_seq.wrapping_add(1);
        self.rcv_seq_next = self.rcv_seq.wrapping_add(1);

        self.snd_seq = self.snd_seq.wrapping_add(1);

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
        self.bytes_acked = 0;

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
    /// подтверждённые пакеты, растит cwnd (slow start / congestion avoidance,
    /// RFC 5681 §3.1) и отправляет pending данные.
    async fn handle_new_ack(&mut self, new_ack: u32, n: u32) {
        // Выход из Fast Recovery — дефляция cwnd до ssthresh; роста на этом же
        // ACK нет, bytes_acked не трогаем (он обнулён в do_fast_retransmit)
        let exit_fast_recovery = self.fast_retransmit_done;
        let now = Instant::now();

        // Семпл RTT по голове очереди; ретранслированный сегмент семпла
        // не даёт (алгоритм Карна)
        if let Some(oldest) = self.unacked_packets.values().next()
            && oldest.retransmits == 0
        {
            self.update_rto(now - oldest.send_at);
        }

        // Новый ACK - сбрасываем счетчик дублирующих ACK
        self.dup_ack_count = 0;
        self.fast_retransmit_done = false;

        // Удаляем подтвержденные пакеты и пересчитываем flight_size
        self.remove_acknowledged_packets(new_ack);

        // Перезапуск таймера RTO (RFC 6298 §5.3); всё подтверждено —
        // остановка (§5.2)
        self.rto_deadline = if self.unacked_packets.is_empty() {
            None
        } else {
            Some(now + self.rto)
        };

        if exit_fast_recovery {
            self.cwnd = self.ssthresh;
        } else if self.cwnd < self.ssthresh {
            // Slow start: увеличиваем cwnd только при получении ACK на данные (не SYN)
            self.cwnd += n.min(self.smss.max(1) as u32);
        } else {
            // Congestion avoidance: +SMSS на каждые cwnd подтверждённых байт
            self.bytes_acked += n;
            if self.bytes_acked >= self.cwnd {
                let cwnd_before = self.cwnd;
                self.cwnd += self.smss.max(1) as u32;
                // Вычитаем cwnd до роста, а не сбрасываем — кредит сохраняется
                self.bytes_acked -= cwnd_before;
            }
        }

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
        self.rto_deadline = None;
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
    use std::{io::{Error, ErrorKind}, net::{Ipv4Addr, SocketAddrV4}, time::Duration};

    use tokio::{io::{AsyncReadExt, AsyncWriteExt}, sync::{mpsc::{UnboundedReceiver, unbounded_channel}}};

    use crate::{net_env::NetEnv, net_packet_parser::{IpTcpPacket, Ipv4TcpPacket, Packet, net_packet_parser}, tcp_state_machine::{TcpState, TcpStateMachine}};

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

    /// Доставляет клиенту головной пакет из сети (сервер → клиент),
    /// ответ клиента возвращает в сеть. Возвращает доставленный пакет.
    async fn deliver_to_client(net: &mut NetEnv, client: &mut Peer) -> Ipv4TcpPacket {
        let packet = net.pop_server_client().expect("очередь сервер→клиент пуста");
        client.accept_request(packet.clone()).await;
        net.push_client_server(client.get_response().await);
        packet
    }

    /// Доставляет серверу головной пакет из сети (клиент → сервер),
    /// ответ сервера возвращает в сеть. Возвращает доставленный пакет.
    async fn deliver_to_server(net: &mut NetEnv, server: &mut Peer) -> Ipv4TcpPacket {
        let packet = net.pop_client_server().expect("очередь клиент→сервер пуста");
        server.accept_request(packet.clone()).await;
        net.push_server_client(server.get_response().await);
        packet
    }

    async fn assert_client_send_data(
        client: &mut Peer,
        server: &mut Peer,
        net: &mut NetEnv,
    ) {
        let data = "123456789";

        client.send_data(data.as_bytes().to_vec()).await;

        // сегменты клиента уходят в сеть
        net.push_client_server(client.get_response().await);

        while net.len_client_server() > 0 {
            let client_data_packet = deliver_to_server(net, server).await;

            // ack сервера доставлен клиенту
            let packet = deliver_to_client(net, client).await;

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

        let mut net = NetEnv::new();

        // ─── Легенда таблиц состояния сети (одна таблица на шаг) ─────────────
        //   un[..] — unacked_packets сервера (по возрастанию seq);
        //   строка «→»: [очередь FSM сервера] => [сегменты в полёте к клиенту] => [данные у клиента]
        //   строка «≤»: [состояние сервера]   <= [сегменты в полёте к серверу] <=
        //   X345 — сегмент потерян в сети (пометка над колонкой полёта к клиенту);
        //   qu[..] — out_of_order_buffer клиента (пометка над колонкой данных у клиента);
        //   «данные у клиента» — принято, но ещё не прочитано приложением
        //   (recv_buffer до флаша по PSH либо накопленный буфер после него);
        //   cwnd — окно перегрузки, fs — flight_size, th — ssthresh,
        //   dp — dup_ack_count, fr — fast_retransmit_done, ba — bytes_acked
        //   (кредит подтверждённых байт для CA), ack(012) — ACK на сегмент «012»
        // ────────────────────────────────────────────────────────────────────────────

        // отправляем syn запрос на сервер. устанавливаем размер окна 3 байта для удобства тестирования
        client.send_syn(Some(3)).await;

        // пакет клиента уходит в сеть
        net.push_client_server(client.get_response().await);

        // un[]                => []                => []
        // []                  <= [syn]             <=
        // сервер: Listen      клиент: SynSent

        assert!(net.front_client_server().unwrap().syn());

        // пакет клиента доставлен на сервер. сервер отвечает syn-ack
        let packet = net.pop_client_server().unwrap();
        server.accept_request(packet.clone()).await;

        // пакет syn-ack уходит в сеть
        net.push_server_client(server.get_response().await);

        // un[]                => [syn-ack]         => []
        // []                  <= []                <=
        // сервер: SynReceived

        // клиент принимает syn-ack и отвечает подтверждением ack
        let syn_ack = deliver_to_client(&mut net, &mut client).await;
        assert!(syn_ack.syn());
        assert!(syn_ack.ack());
        assert_eq!(syn_ack.acknowledgment_number(), packet.sequence_number().wrapping_add(1));

        // un[]                => []                => []
        // []                  <= [ack]             <=
        // сервер: SynReceived клиент: Established

        server.accept_request(net.pop_client_server().unwrap()).await;

        // un[]                => []                => []
        // []                  <= []                <=
        // сервер: Established клиент: Established

        assert_state(server.state.state, TcpState::Established);

        assert_client_send_data(
            &mut client,
            &mut server,
            &mut net,
        ).await;

        let server_data = "0123456789abcdefghjklmnopqristuvwxy";

        // Сервер отправляет пакеты с данными в сеть
        server.send_data(server_data.as_bytes().to_vec()).await;

        net.push_server_client(server.get_response().await);
        assert_eq!(server.state.cwnd, 12);
        assert_eq!(server.state.flight_size, 12);
        assert_eq!(net.len_server_client(), 4); // 012, 345, 678, 9ab

        // un[012, 345, 678, 9ab]
        // [cdefghjklmnopqristuvwxy] => [9ab, 678, 345, 012]      => []
        // [cwnd:12, fs:12]                                <= []                        <=

        // Клиент принимает первый пакет из сети (012) и генерит ack
        deliver_to_client(&mut net, &mut client).await;
        // «012» пришёл без PSH — данные накапливаются в приёмном буфере FSM
        // и уйдут в recv-половинку при следующем флаше по PSH
        assert_eq!(String::from_utf8_lossy(client.state.recv_buffer.as_slice()), "012");

        // un[012, 345, 678, 9ab]
        // [cdefghjklmnopqristuvwxy] =>[9ab, 678, 345]           => [012]
        // [cwnd:12, fs:12]                                <= [ack(012)]               <=

        // запоминаем ack этого пакета
        let last_ack_in_order = net.front_client_server().unwrap().acknowledgment_number();

        // сервер принимает ack на первый пакет: 012 подтверждён, cwnd += SMSS (15)
        deliver_to_server(&mut net, &mut server).await; // отправляет новые два пакета

        // un[345, 678, 9ab, cde, fgh]
        // [jklmnopqristuvwxy] =>[fgh, cde, 9ab, 678, 345] => [012]
        // [cwnd:15, fs:15]                          <= []                       <=

        assert_eq!(server.state.cwnd, 15);
        assert_eq!(server.state.flight_size, 15);
        assert_eq!(net.len_server_client(), 5); // 345, 678, 9ab, cde, fgh

        // Предположим второй пакет теряется в сети (345): дропаем голову очереди
        let seq_345 = net.front_server_client().unwrap().sequence_number();
        net.drop_server_client();

        // un[345, 678, 9ab, cde, fgh]          X345
        // [jklmnopqristuvwxy] =>[fgh, cde, 9ab, 678]      => [012]
        // [cwnd:15, fs:15]                  <= []                        <=

        // Клиент принимает третий пакет (678), но должен сгенерировать ack на первый пакет (1 dup ack)
        deliver_to_client(&mut net, &mut client).await;

        // un[345, 678, 9ab, cde, fgh]          X345                         qu[678]
        // [jklmnopqristuvwxy] =>[fgh, cde, 9ab]           => [012]
        // [cwnd:15, fs:15]                  <= [ack(012)]                <=

        assert_eq!(client.state.out_of_order_buffer.len(), 1); // 678
        assert_eq!(net.len_client_server(), 1);
        assert_eq!(net.front_client_server().unwrap().acknowledgment_number(), last_ack_in_order);

        // сервер принимает первый dup ack (новых данных не отправляет)
        deliver_to_server(&mut net, &mut server).await;

        // un[345, 678, 9ab, cde, fgh]          X345                         qu[678]
        // [jklmnopqristuvwxy] =>[fgh, cde, 9ab]           => [012]
        // [cwnd:15, fs:15, dp=1]            <= []                        <=

        assert_eq!(server.state.cwnd, 15);
        assert_eq!(server.state.flight_size, 15);
        assert_eq!(net.len_server_client(), 3); // 9ab, cde, fgh

        // Клиент принимает четвертый пакет (9ab), но должен сгенерировать ack на первый пакет (2 dup ack)
        deliver_to_client(&mut net, &mut client).await;

        // un[345, 678, 9ab, cde, fgh]          X345                         qu[678, 9ab]
        // [jklmnopqristuvwxy] =>[fgh, cde]                => [012]
        // [cwnd:15, fs:15, dp=1]            <= [ack(012)]                <=

        assert_eq!(client.state.out_of_order_buffer.len(), 2); // 678, 9ab
        assert_eq!(net.len_client_server(), 1);
        assert_eq!(net.front_client_server().unwrap().acknowledgment_number(), last_ack_in_order);

        // сервер принимает второй dup ack (новых данных не отправляет)
        deliver_to_server(&mut net, &mut server).await;

        // un[345, 678, 9ab, cde, fgh]          X345                         qu[678, 9ab]
        // [jklmnopqristuvwxy] =>[fgh, cde]                => [012]
        // [cwnd:15, fs:15, dp=2]            <= []                        <=

        assert_eq!(server.state.cwnd, 15);
        assert_eq!(server.state.flight_size, 15, "При получении dup ack, flight_size не уеньшается");
        assert_eq!(net.len_server_client(), 2); // cde, fgh

        // Клиент принимает пятый пакет (cde), но должен сгенерировать ack на первый пакет (3 dup ack)
        deliver_to_client(&mut net, &mut client).await;

        // un[345, 678, 9ab, cde, fgh]                  X345                        qu[678, 9ab, cde]
        // [jklmnopqristuvwxy]                       => [fgh]                    => [012]
        // [cwnd:15, fs:15, dp=2]                    <= [ack(012)]               <=

        assert_eq!(client.state.out_of_order_buffer.len(), 3);
        assert_eq!(net.len_client_server(), 1);
        assert_eq!(net.front_client_server().unwrap().acknowledgment_number(), last_ack_in_order);

        // сервер принимает третий dup ack: Fast Retransmit —
        // ssthresh = fs/2 = 7, cwnd = ssthresh + 3*SMSS = 16, ретрансмиссия 345
        deliver_to_server(&mut net, &mut server).await;

        // un[345, 678, 9ab, cde, fgh]          X345                         qu[678, 9ab, cde]
        // [jklmnopqristuvwxy] =>[345, fgh]                => [012]
        // [cwnd:16, fs:15, th:7, dp=3, fr]  <= []                        <=

        assert_eq!(server.state.cwnd, 16);
        assert_eq!(server.state.flight_size, 15);
        assert_eq!(server.state.ssthresh, 7, "3 dup ack. Вычисляется ssthresh");
        assert_eq!(net.len_server_client(), 2); // fgh, 345 (ретрансмиссия)

        // клиент принимает шестой пакет (fgh) из сети в порядке очереди
        let fgh = deliver_to_client(&mut net, &mut client).await; // клиент снова отдает dup ack
        let fgh_end = fgh.sequence_number().wrapping_add(fgh.payload().len() as u32);

        // un[345, 678, 9ab, cde, fgh]          X345                         qu[678, 9ab, cde, fgh]
        // [jklmnopqristuvwxy] =>[345]                     => [012]
        // [cwnd:16, fs:15, th:7, dp=3, fr]  <= [ack(012)]                <=

        assert_eq!(client.state.out_of_order_buffer.len(), 4); // 678, 9ab, cde, fgh
        assert_eq!(net.front_client_server().unwrap().acknowledgment_number(), last_ack_in_order);

        // сервер принимает четвертый dup ack: inflate cwnd += SMSS (19) и
        // отправляет новые данные, пока позволяет окно (jkl, m)
        deliver_to_server(&mut net, &mut server).await;

        // un[345, 678, 9ab, cde, fgh, jkl, m]  X345                         qu[678, 9ab, cde, fgh]
        // [nopqristuvwxy] =>[m, jkl, 345]             => [012]
        // [cwnd:19, fs:19, th:7, dp=4, fr]  <= []                        <=

        assert_eq!(server.state.cwnd, 19);
        assert_eq!(server.state.flight_size, 19);
        assert_eq!(net.len_server_client(), 3);

        // клиент принимает ретранслированный пакет:
        // qu флашится, клиент подтверждает всё вплоть до fgh
        let retrans = deliver_to_client(&mut net, &mut client).await;
        assert_eq!(retrans.sequence_number(), seq_345);

        // un[345, 678, 9ab, cde, fgh, jkl, m]     X345                         qu[]
        // [nopqristuvwxy] => [m, jkl]                 => [0123456789abcdefgh]
        // [cwnd:19, fs:19, th:7, dp=4, fr]      <= [ack(fgh)]               <=

        assert_eq!(client.state.out_of_order_buffer.len(), 0); // клиент отдает ack всех ранее принятых пакетов
        assert_eq!(net.len_client_server(), 1);
        assert_eq!(net.front_client_server().unwrap().acknowledgment_number(), fgh_end);

        // сервер принимает ack на все потерянные пакеты — выход из Fast Recovery:
        // dp/fr сбрасываются, cwnd возвращается к ssthresh (7), отправляет nop
        deliver_to_server(&mut net, &mut server).await; // сервер продолжает слать данные

        // un[jkl, m, nop]
        // [qristuvwxy]                       => [nop, m, jkl]        => [0123456789abcdefgh]
        // [cwnd:7, fs:7, th:7]               <= []                   <=

        assert_eq!(server.state.cwnd, 7);
        assert_eq!(server.state.flight_size, 7);
        assert_eq!(net.len_server_client(), 3); // jkl, m, nop

        // cwnd равен ssthresh — congestion avoidance: +SMSS не на каждый
        // ACK, а на каждые cwnd подтверждённых байт (ba).

        // Клиент принимает jkl (ba 0+3=3 < cwnd 7 — окно не растёт)
        deliver_to_client(&mut net, &mut client).await;

        // un[jkl, m, nop]
        // [qristuvwxy]                       => [nop, m]             => [0123456789abcdefghjkl]
        // [cwnd:7, fs:7, th:7, ba:0]         <= [ack(jkl)]           <=

        deliver_to_server(&mut net, &mut server).await;

        // un[m, nop, qri]
        // [stuvwxy]                          => [qri, nop, m]      => [0123456789abcdefghjkl]
        // [cwnd:7, fs:7, th:7, ba:3]         <= []                   <=

        assert_eq!(server.state.cwnd, 7);
        assert_eq!(server.state.flight_size, 7);
        assert_eq!(net.len_server_client(), 3);

        // Клиент принимает m (ba 3+1=4 < cwnd 7)
        deliver_to_client(&mut net, &mut client).await;

        // un[m, nop, qri]
        // [stuvwxy]                          => [qri, nop]         => [0123456789abcdefghjklm]
        // [cwnd:7, fs:7, th:7, ba:3]         <= [ack(m)]             <=

        deliver_to_server(&mut net, &mut server).await;

        // un[nop, qri, s]
        // [tuvwxy]     => [s, qri, nop]      => [0123456789abcdefghjklm]
        // [cwnd:7, fs:7, th:7, ba:4]         <= []                   <=

        assert_eq!(server.state.cwnd, 7);
        assert_eq!(server.state.flight_size, 7);
        assert_eq!(net.len_server_client(), 3);

        // Клиент принимает nop: ba 4+3=7 ≥ cwnd(7) → cwnd 10
        deliver_to_client(&mut net, &mut client).await;

        // un[nop, qri, s]
    // [tuvwxy]                               => [s, qri]            => [0123456789abcdefghjklmnop]
        // [cwnd:7, fs:7, th:7, ba:4]         <= [ack(nop)]           <=

        deliver_to_server(&mut net, &mut server).await;

        // un[qri, s, tuv, wxy]
        // []                                 => [wxy, tuv, s, qri]  => [0123456789abcdefghjklmnop]
        // [cwnd:10, fs:10, th:7, ba:0]       <= []                   <=

        assert_eq!(server.state.cwnd, 10);
        assert_eq!(server.state.flight_size, 10);
        assert_eq!(net.len_server_client(), 4);

        // Клиент принимает qri (ba 0+3=3 < cwnd 10)
        deliver_to_client(&mut net, &mut client).await;

        // un[qri, s, tuv, wxy]
        // []                                 => [wxy, tuv, s]       => [0123456789abcdefghjklmnopqri]
        // [cwnd:10, fs:10, th:7, ba:0]       <= [ack(qri)]           <=

        deliver_to_server(&mut net, &mut server).await;

        // un[s, tuv, wxy]
        // []                                 => [wxy, tuv, s]       => [0123456789abcdefghjklmnopqri]
        // [cwnd:10, fs:7, th:7, ba:3]        <= []                   <=

        assert_eq!(server.state.cwnd, 10);
        assert_eq!(server.state.flight_size, 7);
        assert_eq!(net.len_server_client(), 3); // s, tuv, wxy

        // Клиент принимает s (ba 3+1=4 < cwnd 10)
        deliver_to_client(&mut net, &mut client).await;

        // un[s, tuv, wxy]
        // []                                 => [wxy, tuv]           => [0123456789abcdefghjklmnopqris]
        // [cwnd:10, fs:7, th:7, ba:3]        <= [ack(s)]             <=

        deliver_to_server(&mut net, &mut server).await;

        // un[tuv, wxy]
        // []                                 => [wxy, tuv]   => [0123456789abcdefghjklmnopqris]
        // [cwnd:10, fs:6, th:7, ba:4]        <= []           <=

        assert_eq!(server.state.cwnd, 10);
        assert_eq!(server.state.flight_size, 6);
        assert_eq!(net.len_server_client(), 2); // tuv, wxy

        // Клиент принимает tuv (ba 4+3=7 < cwnd 10)
        deliver_to_client(&mut net, &mut client).await;

        // un[tuv, wxy]
        // []                                 => [wxy]                => [0123456789abcdefghjklmnopqristuv]
        // [cwnd:10, fs:6, th:7, ba:4]        <= [ack(tuv)]           <=

        deliver_to_server(&mut net, &mut server).await;

        // un[wxy]
        // []                                 => [wxy]                => [0123456789abcdefghjklmnopqristuv]
        // [cwnd:10, fs:3, th:7, ba:7]        <= []                   <=

        assert_eq!(server.state.cwnd, 10);
        assert_eq!(server.state.flight_size, 3);
        assert_eq!(net.len_server_client(), 1); // wxy

        // Клиент принимает wxy: ba 7+3=10 ≥ cwnd(10) → cwnd 13;
        // на этом приросте тест останавливается
        deliver_to_client(&mut net, &mut client).await;

        // un[wxy]
        // []                                 => []             => [0123456789abcdefghjklmnopqristuvwxy]
        // [cwnd:10, fs:3, th:7, ba:7]        <= [ack(wxy)]     <=

        deliver_to_server(&mut net, &mut server).await;

        // un[]
        // []                                 => []                       => [0123456789abcdefghjklmnopqristuvwxy]
        // [cwnd:13, fs:0, th:7, ba:0]        <= []                       <=

        assert_eq!(server.state.cwnd, 13);
        assert_eq!(server.state.flight_size, 0);
        assert_eq!(net.len_server_client(), 0);

        // Последний сегмент (wxy) опустошил очередь отправки и ушёл с PSH —
        // флаш по PSH увёл все 35 байт из приёмного буфера FSM в read-половинку
        assert!(client.state.recv_buffer.is_empty());
        let mut buf = vec![0u8; server_data.len()];
        client.recv.read_exact(&mut buf).await.unwrap();
        assert_eq!(String::from_utf8_lossy(&buf), server_data);

    }

    /// RTO (RFC 6298): вычисление srtt/rttvar/rto на нормальных ACK и
    /// ретрансмиссия с бэкоффом после потерь.
    /// Время виртуальное (tokio paused clock): паузы sleep продвигают часы
    /// ровно на заданный интервал, поэтому RTT-семплы и все показатели точны.
    /// Ретрансляция ожидается по явному таймеру FSM (rto_tick), а не вручную.
    #[tokio::test(start_paused = true)]
    async fn test_rto() {
        let server_socket = SocketAddrV4::new(
            Ipv4Addr::new(127, 0, 0, 1),
            8002,
        );

        let client_socket = SocketAddrV4::new(
            Ipv4Addr::new(127, 0, 0, 1),
            8003,
        );

        let mut server = Peer::new_server(
            server_socket,
            client_socket,
        );

        let mut client = Peer::new_client(
            client_socket,
            server_socket,
        );

        let mut net = NetEnv::new();

        // ─── Легенда таблиц состояния сети ──────────────────────────────────
        //   un[..] — unacked_packets сервера (по возрастанию seq);
        //   строка «→»: [очередь FSM сервера] => [сегменты в полёте к клиенту] => [данные у клиента]
        //   строка «≤»: [состояние сервера]   <= [сегменты в полёте к серверу] <=
        //   Xghi — сегмент потерян в сети (пометка над колонкой полёта к клиенту);
        //   ghi(R) — ретрансмиссия по RTO;
        //   cwnd — окно перегрузки, fs — flight_size, th — ssthresh,
        //   srtt — сглаженное RTT, rttvar — вариация RTT,
        //   rto — таймаут ретрансмиссии, ack(ghi) — ACK на сегмент «ghi»
        // ─────────────────────────────────────────────────────────────────────

        // хендшейк; SMSS = 3 → init cwnd = 12
        client.send_syn(Some(3)).await;

        // пакет клиента уходит в сеть
        net.push_client_server(client.get_response().await);

        // un[]                => []                => []
        // []                  <= [syn]             <=
        // сервер: Listen      клиент: SynSent

        let packet = net.pop_client_server().unwrap();
        server.accept_request(packet.clone()).await;

        // пакет syn-ack уходит в сеть
        net.push_server_client(server.get_response().await);

        // клиент принимает syn-ack и подтверждает соединение
        deliver_to_client(&mut net, &mut client).await;

        server.accept_request(net.pop_client_server().unwrap()).await;

        // un[]                => []                => []
        // []                  <= []                <=
        // сервер: Established клиент: Established

        assert_state(server.state.state, TcpState::Established);
        assert_state(client.state.state, TcpState::Established);

        // сервер отправляет 9 байт: сегменты abc, def, ghi — все отправлены
        // в один момент виртуального времени, send_at у всех одинаков
        let server_data = "abcdefghi";

        server.send_data(server_data.as_bytes().to_vec()).await;
        net.push_server_client(server.get_response().await);

        // un[abc, def, ghi]
        // []                  => [ghi, def, abc]      => []
        // [cwnd:12, fs:9]     <= []                   <=

        assert_eq!(server.state.cwnd, 12);
        assert_eq!(server.state.flight_size, 9);
        assert_eq!(net.len_server_client(), 3);

        // ─── Нормальный приём: два сегмента подтверждены, rto вычисляется ───

        // прошло 20 мс с отправки: доставляем abc, клиент подтверждает
        tokio::time::sleep(Duration::from_millis(20)).await;

        // un[abc, def, ghi]
        // []                  => [ghi, def]      => [abc]
        // [cwnd:12, fs:9]     <= [ack(abc)]      <=

        deliver_to_client(&mut net, &mut client).await;
        deliver_to_server(&mut net, &mut server).await;

        // Первый семпл R = 20 мс (время от отправки abc до ACK):
        //   srtt   = R            = 20 мс
        //   rttvar = R / 2        = 10 мс
        //   rto    = srtt + max(G, 4·rttvar) = 20 + max(1, 40) = 60 мс
        //   (G = 1 мс — гранулярность часов)
        // slow start: cwnd 12 → 15, abc подтверждён, fs = 6
        assert_eq!(server.state.srtt, Some(Duration::from_millis(20)));
        assert_eq!(server.state.rttvar, Duration::from_millis(10));
        assert_eq!(server.state.rto, Duration::from_millis(60));
        assert_eq!(server.state.flight_size, 6);
        assert_eq!(server.state.cwnd, 15);

        // ещё 20 мс (def в полёте уже 40 мс): доставляем def
        tokio::time::sleep(Duration::from_millis(20)).await;

        // un[def, ghi]
        // []                  => [ghi]           => [abc, def]
        // [cwnd:15, fs:6]     <= [ack(def)]      <=

        deliver_to_client(&mut net, &mut client).await;
        deliver_to_server(&mut net, &mut server).await;

        // Второй семпл R = 40 мс (def отправлен в тот же момент, что и abc):
        //   rttvar = 3/4·rttvar + 1/4·|srtt − R| = 7.5 + 5 = 12.5 мс
        //   srtt   = 7/8·srtt + 1/8·R            = 17.5 + 5 = 22.5 мс
        //   rto    = srtt + max(G, 4·rttvar)     = 22.5 + max(1, 50) = 72.5 мс
        // slow start: cwnd 15 → 18, fs = 3 (остался только ghi)
        assert_eq!(server.state.srtt, Some(Duration::from_micros(22500)));
        assert_eq!(server.state.rttvar, Duration::from_micros(12500));
        assert_eq!(server.state.rto, Duration::from_micros(72500));
        assert_eq!(server.state.flight_size, 3);
        assert_eq!(server.state.cwnd, 18);

        // ─── Потери: ghi теряется, RTO ретранслирует его дважды ─────────────

        // потеря №1: последний сегмент теряется в сети
        let seq_ghi = *server.state.unacked_packets.keys().next().unwrap();
        net.drop_server_client();

        // un[ghi]             Xghi
        // []                  => []                => [abc, def]
        // [cwnd:18, fs:3]     <= []                <=

        assert_eq!(net.len_server_client(), 0);

        // до дедлайна RTO таймер не стреляет: 10 мс ожидания истекают раньше
        tokio::time::timeout(Duration::from_millis(10), server.state.rto_tick()).await.unwrap_err();
        assert_eq!(net.len_server_client(), 0);

        // RTO №1: cwnd схлопывается до SMSS, ssthresh = max(fs/2, 2·SMSS) = 6,
        // ретрансмиссия ghi, rto удваивается — ждём явный таймер FSM
        assert!(server.state.rto_tick().await);
        net.push_server_client(server.get_response().await);

        // un[ghi]             Xghi
        // []                  => [ghi(R)]          => [abc, def]
        // [cwnd:3, fs:3, th:6, rto:145ms]   <= []   <=

        assert_eq!(server.state.cwnd, 3);
        assert_eq!(server.state.ssthresh, 6);
        assert_eq!(server.state.flight_size, 3);
        assert_eq!(server.state.bytes_acked, 0);
        assert!(!server.state.fast_retransmit_done);
        assert_eq!(server.state.rto, Duration::from_millis(145));
        assert_eq!(net.len_server_client(), 1);
        assert_eq!(net.front_server_client().unwrap().sequence_number(), seq_ghi);

        let now = tokio::time::Instant::now();
        let ghi = server.state.unacked_packets.values().next().unwrap();
        assert_eq!(ghi.retransmits, 1);
        assert_eq!(ghi.send_at, now);

        // потеря №2: ретрансмиссия тоже теряется
        net.drop_server_client();

        // un[ghi]             Xghi
        // []                  => []                => [abc, def]
        // [cwnd:3, fs:3, th:6, rto:145ms]   <= []   <=

        assert_eq!(net.len_server_client(), 0);

        // RTO №2: бэкофф удваивает rto повторно, дедлайн — от обновлённого
        // send_at и нового rto — ждём явный таймер FSM
        assert!(server.state.rto_tick().await);
        net.push_server_client(server.get_response().await);

        // un[ghi]             Xghi
        // []                  => [ghi(R)]          => [abc, def]
        // [cwnd:3, fs:3, th:6, rto:290ms]   <= []   <=

        assert_eq!(server.state.cwnd, 3);
        assert_eq!(server.state.ssthresh, 6);
        assert_eq!(server.state.rto, Duration::from_millis(290));
        assert_eq!(net.len_server_client(), 1);

        let now = tokio::time::Instant::now();
        let ghi = server.state.unacked_packets.values().next().unwrap();
        assert_eq!(ghi.retransmits, 2);
        assert_eq!(ghi.send_at, now);

        // до следующего дедлайна таймер не стреляет
        tokio::time::timeout(Duration::from_millis(10), server.state.rto_tick()).await.unwrap_err();
        assert_eq!(net.len_server_client(), 1);

        // ─── Восстановление: ретрансмиссия доставлена и подтверждена ────────

        let retrans = deliver_to_client(&mut net, &mut client).await;
        assert_eq!(retrans.sequence_number(), seq_ghi);

        // un[]
        // []                  => []                => [abc, def, ghi]
        // [cwnd:3, fs:3, th:6, rto:290ms]   <= [ack(ghi)]   <=

        deliver_to_server(&mut net, &mut server).await;

        // un[]
        // []                  => []                => [abc, def, ghi]
        // [cwnd:6, fs:0, th:6, ba:0, rto:290ms]   <= []   <=

        // slow start заново: cwnd 3 → 6; семпла RTT нет (сегмент
        // ретранслированный — алгоритм Карна), srtt и rto не трогаются
        assert_eq!(server.state.flight_size, 0);
        assert_eq!(server.state.cwnd, 6);
        assert_eq!(server.state.ssthresh, 6);
        assert_eq!(server.state.bytes_acked, 0);
        assert_eq!(server.state.srtt, Some(Duration::from_micros(22500)));
        assert_eq!(server.state.rto, Duration::from_millis(290));

        // Клиент принял abc, def и ретранслированный ghi — все без PSH,
        // данные копятся в приёмном буфере FSM
        assert_eq!(String::from_utf8_lossy(client.state.recv_buffer.as_slice()), "abcdefghi");
    }
}
