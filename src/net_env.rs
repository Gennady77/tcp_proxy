//! Тестовая сетевая среда: имитирует эфир между двумя пирами.
//! Два направления (сервер → клиент и клиент → сервер), каждое — FIFO-очередь пакетов.
//! Доставка — выдача головы очереди; потеря пакета — выдача с выбросом.

use std::collections::VecDeque;

use crate::net_packet_parser::Ipv4TcpPacket;

/// Сетевая среда: принимает пакеты на вход (push) и отдаёт на выходе (pop).
pub struct NetEnv {
    server_client: VecDeque<Ipv4TcpPacket>,
    client_server: VecDeque<Ipv4TcpPacket>,
}

impl NetEnv {
    pub fn new() -> Self {
        Self {
            server_client: VecDeque::new(),
            client_server: VecDeque::new(),
        }
    }

    // ─── Направление сервер → клиент ────────────────────────────────────────

    /// Пакеты уходят в сеть в сторону клиента
    pub fn push_server_client(&mut self, packets: impl IntoIterator<Item = Ipv4TcpPacket>) {
        self.server_client.extend(packets);
    }

    /// Доставка головы очереди клиенту
    pub fn pop_server_client(&mut self) -> Option<Ipv4TcpPacket> {
        self.server_client.pop_front()
    }

    /// Потеря пакета: голова очереди выдаётся и выбрасывается
    pub fn drop_server_client(&mut self) -> Option<Ipv4TcpPacket> {
        self.server_client.pop_front()
    }

    pub fn len_server_client(&self) -> usize {
        self.server_client.len()
    }

    pub fn front_server_client(&self) -> Option<&Ipv4TcpPacket> {
        self.server_client.front()
    }

    // ─── Направление клиент → сервер ────────────────────────────────────────

    /// Пакеты уходят в сеть в сторону сервера
    pub fn push_client_server(&mut self, packets: impl IntoIterator<Item = Ipv4TcpPacket>) {
        self.client_server.extend(packets);
    }

    /// Доставка головы очереди серверу
    pub fn pop_client_server(&mut self) -> Option<Ipv4TcpPacket> {
        self.client_server.pop_front()
    }

    /// Потеря пакета: голова очереди выдаётся и выбрасывается
    pub fn drop_client_server(&mut self) -> Option<Ipv4TcpPacket> {
        self.client_server.pop_front()
    }

    pub fn len_client_server(&self) -> usize {
        self.client_server.len()
    }

    pub fn front_client_server(&self) -> Option<&Ipv4TcpPacket> {
        self.client_server.front()
    }
}
