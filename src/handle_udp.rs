use rand::Rng;
use std::sync::Arc;
use std::{
    collections::HashMap,
    error::Error,
    net::{SocketAddr, SocketAddrV4},
};
use tokio::{
    io::{AsyncWriteExt, copy},
    net::{TcpStream, UdpSocket},
    sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel},
};
use tracing::{debug, error, info, warn};

use crate::tcp_state_machine::{TcpState, TcpStateMachine};
use crate::{
    net_packet_parser::{
        IpTcpPacket, Ipv4TcpPacket, Packet, get_reset_response, net_packet_parser,
    },
    tcp_stream::{TcpRecvHalf, TcpSendHalf},
    utils,
};

/// Ключ потока соединений: пара сокетов (источник, назначение).
#[derive(Hash, Eq, PartialEq, Clone, Debug)]
struct FlowKey {
    source: SocketAddr,
    destination: SocketAddr,
}

impl FlowKey {
    fn from_packet(packet: &Ipv4TcpPacket) -> Self {
        Self {
            source: packet.source_socket(),
            destination: packet.destination_socket(),
        }
    }
}

/// Событие соединения: пакет от пира или команда закрытия от прокси-пайпа.
enum ConnEvent {
    Packet(Ipv4TcpPacket),
    Close,
}

/// Управление таблицей потоков: команды от задач соединений.
enum FlowControl {
    Remove(FlowKey),
}

struct IpUdpStream {
    destination_socket_addr: SocketAddr,
    /// Read-половинка потока поверх FSM (см. tcp_stream.rs)
    recv: TcpRecvHalf,
    /// Write-половинка потока поверх FSM
    send: TcpSendHalf,
    /// Команды задаче соединения (Close и т.п.)
    control_tx: UnboundedSender<ConnEvent>,
}

impl IpUdpStream {
    fn new(
        destination_socket_addr: SocketAddr,
        recv: TcpRecvHalf,
        send: TcpSendHalf,
        control_tx: UnboundedSender<ConnEvent>,
    ) -> Self {
        Self {
            destination_socket_addr,
            recv,
            send,
            control_tx,
        }
    }

    fn split(&self) -> (TcpRecvHalf, TcpSendHalf) {
        (self.recv.clone(), self.send.clone())
    }

    pub async fn close(&self) {
        let _ = self.control_tx.send(ConnEvent::Close);
    }
}

struct IpOverUdpServer {
    socket: Arc<UdpSocket>,
    connections: HashMap<FlowKey, UnboundedSender<ConnEvent>>,
    /// Команды от задач соединений (чистка таблицы)
    flow_control_tx: UnboundedSender<FlowControl>,
    flow_control_rx: UnboundedReceiver<FlowControl>,
}

impl IpOverUdpServer {
    async fn new(bind_addr: &str) -> Result<Self, Box<dyn Error>> {
        let socket = UdpSocket::bind(bind_addr).await?;
        let (flow_control_tx, flow_control_rx) = unbounded_channel::<FlowControl>();

        Ok(Self {
            socket: Arc::new(socket),
            connections: HashMap::new(),
            flow_control_tx,
            flow_control_rx,
        })
    }

    async fn run(&mut self) -> Result<Arc<IpUdpStream>, Box<dyn Error>> {
        loop {
            // Чистим таблицу: задачи соединений сообщают о завершении
            while let Ok(FlowControl::Remove(key)) = self.flow_control_rx.try_recv() {
                self.connections.remove(&key);
            }

            match self.recv().await {
                Ok(Some(stream)) => {
                    return Ok(stream);
                }
                Ok(None) => continue,
                Err(_) => continue,
            }
        }
    }

    async fn recv(&mut self) -> Result<Option<Arc<IpUdpStream>>, Box<dyn Error>> {
        let mut buffer = [0u8; 65535];

        let socket_cloned = Arc::clone(&self.socket);

        match socket_cloned.recv_from(&mut buffer).await {
            Ok((n, socket_addr)) => {
                debug!("===== Received {} from {}", n, socket_addr);

                let raw_ip_packet = buffer[..n].to_vec();

                match self.handle_ip_packet(raw_ip_packet, socket_addr).await {
                    Ok(Some(stream)) => {
                        return Ok(Some(stream));
                    }
                    Ok(None) => {
                        return Ok(None);
                    }
                    Err(e) => {
                        error!("Handle ip packet error {e}");
                        return Err(e);
                    }
                };
            }
            Err(e) => {
                error!("Recieve socket error: {}", e);
            }
        };

        Ok(None)
    }

    async fn handle_ip_packet(
        &mut self,
        raw_ip_packet: Vec<u8>,
        socket_addr: SocketAddr,
    ) -> Result<Option<Arc<IpUdpStream>>, Box<dyn Error>> {
        match net_packet_parser(&raw_ip_packet) {
            Some(Packet::Ipv6Tcp(ip_v6_tcp_packet)) => {
                warn!("Received ipv6/tcp from udp {}", ip_v6_tcp_packet);
            }
            Some(Packet::Ipv4Tcp(ip_tcp_packet)) => {
                debug!("{}", ip_tcp_packet);

                let stream = self
                    .handle_ipv4_tcp_packet(ip_tcp_packet, socket_addr)
                    .await?;

                return Ok(stream);
            }
            None => {
                warn!("Failed to parse packet");
            }
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
        let key = FlowKey::from_packet(&packet);

        if packet.syn() && !packet.ack() {
            let socket = Arc::clone(&self.socket);

            let fsm = TcpStateMachine::new_listen(
                packet.ip.source_address,
                packet.tcp.source_port,
                packet.ip.destination_address,
                packet.tcp.destination_port,
                Box::new(move |resp_packet| {
                    let socket_cloned = Arc::clone(&socket);

                    Box::pin(async move { utils::send_response(resp_packet, socket_cloned, socket_addr).await })
                }),
            );

            let recv_half = fsm.recv_half();
            let send_half = fsm.send_half();

            // Per-flow канал: пакеты этого соединения обрабатывает его задача
            let (event_tx, event_rx) = unbounded_channel::<ConnEvent>();

            self.connections.insert(key.clone(), event_tx.clone());

            let stream = Arc::new(IpUdpStream::new(
                SocketAddr::V4(SocketAddrV4::new(
                    packet.ip.destination_address,
                    packet.tcp.destination_port,
                )),
                recv_half,
                send_half,
                event_tx.clone(),
            ));

            // Задача соединения — единственный владелец FSM
            tokio::spawn(conn_task(
                fsm,
                event_rx,
                self.flow_control_tx.clone(),
                key,
            ));

            // SYN обрабатывается задачей соединения (SYN-ACK уйдёт из PacketHandler)
            let _ = event_tx.send(ConnEvent::Packet(packet));

            return Ok(Some(stream));
        }

        match self.connections.get(&key) {
            Some(event_tx) => {
                let _ = event_tx.send(ConnEvent::Packet(packet));
            }
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
                utils::send_response(response_raw, socket, socket_addr).await?;
            }
        }

        Ok(None)
    }
}

/// Задача соединения: единственный владелец FSM данного потока.
/// Обрабатывает пакеты от пира и пробуждения драйвера отправки;
/// медленная обработка одного соединения не задерживает остальные.
async fn conn_task(
    mut fsm: TcpStateMachine,
    mut rx: UnboundedReceiver<ConnEvent>,
    flow_control_tx: UnboundedSender<FlowControl>,
    key: FlowKey,
) {
    let notify = fsm.notify();

    loop {
        tokio::select! {
            event = rx.recv() => {
                match event {
                    Some(ConnEvent::Packet(packet)) => {
                        if let Err(e) = fsm.process_event(packet).await {
                            error!("process_event failed for {}: {}", key.source, e);
                        }
                    }
                    Some(ConnEvent::Close) => {
                        fsm.close().await;
                    }
                    None => break,
                }
            }
            // Пробуждение драйвера отправки: write-половинка / poll_read
            _ = notify.notified() => {
                fsm.pump_send().await;
            }
        }

        // RST/аборт или завершение закрытия: соединение закончено
        let state = fsm.state();
        if state == TcpState::Closed || state == TcpState::FinWait2 {
            break;
        }
    }

    // Чистим таблицу потоков
    let _ = flow_control_tx.send(FlowControl::Remove(key));
}

pub async fn handle_upd() -> Result<(), Box<dyn Error>> {
    info!("udp-server is running on port 8200");

    let mut server = IpOverUdpServer::new("0.0.0.0:8200").await?;

    loop {
        let client_stream = server.run().await?;

        tokio::spawn(async move {
            let addr = client_stream.destination_socket_addr;

            match TcpStream::connect(addr).await {
                Ok(mut destination_connect) => {
                    let (mut read_destination, mut write_destination) = destination_connect.split();
                    let (mut read_client, mut write_client) = client_stream.split();

                    tokio::select! {
                        v = copy(&mut read_client, &mut write_destination) => {
                            match v {
                                Ok(n) => {
                                    debug!("Translation from client to server is completed succeful {} bytes", n);
                                }
                                Err(e) => {
                                    error!("Failed to trnslate from client to server: {}", e);
                                }
                            }
                        }
                        v = copy(&mut read_destination, &mut write_client) => {
                            match v {
                                Ok(n) => {
                                    debug!("Translation from serber to client is completed succeful {} bytes", n);
                                }
                                Err(e) => {
                                    error!("Failed to trnslate from server to client: {}", e);
                                }
                            }
                        }
                    }

                    // Одна из ног закончилась: закрываем обе исходящие стороны
                    // (EOF таргету; FIN клиенту — poll_shutdown ждёт фактической
                    // отправки FIN, см. tcp_stream.rs)
                    let _ = write_destination.shutdown().await;
                    let _ = write_client.shutdown().await;

                    client_stream.close().await;

                    debug!("Stream/client pipe was closed ({})", addr);
                }
                Err(e) => {
                    error!("Connection error to target {} : {}", addr, e);
                }
            }

            debug!("Thread of stream/clent connection was closed ({})", addr);
        });
    }
}

#[cfg(test)]
mod tests {
    use std::{
        net::{Ipv4Addr, SocketAddr, SocketAddrV4},
        sync::Arc,
        time::{Duration, SystemTime, UNIX_EPOCH},
    };

    use etherparse::{PacketBuilder, TcpOptionElement};
    use rand::Rng;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, UdpSocket},
        time::timeout,
    };

    use crate::{
        handle_udp::{IpOverUdpServer, IpUdpStream},
        net_packet_parser::{
            IpTcpPacket, Packet, RawIpPacket, get_ack_data_response, get_ack_response,
            get_fin_response, net_packet_parser,
        },
    };

    pub fn get_syn_response(
        destination_addr: &Ipv4Addr,
        destination_port: u16,
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
            TcpOptionElement::MaximumSegmentSize(1350),
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

    pub fn get_rst_response(
        destination_addr: Ipv4Addr,
        destination_port: u16,
        seq_num: u32,
        source_addr: Ipv4Addr,
        source_port: u16,
    ) -> Result<RawIpPacket, std::io::Error> {
        let builder = PacketBuilder::ipv4(source_addr.octets(), destination_addr.octets(), 64)
            .tcp(source_port, destination_port, seq_num, 0)
            .rst();

        let payload = Vec::<u8>::new();

        let mut buffer = Vec::<u8>::with_capacity(builder.size(payload.len()));

        builder.write(&mut buffer, &payload).unwrap();

        Ok(buffer)
    }

    async fn assert_syn(
        client: &UdpSocket,
        destination_addr: SocketAddrV4,
        server: &mut IpOverUdpServer,
        source_addr: SocketAddrV4,
    ) -> (Arc<IpUdpStream>, u32, u32, u32) {
        let mut rng = rand::rng();
        let mut client_seq_num = rng.next_u32();

        let syn_packet = get_syn_response(
            destination_addr.ip(),
            destination_addr.port(),
            client_seq_num,
            source_addr.ip(),
            source_addr.port(),
            65535,
        )
        .unwrap();

        client
            .send_to(syn_packet.as_slice(), server.socket.local_addr().unwrap())
            .await
            .unwrap();

        client_seq_num = client_seq_num.saturating_add(1);

        let Some(stream) = server.recv().await.unwrap() else {
            panic!("No stream was created");
        };

        let mut buffer = [0u8; 1024];

        let ack_packet =
            match timeout(Duration::from_millis(500), client.recv_from(&mut buffer)).await {
                Ok(Ok((n, _))) => {
                    let Some(Packet::Ipv4Tcp(packet)) = net_packet_parser(&buffer[..n]) else {
                        panic!("");
                    };

                    assert!(packet.tcp.flags.syn);
                    assert!(packet.tcp.flags.ack);
                    assert_eq!(packet.tcp.acknowledgment_number, client_seq_num);

                    packet
                }
                _ => panic!("No client response received"),
            };

        let server_seq_number = ack_packet.tcp.sequence_number;
        let server_timestamp = ack_packet.options().timestamp.0;

        (stream, client_seq_num, server_seq_number, server_timestamp)
    }

    async fn assert_ack(
        ack_num: u32,
        client: &UdpSocket,
        destination_addr: SocketAddrV4,
        seq_num: u32,
        server: &mut IpOverUdpServer,
        source_addr: SocketAddrV4,
        timestamp: u32,
    ) {
        let raw_packet = get_ack_response(
            ack_num,
            *destination_addr.ip(),
            destination_addr.port(),
            seq_num,
            *source_addr.ip(),
            source_addr.port(),
            timestamp,
            65535,
        )
        .unwrap();

        client
            .send_to(raw_packet.as_slice(), server.socket.local_addr().unwrap())
            .await
            .unwrap();

        server.recv().await.unwrap();
    }

    async fn assert_data_request(
        ack_num: u32,
        client: &UdpSocket,
        destination_addr: SocketAddrV4,
        payload: &str,
        seq_num: u32,
        server: &mut IpOverUdpServer,
        source_addr: SocketAddrV4,
        stream: Arc<IpUdpStream>,
        timestamp: u32,
    ) -> u32 {
        let payload_data = payload.as_bytes().to_vec();

        let raw_packet_data = get_ack_data_response(
            ack_num,
            *destination_addr.ip(),
            destination_addr.port(),
            &payload_data,
            true,
            seq_num,
            *source_addr.ip(),
            source_addr.port(),
            timestamp,
            65535,
        )
        .unwrap();

        client
            .send_to(
                raw_packet_data.as_slice(),
                server.socket.local_addr().unwrap(),
            )
            .await
            .unwrap();

        let nex_seq_num = seq_num.saturating_add(payload_data.len() as u32);

        server.recv().await.unwrap();

        let mut buffer = [0u8; 1024];

        match timeout(Duration::from_millis(1000), client.recv_from(&mut buffer)).await {
            Ok(Ok((n, _))) => {
                let Some(Packet::Ipv4Tcp(packet)) = net_packet_parser(&buffer[..n]) else {
                    panic!("");
                };

                assert!(packet.tcp.flags.ack);
                assert_eq!(packet.tcp.acknowledgment_number, nex_seq_num);
            }
            _ => panic!("No client response received"),
        };

        // Данные, отправленные с PSH, FSM флашит в recv-половинку потока
        let mut recv = stream.recv.clone();
        let mut read_buffer = vec![0u8; payload.len()];
        timeout(Duration::from_millis(1000), recv.read_exact(&mut read_buffer))
            .await
            .expect("Данные не дошли до recv-половинки")
            .unwrap();

        assert_eq!(String::from_utf8_lossy(&read_buffer), "Hello world".to_string());

        nex_seq_num
    }

    async fn assert_data_response(client: &UdpSocket, stream: Arc<IpUdpStream>) {
        // Пишем через write-половинку: драйвер перекачает данные в FSM и отправит
        let mut send = stream.send.clone();

        send.write_all("The world is here".as_bytes()).await.unwrap();

        let mut buffer = [0u8; 1024];

        match timeout(Duration::from_millis(1000), client.recv_from(&mut buffer)).await {
            Ok(Ok((n, _))) => {
                let Some(Packet::Ipv4Tcp(packet)) = net_packet_parser(&buffer[..n]) else {
                    panic!("");
                };

                assert_eq!(packet.payload(), "The world is here".as_bytes().to_vec());
            }
            _ => panic!("No client response received"),
        };
    }

    async fn assert_initial_data_exchange(
        client: &UdpSocket,
        destination_addr: SocketAddrV4,
        server: &mut IpOverUdpServer,
        source_addr: SocketAddrV4,
    ) -> (Arc<IpUdpStream>, u32) {
        let (stream, client_seq_num, server_seq_num, server_timestamp) =
            assert_syn(&client, destination_addr, server, source_addr).await;

        let ack_num = server_seq_num + 1;

        assert_ack(
            ack_num,
            &client,
            destination_addr,
            client_seq_num,
            server,
            source_addr,
            server_timestamp,
        )
        .await;

        let seq_num = assert_data_request(
            ack_num,
            &client,
            destination_addr,
            "Hello world",
            client_seq_num,
            server,
            source_addr,
            stream.clone(),
            server_timestamp,
        )
        .await;

        assert_data_response(&client, stream.clone()).await;

        (stream, seq_num)
    }

    #[tokio::test]
    async fn test_syn() {
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let destination = TcpListener::bind("127.0.0.1:0").await.unwrap();

        let mut server = IpOverUdpServer::new("127.0.0.1:0").await.unwrap();

        let SocketAddr::V4(destination_addr) = destination.local_addr().unwrap() else {
            panic!("Expected IPv4 address");
        };

        let SocketAddr::V4(source_addr) = client.local_addr().unwrap() else {
            panic!("Expected IPv4 address");
        };

        assert_initial_data_exchange(&client, destination_addr, &mut server, source_addr).await;
    }

    #[tokio::test]
    async fn test_rst() {
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let destination = TcpListener::bind("127.0.0.1:0").await.unwrap();

        let mut server = IpOverUdpServer::new("127.0.0.1:0").await.unwrap();

        let SocketAddr::V4(destination_addr) = destination.local_addr().unwrap() else {
            panic!("Expected IPv4 address");
        };

        let SocketAddr::V4(source_addr) = client.local_addr().unwrap() else {
            panic!("Expected IPv4 address");
        };

        let (stream, seq_num) =
            assert_initial_data_exchange(&client, destination_addr, &mut server, source_addr).await;

        let raw_rst_packet = get_rst_response(
            *destination_addr.ip(),
            destination_addr.port(),
            seq_num,
            *source_addr.ip(),
            source_addr.port(),
        )
        .unwrap();

        client
            .send_to(
                raw_rst_packet.as_slice(),
                server.socket.local_addr().unwrap(),
            )
            .await
            .unwrap();

        server.recv().await.unwrap();

        // Детерминированный синк: RST обрабатывается задачей соединения
        // асинхронно; EOF на read-половинке означает, что RST обработан
        let mut recv = stream.recv.clone();
        let mut eof_buf = [0u8; 1];
        let eof_n = timeout(Duration::from_millis(1000), recv.read(&mut eof_buf))
            .await
            .expect("RST не обработан: EOF не получен")
            .unwrap();
        assert_eq!(eof_n, 0, "Ожидался EOF после RST");

        // После RST write-половинка может принять данные, но драйвер не должен
        // отправить ни одного пакета (guard send_pending_data при Closed)
        let mut send = stream.send.clone();
        send.write_all("The world is here".as_bytes()).await.unwrap();

        let mut buffer = [0u8; 1024];

        match timeout(Duration::from_millis(1000), client.recv_from(&mut buffer)).await {
            Ok(Ok((n, _))) => {
                if let Some(Packet::Ipv4Tcp(packet)) = net_packet_parser(&buffer[..n]) {
                    let tcp = packet.tcp();
                    panic!(
                        "Client shouldn't receive any data. packet: seq={} ack={} syn={} fin={} rst={} psh={} payload={:?}",
                        packet.sequence_number(),
                        packet.acknowledgment_number(),
                        tcp.flags.syn,
                        tcp.flags.fin,
                        tcp.flags.rst,
                        tcp.flags.psh,
                        String::from_utf8_lossy(&tcp.payload)
                    );
                }
                panic!("Client shouldn't receive any data (unparsed).");
            }
            _ => {}
        };
    }

    #[tokio::test]
    async fn test_two_flows() {
        let destination = TcpListener::bind("127.0.0.1:0").await.unwrap();

        let mut server = IpOverUdpServer::new("127.0.0.1:0").await.unwrap();

        let SocketAddr::V4(destination_addr) = destination.local_addr().unwrap() else {
            panic!("Expected IPv4 address");
        };

        // Два независимых клиента: полный обмен данными в каждом потоке.
        // Проверяет, что обработка одного потока не блокирует другой.
        let client1 = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client2 = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        let SocketAddr::V4(source_addr1) = client1.local_addr().unwrap() else {
            panic!("Expected IPv4 address");
        };
        let SocketAddr::V4(source_addr2) = client2.local_addr().unwrap() else {
            panic!("Expected IPv4 address");
        };

        assert_initial_data_exchange(&client1, destination_addr, &mut server, source_addr1).await;
        assert_initial_data_exchange(&client2, destination_addr, &mut server, source_addr2).await;
    }

    #[tokio::test]
    async fn test_fin() {
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let destination = TcpListener::bind("127.0.0.1:0").await.unwrap();

        let mut server = IpOverUdpServer::new("127.0.0.1:0").await.unwrap();

        let SocketAddr::V4(destination_addr) = destination.local_addr().unwrap() else {
            panic!("Expected IPv4 address");
        };

        let SocketAddr::V4(source_addr) = client.local_addr().unwrap() else {
            panic!("Expected IPv4 address");
        };

        let (stream, seq_num, server_seq_num, server_timestamp) =
            assert_syn(&client, destination_addr, &mut server, source_addr).await;

        // Завершаем установление соединения и обмен данными
        assert_ack(
            server_seq_num + 1,
            &client,
            destination_addr,
            seq_num,
            &mut server,
            source_addr,
            server_timestamp,
        )
        .await;

        assert_ack(
            server_seq_num + 18, // SYN + 17 байт данных "The world is here"
            &client,
            destination_addr,
            seq_num,
            &mut server,
            source_addr,
            server_timestamp,
        )
        .await;

        // --- Часть 1: пир закрывает свою сторону (FIN) → EOF на read ---
        let curr_timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u32;

        let fin_packet = get_fin_response(
            server_seq_num + 18,
            *destination_addr.ip(),
            destination_addr.port(),
            seq_num,
            *source_addr.ip(),
            source_addr.port(),
            curr_timestamp,
            65535,
        )
        .unwrap();

        client
            .send_to(fin_packet.as_slice(), server.socket.local_addr().unwrap())
            .await
            .unwrap();

        server.recv().await.unwrap();

        // Сервер отвечает ACK на FIN
        let mut buffer = [0u8; 1024];

        match timeout(Duration::from_millis(1000), client.recv_from(&mut buffer)).await {
            Ok(Ok((n, _))) => {
                let Some(Packet::Ipv4Tcp(packet)) = net_packet_parser(&buffer[..n]) else {
                    panic!("Expected ipv4/tcp packet");
                };

                assert!(packet.tcp.flags.ack);
                assert_eq!(packet.tcp.acknowledgment_number, seq_num + 1);
            }
            _ => panic!("No FIN-ACK received"),
        }

        // Read-половинка сигналит EOF после опустошения буфера
        let mut recv = stream.recv.clone();
        let mut eof_buf = [0u8; 1];
        let n = timeout(Duration::from_millis(1000), recv.read(&mut eof_buf))
            .await
            .expect("EOF после FIN не получен")
            .unwrap();
        assert_eq!(n, 0, "Ожидался EOF (Ok(0)) после FIN");

        // --- Часть 2: прокси закрывает свою сторону (shutdown → FIN) ---
        let mut send = stream.send.clone();
        send.shutdown().await.unwrap();

        match timeout(Duration::from_millis(1000), client.recv_from(&mut buffer)).await {
            Ok(Ok((n, _))) => {
                let Some(Packet::Ipv4Tcp(packet)) = net_packet_parser(&buffer[..n]) else {
                    panic!("Expected ipv4/tcp packet");
                };

                assert!(packet.tcp.flags.fin, "Ожидался FIN после shutdown");
            }
            _ => panic!("No FIN received after shutdown"),
        }
    }
}
