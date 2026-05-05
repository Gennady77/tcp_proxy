use rand::Rng;
use std::sync::Arc;
use std::{
    cmp::min,
    collections::HashMap,
    error::Error,
    net::{SocketAddr, SocketAddrV4},
    task::{Poll, Waker},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, copy},
    net::{TcpStream, UdpSocket},
    sync::Mutex,
    time::sleep,
};
use tracing::{debug, error, info, warn};

use crate::{
    net_packet_parser::{
        IpTcpPacket, Ipv4TcpPacket, Packet, get_reset_response, net_packet_parser,
    },
    tcp_actor::{TcpActor, TcpActorEvent, TcpHandle},
    utils::dump_raw_packet,
};

struct ReadHalf {
    buffer: Arc<Mutex<Vec<u8>>>,
    waker: Arc<Mutex<Option<Waker>>>,
}

struct WriteHalf {
    buffer: Arc<Mutex<Vec<u8>>>,
    closed: Arc<Mutex<bool>>,
}

struct IpUdpStream {
    closed: Arc<Mutex<bool>>,
    destination_socket_addr: SocketAddr,
    handle: TcpHandle,
    read_buffer: Arc<Mutex<Vec<u8>>>,
    read_waker: Arc<Mutex<Option<Waker>>>,
    write_buffer: Arc<Mutex<Vec<u8>>>,
}

impl IpUdpStream {
    fn new(destination_socket_addr: SocketAddr, handle: TcpHandle) -> Self {
        Self {
            closed: Arc::new(Mutex::new(false)),
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

        let write_half = WriteHalf {
            buffer: write_buffer,
            closed: self.closed.clone(),
        };

        (read_half, write_half)
    }

    pub async fn is_closed(&self) -> bool {
        let closed_guard = self.closed.lock().await;

        *closed_guard
    }
}

impl AsyncWrite for WriteHalf {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        let write_buffer = this.buffer.clone();

        let closed = match this.closed.try_lock() {
            Ok(cls) => *cls,
            Err(_) => return Poll::Pending,
        };

        if closed {
            return Poll::Ready(Ok(0));
        }

        match write_buffer.try_lock() {
            Ok(mut wb) => {
                let bytes_to_write = buf.len();

                wb.extend_from_slice(buf);

                Poll::Ready(Ok(bytes_to_write))
            }
            Err(_) => Poll::Pending,
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let write_buffer = this.buffer.clone();

        match write_buffer.try_lock() {
            Ok(wb) => {
                if wb.is_empty() {
                    Poll::Ready(Ok(()))
                } else {
                    Poll::Pending
                }
            }
            Err(_) => Poll::Pending,
        }
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.poll_flush(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
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
            }
            Err(_) => {
                let mut waker = match waker_clone.try_lock() {
                    Ok(wk) => wk,
                    Err(_) => {
                        return Poll::Pending;
                    }
                };

                *waker = Some(cx.waker().clone());
                Poll::Pending
            }
        }
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

    async fn run(&mut self) -> Result<Arc<IpUdpStream>, Box<dyn Error>> {
        loop {
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
                debug!("Received ipv4/tcp from udp {}", ip_tcp_packet);

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

            let stream = Arc::new(IpUdpStream::new(
                SocketAddr::V4(SocketAddrV4::new(
                    packet.ip.destination_address,
                    packet.tcp.destination_port,
                )),
                handle,
            ));

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
                            let mut rb = stream_cloned.read_buffer.lock().await;

                            rb.append(&mut data);

                            let waker_clone = stream_cloned.read_waker.clone();
                            let mut waker = waker_clone.lock().await;

                            if let Some(waker) = waker.take() {
                                waker.wake();
                            }
                        }
                        Some(TcpActorEvent::Close) => {
                            let mut closed_guard = stream_cloned.closed.lock().await;

                            *closed_guard = true;

                            break;
                        }
                        None => {
                            break;
                        }
                    }
                }
            });

            let stream_cloned = stream.clone();

            tokio::spawn(async move {
                loop {
                    if stream_cloned.is_closed().await {
                        break;
                    }

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

            let key = (
                packet.source_socket().to_string(),
                packet.destination_socket().to_string(),
            );

            self.conections.insert(key, stream.clone());

            stream.handle.send_packet(packet.clone())?;

            return Ok(Some(stream));
        }

        let key = (
            packet.source_socket().to_string(),
            packet.destination_socket().to_string(),
        );

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
    addr: SocketAddr,
) -> Result<(), std::io::Error> {
    if let Err(e) = socket.send_to(response_raw.as_slice(), addr).await {
        error!("Failed to send answer to udp socket: {}", e);

        return Err(std::io::Error::other(e.to_string()));
    }

    dump_raw_packet(response_raw, "Sent");

    Ok(())
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
        net::{TcpListener, UdpSocket},
        time::timeout,
    };

    use crate::{
        handle_udp::{IpOverUdpServer, IpUdpStream},
        net_packet_parser::{
            IpTcpPacket, Packet, RawIpPacket, get_ack_data_response, get_ack_response,
            net_packet_parser,
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
            payload_data.clone(),
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

        let buffer = stream.read_buffer.lock().await;

        let read_buffer = String::from_utf8_lossy(&buffer);

        assert_eq!(read_buffer, "Hello world".to_string());

        nex_seq_num
    }

    async fn assert_data_response(client: &UdpSocket, stream: Arc<IpUdpStream>) {
        let mut write_buffer = stream.write_buffer.lock().await;

        *write_buffer = "The world is here".as_bytes().to_vec();

        drop(write_buffer);

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

        let mut write_buffer = stream.write_buffer.lock().await;

        *write_buffer = "The world is here".as_bytes().to_vec();

        drop(write_buffer);

        let mut buffer = [0u8; 1024];

        match timeout(Duration::from_millis(1000), client.recv_from(&mut buffer)).await {
            Ok(Ok((_, _))) => {
                panic!("Client shouldn't receive any data.");
            }
            _ => {}
        };
    }
}
