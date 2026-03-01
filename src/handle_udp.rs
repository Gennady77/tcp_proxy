use std::error::Error;

use etherparse::{NetSlice, SlicedPacket, TransportSlice};
use tokio::{io::{AsyncReadExt, AsyncWriteExt}, net::{TcpStream, UdpSocket}};
use tracing::{debug, error, info};

struct IpOverUdpServer {
    socket: UdpSocket
}

impl IpOverUdpServer {
    async fn new(bind_addr: &str) -> Result<Self, Box<dyn Error>> {
        let socket = UdpSocket::bind(bind_addr).await?;

        Ok(Self {
            socket,
        })
    }

    async fn run(&self) -> Result<(), Box<dyn Error>>{
        let mut buffer = [0u8; 65535];

        loop {
            match self.socket.recv_from(&mut buffer).await {
                Ok((n, socket_addr)) => {
                    debug!("Received {} from {}", n, socket_addr);

                    let raw_ip_packet = &buffer[..n];

                    match SlicedPacket::from_ip(&raw_ip_packet) {
                        Ok(packet) => {
                            let dest_ip = packet.net.and_then(|net| {
                                match net {
                                    NetSlice::Ipv4(ip_header) => Some(ip_header.header().destination_addr()),
                                    _ => None
                                }
                            }).unwrap();

                            if let Some(transport) = packet.transport {
                                match transport {
                                    TransportSlice::Tcp(tcp) => {
                                        let dest_port = tcp.destination_port();
                                        let payload = tcp.payload();

                                        let dest_addr = format!("{}:{}", dest_ip, dest_port);

                                        let mut connect = TcpStream::connect(dest_addr).await.unwrap();

                                        connect.write_all(payload).await.unwrap();

                                        let mut buffer = [0u8; 1024];

                                        let n = connect.read(&mut buffer).await.unwrap();

                                        match self.socket.send_to(&buffer[..n], socket_addr).await {
                                            Ok(n) => {
                                                info!("TCP response. {} bytes sended to {}", n, socket_addr);
                                            }
                                            Err(e) => {
                                                error!("TCP response error. Sending to socket {} error: {}", socket_addr, e);
                                            }
                                        }
                                    },
                                    TransportSlice::Udp(udp) => {
                                        let socket = UdpSocket::bind("0.0.0.0:0").await?;
                                        let dest_port = udp.destination_port();
                                        let payload = udp.payload();

                                        let dest_addr = format!("{}:{}", dest_ip, dest_port);

                                        socket.connect(dest_addr.clone()).await?;

                                        socket.send(payload).await?;

                                        let mut buffer = [0u8; 65535];

                                        match socket.recv_from(&mut buffer).await {
                                            Ok((n, _)) => {
                                                self.socket.send_to(&buffer[..n], socket_addr).await?;
                                            }
                                            Err(e) => {
                                                error!("UDP response. Receiving data from {} error: {}", dest_addr, e);
                                            }
                                        }
                                    }
                                    _ => {
                                        info!("Unknown protocol");
                                    }
                                };
                            }
                        },
                        Err(e) => {
                            error!("Parse ip packet erorr: {}", e);
                        }
                    }
                },
                Err(e) => {
                    error!("Recieve socket error: {}", e);
                }
            }
        }
    }
}

pub async fn handle_upd() -> Result<(), Box<dyn Error>> {
    let server = IpOverUdpServer::new("0.0.0.0:8090").await?;

    server.run().await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{error::Error, net::Ipv4Addr, sync::Arc, time::Duration};

    use tokio::{io::{AsyncReadExt, AsyncWriteExt}, net::{TcpListener, UdpSocket}, sync::Mutex, time};
    use etherparse::PacketBuilder;

    use crate::handle_udp::handle_upd;

    fn create_ip_tcp_packet(dest_ip: Ipv4Addr, dest_port: u16, payload: &[u8]) -> Vec<u8> {
        let builder = PacketBuilder::
            ipv4(
                [192, 168, 1, 2].into(),
                dest_ip.octets(), 
                64
            )
            .tcp(
                12345, 
                dest_port,
                0,
                65535
            );

        let mut result = Vec::<u8>::with_capacity(builder.size(payload.len()));

        builder.write(&mut result, payload).unwrap();

        result
    }

    fn create_ip_udp_packet(dest_ip: Ipv4Addr, dest_port: u16, payload: &[u8]) -> Vec<u8> {
        let builder = PacketBuilder::
            ipv4(
                [192, 168, 1, 2].into(),
                dest_ip.octets(), 
                64
            )
            .udp(
                12345, 
                dest_port,
            );

        let mut result = Vec::<u8>::with_capacity(builder.size(payload.len()));

        builder.write(&mut result, payload).unwrap();

        result
    }

    struct DestinationTcpServer {
        received_request: Arc<Mutex<Option<String>>>,
        response: Arc<String>,
    }

    impl DestinationTcpServer {
        fn new(response: String) -> Self {
            DestinationTcpServer {
                received_request: Arc::new(Mutex::new(None)),
                response: Arc::new(response),
            }
        }

        async fn run(&mut self) -> Result<u16, Box<dyn Error>> {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = listener.local_addr().unwrap().port();

            let received_request_cloned = Arc::clone(&self.received_request);
            let response_cloned = Arc::clone(&self.response);

            tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();

                let mut buffer = [0u8; 1024];
                let n = stream.read(&mut buffer).await.unwrap();

                let mut received_request_guard = received_request_cloned.lock().await;

                *received_request_guard = Some(String::from_utf8_lossy(&buffer[..n]).to_string());

                stream.write_all(response_cloned.as_bytes()).await.unwrap();
            });

            Ok(port)
        }

        async fn get_received_request(&self) -> String {
            let received_request_cloned = Arc::clone(&self.received_request);

            let received_request_guard = received_request_cloned.lock().await;

            let received_request = received_request_guard.clone();

            received_request.unwrap()
        }
    }

    struct DestinationUdpServer {
        received_request: Arc<Mutex<Option<String>>>,
        response: Arc<String>,
    }

    impl DestinationUdpServer {
        fn new(response: String) -> Self {
            DestinationUdpServer {
                received_request: Arc::new(Mutex::new(None)),
                response: Arc::new(response),
            }
        }

        async fn run(&mut self) -> Result<u16, Box<dyn Error>> {
            let socket = UdpSocket::bind("127.0.0.1:0").await?;

            let received_request_cloned = self.received_request.clone();
            let response_cloned = Arc::clone(&self.response);

            let port = socket.local_addr().unwrap().port();

            tokio::spawn(async move {
                loop {
                    let mut buffer = [0u8; 65535];

                    let (n, socket_addr) = socket.recv_from(&mut buffer).await.unwrap();

                    let mut received_request_guard = received_request_cloned.lock().await;

                    *received_request_guard = Some(String::from_utf8_lossy(&buffer[..n]).to_string());

                    socket.send_to(response_cloned.as_bytes(), socket_addr).await.unwrap();
                }
            });

            Ok(port)
        }

        async fn get_received_request(&self) -> String {
            let received_request_cloned = Arc::clone(&self.received_request);

            let received_request_guard = received_request_cloned.lock().await;

            let received_request = received_request_guard.clone();

            received_request.unwrap()
        }
    }

    struct UdpInIpClient {
        socket: Arc<UdpSocket>,
        response: Arc<Mutex<Option<String>>>,
    }

    impl UdpInIpClient {
        async fn new() -> Self {
            let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());

            let response:Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
            let response_cloned = Arc::clone(&response);

            let socket_cloned = Arc::clone(&socket);

            tokio::spawn(async move {
                let mut buffer = [0u8; 65535];

                let (n, _) = socket_cloned.recv_from(&mut buffer).await.unwrap();

                let mut client_response_guard = response_cloned.lock().await;

                *client_response_guard = Some(String::from_utf8_lossy(&buffer[..n]).to_string());
            });

            UdpInIpClient {
                socket,
                response,
            }
        }

        async fn get_response(&self) -> Option<String> {
            let response_cloned = Arc::clone(&self.response);
            let response_guard = response_cloned.lock().await;
            let response = response_guard.clone();

            response
        }
    }

    #[tokio::test]
    async fn test_ip_tcp_packet() {
        let client = UdpInIpClient::new().await;

        let dest_response= "Ok/200".to_string();
        let mut dest_server = DestinationTcpServer::new(dest_response.clone());
        let dest_ip = Ipv4Addr::new(127, 0, 0, 1);
        let dest_port = dest_server.run().await.unwrap();

        tokio::spawn(async move {
            handle_upd().await.unwrap();
        });

        let payload = "POST /list HTTP/1.1\r\n";
        let ip_packet = create_ip_tcp_packet(dest_ip, dest_port, payload.as_bytes());
        client.socket.send_to(&ip_packet, "127.0.0.1:8090").await.unwrap();

        time::sleep(Duration::from_millis(100)).await;

        assert_eq!(payload, dest_server.get_received_request().await);

        let client_response = client.get_response().await;

        assert!(client_response.is_some());
        assert_eq!(dest_response, client_response.unwrap());
    }

    #[tokio::test]
    async fn test_ip_other_packet() {
        let client = UdpInIpClient::new().await;

        let dest_response= "Ok/200".to_string();
        let mut dest_server = DestinationUdpServer::new(dest_response.clone());
        let dest_ip = Ipv4Addr::new(127, 0, 0, 1);
        let dest_port = dest_server.run().await.unwrap();

        tokio::spawn(async move {
            handle_upd().await.unwrap();
        });

        let payload = "some udp payload";
        let udp_packet = create_ip_udp_packet(dest_ip, dest_port, payload.as_bytes());
        client.socket.send_to(&udp_packet, "127.0.0.1:8090").await.unwrap();

        time::sleep(Duration::from_millis(100)).await;

        let dest_request = dest_server.get_received_request().await;

        assert_eq!(payload, dest_request);

        let client_response = client.get_response().await;

        assert!(client_response.is_some());
        assert_eq!(dest_response, client_response.unwrap());
    }
}
