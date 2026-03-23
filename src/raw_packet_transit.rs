use etherparse::{NetSlice, SlicedPacket};
use socket2::{Domain, MaybeUninitSlice, Protocol, Socket, Type};
use tokio::{net::UdpSocket, time::{Duration, Instant}};
use tracing::{debug, error};
use std::{error::Error, mem::MaybeUninit, net::SocketAddr, sync::Arc};

async fn send_raw_ip_packet_transit(raw_ip_packet: &[u8], socket_addr: SocketAddr, udp_socket: Arc<UdpSocket>) -> Result<(), Box<dyn Error>> {
    let packet = SlicedPacket::from_ip(raw_ip_packet)?;
    
    let (source_ip, dest_ip) = match packet.net {
        Some(NetSlice::Ipv4(ipv4)) => (ipv4.header().source_addr(), ipv4.header().destination_addr()),
        _ => {
            error!("Unsupported network layer");
            return Ok(());
        }
    };

    debug!{"=================== {:?}", raw_ip_packet};
    debug!("==============={}", raw_ip_packet[0]);

    let dest_ip_copy = dest_ip;
    let source_ip_copy = source_ip;
    let udp_socket_clone = Arc::clone(&udp_socket);
    let socket_addr_copy = socket_addr;

    let socket = Socket::new(Domain::IPV4, Type::RAW, None)?;

    socket.set_header_included_v4(true)?;
    // socket.set_nonblocking(true)?;

    let dest_addr = SocketAddr::new(dest_ip_copy.into(), 0);
    debug!("==============={}", dest_addr);
    match socket.send_to(&raw_ip_packet, &dest_addr.into()) {
        Ok(n) => {
            debug!("Sent raw {} bytes IP packet {} > {}", n, source_ip_copy, dest_ip_copy);
        }
        Err(e) => {
            error!("Failed to send IP packet to {}: {}", dest_ip_copy, e);
        }
    }

    // Создаем raw socket для приема ответов
    let recv_handle = tokio::spawn(async move {
        let recv_socket = Socket::new(
            Domain::IPV4, 
            Type::RAW, 
            Some(Protocol::TCP) // Важно! Используем протокол из пакета
        ).unwrap();

        let mut buf: [MaybeUninit<u8>; 65535] = unsafe { MaybeUninit::uninit().assume_init() };
        let timeout_duration = Duration::from_secs(10); // Таймаут на ответ
        let start = Instant::now();

        let mut slice = MaybeUninitSlice::new(&mut buf);

        loop {
            if start.elapsed() > timeout_duration {
                debug!("Timeout waiting for response");
                break;
            }

            debug!("Start receiving data from socket");

            match recv_socket.recv_from(&mut slice) {
                Ok((n, _)) => {
                    debug!("Received {} from socket", n);

                    let received_packet = unsafe {
                        std::slice::from_raw_parts(slice.as_ptr() as *const u8, n)
                    };

                    // Парсим и фильтруем пакет
                    if let Ok(received_parsed) = SlicedPacket::from_ip(received_packet) {
                        if let Some(NetSlice::Ipv4(ipv4)) = received_parsed.net {
                            let recv_source = ipv4.header().source_addr();
                            let recv_dest = ipv4.header().destination_addr();

                            // Проверяем, что это ответ на наш пакет
                            if recv_source == dest_ip_copy && recv_dest == source_ip_copy {
                                debug!("Received matching response packet from {}", recv_source);

                                // Отправляем обратно на UDP
                                if let Err(e) = udp_socket_clone.send_to(received_packet, socket_addr_copy).await {
                                    error!("Failed to send response back to UDP: {}", e);
                                }
                                // Можно break после первого подходящего пакета, или продолжать
                                break;
                            }
                        }
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                Err(e) => {
                    error!("Recv error: {}", e);
                    break;
                }
            }
        }
    });

    recv_handle.await?;

    Ok(())
}