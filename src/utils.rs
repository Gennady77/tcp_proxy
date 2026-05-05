use std::{net::SocketAddr, pin::Pin, sync::Arc};

use tokio::net::UdpSocket;
use tracing::{debug, error};

use crate::net_packet_parser::{Packet, RawIpPacket, net_packet_parser};

pub type PacketHandler = Box<
    dyn Fn(Vec<u8>) -> Pin<Box<dyn Future<Output = Result<(), std::io::Error>> + Send>>
        + Send
        + Sync,
>;

pub fn dump_raw_packet(raw_packet: &RawIpPacket, prefix: &str) {
    match net_packet_parser(raw_packet) {
        Some(Packet::Ipv4Tcp(parsed_response)) => {
            debug!("{} Ipv4Tcp packet {}", prefix, parsed_response);
        }
        Some(Packet::Ipv6Tcp(parsed_response)) => {
            debug!("{} Ipv6Tcp packet {}", prefix, parsed_response);
        }
        Some(Packet::Unknown) => {
            debug!("Unknown type of raw packet")
        }
        None => {
            debug!("Received response packet from server");
        }
    }
}

pub async fn send_response(
    response_raw: Vec<u8>,
    socket: Arc<UdpSocket>,
    addr: SocketAddr,
) -> Result<(), std::io::Error> {
    if let Err(e) = socket.send_to(response_raw.as_slice(), addr).await {
        error!("Failed to send answer to udp socket: {}", e);

        return Err(std::io::Error::other(e.to_string()));
    }

    dump_raw_packet(&response_raw, "Sent");

    Ok(())
}
