use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
};

use tokio::{
    net::UdpSocket,
    sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel},
};
use tracing::error;

use crate::{
    net_packet_parser::{IpTcpPacket, Ipv4TcpPacket},
    tcp_state_machine::{TcpState, TcpStateMachine},
    utils::send_response,
};

pub enum TcpCommand {
    Packet(Ipv4TcpPacket),
    Write(Vec<u8>),
}

pub enum TcpActorEvent {
    Data(Vec<u8>),
    Close,
}

pub struct TcpHandle {
    cmd_tx: UnboundedSender<TcpCommand>,
}

impl TcpHandle {
    pub fn send_packet(&self, packet: Ipv4TcpPacket) -> Result<(), std::io::Error> {
        if let Err(e) = self.cmd_tx.send(TcpCommand::Packet(packet.clone())) {
            error!(
                "Failed to send packet {}, {}: {}",
                packet.destination_socket().to_string(),
                packet.sequence_number(),
                e
            );
        }

        Ok(())
    }

    pub fn write(&self, data: Vec<u8>) {
        let _ = self.cmd_tx.send(TcpCommand::Write(data));
    }
}

pub struct TcpActor {
    state: TcpStateMachine,
    cmd_rx: UnboundedReceiver<TcpCommand>,
    read_tx: UnboundedSender<TcpActorEvent>,
}

impl TcpActor {
    pub fn new(
        socket: Arc<UdpSocket>,
        socket_addr: SocketAddr,
        source_addr: Ipv4Addr,
        source_port: u16,
        destination_addr: Ipv4Addr,
        destination_port: u16,
    ) -> (TcpHandle, UnboundedReceiver<TcpActorEvent>, Self) {
        let (cmd_tx, cmd_rx) = unbounded_channel();
        let (read_tx, read_rx) = unbounded_channel();

        let mut state = TcpStateMachine::new(
            source_addr,
            source_port,
            destination_addr,
            destination_port,
            Box::new(move |packet| {
                let socket_cloned = Arc::clone(&socket);

                Box::pin(async move { send_response(packet, socket_cloned, socket_addr).await })
            }),
        );

        state.state = TcpState::Listen;

        let actor = Self {
            state,
            cmd_rx,
            read_tx,
        };

        (TcpHandle { cmd_tx }, read_rx, actor)
    }

    pub async fn run(&mut self) -> Result<(), std::io::Error> {
        while let Some(cmd) = self.cmd_rx.recv().await {
            match cmd {
                TcpCommand::Packet(packet) => {
                    self.state.process_event(packet).await?;

                    if let TcpState::Close = self.state.state {
                        let _ = self.read_tx.send(TcpActorEvent::Close);
                        break;
                    }

                    if !self.state.read_buffer.is_empty() {
                        let data = std::mem::take(&mut self.state.read_buffer);
                        let _ = self.read_tx.send(TcpActorEvent::Data(data));
                    }
                }
                TcpCommand::Write(data) => {
                    self.state.try_send_data(data).await;
                }
            }
        }

        Ok(())
    }
}
