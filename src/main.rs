mod handel_tcp;
mod handle_udp;
mod net_packet_parser;
mod tcp_actor;
mod tcp_state_machine;
mod utils;

use handle_udp::handle_upd;
use std::error::Error;
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt};

use crate::handel_tcp::handle_tcp;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let file_appender = tracing_appender::rolling::hourly("./logs", "tcp_proxy.log");

    let (non_blocking, _guard) = tracing_appender::non_blocking(file_appender);

    let console_layer = fmt::layer().with_writer(std::io::stdout).pretty();

    let file_layer = fmt::layer()
        .with_writer(non_blocking)
        .with_ansi(true)
        .with_target(true)
        .with_level(true);

    tracing_subscriber::registry()
        .with(console_layer)
        .with(file_layer)
        .init();

    tokio::select! {
        _ = handle_tcp() => {},
        _ = handle_upd() => {}
    }

    Ok(())
}
