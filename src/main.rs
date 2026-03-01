mod handel_tcp;
mod handle_udp;

use handel_tcp::handle_tcp;
use handle_udp::handle_upd;
use std::{error::Error};

use tracing::Level;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt()
        .with_max_level(Level::DEBUG)
        .init();

    tokio::select! {
        _ = handle_tcp() => {}
        _ = handle_upd() => {}
    }

    Ok(())
}
