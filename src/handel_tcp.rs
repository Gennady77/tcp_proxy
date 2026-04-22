use std::{error::Error, net::ToSocketAddrs};

use tokio::{io::{AsyncReadExt, AsyncWriteExt, copy}, net::{TcpListener, TcpStream}};
use tracing::{debug, error, info};

pub async fn handle_tcp() -> Result<(), Box<dyn Error>> {
    info!("tcp-server is running on port 8090");

    let listener = TcpListener::bind("0.0.0.0:8090").await?;

    loop {
        let (mut client_stream, addr) = listener.accept().await?;

        tokio::spawn(async move {
            let mut buffer = [0u8; 1024];

            match client_stream.read(&mut buffer).await {
                Ok(0) => {
                    error!("Connection was closed");
                }
                Ok(n) => {
                    debug!("Received from {}, {} bytes", addr, n);

                    if buffer.starts_with(b"=====") {
                        let request = String::from_utf8_lossy(&buffer);

                        let host = request.split_ascii_whitespace().nth(1).unwrap_or("");

                        match format!("{}", host).to_socket_addrs() {
                            Ok(mut socket_addrs) => {
                                if let Some(addr) = socket_addrs.next() {
                                    debug!("Целевой адрес для {host} определился успешно: {}", addr);
                                    
                                    match TcpStream::connect(addr).await {
                                        Ok(mut target_connect) => {

                                            client_stream.write_all(b"Ok").await.unwrap();

                                            let (mut read_target, mut wright_target) = target_connect.split();
                                            let (mut read_client, mut wright_client) = client_stream.split();

                                            tokio::select! {
                                                _ = copy(&mut read_client, &mut wright_target) => {}
                                                _ = copy(&mut read_target, &mut wright_client) => {}
                                            }
                                        }
                                        Err(e) => {
                                            error!("Connection error to target: {}", e);
                                        }
                                    }
                                }
                            }
                            Err(e) => {
                                error!("DNS error: {}", e);
                            }
                        }
                    }
                }
                Err(_) => {
                    error!("Reading stream error");
                }
            };
        });
    }
}