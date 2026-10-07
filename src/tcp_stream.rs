//! Мост между задачей-драйвером FSM и половинками AsyncRead/AsyncWrite.
//!
//! Задача-драйвер единолично владеет `TcpStateMachine`; половинки (`TcpRecvHalf` /
//! `TcpSendHalf`) реализуют `AsyncRead`/`AsyncWrite` поверх разделяемого
//! `ConnShared`. Данные пересекают границу через `std::sync::Mutex` (методы
//! `poll_*` синхронны, `.await` внутри них запрещён), пробуждение половинок —
//! через слоты `Option<Waker>`, пробуждение драйвера — через `tokio::sync::Notify`
//! (`notify_one()` хранит разрешение, если драйвер ещё не ждёт).

use std::{
    io,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll, Waker},
};

use tokio::{io::{AsyncRead, AsyncWrite, ReadBuf}, sync::Notify};

/// Backpressure перед cwnd/rwnd: выше этого уровня poll_write возвращает Pending.
pub(crate) const SEND_HIGH_WATER: usize = 2 * 65535;

/// Разделяемое состояние одного соединения между драйвером FSM и половинками.
pub(crate) struct ConnShared {
    // --- Приём: данные выгружены из FSM и ждут poll_read ---
    recv_buf: Vec<u8>,
    recv_waker: Option<Waker>,
    recv_eof: bool,

    // --- Передача: данные от poll_write ждут драйвера FSM ---
    send_buf: Vec<u8>,
    send_waker: Option<Waker>,
    send_shutdown: bool,
    fin_sent: bool,
}

impl ConnShared {
    fn new() -> Self {
        Self {
            recv_buf: Vec::new(),
            recv_waker: None,
            recv_eof: false,
            send_buf: Vec::new(),
            send_waker: None,
            send_shutdown: false,
            fin_sent: false,
        }
    }

    /// Кладёт принятые данные FSM и будит ждущего читателя.
    pub(crate) fn push_recv(&mut self, data: &[u8]) {
        self.recv_buf.extend_from_slice(data);

        if let Some(waker) = self.recv_waker.take() {
            waker.wake();
        }
    }

    /// Ставит EOF на read-половинку (FIN или RST от пира) и будит читателя.
    pub(crate) fn set_recv_eof(&mut self) {
        self.recv_eof = true;

        if let Some(waker) = self.recv_waker.take() {
            waker.wake();
        }
    }

    /// Забирает данные, накопленные poll_write, и будит ждущего писателя.
    pub(crate) fn take_send(&mut self) -> Vec<u8> {
        let data = std::mem::take(&mut self.send_buf);

        if let Some(waker) = self.send_waker.take() {
            waker.wake();
        }

        data
    }

    /// Shutdown запрошен, но FIN ещё не отправлен (для драйвера FSM).
    pub(crate) fn shutdown_pending(&self) -> bool {
        self.send_shutdown && !self.fin_sent
    }

    /// Отмечает фактическую отправку FIN и будит ждущий poll_shutdown.
    pub(crate) fn set_fin_sent(&mut self) {
        self.fin_sent = true;

        if let Some(waker) = self.send_waker.take() {
            waker.wake();
        }
    }
}

/// Создаёт разделяемое состояние и уведомитель драйвера для нового соединения.
pub(crate) fn new_conn_shared() -> (Arc<Mutex<ConnShared>>, Arc<Notify>) {
    (Arc::new(Mutex::new(ConnShared::new())), Arc::new(Notify::new()))
}

// --- Read-половинка ---

/// Клонирование допустимо: поля — Arc, при этом читатель один
/// (слот recv_waker общий, как и сам буфер).
#[derive(Clone)]
pub struct TcpRecvHalf {
    shared: Arc<Mutex<ConnShared>>,
    notify: Arc<Notify>,
}

impl TcpRecvHalf {
    pub(crate) fn new(shared: Arc<Mutex<ConnShared>>, notify: Arc<Notify>) -> Self {
        Self { shared, notify }
    }
}

impl AsyncRead for TcpRecvHalf {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let mut shared = self.shared.lock().unwrap();

        if shared.recv_buf.is_empty() {
            if shared.recv_eof {
                return Poll::Ready(Ok(()));
            }

            shared.recv_waker = Some(cx.waker().clone());

            return Poll::Pending;
        }

        let n = shared.recv_buf.len().min(buf.remaining());

        buf.initialize_unfilled_to(n)
            .copy_from_slice(&shared.recv_buf[..n]);
        buf.advance(n);
        shared.recv_buf.drain(..n);

        // Хук для будущего восстановления окна: драйвер узнаёт, что читатель
        // забрал данные (на текущую математику окна не влияет).
        self.notify.notify_one();

        Poll::Ready(Ok(()))
    }
}

// --- Write-половинка ---

/// Клонирование допустимо: поля — Arc, при этом писатель один
/// (слот send_waker общий, как и сам буфер).
#[derive(Clone)]
pub struct TcpSendHalf {
    shared: Arc<Mutex<ConnShared>>,
    notify: Arc<Notify>,
}

impl TcpSendHalf {
    pub(crate) fn new(shared: Arc<Mutex<ConnShared>>, notify: Arc<Notify>) -> Self {
        Self { shared, notify }
    }
}

impl AsyncWrite for TcpSendHalf {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut shared = self.shared.lock().unwrap();

        if shared.send_shutdown {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "поток закрыт (shutdown)",
            )));
        }

        // Backpressure: не принимаем данные сверх SEND_HIGH_WATER, иначе
        // память не ограничена и cwnd-логика обходится.
        if shared.send_buf.len() >= SEND_HIGH_WATER {
            shared.send_waker = Some(cx.waker().clone());

            return Poll::Pending;
        }

        shared.send_buf.extend_from_slice(buf);
        self.notify.notify_one();

        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut shared = self.shared.lock().unwrap();

        if shared.send_buf.is_empty() {
            return Poll::Ready(Ok(()));
        }

        shared.send_waker = Some(cx.waker().clone());

        Poll::Pending
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut shared = self.shared.lock().unwrap();

        // Запрашиваем закрытие: драйвер отправит FIN после осушения очереди
        shared.send_shutdown = true;
        self.notify.notify_one();

        if shared.fin_sent {
            return Poll::Ready(Ok(()));
        }

        // Ждём фактической отправки FIN (set_fin_sent будит)
        shared.send_waker = Some(cx.waker().clone());

        Poll::Pending
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

    #[tokio::test]
    async fn recv_half_reads_data_and_eof() {
        let (shared, _notify) = new_conn_shared();
        let recv = TcpRecvHalf::new(Arc::clone(&shared), Arc::new(Notify::new()));
        let mut pinned = std::pin::pin!(recv);

        let mut buf = [0u8; 16];
        let mut cx = Context::from_waker(Waker::noop());

        // Пока буфер пуст (не EOF), poll_read регистрирует waker и возвращает Pending.
        {
            let mut read_buf = ReadBuf::new(&mut buf);
            assert!(matches!(
                pinned.as_mut().poll_read(&mut cx, &mut read_buf),
                Poll::Pending
            ));
        }
        assert!(shared.lock().unwrap().recv_waker.is_some());

        // push_recv забирает waker (будит читателя) и кладёт данные.
        shared.lock().unwrap().push_recv(b"hello");
        assert!(shared.lock().unwrap().recv_waker.is_none());

        let mut read_buf = ReadBuf::new(&mut buf);
        assert!(matches!(
            pinned.as_mut().poll_read(&mut cx, &mut read_buf),
            Poll::Ready(Ok(()))
        ));
        assert_eq!(read_buf.filled(), b"hello");

        // После set_recv_eof и опустошения буфера poll_read = Ready(Ok(())) с 0 байт — EOF.
        shared.lock().unwrap().set_recv_eof();

        let mut read_buf = ReadBuf::new(&mut buf);
        assert!(matches!(
            pinned.as_mut().poll_read(&mut cx, &mut read_buf),
            Poll::Ready(Ok(()))
        ));
        assert_eq!(read_buf.filled().len(), 0);
    }

    #[tokio::test]
    async fn send_half_writes_and_notifies_driver() {
        let (shared, notify) = new_conn_shared();
        let mut send = TcpSendHalf::new(Arc::clone(&shared), Arc::clone(&notify));

        send.write_all(b"payload").await.unwrap();

        // Данные на месте; take_send будит ждущий flush.
        assert_eq!(shared.lock().unwrap().take_send(), b"payload");

        // Буфер пуст → flush завершается сразу.
        send.flush().await.unwrap();

        // notify_one сохранил разрешение — notified() срабатывает немедленно.
        notify.notified().await;
    }

    #[tokio::test]
    async fn send_half_backpressure_pends_above_high_water() {
        let (shared, _notify) = new_conn_shared();

        // Заполняем до high-water.
        {
            let mut shared = shared.lock().unwrap();
            shared.send_buf = vec![0u8; SEND_HIGH_WATER];
        }

        let send = TcpSendHalf::new(Arc::clone(&shared), Arc::new(Notify::new()));
        let mut pinned = std::pin::pin!(send);

        let pending = std::pin::pin!(std::future::poll_fn(|cx| {
            pinned.as_mut().poll_write(cx, b"data")
        }));

        let mut cx = Context::from_waker(Waker::noop());
        assert!(matches!(pending.poll(&mut cx), Poll::Pending));
        // Waker зарегистрирован до возврата Pending.
        assert!(shared.lock().unwrap().send_waker.is_some());

        // Осушение буфера драйвером будит писателя.
        shared.lock().unwrap().take_send();
    }

    #[tokio::test]
    async fn poll_read_on_empty_registers_waker_and_pends() {
        let (shared, _notify) = new_conn_shared();

        let recv = TcpRecvHalf::new(Arc::clone(&shared), Arc::new(Notify::new()));
        let mut pinned = std::pin::pin!(recv);

        let mut buf = [0u8; 4];
        let mut read_buf = ReadBuf::new(&mut buf);
        let mut cx = Context::from_waker(Waker::noop());

        // Пустой буфер, не EOF → Pending с зарегистрированным waker.
        assert!(matches!(
            pinned.as_mut().poll_read(&mut cx, &mut read_buf),
            Poll::Pending
        ));
        assert!(shared.lock().unwrap().recv_waker.is_some());
    }

    #[tokio::test]
    async fn shutdown_waits_for_fin_sent() {
        let (shared, _notify) = new_conn_shared();
        let mut send = TcpSendHalf::new(Arc::clone(&shared), Arc::new(Notify::new()));

        let sh = send.shutdown();
        let mut sh = std::pin::pin!(sh);

        // Драйвер (фейковый) ставит fin_sent после того, как shutdown выставил флаг
        for _ in 0..100 {
            if shared.lock().unwrap().send_shutdown {
                break;
            }
            tokio::task::yield_now().await;
        }

        // Пока FIN не отправлен — shutdown возвращает Pending
        let mut cx = Context::from_waker(Waker::noop());
        assert!(matches!(sh.as_mut().poll(&mut cx), Poll::Pending));

        // Драйвер отправил FIN → shutdown завершается
        shared.lock().unwrap().set_fin_sent();
        assert!(matches!(sh.as_mut().poll(&mut cx), Poll::Ready(Ok(()))));

        // Запись после shutdown — ошибка
        assert!(send.write_all(b"x").await.is_err());
    }
}
