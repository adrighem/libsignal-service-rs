use futures::{channel::oneshot, prelude::*};
use prost::Message;

pub use crate::{
    configuration::ServiceCredentials,
    proto::{
        web_socket_message, Envelope, WebSocketMessage,
        WebSocketRequestMessage, WebSocketResponseMessage,
    },
};

use crate::{
    push_service::ServiceError,
    websocket::{self, SignalRequestStream, SignalWebSocket},
};

#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum Incoming {
    Envelope(Envelope),
    QueueEmpty,
}

pub struct MessagePipe {
    ws: SignalWebSocket<websocket::Identified>,
}

impl MessagePipe {
    pub fn from_socket(ws: SignalWebSocket<websocket::Identified>) -> Self {
        MessagePipe { ws }
    }

    /// Return a SignalWebSocket for sending messages and other purposes beyond receiving messages.
    pub fn ws(&self) -> SignalWebSocket<websocket::Identified> {
        self.ws.clone()
    }

    /// Returns the stream of `Envelope`s
    ///
    /// Envelopes yielded are acknowledged *after* the stream consumer polls again,
    /// ensuring that the message was fully processed and persisted before acknowledging.
    pub fn stream(self) -> impl Stream<Item = Result<Incoming, ServiceError>> {
        futures::stream::unfold(
            (self.ws, None, None),
            |(mut ws, mut stream_opt, mut pending_ack): (
                SignalWebSocket<websocket::Identified>,
                Option<SignalRequestStream>,
                Option<(
                    oneshot::Sender<WebSocketResponseMessage>,
                    WebSocketResponseMessage,
                )>,
            )| async move {
                let mut stream = match stream_opt.take() {
                    Some(s) => s,
                    None => ws
                        .take_request_stream()
                        .expect("web socket request handler not in use"),
                };

                // If the stream was polled again, the caller has finished processing
                // the previous item. We can now safely ACK that previous envelope.
                if let Some((responder, response)) = pending_ack.take() {
                    if responder.send(response).is_err() {
                        ws.return_request_stream(stream);
                        return Some((
                            Err(ServiceError::WsClosing {
                                reason:
                                    "could not respond to message pipe request",
                            }),
                            (ws, None, None),
                        ));
                    }
                }

                while let Some((request, responder)) = stream.next().await {
                    let response =
                        WebSocketResponseMessage::from_request(&request);

                    if request.is_signal_service_envelope() {
                        let Some(body) = request.body.as_ref() else {
                            return Some((
                                Err(ServiceError::InvalidFrame {
                                    reason: "request without body.",
                                }),
                                (ws, Some(stream), None),
                            ));
                        };
                        match Envelope::decode(body.as_slice()) {
                            Ok(envelope) => {
                                // Defer ACK until the consumer polls for the next item.
                                pending_ack = Some((responder, response));
                                return Some((
                                    Ok(Incoming::Envelope(envelope)),
                                    (ws, Some(stream), pending_ack),
                                ));
                            },
                            Err(e) => {
                                return Some((
                                    Err(e.into()),
                                    (ws, Some(stream), None),
                                ));
                            },
                        }
                    } else if request.is_queue_empty() {
                        if responder.send(response).is_err() {
                            ws.return_request_stream(stream);
                            return Some((
                                Err(ServiceError::WsClosing {
                                    reason: "could not respond to message pipe request",
                                }),
                                (ws, None, None),
                            ));
                        }
                        return Some((
                            Ok(Incoming::QueueEmpty),
                            (ws, Some(stream), None),
                        ));
                    } else {
                        tracing::trace!("got empty message in websocket");
                        if responder.send(response).is_err() {
                            ws.return_request_stream(stream);
                            return Some((
                                Err(ServiceError::WsClosing {
                                    reason: "could not respond to message pipe request",
                                }),
                                (ws, None, None),
                            ));
                        }
                    }
                }

                ws.return_request_stream(stream);
                None
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::Envelope;

    #[tokio::test]
    async fn deferred_envelope_ack_waits_until_next_poll() {
        let (mut tx, rx) = futures::channel::mpsc::unbounded::<(
            WebSocketRequestMessage,
            oneshot::Sender<WebSocketResponseMessage>,
        )>();

        let mut pipe_stream = Box::pin(futures::stream::unfold(
            (rx, None),
            |(mut stream, mut pending_ack): (
                _,
                Option<(
                    oneshot::Sender<WebSocketResponseMessage>,
                    WebSocketResponseMessage,
                )>,
            )| async move {
                if let Some((responder, response)) = pending_ack.take() {
                    responder.send(response).unwrap();
                }
                while let Some((request, responder)) = stream.next().await {
                    let response =
                        WebSocketResponseMessage::from_request(&request);
                    if request.is_signal_service_envelope() {
                        let body = request.body.as_ref().unwrap();
                        let envelope =
                            Envelope::decode(body.as_slice()).unwrap();
                        pending_ack = Some((responder, response));
                        return Some((
                            Incoming::Envelope(envelope),
                            (stream, pending_ack),
                        ));
                    } else if request.is_queue_empty() {
                        responder.send(response).unwrap();
                        return Some((
                            Incoming::QueueEmpty,
                            (stream, None),
                        ));
                    }
                }
                None
            },
        ));

        let env = Envelope::default();
        let req1 = WebSocketRequestMessage {
            verb: Some("PUT".into()),
            path: Some("/api/v1/message".into()),
            body: Some(env.encode_to_vec()),
            headers: vec![],
            id: Some(1),
        };
        let (ack_tx1, mut ack_rx1) = oneshot::channel();
        tx.send((req1, ack_tx1)).await.unwrap();

        let req2 = WebSocketRequestMessage {
            verb: Some("PUT".into()),
            path: Some("/api/v1/queue/empty".into()),
            body: None,
            headers: vec![],
            id: Some(2),
        };
        let (ack_tx2, mut ack_rx2) = oneshot::channel();
        tx.send((req2, ack_tx2)).await.unwrap();

        // First poll yields Envelope(1), but must NOT have sent ack_rx1 yet!
        let item1 = pipe_stream.next().await.unwrap();
        assert!(matches!(item1, Incoming::Envelope(_)));
        assert!(
            ack_rx1.try_recv().unwrap().is_none(),
            "envelope must not be ACKed before caller finishes processing and polls next"
        );

        // Second poll ACKs Envelope(1) and yields QueueEmpty (which ACKs immediately).
        let item2 = pipe_stream.next().await.unwrap();
        assert!(matches!(item2, Incoming::QueueEmpty));
        let resp1 = ack_rx1.await.expect("envelope 1 should now be ACKed");
        assert_eq!(resp1.id, Some(1));
        let resp2 = ack_rx2
            .await
            .expect("queue empty should be ACKed immediately");
        assert_eq!(resp2.id, Some(2));
    }
}
