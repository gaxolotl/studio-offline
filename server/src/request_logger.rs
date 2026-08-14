use axum::{body::Body, extract::Request, http::Response};
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use tower::{Layer, Service};

#[derive(Clone)]
pub struct RequestLoggerLayer;

impl<S> Layer<S> for RequestLoggerLayer {
    type Service = RequestLogger<S>;

    fn layer(&self, inner: S) -> Self::Service {
        RequestLogger { inner }
    }
}

#[derive(Clone)]
pub struct RequestLogger<S> {
    inner: S,
}

impl<S> Service<Request<Body>> for RequestLogger<S>
where
    S: Service<Request<Body>, Response = Response<Body>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    S::Error: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<Body>) -> Self::Future {
        let mut inner = self.inner.clone();
        Box::pin(async move {
            let method = req.method().clone();
            let uri = req.uri().clone();
            let headers = req.headers().clone();

            let host = headers
                .get("host")
                .and_then(|h| h.to_str().ok())
                .unwrap_or("")
                .to_string();
            let content_type = headers
                .get("content-type")
                .and_then(|h| h.to_str().ok())
                .unwrap_or("")
                .to_string();
            let content_length = headers
                .get("content-length")
                .and_then(|h| h.to_str().ok())
                .unwrap_or("")
                .to_string();

            tracing::info!(
                ">>> {} {} host={} content-type={} content-length={}",
                method,
                uri,
                host,
                content_type,
                content_length
            );

            let start = std::time::Instant::now();
            let res = inner.call(req).await;
            if let Ok(r) = &res {
                tracing::info!(
                    "<<< {} {} status={} took={:?}",
                    method,
                    uri,
                    r.status().as_u16(),
                    start.elapsed()
                );
            }
            res
        })
    }
}