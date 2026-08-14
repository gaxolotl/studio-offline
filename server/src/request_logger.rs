use axum::{
    body::{to_bytes, Body},
    extract::Request,
    http::Response,
};
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
            let (parts, body) = req.into_parts();

            let bytes = match to_bytes(body, 8 * 1024 * 1024).await {
                Ok(b) => b,
                Err(e) => {
                    tracing::error!("failed to read request body: {e}");
                    return inner.call(Request::from_parts(parts, Body::empty())).await;
                }
            };

            let body_text = String::from_utf8_lossy(&bytes);
            tracing::info!(
                ">>> {} {} body_len={} body={}",
                method,
                uri,
                bytes.len(),
                truncate(&body_text, 4000)
            );

            let req = Request::from_parts(parts, Body::from(bytes));
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

fn truncate(s: &str, max: usize) -> String {
    let chars: Vec<char> = s.chars().collect();
    if chars.len() <= max {
        s.to_string()
    } else {
        let mut out: String = chars[..max].iter().collect();
        out.push_str("... [truncated]");
        out
    }
}