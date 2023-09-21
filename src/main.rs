use hyper::client::HttpConnector;
use hyper::{Body, Client};
use hyper_tls::HttpsConnector;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

#[derive(Clone)]
struct CORSProxy(Arc<Client<HttpsConnector<HttpConnector>>>);

impl tower::Service<hyper::Request<Body>> for CORSProxy {
    type Response = hyper::Response<Body>;
    type Error = hyper::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send + Sync>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, mut req: hyper::Request<Body>) -> Self::Future {
        let client = self.0.clone();
        Box::pin(async move {
            *req.uri_mut() = dbg!(req.uri().path().strip_prefix('/').unwrap().parse().unwrap());
            let host = req.uri().host().unwrap().to_owned();
            // set the host header
            req.headers_mut().append("host", host.parse().unwrap());

            let req_origin = req
                .headers()
                .get("Origin")
                .and_then(|v| v.to_str().ok())
                .map(String::from);

            println!("{:?}", req_origin);
            let proxy_res = client.request(req).await.unwrap();

            println!("got");

            let mut res = hyper::Response::new(Body::empty());
            // forwards the headers
            *res.headers_mut() = proxy_res.headers().clone();
            *res.status_mut() = proxy_res.status();

            *res.body_mut() = hyper::body::to_bytes(proxy_res).await.unwrap().into();

            // add CORS headers (Access-Control-Allow-Origin, Access-Control-Allow-Methods, Access-Control-Allow-Headers, Access-Control-Allow-Credentials)
            res.headers_mut().insert(
                "Access-Control-Allow-Origin",
                req_origin
                    .unwrap_or_else(|| String::from("*"))
                    .parse()
                    .unwrap(),
            );
            res.headers_mut().insert(
                "Access-Control-Allow-Methods",
                "GET, POST, OPTIONS".parse().unwrap(),
            );
            res.headers_mut().insert(
                "Access-Control-Allow-Headers",
                "Content-Type, *".parse().unwrap(),
            );
            res.headers_mut()
                .insert("Access-Control-Allow-Credentials", "true".parse().unwrap());

            println!("{:?}", res);

            Ok(res)
        })
    }
}

#[shuttle_runtime::main]
async fn tower() -> shuttle_tower::ShuttleTower<CORSProxy> {
    let service = CORSProxy(Arc::new(
        Client::builder().build::<_, hyper::Body>(HttpsConnector::new()),
    ));

    Ok(service.into())
}
