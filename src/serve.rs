use log::{debug, error, info, trace};
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;

use lazy_static::lazy_static;

use bytes::Bytes;
use http::{uri::Uri, StatusCode};
use hyper::client::HttpConnector;
use hyper::header::{HeaderMap, HeaderName};
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Client, Method, Request, Response, Server};
use hyper_tls::HttpsConnector;

use crate::aws::AutomaticSigner;
use crate::consts::*;
use crate::errors::*;
use crate::{init_logger, ServeArgs};

lazy_static! {
    pub static ref CLIENT: Client<HttpsConnector<HttpConnector>> = make_client();
}

fn make_client() -> Client<HttpsConnector<HttpConnector>, hyper::Body> {
    let https = HttpsConnector::new();
    Client::builder().build::<_, hyper::Body>(https)
}

#[derive(Debug)]
struct ForwardTarget {
    target_url: String,
    signer: AutomaticSigner,
}

impl ForwardTarget {
    pub fn new(url: &str) -> Result<Self, ConfigErrors> {
        let captures = match AWS_URL_RE.captures(&url) {
            Some(capture) => capture,
            None => return Err(ConfigErrors::InvalidAwsTarget(url.to_string())),
        };

        let signer = AutomaticSigner::new(
            captures["service"].to_string(),
            captures["region"].to_string(),
        );

        Ok(ForwardTarget {
            signer,
            target_url: url.to_string(),
        })
    }

    pub async fn sign_request(&self, uri: &Uri, method: Method, body: &Bytes) -> Option<HeaderMap> {
        self.signer.sign_request(&uri, method.clone(), &body).await
    }
}

pub(crate) async fn serve(args: &ServeArgs) -> Result<(), CliErrors> {
    init_logger(&args.logging_opts);

    // Construct our SocketAddr to listen on...
    let server_addr: SocketAddr = args.listen_address.parse().expect("Valid Socket Address");
    info!("Listening on {}", server_addr);
    info!("Forwarding request to {}", args.destination);

    let request_signer = Arc::new(ForwardTarget::new(&args.destination)?);
    debug!("aws_target: {:?}", request_signer);

    // And a MakeService to handle each connection...
    let make_service = make_service_fn(move |_| {
        let aws_target = request_signer.clone();
        async move {
            let handle = move |req| process_request(aws_target.clone(), req);
            Ok::<_, Infallible>(service_fn(handle))
        }
    });

    let server = Server::bind(&server_addr).serve(make_service);
    let server = server.with_graceful_shutdown(shutdown_signal());

    // And run forever...
    match server.await {
        Err(e) => Err(CliErrors::Unknown(UnknownErrors::Unknown(e.to_string()))),
        Ok(_) => Ok(()),
    }
}

async fn shutdown_signal() {
    // Wait for the CTRL+C signal
    tokio::signal::ctrl_c()
        .await
        .expect("failed to install CTRL+C signal handler");
}

async fn process_request(
    aws_target: Arc<ForwardTarget>,
    req: Request<Body>,
) -> Result<Response<Body>, Infallible> {
    trace!("Processing request for {:?}", req);

    let mut downstream_headers = make_downstream_headers(req.headers());
    let path_and_query = req
        .uri()
        .path_and_query()
        .map(|x| x.as_str())
        .unwrap_or_else(|| "");

    let canonical_url = format!("{}{}", aws_target.target_url, path_and_query);
    let target_uri = canonical_url.parse::<Uri>().unwrap();

    debug!("AWS URL: {}", target_uri);

    let method = req.method().clone();
    let full_body = hyper::body::to_bytes(req.into_body()).await.unwrap();
    let aws_headers = match aws_target
        .sign_request(&target_uri, method.clone(), &full_body)
        .await
    {
        Some(headers) => headers,
        None => {
            return Ok(Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Body::from("Unable to auth with AWS"))
                .unwrap());
        }
    };

    for (key, value) in aws_headers.iter() {
        downstream_headers.insert(key, value.clone());
    }

    trace!("Downstream Headers: {:?}", downstream_headers);

    let mut builder = Request::builder().method(method).uri(target_uri);

    {
        let request_headers = builder.headers_mut().unwrap();
        for (key, value) in downstream_headers.iter() {
            request_headers.insert(key, value.clone());
        }
    }

    let downstream_request = match builder.body(Body::from(full_body)) {
        Ok(req) => req,
        Err(e) => {
            error!("Unable to create request: {}", e);
            return Ok(Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Body::from("Unable to create request"))
                .unwrap());
        }
    };

    let response = match CLIENT.request(downstream_request).await {
        Err(e) => {
            error!("Unable to execute downstream request: {}", e);
            return Ok(Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Body::from("Unable to execute downstream request"))
                .unwrap());
        }
        Ok(resp) => resp,
    };

    Ok(response)
}

fn make_downstream_headers(origonal_headers: &HeaderMap) -> HeaderMap {
    let mut new_headers = HeaderMap::new();

    for (name, value) in origonal_headers.iter() {
        if allow_header(&name) {
            new_headers.append(name, value.clone());
        }
    }

    new_headers
}

fn allow_header(header_name: &HeaderName) -> bool {
    for dropped in DROPPED_HEADERS.iter() {
        if header_name == dropped {
            return false;
        }
    }
    return true;
}
