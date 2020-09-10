use log::{debug, info, trace};
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;

use lazy_static::lazy_static;

use http::{StatusCode, uri::Uri};
use hyper::client::HttpConnector;
use hyper::header::{HeaderMap, HeaderName};
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Client, Request, Response, Server};
use hyper_tls::HttpsConnector;


use crate::consts::*;
use crate::errors::*;
use crate::{init_logger, ServeArgs};
use crate::aws::AwsTarget;

lazy_static! {
    static ref CLIENT: Client<HttpsConnector<HttpConnector>> = make_client();
}

fn make_client() -> Client<HttpsConnector<HttpConnector>, hyper::Body> {
    let https = HttpsConnector::new();
    Client::builder().build::<_, hyper::Body>(https)
}

pub(crate) async fn serve(args: &ServeArgs) -> Result<(), CliErrors> {
    init_logger(&args.logging_opts);

    // Construct our SocketAddr to listen on...
    let server_addr: SocketAddr = args.listen_address.parse().expect("Valid Socket Address");
    info!("Forwarding request to {}", args.destination);

    let aws_target = Arc::new(AwsTarget::new(&args.destination)?);
    debug!("aws_target: {:?}", aws_target);

    // And a MakeService to handle each connection...
    let make_service = make_service_fn(move |_| {
        let aws_target = aws_target.clone();
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
    aws_target: Arc<AwsTarget>,
    req: Request<Body>,
) -> Result<Response<Body>, Infallible> {
    trace!("Processing request for {:?}", req);

    let mut downstream_headers = make_downstream_headers(req.headers());
    trace!("Downstream Headers: {:?}", downstream_headers);

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
    let aws_headers = match crate::request::create_aws_headers(target_uri, method, aws_target).await {
        Some(headers) => headers,
        None => {
            return Ok(Response::builder().status(StatusCode::INTERNAL_SERVER_ERROR).body(Body::from("Unable to auth with AWS")).unwrap())
        }
    };

    for (key, value) in aws_headers.iter() {
        downstream_headers.insert(key, value.clone());
    }

    Ok(Response::new(Body::from("Hello World")))
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
