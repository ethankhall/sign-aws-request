use log::{info};
use std::sync::Arc;

use hyper::{Body, Request};

use http::{uri::Uri};
use hyper::Method;

use crate::aws::AwsTarget;
use crate::errors::*;
use crate::{init_logger, TestArgs};
use bytes::Bytes;

pub(crate) async fn test(args: &TestArgs) -> Result<(), CliErrors> {
    init_logger(&args.logging_opts);

    let target_uri: Uri = "https://vpc-cross-cluster-logging-maw5ztijt5whnc3fgewmm5ozzi.us-west-2.es.amazonaws.com/_plugin/kibana/bundles/kbn-ui-shared-deps/kbn-ui-shared-deps.@elastic.js".parse().unwrap();
    let aws_target = AwsTarget::new("https://vpc-cross-cluster-logging-maw5ztijt5whnc3fgewmm5ozzi.us-west-2.es.amazonaws.com").unwrap();

    let body = Bytes::new();
    let headers = crate::request::create_aws_headers(target_uri.clone(), Method::GET, Arc::new(aws_target), &body).await.unwrap();

    info!("headers: {:?}", headers);


    let mut builder = Request::builder().method(Method::GET).uri(target_uri);

    {
        let request_headers = builder.headers_mut().unwrap();
        for (key, value) in headers.iter() {
            request_headers.insert(key, value.clone());
        }
    }

    let downstream_request = builder.body(Body::from(body)).unwrap();

    info!("Downstream Request: {:?}", downstream_request);

    let response = crate::serve::CLIENT.request(downstream_request).await.unwrap();
    info!("Response Status: {:?}", response.status());
    info!("Response Headers: {:?}", response.headers());
    let full_body = hyper::body::to_bytes(response.into_body()).await.unwrap();
    info!("Response Body: {:?}", full_body);

    Ok(())
}