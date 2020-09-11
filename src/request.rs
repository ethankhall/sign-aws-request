use std::collections::BTreeSet;
use std::sync::Arc;

use log::{error, trace};

use http::Uri;
use hyper::header::{self, HeaderMap, HeaderValue};
use hyper::Method;
use rusoto_credential::{AwsCredentials, ProvideAwsCredentials};

use time::OffsetDateTime;
use percent_encoding::{utf8_percent_encode};

use hex;
use hmac::{Hmac, Mac, NewMac};
use sha2::{Digest, Sha256};
use bytes::Bytes;

use crate::aws::{AwsTarget, CREDENTIALS};
use crate::consts::{STRICT_PATH_ENCODE_SET, STRICT_ENCODE_SET};

pub(crate) async fn create_aws_headers(
    uri: Uri,
    method: Method,
    target: Arc<AwsTarget>,
    body: &Bytes
) -> Option<HeaderMap> {
    let creds = match CREDENTIALS.credentials().await {
        Ok(creds) => creds,
        Err(e) => {
            error!("Unable to fetch credentials: {:?}", e);
            return None;
        }
    };

    let payload_hash = if body.is_empty() {
        String::from("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    } else {
        to_hexdigest(body)
    };

    trace!("Payload Hash: {}", payload_hash);

    let signer = RequestSigner::new(uri, method, creds, target, payload_hash);
    Some(signer.create_signed_headers())
}

struct RequestSigner {
    host: String,
    path: String,
    query: String,
    region: String,
    service: String,
    method: Method,
    date: OffsetDateTime,
    creds: AwsCredentials,
    payload_hash: String,
}

struct CanonicalRequest {
    hash: String,
    signed_headers: String,
}

fn encode_query_string(uri: Uri) -> String {
    let url = url::Url::parse(&uri.to_string()).unwrap();

    let mut params: Vec<String> = Vec::new();

    for (name, value) in url.query_pairs() {
        params.push(format!("{}={}", encode_uri_strict(&name), encode_uri_strict(&value)))
    }

    params.sort();

    params.join("&")
}

impl RequestSigner {
    fn new(uri: Uri, method: Method, creds: AwsCredentials, target: Arc<AwsTarget>, payload_hash: String) -> Self {
        let host = uri.host().unwrap().to_string();
        let path = uri.path().to_string();
        // let query = uri.query().map(|q| q.to_string()).unwrap_or_default();
        let query = encode_query_string(uri);

        let path = utf8_percent_encode(&path, &STRICT_PATH_ENCODE_SET).collect();

        Self {
            host,
            path,
            query,
            method,
            creds,
            region: target.region.clone(),
            service: target.service.clone(),
            payload_hash,
            date: OffsetDateTime::now_utc(),
            // date: OffsetDateTime::from_unix_timestamp(1599758038)
        }
    }

    pub fn create_signed_headers(&self) -> HeaderMap {
        let mut signed_headers = HeaderMap::new();

        signed_headers.insert(header::HOST, to_header_value(&self.host));
        signed_headers.insert(
            "x-amz-date",
            to_header_value(self.date.format("%Y%m%dT%H%M%SZ")),
        );

        let auth_header = self.create_auth_header(&signed_headers);

        signed_headers.insert(header::AUTHORIZATION, to_header_value(auth_header));

        if let Some(token) = self.creds.token() {
            signed_headers.insert("x-amz-security-token", to_header_value(token.to_string()));
        }

        signed_headers.insert("x-amz-content-sha256", to_header_value(self.payload_hash.clone()));

        signed_headers
    }

    fn create_auth_header(&self, header_map: &HeaderMap) -> String {
        let canonical_request = self.create_canonical_request(header_map);

        let scope = format!(
            "{}/{}/{}/aws4_request",
            self.date.format("%Y%m%d"),
            &self.region,
            &self.service
        );
        let string_to_sign = self.string_to_sign(&canonical_request.hash, &scope);
        // sign the string
        let signature = self.sign_string(&string_to_sign);

        format!(
            "AWS4-HMAC-SHA256 Credential={}/{}, SignedHeaders={}, Signature={}",
            self.creds.aws_access_key_id(),
            scope,
            canonical_request.signed_headers,
            signature
        )
    }

    fn create_canonical_request(&self, header_map: &HeaderMap) -> CanonicalRequest {
        let mut header_list: Vec<String> = Vec::new();
        let mut signed_header_set: BTreeSet<String> = BTreeSet::new();
        for (key, value) in header_map.iter() {
            header_list.push(format!("{}:{}", key, value.to_str().unwrap()));
            signed_header_set.insert(key.to_string());
        }

        header_list.sort();
        let mut signed_headers: Vec<String> = signed_header_set.into_iter().collect();
        signed_headers.sort();
        let signed_headers = signed_headers.join(";");

        let canonical_request = format!(
            "{}\n{}\n{}\n{}\n{}\n{}",
            self.method.as_str(),
            self.path,
            self.query,
            format!("{}\n", header_list.join("\n")),
            signed_headers,
            self.payload_hash,
        );

        trace!(
            "canonical_request: {}",
            canonical_request
        );

        let hash = to_hexdigest(&canonical_request);

        CanonicalRequest {
            hash,
            signed_headers,
        }
    }

    /// Mark string as AWS4-HMAC-SHA256 hashed
    fn string_to_sign(&self, hashed_canonical_request: &str, scope: &str) -> String {
        format!(
            "AWS4-HMAC-SHA256\n{}\n{}\n{}",
            self.date.format("%Y%m%dT%H%M%SZ"),
            scope,
            hashed_canonical_request
        )
    }

    /// Takes a message and signs it using AWS secret, time, region keys and service keys.
    fn sign_string(&self, string_to_sign: &str) -> String {
        let date_str = self.date.date().format("%Y%m%d");
        let date_hmac = hmac(
            format!("AWS4{}", self.creds.aws_secret_access_key()).as_bytes(),
            date_str.as_bytes(),
        )
        .finalize()
        .into_bytes();
        let region_hmac = hmac(date_hmac.as_ref(), self.region.as_bytes())
            .finalize()
            .into_bytes();
        let service_hmac = hmac(region_hmac.as_ref(), self.service.as_bytes())
            .finalize()
            .into_bytes();
        let signing_hmac = hmac(service_hmac.as_ref(), b"aws4_request")
            .finalize()
            .into_bytes();
        hex::encode(
            hmac(signing_hmac.as_ref(), string_to_sign.as_bytes())
                .finalize()
                .into_bytes(),
        )
    }
}

#[inline]
fn hmac(secret: &[u8], message: &[u8]) -> Hmac<Sha256> {
    let mut hmac = Hmac::<Sha256>::new_varkey(secret).expect("failed to create hmac");
    hmac.update(message);
    hmac
}

#[inline]
fn encode_uri_strict(uri: &str) -> String {
    utf8_percent_encode(uri, &STRICT_ENCODE_SET).collect::<String>()
}

fn to_hexdigest<T: AsRef<[u8]>>(t: T) -> String {
    let h = Sha256::digest(t.as_ref());
    hex::encode(h)
}

fn to_header_value<T: AsRef<str>>(value: T) -> HeaderValue {
    HeaderValue::from_str(value.as_ref()).unwrap()
}