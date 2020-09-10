use std::collections::BTreeSet;
use std::sync::Arc;

use log::{error, trace};

use http::Uri;
use hyper::header::{self, HeaderMap, HeaderValue};
use hyper::Method;
use rusoto_credential::{ProvideAwsCredentials, AwsCredentials};

use time::{OffsetDateTime};

use hex;
use hmac::{Hmac, Mac, NewMac};
use sha2::{Digest, Sha256};

use crate::consts::*;
use crate::aws::{AwsTarget, CREDENTIALS};

pub(crate) async fn create_aws_headers(uri: Uri, method: Method, target: Arc<AwsTarget>) -> Option<HeaderMap> {
    let creds = match CREDENTIALS.credentials().await {
        Ok(creds) => creds,
        Err(e) => {
            error!("Unable to fetch credentials: {:?}", e);
            return None;
        }
    };

    let signer = RequestSigner::new(uri, method, creds, target);
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
}

struct CanonicalRequest {
    hash: String,
    signed_headers: String
}

impl RequestSigner {
    fn new(uri: Uri, method: Method, creds: AwsCredentials, target: Arc<AwsTarget>) -> Self {
        let host = uri.host().unwrap().to_string();
        let path = uri.path().to_string();
        let query = uri.query().map(|q| q.to_string()).unwrap_or_default();

        Self {
            host,
            path,
            query,
            method,
            creds,
            region: target.region.clone(),
            service: target.service.clone(),
            date: OffsetDateTime::now_utc(),
        }
    }

    pub fn create_signed_headers(&self) -> HeaderMap {
        let mut signed_headers = HeaderMap::new();

        signed_headers.insert(header::HOST, to_header_value(&self.host));
        signed_headers.insert(
            "x-amz-date",
            to_header_value(self.date.format("%Y%m%dT%H%M%SZ")),
        );

        if let Some(token) = self.creds.token() {
            signed_headers.insert("x-amz-security-token", to_header_value(token.to_string()));
        }

        let auth_header = self.create_auth_header(&signed_headers);

        signed_headers.insert(header::AUTHORIZATION, to_header_value(auth_header));
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
            &self.method,
            self.path,
            self.query,
            header_list.join("\n"),
            signed_headers,
            UNSIGNED_PAYLOAD
        );

        trace!(
            "canonical_request: {}",
            canonical_request.replace("\n", "\\n")
        );

        let hash = to_hexdigest(&canonical_request);

        CanonicalRequest {
            hash,
            signed_headers
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
    fn sign_string(
        &self,
        string_to_sign: &str
    ) -> String {
        let date_str = self.date.date().format("%Y%m%d");
        let date_hmac = hmac(format!("AWS4{}", self.creds.aws_secret_access_key()).as_bytes(), date_str.as_bytes())
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

fn to_hexdigest<T: AsRef<[u8]>>(t: T) -> String {
    let h = Sha256::digest(t.as_ref());
    hex::encode(h)
}

fn to_header_value<T: AsRef<str>>(value: T) -> HeaderValue {
    HeaderValue::from_str(value.as_ref()).unwrap()
}
