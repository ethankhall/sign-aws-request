use std::collections::BTreeSet;

use log::trace;

use http::{Method, Uri};
use hyper::header::{self, HeaderMap, HeaderValue};
use rusoto_credential::AwsCredentials;

use percent_encoding::utf8_percent_encode;
use time::OffsetDateTime;

use bytes::Bytes;
use hmac::{Hmac, Mac, NewMac};
use sha2::{Digest, Sha256};

use crate::consts::{ISO_8601_DATE, ISO_8601_DATETIME, STRICT_ENCODE_SET, STRICT_PATH_ENCODE_SET};

#[derive(Debug)]
pub struct Signer {
    service: String,
    region: String,
}

impl Signer {
    pub fn new(service: String, region: String) -> Self {
        Signer { service, region }
    }

    pub fn sign_request(
        &self,
        uri: &Uri,
        method: Method,
        body: &Bytes,
        creds: AwsCredentials,
    ) -> Option<HeaderMap> {
        let init = SigningInit::new(uri, method, body);
        let canonical_request = CanonicalRequest::from(&init);
        let unsigned_string = UnsignedString::from(&self.service, &self.region, &canonical_request);
        let signed = unsigned_string.sign(creds.aws_secret_access_key());

        let mut signed_headers = init.headers;
        signed_headers.insert(header::AUTHORIZATION, to_header_value(create_auth_header(&creds, canonical_request, unsigned_string, signed)));

        if let Some(token) = creds.token() {
            signed_headers.insert("x-amz-security-token", to_header_value(token.to_string()));
        }

        signed_headers.insert(
            "x-amz-content-sha256",
            to_header_value(init.payload_hash),
        );

        Some(signed_headers)
    }
}

fn create_auth_header(creds: &AwsCredentials, canonical_request: CanonicalRequest, unsigned: UnsignedString, signature: RequestSignature) -> String {
    format!(
        "AWS4-HMAC-SHA256 Credential={}/{}, SignedHeaders={}, Signature={}",
        creds.aws_access_key_id(),
        unsigned.scope,
        canonical_request.signed_headers,
        signature.token
    )
}

struct SigningInit {
    uri: Uri,
    method: Method,
    payload_hash: String,
    headers: HeaderMap,
    date: OffsetDateTime,
}

impl SigningInit {
    fn new(uri: &Uri, method: Method, body: &Bytes) -> Self {
        SigningInit::new_with_date(uri, method, body, OffsetDateTime::now_utc())
    }

    fn new_with_date(uri: &Uri, method: Method, body: &Bytes, date: OffsetDateTime) -> Self {
        let mut headers = HeaderMap::new();
        let uri = uri.clone();

        headers.insert(
            header::HOST,
            to_header_value(uri.host().unwrap().to_string()),
        );
        headers.insert(
            "x-amz-date",
            to_header_value(date.format(ISO_8601_DATETIME)),
        );

        SigningInit {
            uri,
            method,
            payload_hash: payload_hash(body),
            date,
            headers,
        }
    }
}

fn payload_hash(body: &Bytes) -> String {
    if body.is_empty() {
        String::from("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    } else {
        to_hexdigest(body)
    }
}

struct UnsignedString {
    service: String,
    region: String,
    string_to_sign: String,
    scope: String,
    date: OffsetDateTime,
}

impl UnsignedString {
    fn from(service: &str, region: &str, canonical_request: &CanonicalRequest) -> Self {
        let scope = format!(
            "{}/{}/{}/aws4_request",
            canonical_request.date.format(ISO_8601_DATE),
            region,
            service
        );

        let string_to_sign = format!(
            "AWS4-HMAC-SHA256\n{}\n{}\n{}",
            canonical_request.date.format(ISO_8601_DATETIME),
            scope,
            canonical_request.hash
        );

        UnsignedString {
            service: String::from(service),
            region: String::from(region),
            date: canonical_request.date,
            scope,
            string_to_sign,
        }
    }

    fn sign(&self, secres_access_key: &str) -> RequestSignature {
        let date_str = self.date.date().format("%Y%m%d");
        let date_hmac = hmac(
            format!("AWS4{}", secres_access_key).as_bytes(),
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
        let token = hex::encode(
            hmac(signing_hmac.as_ref(), self.string_to_sign.as_bytes())
                .finalize()
                .into_bytes(),
        );

        RequestSignature { token }
    }
}

struct RequestSignature {
    token: String,
}

struct CanonicalRequest {
    date: OffsetDateTime,
    hash: String,
    signed_headers: String,
}

impl CanonicalRequest {
    fn from(request: &SigningInit) -> Self {
        let mut header_list: Vec<String> = Vec::new();
        let mut signed_header_set: BTreeSet<String> = BTreeSet::new();

        for (key, value) in request.headers.iter() {
            header_list.push(format!("{}:{}", key, value.to_str().unwrap()));
            signed_header_set.insert(key.to_string());
        }

        header_list.sort();
        let mut signed_headers: Vec<String> = signed_header_set.into_iter().collect();
        signed_headers.sort();
        let signed_headers = signed_headers.join(";");

        let path = request.uri.path().to_string();
        let path: String = utf8_percent_encode(&path, &STRICT_PATH_ENCODE_SET).collect();
        let query = encode_query_string(&request.uri);

        let canonical_request = format!(
            "{}\n{}\n{}\n{}\n{}\n{}",
            request.method.as_str(),
            path,
            query,
            format!("{}\n", header_list.join("\n")),
            signed_headers,
            request.payload_hash
        );

        trace!("canonical_request: {}", canonical_request);
        let hash = to_hexdigest(&canonical_request);

        CanonicalRequest {
            hash,
            signed_headers,
            date: request.date,
        }
    }
}

#[cfg(test)]
fn init_test_logging() {
    let filter = log::LevelFilter::Info;
    // let filter = log::LevelFilter::Trace;
    let _ = env_logger::builder()
        .is_test(true)
        .filter_level(filter)
        .try_init();
}

#[cfg(test)]
fn make_aws_example_signing_init() -> SigningInit {
    let date = OffsetDateTime::from_unix_timestamp(1440938160);
    let uri = "https://iam.amazonaws.com/?Action=ListUsers&Version=2010-05-08"
        .parse()
        .unwrap();
    let body = Bytes::new();
    let mut siging_request = SigningInit::new_with_date(&uri, Method::GET, &body, date);
    siging_request.headers.insert(
        header::CONTENT_TYPE,
        to_header_value("application/x-www-form-urlencoded; charset=utf-8"),
    );
    siging_request
}

// Example taken from https://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html
#[test]
fn test_canonical_request() {
    init_test_logging();
    let siging_request = make_aws_example_signing_init();
    let canonical_request = CanonicalRequest::from(&siging_request);
    assert_eq!(
        "content-type;host;x-amz-date",
        canonical_request.signed_headers
    );
    assert_eq!(
        "f536975d06c0309214f805bb90ccff089219ecd68b2577efef23edd43b7e1a59",
        canonical_request.hash
    );
}

// Example taken from https://docs.aws.amazon.com/general/latest/gr/sigv4-create-string-to-sign.html
#[test]
fn test_create_string_to_sign() {
    init_test_logging();

    let expected = "AWS4-HMAC-SHA256
20150830T123600Z
20150830/us-east-1/iam/aws4_request
f536975d06c0309214f805bb90ccff089219ecd68b2577efef23edd43b7e1a59";

    let siging_request = make_aws_example_signing_init();
    let canonical_request = CanonicalRequest::from(&siging_request);
    let unsigned_string = UnsignedString::from("iam", "us-east-1", &canonical_request);

    assert_eq!(expected, unsigned_string.string_to_sign);
}

// Example taken from https://docs.aws.amazon.com/general/latest/gr/sigv4-calculate-signature.html
#[test]
fn test_creat_auth_token() {
    let example_secret = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
    let siging_request = make_aws_example_signing_init();
    let canonical_request = CanonicalRequest::from(&siging_request);
    let unsigned_string = UnsignedString::from("iam", "us-east-1", &canonical_request);
    let token = unsigned_string.sign(example_secret);

    assert_eq!(
        "5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7",
        token.token
    );
}

fn encode_query_string(uri: &Uri) -> String {
    let url = url::Url::parse(&uri.to_string()).unwrap();

    let mut params: Vec<String> = Vec::new();

    for (name, value) in url.query_pairs() {
        params.push(format!(
            "{}={}",
            encode_uri_strict(&name),
            encode_uri_strict(&value)
        ))
    }

    params.sort();
    params.join("&")
}

#[test]
fn test_encode_query_string() {
    assert_eq!(
        "",
        encode_query_string(&"http://localhost".parse().unwrap())
    );
    assert_eq!(
        "foo=bar",
        encode_query_string(&"http://localhost?foo=bar".parse().unwrap())
    );

    // both name and value are encoded
    assert_eq!(
        "%2Afoo=%2Abar",
        encode_query_string(&"http://localhost?*foo=*bar".parse().unwrap())
    );

    // ensure order
    assert_eq!(
        "%2Abar=%2Afoo&%2Afoo=%2Abar",
        encode_query_string(&"http://localhost?*foo=*bar&*bar=*foo".parse().unwrap())
    );

    // same key multiple times
    assert_eq!(
        "%2Afoo=%2Abar&%2Afoo=%2Afoo",
        encode_query_string(&"http://localhost?*foo=*bar&*foo=*foo".parse().unwrap())
    );
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
