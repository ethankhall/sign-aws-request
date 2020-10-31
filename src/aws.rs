use async_trait::async_trait;
use log::{error, debug};

use lazy_static::lazy_static;
use rusoto_credential::{
    AutoRefreshingProvider, AwsCredentials, CredentialsError, DefaultCredentialsProvider,
    ProvideAwsCredentials,
};
use rusoto_sts::WebIdentityProvider;

use crate::request::Signer;

use http::{Method, Uri};
use hyper::header::HeaderMap;

use bytes::Bytes;

lazy_static! {
    pub static ref CREDENTIALS: AwsCredentialProvider = AwsCredentialProvider::new();
}

pub struct AwsCredentialProvider {
    default_provider: DefaultCredentialsProvider,
    web_id_provider: AutoRefreshingProvider<WebIdentityProvider>,
}

impl AwsCredentialProvider {
    fn new() -> Self {
        AwsCredentialProvider {
            default_provider: DefaultCredentialsProvider::new().unwrap(),
            web_id_provider: AutoRefreshingProvider::new(WebIdentityProvider::from_k8s_env())
                .unwrap(),
        }
    }
}

#[async_trait]
impl ProvideAwsCredentials for AwsCredentialProvider {
    async fn credentials(&self) -> Result<AwsCredentials, CredentialsError> {
        match self.web_id_provider.credentials().await {
            Ok(creds) => {
                debug!("Using Web Identity Provider for creds");
                return Ok(creds);
            },
            Err(e) => {
                debug!("Unable to use Web Identity Provider to get creds: {}", e);
            }
        }

        debug!("Using Default Provider for creds");
        self.default_provider.credentials().await
    }
}

#[derive(Debug)]
pub struct AutomaticSigner {
    signer: Signer,
}

impl AutomaticSigner {
    pub fn new(service: String, region: String) -> Self {
        AutomaticSigner {
            signer: Signer::new(service, region),
        }
    }
    pub async fn sign_request(&self, uri: &Uri, method: Method, body: &Bytes) -> Option<HeaderMap> {
        let creds = match CREDENTIALS.credentials().await {
            Ok(creds) => creds,
            Err(e) => {
                error!("Unable to fetch credentials: {:?}", e);
                return None;
            }
        };

        self.signer.sign_request(uri, method, body, creds)
    }
}
