use async_trait::async_trait;

use rusoto_credential::{
    AutoRefreshingProvider, AwsCredentials, CredentialsError, DefaultCredentialsProvider,
    ProvideAwsCredentials,
};
use rusoto_sts::WebIdentityProvider;
use lazy_static::lazy_static;

use crate::errors::*;
use crate::consts::AWS_URL_RE;

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
        if let Ok(creds) = self.web_id_provider.credentials().await {
            return Ok(creds);
        }

        self.default_provider.credentials().await
    }
}

#[derive(Debug)]
pub(crate) struct AwsTarget {
    pub(crate) service: String,
    pub(crate) region: String,
    pub(crate) endpoint: String,
    pub(crate) target_url: String,
}

impl AwsTarget {
    pub fn new(url: &str) -> Result<Self, ConfigErrors> {
        let captures = match AWS_URL_RE.captures(&url) {
            Some(capture) => capture,
            None => return Err(ConfigErrors::InvalidAwsTarget(url.to_string())),
        };

        Ok(AwsTarget {
            endpoint: captures["endpoint"].to_string(),
            region: captures["region"].to_string(),
            service: captures["service"].to_string(),
            target_url: url.to_string(),
        })
    }
}