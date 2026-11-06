use std::sync::OnceLock;

use reqwest::{Client, ClientBuilder, RequestBuilder, header};
use serde::{Deserialize, Serialize, de::DeserializeOwned};

use crate::{
    api::{
        ac::{ACHeaders, GenerateSignatureError},
        enc::{self, EncryptedAccountBody, FromAccountApiEncryption, IntoAccountApiEncryption},
    },
    env::Config,
};

static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("reqwest error: {0}")]
    Reqwest(#[from] reqwest::Error),
    #[error("serde_json error: {0}")]
    SerdeJson(#[from] serde_json::Error),
    #[error("encrypt error: {0}")]
    Encrypt(#[from] enc::Error),
    #[error("generate signature: {0}")]
    GenerateSignature(#[from] GenerateSignatureError),
}

#[derive(Debug, Clone)]
pub struct GeneralArgs {
    pub device_name: String,
}

fn get_client() -> &'static Client {
    CLIENT.get_or_init(|| {
        let mut headers = header::HeaderMap::new();
        headers.insert(
            header::USER_AGENT,
            header::HeaderValue::from_static("okhttp/4.10.0"),
        );
        ClientBuilder::new()
            .default_headers(headers)
            .build()
            .expect("should success")
    })
}

#[derive(Debug, Serialize)]
pub struct SmsLoginArgs {
    pub mobile: String,
    pub client_id: String,
    pub pack_key: String,
    pub mobile_check: String,
}

#[derive(Debug, Deserialize)]
pub struct SmsLoginResult {
    pub errno: i64,
    #[serde(rename = "errinfo")]
    pub error_info: String,
}

/// # Errors
/// 见[`Error`]
pub async fn sms_login(
    config: &Config,
    args: SmsLoginArgs,
    general_args: GeneralArgs,
) -> Result<SmsLoginResult, Error> {
    account_api_call(
        config,
        |it| {
            it.post(format!(
                "{}{}",
                config.api_account_prefix, config.api_account_sms_login
            ))
        },
        args,
        general_args,
    )
    .await
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OauthTokenArgs {
    pub principal: String,
    pub client_id: String,
    pub pack_key: String,
    pub r#type: String,
    pub auto_register: String,
    pub identity: String,
}

#[derive(Debug, Deserialize)]
pub struct OauthTokenResultData {
    pub access_token: String,
    pub app_session: String,
    pub expire_in: i64,
}

#[derive(Debug, Deserialize)]
pub struct OauthTokenResult {
    pub errno: i64,
    #[serde(rename = "errinfo")]
    pub error_info: String,
    pub data: OauthTokenResultData,
}

/// # Errors
/// 见[`Error`]
pub async fn oauth_token(
    config: &Config,
    args: OauthTokenArgs,
    general_args: GeneralArgs,
) -> Result<OauthTokenResult, Error> {
    account_api_call(
        config,
        |it| {
            it.post(format!(
                "{}{}",
                config.api_account_prefix, config.api_account_oauth_token
            ))
        },
        args,
        general_args,
    )
    .await
}

async fn account_api_call<T, R, F>(
    config: &Config,
    url: F,
    args: T,
    general_args: GeneralArgs,
) -> Result<R, Error>
where
    T: Serialize,
    R: DeserializeOwned,
    F: FnOnce(&Client) -> RequestBuilder,
{
    Ok(url(get_client())
        .attach_encrypt_json_and_ac_headers(args, config, &general_args.device_name)?
        .send()
        .await?
        .error_for_status()?
        .json::<EncryptedAccountBody>()
        .await?
        .account_api_decrypt::<R>(&config.encrypt_account_key)?)
}

trait AccountApiTrait {
    fn attach_ac_headers(self, ac_headers: ACHeaders) -> Self;

    fn attach_encrypt_json_and_ac_headers<T>(
        self,
        t: T,
        config: &Config,
        device_name: &str,
    ) -> Result<Self, Error>
    where
        Self: Sized,
        T: Serialize + Sized;
}

impl AccountApiTrait for RequestBuilder {
    fn attach_ac_headers(self, ac_headers: ACHeaders) -> Self {
        self.header("x-ac-app-id", ac_headers.app_id)
            .header("x-ac-api-ver", ac_headers.api_ver)
            .header("x-ac-sdk-ver", ac_headers.sdk_ver)
            .header("x-ac-enc-ver", ac_headers.enc_ver)
            .header("x-ac-enc-kid", ac_headers.enc_kid)
            .header("x-ac-timestamp", ac_headers.timestamp)
            .header("x-ac-nonce", ac_headers.nonce)
            .header("x-ac-device-name", ac_headers.device_name)
            .header("x-ac-device-id", ac_headers.device_id)
            .header("x-ac-sys-ver", ac_headers.sys_ver)
            .header("x-ac-lang", ac_headers.lang)
            .header("x-ac-sign", ac_headers.sign)
    }

    fn attach_encrypt_json_and_ac_headers<T>(
        self,
        t: T,
        config: &Config,
        device_name: &str,
    ) -> Result<Self, Error>
    where
        Self: Sized,
        T: Serialize + Sized,
    {
        let encrypted_base64 = t.account_api_encrypt(&config.encrypt_account_key)?;
        let ac_headers =
            ACHeaders::new_hash_device_id(config, device_name, Some(&encrypted_base64))?;
        Ok(self.body(encrypted_base64).attach_ac_headers(ac_headers))
    }
}
