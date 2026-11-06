use std::{iter, sync::OnceLock};

use rand::{RngExt, SeedableRng, rngs::StdRng};
use reqwest::{Client, ClientBuilder, RequestBuilder, header};
use serde::{Deserialize, Serialize, Serializer, de::DeserializeOwned};
use sha1::Digest;

use crate::{
    api::enc::{self, EncryptedGameBody, FromGameApiEncryption, IntoGameApiEncryption},
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
}

#[derive(Debug, Clone)]
pub struct GeneralArgs {
    /// For `FX_TOKEN`
    device_name: String,
}

impl GeneralArgs {
    #[must_use]
    pub fn new_from_device_model_name(device_name: &str) -> Self {
        let mut rnd = StdRng::from_seed(sha2::Sha256::digest(device_name.as_bytes()).into());
        let available_char = [
            'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q',
            'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7',
            '8', '9',
        ];
        Self {
            device_name: iter::from_fn(|| {
                Some(available_char[rnd.random_range(0..available_char.len())])
            })
            .take(16)
            .collect(),
        }
    }
}

fn get_client() -> &'static Client {
    CLIENT.get_or_init(|| {
        let mut headers = header::HeaderMap::new();
        headers.insert(
            header::USER_AGENT,
            header::HeaderValue::from_static(
                "UnityPlayer/6000.0.66f2 (UnityWebRequest/1.0, libcurl/8.10.1-DEV)",
            ),
        );
        ClientBuilder::new()
            .default_headers(headers)
            .build()
            .expect("should success")
    })
}

fn serialize_as_json_string<S, T>(value: &T, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
    T: Serialize,
{
    let s = serde_json::to_string(value).map_err(serde::ser::Error::custom)?;
    serializer.serialize_str(&s)
}

#[derive(Debug, Serialize)]
pub struct LoginArgs {
    #[serde(rename = "_version")]
    pub version_alt: String,
    #[serde(rename = "_platform")]
    pub platform_alt: String,
    pub pid: String,
    pub hardware: String,
    pub channel: String,
    #[serde(serialize_with = "serialize_as_json_string")]
    pub channel_info: LoginArgsChannelInfo,
    pub platform: String,
}

#[derive(Debug, Serialize)]
pub struct LoginArgsChannelInfo {
    pub session: String,
}

#[derive(Debug, Deserialize)]
pub struct LoginResult {
    pub channel_detail: LoginResultChannelDetail,
    pub user_detail: LoginResultUserDetail,
}

#[derive(Debug, Deserialize)]
pub struct LoginResultChannelDetail {
    pub phone: String,
    pub name: String,
    pub nickname: String,
    pub apple_sub: String,
    pub id: String,
    pub r#type: i64,
    pub email: String,
    pub real_uid: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LoginResultUserDetail {
    pub session: String,
    pub channel_uid: String,
    pub user_id: String,
    #[serde(rename = "channel_username")]
    pub channel_username: String,
    pub last_login_time: i64,
}

/// # Errors
/// 见[`Error`]
pub async fn login(
    config: &Config,
    args: LoginArgs,
    general_args: GeneralArgs,
) -> Result<LoginResult, Error> {
    game_api_call(
        config,
        |it| {
            it.post(format!(
                "{}{}",
                config.api_game_prefix, config.api_game_login
            ))
        },
        args,
        general_args,
    )
    .await
}

#[derive(Debug, Serialize)]
pub struct SyncArgs {
    #[serde(rename = "_version")]
    pub version_alt: String,
    #[serde(rename = "_platform")]
    pub platform_alt: String,
    pub channel: String,
    pub session: String,
}

/// # Errors
/// 见[`Error`]
pub async fn sync(
    config: &Config,
    args: SyncArgs,
    general_args: GeneralArgs,
) -> Result<String, Error> {
    game_api_call_raw(
        config,
        |it| {
            it.post(format!(
                "{}{}",
                config.api_game_prefix, config.api_game_sync
            ))
        },
        args,
        general_args,
    )
    .await
}

async fn game_api_call<T, R, F>(
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
        .attach_headers(config, &general_args.device_name)
        .attach_encrypt_json(args, config)?
        .send()
        .await?
        .error_for_status()?
        .json::<EncryptedGameBody>()
        .await?
        .game_api_decrypt::<R>(&config.encrypt_game_key, &config.encrypt_game_iv)?)
}

async fn game_api_call_raw<T, F>(
    config: &Config,
    url: F,
    args: T,
    general_args: GeneralArgs,
) -> Result<String, Error>
where
    T: Serialize,
    F: FnOnce(&Client) -> RequestBuilder,
{
    Ok(url(get_client())
        .attach_headers(config, &general_args.device_name)
        .attach_encrypt_json(args, config)?
        .send()
        .await?
        .error_for_status()?
        .json::<EncryptedGameBody>()
        .await?
        .game_api_decrypt_raw(&config.encrypt_game_key, &config.encrypt_game_iv)?)
}

trait GameApiTrait {
    fn attach_headers(self, config: &Config, device_name: &str) -> Self;

    fn attach_encrypt_json<T>(self, t: T, config: &Config) -> Result<Self, Error>
    where
        Self: Sized,
        T: Serialize + Sized;
}

impl GameApiTrait for RequestBuilder {
    fn attach_encrypt_json<T>(self, t: T, config: &Config) -> Result<Self, Error>
    where
        Self: Sized,
        T: Serialize + Sized,
    {
        let encrypted_base64 =
            t.game_api_encrypt(&config.encrypt_game_key, &config.encrypt_game_iv)?;
        Ok(self.body(encrypted_base64))
    }

    fn attach_headers(self, config: &Config, device_name: &str) -> Self {
        self.header("VERSION", config.game_header_version.clone())
            .header("CLEARANCE", config.game_header_clearance.clone())
            .header("ADCHANNEL", config.game_header_ad_channel.clone())
            .header("FXTOKEN", format!("deviceId_{device_name}"))
            .header("PACKID", config.game_header_pack_id.clone())
            .header("X-Unity-Version", config.game_header_unity_version.clone())
    }
}
