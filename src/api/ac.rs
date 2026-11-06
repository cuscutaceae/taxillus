use std::iter;

use chrono::Utc;

use crate::env::Config;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use hmac::{Hmac, KeyInit, Mac};
use sha1::{Digest, Sha1};

pub struct ACHeaders {
    pub app_id: String,
    pub api_ver: String,
    pub sdk_ver: String,
    pub enc_ver: String,
    pub enc_kid: String,
    pub timestamp: String,
    pub nonce: String,
    pub device_name: String,
    pub device_id: String,
    pub sys_ver: String,
    pub lang: String,
    pub sign: String,
}

#[derive(Debug, thiserror::Error)]
pub enum GenerateSignatureError {
    #[error("app id too short: actual: {actual}, required: {required}")]
    AppIdTooShort { actual: usize, required: usize },
    #[error("invalid hmac key length")]
    InvalidHmacKeyLength,
}

#[must_use]
pub fn generate_device_id(device_name: &str) -> String {
    hex::encode(&sha2::Sha256::digest(device_name.as_bytes()).to_vec()[0..8])
}

impl ACHeaders {
    /// # Errors
    /// 见[`GenerateSignatureError`]
    pub fn new_hash_device_id(
        config: &Config,
        device_name: &str,
        encrypted_content: Option<&str>,
    ) -> Result<Self, GenerateSignatureError> {
        let device_id = generate_device_id(device_name);
        Self::new(config, device_name, &device_id, encrypted_content)
    }

    /// # Errors
    /// 见[`GenerateSignatureError`]
    pub fn new(
        config: &Config,
        device_name: &str,
        device_id: &str,
        encrypted_content: Option<&str>,
    ) -> Result<Self, GenerateSignatureError> {
        let timestamp = Utc::now().timestamp_millis().to_string();
        let nonce = random_string();
        let sign = generate_signature(
            encrypted_content.unwrap_or_default(),
            &config.ac_app_id,
            &config.ac_api_ver,
            &config.ac_sdk_ver,
            &nonce,
            &timestamp,
            config.ac_h_key.as_deref(),
        )?;
        Ok(Self {
            app_id: config.ac_app_id.clone(),
            api_ver: config.ac_api_ver.clone(),
            sdk_ver: config.ac_sdk_ver.clone(),
            enc_ver: config.ac_enc_ver.clone(),
            enc_kid: config.ac_enc_kid.clone(),
            sys_ver: config.ac_sys_ver.clone(),
            lang: config.ac_lang.clone(),
            timestamp,
            nonce,
            device_name: device_name.to_string(),
            device_id: device_id.to_string(),
            sign,
        })
    }
}

type HmacSha1 = Hmac<Sha1>;

fn random_string() -> String {
    let available_char = [
        'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r',
        's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
    ];
    iter::from_fn(|| Some(available_char[rand::random_range(0..available_char.len())]))
        .take(12)
        .collect()
}

fn generate_signature(
    encrypted_content: &str,
    app_id: &str,
    api_ver: &str,
    sdk_ver: &str,
    nonce: &str,
    timestamp: &str,
    h_key: Option<&[u8]>,
) -> Result<String, GenerateSignatureError> {
    let full = format!("{encrypted_content}{app_id}{api_ver}{sdk_ver}{nonce}{timestamp}");
    let encoded = STANDARD.encode(full.as_bytes());
    let fallback_key;
    let key: &[u8] = if let Some(key) = h_key {
        key
    } else {
        let bytes = app_id.as_bytes();
        if bytes.len() < 16 {
            return Err(GenerateSignatureError::AppIdTooShort {
                actual: bytes.len(),
                required: 16,
            });
        }
        fallback_key = &bytes[..16];
        fallback_key
    };
    let mut mac =
        HmacSha1::new_from_slice(key).map_err(|_| GenerateSignatureError::InvalidHmacKeyLength)?;
    mac.update(encoded.as_bytes());
    let hmac_bytes = mac.finalize().into_bytes();
    let hmac_hex = hex::encode(hmac_bytes);
    let digest = md5::compute(hmac_hex.as_bytes());
    Ok(hex::encode(digest.0))
}
