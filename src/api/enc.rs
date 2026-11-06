use std::string::FromUtf8Error;

use aes::{
    Aes128, Aes256,
    cipher::{
        BlockModeDecrypt, BlockModeEncrypt, KeyInit, KeyIvInit,
        block_padding::{self, Pkcs7, ZeroPadding},
        inout::{self},
    },
};
use base64::Engine;
use serde::{Deserialize, Serialize, de::DeserializeOwned};

#[derive(Debug, Serialize, Deserialize)]
pub struct EncryptedAccountBody {
    len: u64,
    res: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EncryptedGameBody {
    pub errno: i64,
    pub data: EncryptedGameBodyData,
    #[serde(rename = "errinfo")]
    pub error_info: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EncryptedGameBodyData {
    pub enc_data: String,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("encryption error: {0}")]
    Encrypt(#[from] block_padding::Error),
    #[error("decryption error: {0}")]
    Decrypt(#[from] inout::PadError),
    #[error("serde_json error: {0}")]
    SerdeJson(#[from] serde_json::Error),
    #[error("base64 decode error: {0}")]
    Base64Decode(#[from] base64::DecodeError),
    #[error("utf8 decode error: {0}")]
    Utf8Decode(#[from] FromUtf8Error),
    #[error("invalid length: actual: {decrypted}, expect: {expect}")]
    WrongLength { decrypted: usize, expect: u64 },
}

pub trait IntoAccountApiEncryption {
    fn account_api_encrypt(self, key: &[u8; 16]) -> Result<String, Error>;
}

pub trait FromAccountApiEncryption {
    fn account_api_decrypt<T>(self, key: &[u8; 16]) -> Result<T, Error>
    where
        T: DeserializeOwned;
}

pub trait IntoGameApiEncryption {
    fn game_api_encrypt(self, key: &[u8; 32], iv: &[u8; 16]) -> Result<String, Error>;
}

pub trait FromGameApiEncryption {
    fn game_api_decrypt<T>(self, key: &[u8; 32], iv: &[u8; 16]) -> Result<T, Error>
    where
        T: DeserializeOwned;
}

impl<T> IntoAccountApiEncryption for T
where
    T: Serialize,
{
    fn account_api_encrypt(self, key: &[u8; 16]) -> Result<String, Error> {
        let string = serde_json::to_string(&self)?;
        let buf = string.as_bytes();
        let encrypted = encrypt_account(key, buf)?;
        let base64 = base64::prelude::BASE64_STANDARD.encode(encrypted);
        Ok(urlencoding::encode(&base64).to_string())
    }
}

impl FromAccountApiEncryption for EncryptedAccountBody {
    fn account_api_decrypt<T>(self, key: &[u8; 16]) -> Result<T, Error>
    where
        T: DeserializeOwned,
    {
        let origin = base64::prelude::BASE64_STANDARD.decode(self.res)?;
        let decrypted = decrypt_account(key, &origin)?;
        if decrypted.len() as u64 != self.len {
            return Err(Error::WrongLength {
                decrypted: decrypted.len(),
                expect: self.len,
            });
        }
        let decrypted_string = String::from_utf8(decrypted)?;
        let t = serde_json::from_str::<T>(&decrypted_string)?;
        Ok(t)
    }
}

impl<T> IntoGameApiEncryption for T
where
    T: Serialize,
{
    fn game_api_encrypt(self, key: &[u8; 32], iv: &[u8; 16]) -> Result<String, Error> {
        let string = serde_json::to_string(&self)?;
        let buf = string.as_bytes();
        let encrypted = encrypt_game(key, iv, buf)?;
        let base64 = base64::prelude::BASE64_STANDARD.encode(encrypted);
        Ok(base64)
    }
}

impl FromGameApiEncryption for EncryptedGameBody {
    fn game_api_decrypt<T>(self, key: &[u8; 32], iv: &[u8; 16]) -> Result<T, Error>
    where
        T: DeserializeOwned,
    {
        let origin = base64::prelude::BASE64_STANDARD.decode(self.data.enc_data)?;
        let decrypted = decrypt_game(key, iv, &origin)?;
        let decrypted_string = String::from_utf8(decrypted)?;
        let t = serde_json::from_str::<T>(&decrypted_string)?;
        Ok(t)
    }
}

fn decrypt_account(key: &[u8; 16], cipher_text: &[u8]) -> Result<Vec<u8>, block_padding::Error> {
    let mut buf = cipher_text.to_vec();
    let plaintext =
        ecb::Decryptor::<Aes128>::new(key.into()).decrypt_padded::<ZeroPadding>(&mut buf)?;
    Ok(plaintext.to_vec())
}

fn encrypt_account(key: &[u8; 16], origin_text: &[u8]) -> Result<Vec<u8>, inout::PadError> {
    let mut buf = origin_text.to_vec();
    let buf_len = buf.len();
    let plaintext = ecb::Encryptor::<Aes128>::new(key.into())
        .encrypt_padded::<ZeroPadding>(&mut buf, buf_len)?;
    Ok(plaintext.to_vec())
}

fn decrypt_game(
    key: &[u8; 32],
    iv: &[u8; 16],
    cipher_text: &[u8],
) -> Result<Vec<u8>, block_padding::Error> {
    let mut buf = cipher_text.to_vec();
    let plaintext =
        cbc::Decryptor::<Aes256>::new(key.into(), iv.into()).decrypt_padded::<Pkcs7>(&mut buf)?;
    Ok(plaintext.to_vec())
}

fn encrypt_game(
    key: &[u8; 32],
    iv: &[u8; 16],
    origin_text: &[u8],
) -> Result<Vec<u8>, inout::PadError> {
    let mut buf = origin_text.to_vec();
    let buf_len = buf.len();
    let plaintext = cbc::Encryptor::<Aes256>::new(key.into(), iv.into())
        .encrypt_padded::<Pkcs7>(&mut buf, buf_len)?;
    Ok(plaintext.to_vec())
}
