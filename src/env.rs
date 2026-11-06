use std::sync::OnceLock;

use serde::Deserialize;

static CONFIG: OnceLock<Config> = OnceLock::new();

#[derive(Debug)]
pub struct Config {
    pub ac_appid: String,
    pub ac_app_id: String,
    pub ac_api_ver: String,
    pub ac_sdk_ver: String,
    pub ac_enc_ver: String,
    pub ac_enc_kid: String,
    pub ac_sys_ver: String,
    pub ac_lang: String,
    pub ac_h_key: Option<Vec<u8>>,
    pub game_header_version: String,
    pub game_header_clearance: String,
    pub game_header_ad_channel: String,
    pub game_header_pack_id: String,
    pub game_header_unity_version: String,
    pub api_account_prefix: String,
    pub api_account_sms_login: String,
    pub api_account_oauth_token: String,
    pub api_account_user_detail: String,
    pub api_game_prefix: String,
    pub api_game_login: String,
    pub encrypt_account_key: [u8; 16],
    pub encrypt_game_key: [u8; 32],
    pub encrypt_game_iv: [u8; 16],
}

#[derive(Debug, Deserialize)]
pub struct ConfigRaw {
    pub ac_appid: String,
    pub ac_app_id: String,
    pub ac_api_ver: String,
    pub ac_sdk_ver: String,
    pub ac_enc_ver: String,
    pub ac_enc_kid: String,
    pub ac_sys_ver: String,
    pub ac_lang: String,
    pub ac_h_key: Option<String>,
    pub game_header_version: String,
    pub game_header_clearance: String,
    pub game_header_ad_channel: String,
    pub game_header_pack_id: String,
    pub game_header_unity_version: String,
    pub api_account_prefix: String,
    pub api_account_sms_login: String,
    pub api_account_oauth_token: String,
    pub api_account_user_detail: String,
    pub api_game_prefix: String,
    pub api_game_login: String,
    pub encrypt_account_key: String,
    pub encrypt_game_key: String,
    pub encrypt_game_iv: String,
}

impl Config {
    pub fn init() -> &'static Self {
        let config_raw = envy::from_env::<ConfigRaw>().expect("failed to initialize config");
        CONFIG.get_or_init(|| Self {
            ac_appid: config_raw.ac_appid,
            ac_app_id: config_raw.ac_app_id,
            ac_api_ver: config_raw.ac_api_ver,
            ac_sdk_ver: config_raw.ac_sdk_ver,
            ac_enc_ver: config_raw.ac_enc_ver,
            ac_enc_kid: config_raw.ac_enc_kid,
            ac_sys_ver: config_raw.ac_sys_ver,
            ac_lang: config_raw.ac_lang,
            ac_h_key: config_raw.ac_h_key.map_or_else(
                || {
                    tracing::warn!(target = "", "");
                    None
                },
                |it| Some(hex::decode(it).expect("failed to decode AC_H_KEY")),
            ),
            game_header_version: config_raw.game_header_version,
            game_header_clearance: config_raw.game_header_clearance,
            game_header_ad_channel: config_raw.game_header_ad_channel,
            game_header_pack_id: config_raw.game_header_pack_id,
            game_header_unity_version: config_raw.game_header_unity_version,
            api_account_prefix: config_raw.api_account_prefix,
            api_account_sms_login: config_raw.api_account_sms_login,
            api_account_oauth_token: config_raw.api_account_oauth_token,
            api_account_user_detail: config_raw.api_account_user_detail,
            api_game_prefix: config_raw.api_game_prefix,
            api_game_login: config_raw.api_game_login,
            encrypt_account_key: hex::decode(config_raw.encrypt_account_key)
                .expect("failed to initialize ENCRYPT_ACCOUNT_KEY: bad hex")
                .try_into()
                .expect("failed to initialize ENCRYPT_ACCOUNT_KEY: bad length"),
            encrypt_game_key: hex::decode(config_raw.encrypt_game_key)
                .expect("failed to initialize ENCRYPT_GAME_KEY: bad hex")
                .try_into()
                .expect("failed to initialize ENCRYPT_GAME_KEY: bad length"),
            encrypt_game_iv: hex::decode(config_raw.encrypt_game_iv)
                .expect("failed to initialize ENCRYPT_GAME_IV: bad hex")
                .try_into()
                .expect("failed to initialize ENCRYPT_GAME_IV: bad length"),
        })
    }

    pub fn get() -> &'static Self {
        CONFIG.get().expect("should initialize config first")
    }
}
