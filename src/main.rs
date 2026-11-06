use std::fs;

use taxillus::api::{
    self, ac,
    accounts::{OauthTokenArgs, SmsLoginArgs},
    games::{LoginArgs, LoginArgsChannelInfo, SyncArgs},
};

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();
    let config = taxillus::env::Config::init();
    let device_name = "XXXXXX-Taxillus";
    println!("calling sms login...");
    let account_general_args = api::accounts::GeneralArgs {
        device_name: device_name.to_string(),
    };
    let sms_send_result = api::accounts::sms_login(
        config,
        SmsLoginArgs {
            mobile: "12345678901".to_owned(),
            client_id: config.ac_app_id.clone(),
            pack_key: "15fe6f14f9a6ad22F".to_owned(),
            mobile_check: "false".to_owned(),
        },
        account_general_args.clone(),
    )
    .await
    .expect("failed");
    assert!(
        sms_send_result.errno == 200,
        "sms send failed: {}",
        sms_send_result.error_info
    );
    println!("{sms_send_result:?}");
    let mut sms_code = String::new();
    let _ = std::io::stdin().read_line(&mut sms_code);
    sms_code = sms_code.trim_end().to_string();
    let oauth_token_result = api::accounts::oauth_token(
        config,
        OauthTokenArgs {
            principal: "12345678901".to_owned(),
            client_id: config.ac_app_id.clone(),
            pack_key: "15fe6f14f9a6ad22F".to_owned(),
            r#type: "phone".to_owned(),
            auto_register: "true".to_owned(),
            identity: sms_code,
        },
        account_general_args,
    )
    .await
    .expect("failed");
    assert!(
        oauth_token_result.errno == 200,
        "sms check failed: {}",
        oauth_token_result.error_info
    );
    println!("ly login success: ");
    println!("  token: {}", oauth_token_result.data.access_token);
    println!("  session: {}", oauth_token_result.data.app_session);
    println!("  expire: {}", oauth_token_result.data.expire_in);
    let game_general_args = api::games::GeneralArgs::new_from_device_model_name(device_name);
    let game_login_result = api::games::login(
        config,
        LoginArgs {
            version_alt: config.game_header_version.clone(),
            platform_alt: "android".to_owned(),
            pid: ac::generate_device_id(device_name),
            hardware: device_name.to_string(),
            channel: "ly".to_owned(),
            channel_info: LoginArgsChannelInfo {
                session: oauth_token_result.data.app_session.clone(),
            },
            platform: "android".to_owned(),
        },
        game_general_args.clone(),
    )
    .await
    .expect("failed");
    println!("game login success:");
    println!(" {game_login_result:?}");
    let game_sync_result = api::games::sync(
        config,
        SyncArgs {
            version_alt: config.game_header_version.clone(),
            platform_alt: "android".to_owned(),
            channel: "ly".to_owned(),
            session: game_login_result.user_detail.session.clone(),
        },
        game_general_args,
    )
    .await
    .expect("failed");
    fs::write("out.txt", game_sync_result).unwrap();
}
