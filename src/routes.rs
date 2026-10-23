use crate::auth::{require_owner, AuthedPubkey};
use crate::models::subscription_config::SubscriptionConfig;
use crate::models::user::User;
use crate::models::wallet_auth::{WalletAuth, MAX_PENDING_WALLET_AUTHS};
use crate::models::zap_config::ZapConfig;
use crate::models::zap_event::ZapEvent;
use crate::nip49::{NIP49Budget, SubscriptionPeriod, NIP49URI};
use crate::utils::map_emoji;
use crate::{utils, State, DEFAULT_AUTH_RELAY};
use axum::body::Bytes;
use axum::extract::{Path, Query};
use axum::http::StatusCode;
use axum::{Extension, Json};
use diesel::{Connection, PgConnection};
use lnurl::lightning_address::LightningAddress;
use lnurl::lnurl::LnUrl;
use log::*;
use nostr::key::PublicKey;
use nostr::nips::nip47::NostrWalletConnectURI;
use nostr::prelude::Method;
#[cfg(not(test))]
use nostr::prelude::ToBech32;
use nostr::{Keys, Url, SECP256K1};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::str::FromStr;

pub(crate) fn handle_anyhow_error(err: anyhow::Error) -> (StatusCode, String) {
    error!("Error: {:?}", err);
    (StatusCode::INTERNAL_SERVER_ERROR, format!("{err}"))
}

pub async fn nip05(
    Extension(state): Extension<State>,
) -> Result<Json<Value>, (StatusCode, String)> {
    let npub = state.server_keys.public_key().to_string();
    let json = json!({"names": {
        "_": npub,
        "zapplepay": npub,
    }});

    Ok(Json(json))
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct UserConfigs {
    zaps: Vec<SetUserConfig>,
    subscriptions: Vec<CreateUserSubscription>,
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct SetUserConfig {
    pub npub: PublicKey,
    pub amount_sats: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nwc: Option<NostrWalletConnectURI>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_id: Option<PublicKey>,
    pub emoji: Option<String>,
    pub donations: Option<Vec<DonationConfig>>,
}

/// Manual `Debug` with the NWC field redacted.
///
/// `NostrWalletConnectURI`'s derived `Debug` happens to be safe today only
/// because `secp256k1::SecretKey` prints a hash fingerprint instead of the key
/// (`impl_display_secret!`). That is an implementation detail of a transitive
/// dependency, and the nostr crates are about to be bumped. The most dangerous
/// value in this service should not rely on it: redact locally and keep the
/// invariant under test (`debug_output_never_contains_nwc_secret`).
impl std::fmt::Debug for SetUserConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SetUserConfig")
            .field("npub", &self.npub)
            .field("amount_sats", &self.amount_sats)
            .field("nwc", &self.nwc.as_ref().map(|_| "<redacted>"))
            .field("auth_id", &self.auth_id)
            .field("emoji", &self.emoji)
            .field("donations", &self.donations)
            .finish()
    }
}

impl SetUserConfig {
    pub fn verify(&self) -> anyhow::Result<()> {
        if self.amount_sats == 0 {
            return Err(anyhow::anyhow!("Invalid amount"));
        }

        if self.nwc.is_some() == self.auth_id.is_some() {
            return Err(anyhow::anyhow!("Can only have nwc or auth_id"));
        }

        // verify donations have a valid lnurl / lightning address / npub
        if self
            .donations
            .as_ref()
            .map_or(false, |d| d.iter().any(|d| !d.is_valid()))
        {
            return Err(anyhow::anyhow!("Invalid lnurl in donation"));
        }

        Ok(())
    }

    pub fn emoji(&self) -> String {
        self.emoji
            .clone()
            .map(|e| map_emoji(&e).unwrap_or(&e).trim().to_string())
            .unwrap_or("⚡".to_string())
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct DonationConfig {
    pub amount_sats: u64,
    pub lnurl: Option<String>,
    pub npub: Option<PublicKey>,
}

impl DonationConfig {
    pub fn is_valid(&self) -> bool {
        match (self.lnurl.as_ref(), self.npub.as_ref()) {
            (Some(lnurl), None) => {
                LnUrl::from_str(lnurl).is_ok() || LightningAddress::from_str(lnurl).is_ok()
            }
            (None, Some(_)) => true, // valid by parser
            _ => false,
        }
    }
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct CreateUserSubscription {
    pub npub: PublicKey,
    pub to_npub: PublicKey,
    pub amount_sats: u64,
    pub time_period: SubscriptionPeriod,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nwc: Option<NostrWalletConnectURI>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_id: Option<PublicKey>,
}

/// Manual `Debug` with the NWC field redacted; rationale on `SetUserConfig`.
impl std::fmt::Debug for CreateUserSubscription {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CreateUserSubscription")
            .field("npub", &self.npub)
            .field("to_npub", &self.to_npub)
            .field("amount_sats", &self.amount_sats)
            .field("time_period", &self.time_period)
            .field("nwc", &self.nwc.as_ref().map(|_| "<redacted>"))
            .field("auth_id", &self.auth_id)
            .finish()
    }
}

impl CreateUserSubscription {
    pub fn verify(&self) -> anyhow::Result<()> {
        if self.amount_sats == 0 {
            return Err(anyhow::anyhow!("Invalid amount"));
        }

        if self.nwc.is_some() == self.auth_id.is_some() {
            return Err(anyhow::anyhow!("Can only have nwc or auth_id"));
        }

        if self.npub == self.to_npub {
            return Err(anyhow::anyhow!("Cannot subscribe to yourself"));
        }

        Ok(())
    }
}

#[cfg(not(test))]
async fn send_config_dm(
    keys: Keys,
    npub: PublicKey,
    emoji: String,
    amt: u64,
) -> anyhow::Result<()> {
    let client = nostr_sdk::Client::new(&keys);
    client.add_relay("wss://relay.damus.io").await?;
    client.connect().await;

    let sats = if amt == 1 { "sat" } else { "sats" };
    let content = format!("You have configured Zapple Pay to zap {amt} {sats} anytime you react to a note with a {emoji} emoji!");

    let event_id = client.send_direct_msg(npub, content, None).await?;
    debug!("Sent DM: {event_id}");
    client.disconnect().await?;

    Ok(())
}

#[cfg(not(test))]
async fn send_subscription_dm(
    keys: Keys,
    npub: PublicKey,
    to_npub: PublicKey,
    period: SubscriptionPeriod,
    amt: u64,
) -> anyhow::Result<()> {
    let client = nostr_sdk::Client::new(&keys);
    client.add_relay("wss://relay.damus.io").await?;
    client.connect().await;

    let sats = if amt == 1 { "sat" } else { "sats" };
    let content = format!(
        "You have subscribed to {} by zapping them {amt} {sats} every {period}!",
        to_npub.to_bech32().expect("bech32")
    );

    let event_id = client.send_direct_msg(npub, content, None).await?;
    debug!("Sent DM: {event_id}");
    client.disconnect().await?;

    Ok(())
}

#[cfg(not(test))]
async fn send_deleted_config_dm(keys: Keys, npub: PublicKey, emoji: String) -> anyhow::Result<()> {
    let client = nostr_sdk::Client::new(&keys);
    client.add_relay("wss://relay.damus.io").await?;
    client.connect().await;

    let content =
        format!("You have deleted your Zapple Pay config for reactions with a {emoji} emoji!");

    let event_id = client.send_direct_msg(npub, content, None).await?;
    debug!("Sent DM: {event_id}");
    client.disconnect().await?;

    Ok(())
}

#[cfg(not(test))]
async fn send_deleted_subscription_dm(
    keys: Keys,
    npub: PublicKey,
    to_npub: PublicKey,
) -> anyhow::Result<()> {
    let client = nostr_sdk::Client::new(&keys);
    client.add_relay("wss://relay.damus.io").await?;
    client.connect().await;

    let content = format!(
        "You have canceled your subscription to {}",
        to_npub.to_bech32().expect("bech32")
    );

    let event_id = client.send_direct_msg(npub, content, None).await?;
    debug!("Sent DM: {event_id}");
    client.disconnect().await?;

    Ok(())
}

#[cfg(not(test))]
async fn send_deleted_user_dm(keys: Keys, npub: PublicKey) -> anyhow::Result<()> {
    let client = nostr_sdk::Client::new(&keys);
    client.add_relay("wss://relay.damus.io").await?;
    client.connect().await;

    let content = String::from("You have deleted your Zapple Pay account.");

    let event_id = client.send_direct_msg(npub, content, None).await?;
    debug!("Sent DM: {event_id}");
    client.disconnect().await?;

    Ok(())
}

pub(crate) async fn set_user_config_impl(
    payload: SetUserConfig,
    state: &State,
) -> anyhow::Result<UserConfigs> {
    payload.verify()?;

    let emoji_str = payload.emoji();

    if emoji_str.is_empty() {
        return Err(anyhow::anyhow!("Invalid emoji"));
    }

    let npub = payload.npub;
    let amt = payload.amount_sats;
    let secret_key_pk: PublicKey = match payload.nwc.as_ref() {
        Some(nwc) => nwc.secret.x_only_public_key(&SECP256K1).0.into(),
        None => payload.auth_id.unwrap(),
    };
    let mut conn = state.db_pool.get()?;
    crate::models::upsert_user(&mut conn, payload)?;
    drop(conn);

    info!("New user: {npub} {emoji_str} {amt}!");
    // notify new pubkey
    let keys = state.pubkey_channel.lock().await;
    keys.send_if_modified(|current| {
        if current.contains(&npub) {
            false
        } else {
            current.push(npub);
            true
        }
    });

    // notify new secret key
    let secrets = state.secret_channel.lock().await;
    secrets.send_if_modified(|current| {
        if current.contains(&secret_key_pk) {
            false
        } else {
            current.push(secret_key_pk);
            true
        }
    });

    #[cfg(not(test))]
    {
        let keys = state.server_keys.clone();
        tokio::spawn(send_config_dm(keys, npub, emoji_str, amt));
    }

    get_user_configs_impl(npub, state)
}

pub async fn set_user_config(
    Extension(state): Extension<State>,
    Extension(auth): Extension<AuthedPubkey>,
    Json(payload): Json<SetUserConfig>,
) -> Result<Json<UserConfigs>, (StatusCode, String)> {
    require_owner(&auth, &payload.npub)?;
    match set_user_config_impl(payload, &state).await {
        Ok(res) => Ok(Json(res)),
        Err(e) => Err(handle_anyhow_error(e)),
    }
}

pub(crate) async fn create_user_subscription_impl(
    payload: CreateUserSubscription,
    state: &State,
) -> anyhow::Result<UserConfigs> {
    payload.verify()?;

    let npub = payload.npub;
    let to_npub = payload.to_npub;
    let amt = payload.amount_sats;
    let period = payload.time_period;
    let secret_key_pk: PublicKey = match payload.nwc.as_ref() {
        Some(nwc) => nwc.secret.x_only_public_key(&SECP256K1).0.into(),
        None => payload.auth_id.unwrap(),
    };
    let mut conn = state.db_pool.get()?;
    crate::models::upsert_subscription(&mut conn, payload)?;
    drop(conn);

    // notify new secret key
    let secrets = state.secret_channel.lock().await;
    secrets.send_if_modified(|current| {
        if current.contains(&secret_key_pk) {
            false
        } else {
            current.push(secret_key_pk);
            true
        }
    });

    info!("New subscription: {npub} -> {to_npub} {amt} every {period}!");

    #[cfg(not(test))]
    {
        let keys = state.server_keys.clone();
        tokio::spawn(send_subscription_dm(keys, npub, to_npub, period, amt));
    }

    get_user_configs_impl(npub, state)
}

pub async fn create_user_subscription(
    Extension(state): Extension<State>,
    Extension(auth): Extension<AuthedPubkey>,
    Json(payload): Json<CreateUserSubscription>,
) -> Result<Json<UserConfigs>, (StatusCode, String)> {
    require_owner(&auth, &payload.npub)?;
    match create_user_subscription_impl(payload, &state).await {
        Ok(res) => Ok(Json(res)),
        Err(e) => Err(handle_anyhow_error(e)),
    }
}

pub(crate) fn get_user_config_impl(
    npub: PublicKey,
    emoji: String,
    state: &State,
) -> anyhow::Result<Option<SetUserConfig>> {
    let mut conn = state.db_pool.get()?;
    crate::models::get_user_zap_config(&mut conn, npub, &emoji).map(|user| {
        user.map(|user| {
            let donations = user
                .donations
                .into_iter()
                .map(|donation| DonationConfig {
                    amount_sats: donation.amount as u64,
                    npub: donation.npub(),
                    lnurl: donation.lnurl,
                })
                .collect::<Vec<DonationConfig>>();

            let donations = if donations.is_empty() {
                None
            } else {
                Some(donations)
            };

            SetUserConfig {
                npub,
                amount_sats: user.zap_config.amount as u64,
                nwc: None, // don't return the nwc
                auth_id: None,
                emoji: Some(user.zap_config.emoji),
                donations,
            }
        })
    })
}

pub async fn get_user_config(
    Path((npub, emoji)): Path<(String, String)>,
    Extension(state): Extension<State>,
) -> Result<Json<SetUserConfig>, (StatusCode, String)> {
    let npub = PublicKey::from_str(&npub).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            String::from("{\"status\":\"ERROR\",\"reason\":\"Invalid npub\"}"),
        )
    })?;
    match get_user_config_impl(npub, emoji, &state) {
        Ok(Some(res)) => Ok(Json(res)),
        Ok(None) => Err((StatusCode::NOT_FOUND, String::from("{\"status\":\"ERROR\",\"reason\":\"The user you're searching for could not be found.\"}"))),
        Err(e) => Err(handle_anyhow_error(e)),
    }
}

pub(crate) fn get_user_configs_impl(npub: PublicKey, state: &State) -> anyhow::Result<UserConfigs> {
    let mut conn = state.db_pool.get()?;
    let zaps = crate::models::get_user_zap_configs(&mut conn, npub).map(|configs| {
        configs
            .into_iter()
            .map(|user| {
                let donations = user
                    .donations
                    .into_iter()
                    .map(|donation| DonationConfig {
                        amount_sats: donation.amount as u64,
                        npub: donation.npub(),
                        lnurl: donation.lnurl,
                    })
                    .collect::<Vec<DonationConfig>>();

                let donations = if donations.is_empty() {
                    None
                } else {
                    Some(donations)
                };

                SetUserConfig {
                    npub,
                    amount_sats: user.zap_config.amount as u64,
                    nwc: None, // don't return the nwc
                    auth_id: None,
                    emoji: Some(user.zap_config.emoji),
                    donations,
                }
            })
            .collect()
    })?;

    let subscriptions = SubscriptionConfig::get_by_pubkey(&mut conn, &npub)?
        .into_iter()
        .map(|c| CreateUserSubscription {
            npub,
            to_npub: c.to_npub(),
            amount_sats: c.amount as u64,
            time_period: c.time_period(),
            nwc: None,
            auth_id: None,
        })
        .collect();

    Ok(UserConfigs {
        zaps,
        subscriptions,
    })
}

pub async fn get_user_configs(
    Path(npub): Path<String>,
    Extension(state): Extension<State>,
) -> Result<Json<UserConfigs>, (StatusCode, String)> {
    let npub = PublicKey::from_str(&npub).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            String::from("{\"status\":\"ERROR\",\"reason\":\"Invalid npub\"}"),
        )
    })?;
    match get_user_configs_impl(npub, &state) {
        Ok(res) => Ok(Json(res)),
        Err(e) => Err(handle_anyhow_error(e)),
    }
}

pub(crate) fn get_user_subscriptions_impl(
    conn: &mut PgConnection,
    npub: PublicKey,
) -> anyhow::Result<Vec<CreateUserSubscription>> {
    let configs = SubscriptionConfig::get_by_pubkey(conn, &npub)?;
    let res = configs
        .into_iter()
        .map(|c| CreateUserSubscription {
            npub,
            to_npub: c.to_npub(),
            amount_sats: c.amount as u64,
            time_period: c.time_period(),
            nwc: None,
            auth_id: None,
        })
        .collect();

    Ok(res)
}

pub async fn get_user_subscriptions(
    Path(npub): Path<String>,
    Extension(state): Extension<State>,
) -> Result<Json<Vec<CreateUserSubscription>>, (StatusCode, String)> {
    let npub = PublicKey::from_str(&npub).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            String::from("{\"status\":\"ERROR\",\"reason\":\"Invalid npub\"}"),
        )
    })?;
    let mut conn = state.db_pool.get().map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            String::from("{\"status\":\"ERROR\",\"reason\":\"Could not get db connection\"}"),
        )
    })?;
    match get_user_subscriptions_impl(&mut conn, npub) {
        Ok(res) => Ok(Json(res)),
        Err(e) => Err(handle_anyhow_error(e)),
    }
}

pub(crate) fn get_user_subscription_impl(
    conn: &mut PgConnection,
    npub: PublicKey,
    to_npub: PublicKey,
) -> anyhow::Result<Option<CreateUserSubscription>> {
    let c = SubscriptionConfig::get_by_pubkey_and_to_npub(conn, &npub, &to_npub)?;

    Ok(c.map(|c| CreateUserSubscription {
        npub,
        to_npub: c.to_npub(),
        amount_sats: c.amount as u64,
        time_period: c.time_period(),
        nwc: None,
        auth_id: None,
    }))
}

pub async fn get_user_subscription(
    Path((npub, to_npub)): Path<(String, String)>,
    Extension(state): Extension<State>,
) -> Result<Json<CreateUserSubscription>, (StatusCode, String)> {
    let npub = PublicKey::from_str(&npub).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            String::from("{\"status\":\"ERROR\",\"reason\":\"Invalid npub\"}"),
        )
    })?;
    let to_npub = PublicKey::from_str(&to_npub).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            String::from("{\"status\":\"ERROR\",\"reason\":\"Invalid to_npub\"}"),
        )
    })?;
    let mut conn = state.db_pool.get().map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            String::from("{\"status\":\"ERROR\",\"reason\":\"Could not get db connection\"}"),
        )
    })?;

    match get_user_subscription_impl(&mut conn, npub, to_npub) {
        Ok(Some(res)) => Ok(Json(res)),
        Ok(None) => Err((
            StatusCode::NOT_FOUND,
            String::from("{\"status\":\"ERROR\",\"reason\":\"Subscription not found.\"}"),
        )),
        Err(e) => Err(handle_anyhow_error(e)),
    }
}

pub async fn delete_user_config(
    Path((npub, emoji)): Path<(String, String)>,
    Extension(state): Extension<State>,
    Extension(auth): Extension<AuthedPubkey>,
) -> Result<Json<UserConfigs>, (StatusCode, String)> {
    let npub = PublicKey::from_str(&npub).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            String::from("{\"status\":\"ERROR\",\"reason\":\"Invalid npub\"}"),
        )
    })?;
    require_owner(&auth, &npub)?;

    let mut conn = state.db_pool.get().map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            String::from("{\"status\":\"ERROR\",\"reason\":\"Could not get db connection\"}"),
        )
    })?;

    match crate::models::delete_user_config(&mut conn, npub, &emoji) {
        Ok(_) => {
            #[cfg(not(test))]
            {
                let keys = state.server_keys.clone();
                tokio::spawn(send_deleted_config_dm(keys, npub, emoji));
            }

            get_user_configs_impl(npub, &state)
                .map(Json)
                .map_err(handle_anyhow_error)
        }
        Err(e) => Err(handle_anyhow_error(e)),
    }
}

pub async fn delete_user_configs(
    Path(npub): Path<String>,
    Extension(state): Extension<State>,
    Extension(auth): Extension<AuthedPubkey>,
) -> Result<Json<UserConfigs>, (StatusCode, String)> {
    let npub = PublicKey::from_str(&npub).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            String::from("{\"status\":\"ERROR\",\"reason\":\"Invalid npub\"}"),
        )
    })?;
    require_owner(&auth, &npub)?;

    let mut conn = state.db_pool.get().map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            String::from("{\"status\":\"ERROR\",\"reason\":\"Could not get db connection\"}"),
        )
    })?;

    match crate::models::delete_user(&mut conn, npub) {
        Ok(_) => {
            #[cfg(not(test))]
            {
                let keys = state.server_keys.clone();
                tokio::spawn(send_deleted_user_dm(keys, npub));
            }

            get_user_configs_impl(npub, &state)
                .map(Json)
                .map_err(handle_anyhow_error)
        }
        Err(e) => Err(handle_anyhow_error(e)),
    }
}

pub async fn delete_user_subscription(
    Path((npub, to_npub)): Path<(String, String)>,
    Extension(state): Extension<State>,
    Extension(auth): Extension<AuthedPubkey>,
) -> Result<Json<UserConfigs>, (StatusCode, String)> {
    let npub = PublicKey::from_str(&npub).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            String::from("{\"status\":\"ERROR\",\"reason\":\"Invalid npub\"}"),
        )
    })?;
    require_owner(&auth, &npub)?;
    let to_npub = PublicKey::from_str(&to_npub).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            String::from("{\"status\":\"ERROR\",\"reason\":\"Invalid to_npub\"}"),
        )
    })?;

    let mut conn = state.db_pool.get().map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            String::from("{\"status\":\"ERROR\",\"reason\":\"Could not get db connection\"}"),
        )
    })?;

    match crate::models::delete_user_subscription(&mut conn, npub, to_npub) {
        Ok(_) => {
            #[cfg(not(test))]
            {
                let keys = state.server_keys.clone();
                tokio::spawn(send_deleted_subscription_dm(keys, npub, to_npub));
            }

            get_user_configs_impl(npub, &state)
                .map(Json)
                .map_err(handle_anyhow_error)
        }
        Err(e) => Err(handle_anyhow_error(e)),
    }
}

#[allow(dead_code)]
pub async fn delete_subscribed_user(
    Path(to_npub): Path<String>,
    Extension(state): Extension<State>,
) -> Result<Json<usize>, (StatusCode, String)> {
    let to_npub = PublicKey::from_str(&to_npub).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            String::from("{\"status\":\"ERROR\",\"reason\":\"Invalid to_npub\"}"),
        )
    })?;

    let mut conn = state.db_pool.get().map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            String::from("{\"status\":\"ERROR\",\"reason\":\"Could not get db connection\"}"),
        )
    })?;

    match crate::models::delete_subscribed_user(&mut conn, to_npub) {
        Ok(count) => Ok(Json(count)),
        Err(e) => Err(handle_anyhow_error(e)),
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct WalletAuthParams {
    pub time_period: SubscriptionPeriod,
    pub amount: u64,
    pub identity: Option<PublicKey>,
}

pub async fn wallet_auth_impl(
    state: &State,
    params: Option<WalletAuthParams>,
) -> anyhow::Result<NIP49URI> {
    let auth = {
        let mut conn = state.db_pool.get()?;
        WalletAuth::create(&mut conn, state.xpriv)?
    };

    let public_key = auth.pubkey();
    let secret = utils::calculate_nwa_secret(state.xpriv, public_key);

    let budget = params.as_ref().map(|p| NIP49Budget {
        time_period: p.time_period,
        amount: p.amount,
    });

    let identity = params
        .and_then(|p| p.identity)
        .unwrap_or(state.server_keys.public_key());

    let uri = NIP49URI {
        public_key,
        relay_url: Url::parse(DEFAULT_AUTH_RELAY)?,
        secret,
        required_commands: vec![Method::PayInvoice],
        optional_commands: vec![],
        budget,
        identity: Some(identity),
    };

    // notify new auth key
    let auths = state.auth_channel.lock().await;
    auths.send_if_modified(|current| push_pending_auth(current, public_key));

    Ok(uri)
}

/// Add `key` to the list of pending NWA keys the listener subscribes to.
/// Duplicates are ignored and the list never exceeds
/// [`MAX_PENDING_WALLET_AUTHS`]; when full, the oldest pending key is dropped
/// from the watch list. Its DB row stays unlinked, and a wallet response for
/// it is simply never delivered by the relay (the identifier is no longer in
/// the filter), so the user has to start that connection again. Returns
/// whether the list changed, which is what `watch::Sender::send_if_modified`
/// wants.
pub(crate) fn push_pending_auth(current: &mut Vec<PublicKey>, key: PublicKey) -> bool {
    if current.contains(&key) {
        return false;
    }
    if current.len() >= MAX_PENDING_WALLET_AUTHS {
        let excess = current.len() + 1 - MAX_PENDING_WALLET_AUTHS;
        current.drain(..excess);
    }
    current.push(key);
    true
}

/// NWA bootstrap. POST-only and behind the NIP-98 + allowlist layer: each call
/// inserts a `wallet_auth` row, derives a key from the server xpriv and grows
/// the relay subscription, so it must never be reachable anonymously. The
/// optional JSON body carries the budget and the autozap target `identity`;
/// an empty body means "no budget". A body that is present but not valid
/// `WalletAuthParams` is a 400 rather than silently becoming "no budget".
///
/// The `AuthedPubkey` extension is a trip-wire, not the gate: the gate is the
/// `route_layer` in `build_router`. If this handler were ever registered
/// outside that layer the extractor fails with a 500 instead of running.
pub async fn wallet_auth(
    Extension(state): Extension<State>,
    Extension(_auth): Extension<AuthedPubkey>,
    body: Bytes,
) -> Result<Json<Value>, (StatusCode, String)> {
    let params = if body.is_empty() {
        None
    } else {
        Some(
            serde_json::from_slice::<WalletAuthParams>(&body).map_err(|_| {
                (
                    StatusCode::BAD_REQUEST,
                    String::from(
                        "{\"status\":\"ERROR\",\"reason\":\"Invalid wallet auth params\"}",
                    ),
                )
            })?,
        )
    };
    match wallet_auth_impl(&state, params).await {
        Ok(uri) => Ok(Json(json!({"id": uri.public_key.to_string(), "uri": uri}))),
        Err(e) => Err(handle_anyhow_error(e)),
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct CheckWalletAuthPayload {
    id: PublicKey,
}

pub async fn check_wallet_auth_impl(state: &State, id: PublicKey) -> anyhow::Result<bool> {
    let mut conn = state.db_pool.get()?;
    let auth = WalletAuth::get_by_pubkey(&mut conn, id)?;

    Ok(auth.is_some_and(|x| x.user_pubkey().is_some()))
}

pub async fn check_wallet_auth(
    Extension(state): Extension<State>,
    Query(query): Query<CheckWalletAuthPayload>,
) -> Result<Json<bool>, (StatusCode, String)> {
    match check_wallet_auth_impl(&state, query.id).await {
        Ok(res) => Ok(Json(res)),
        Err(e) => Err(handle_anyhow_error(e)),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Counts {
    users: i64,
    zap_configs: i64,
    subscription_configs: i64,
    zap_count: i64,
    unconfirmed_count: i64,
    zap_total: i64,
}

pub async fn count_impl(state: &State) -> anyhow::Result<Counts> {
    let mut conn = state.db_pool.get()?;

    conn.transaction(|conn| {
        let users = User::get_user_count(conn)?;
        let zap_configs = ZapConfig::get_config_count(conn)?;
        let subscription_configs = SubscriptionConfig::get_config_count(conn)?;
        let zap_count = ZapEvent::get_zap_count(conn)?;
        let unconfirmed_count = ZapEvent::get_unconfirmed_zap_count(conn)?;
        let zap_total = ZapEvent::get_zap_total(conn)?;

        Ok(Counts {
            users,
            zap_configs,
            subscription_configs,
            zap_count,
            unconfirmed_count,
            zap_total,
        })
    })
}

pub async fn count(
    Extension(state): Extension<State>,
) -> Result<Json<Counts>, (StatusCode, String)> {
    match count_impl(&state).await {
        Ok(res) => Ok(Json(res)),
        Err(e) => Err(handle_anyhow_error(e)),
    }
}

pub async fn relays_impl(state: &State) -> anyhow::Result<HashMap<Url, usize>> {
    let mut conn = state.db_pool.get()?;
    let mut zap = ZapConfig::get_nwc_relays(&mut conn)?;
    let subs = SubscriptionConfig::get_nwc_relays(&mut conn)?;

    for (key, count) in subs {
        *zap.entry(key).or_insert(0) += count;
    }

    Ok(zap)
}

pub async fn relays(
    Extension(state): Extension<State>,
) -> Result<Json<HashMap<Url, usize>>, (StatusCode, String)> {
    match relays_impl(&state).await {
        Ok(res) => Ok(Json(res)),
        Err(e) => Err(handle_anyhow_error(e)),
    }
}

pub async fn migrate_emojis(
    Extension(state): Extension<State>,
    Extension(auth): Extension<AuthedPubkey>,
) -> Result<Json<usize>, (StatusCode, String)> {
    // Instance-wide maintenance: any allowlisted key may run it. The auth
    // layer already rejected everyone else.
    info!("migrate_emojis requested by {}", auth.0);
    let mut conn = state.db_pool.get().map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            String::from("{\"status\":\"ERROR\",\"reason\":\"Could not get db connection\"}"),
        )
    })?;
    match ZapConfig::migrate_emojis(&mut conn) {
        Ok(res) => Ok(Json(res)),
        Err(e) => Err(handle_anyhow_error(e)),
    }
}

#[cfg(test)]
mod test {
    use crate::models::MIGRATIONS;
    use crate::routes::*;
    use axum::body::Body;
    use axum::http::{header, Request};
    use axum::response::Response;
    use bitcoin::bip32::ExtendedPrivKey;
    use diesel::r2d2::{ConnectionManager, Pool};
    use diesel::RunQueryDsl;
    use diesel_migrations::MigrationHarness;
    use nostr::{HttpMethod, Timestamp};
    use std::sync::Arc;
    use tokio::sync::{watch, Mutex};
    use tower::ServiceExt;

    const PUBKEY: &str = "e1ff3bfdd4e40315959b08b4fcc8245eaa514637e1d4ec2ae166b743341be1af";
    const PUBKEY2: &str = "82341f882b6eabcd2ba7f1ef90aad961cf074af15b9ef44a09f9d2a8fbfbe6a2";
    const NWC: &str = "nostr+walletconnect://246be70a7e4966f138e9e48401f33c32a1c428bbfb7aab42e3946beb8bc15e7c?relay=wss%3A%2F%2Frelay.damus.io%2F&secret=23ea701003500d852ba2756460099217f839e1fbc9665e493b56bd2d5912e31b";

    fn init_state() -> State {
        init_state_allowing(&[])
    }

    fn init_state_allowing(allowed: &[PublicKey]) -> State {
        dotenv::dotenv().ok();
        let url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
        let manager = ConnectionManager::<PgConnection>::new(url);
        let db_pool = Pool::builder()
            .max_size(16)
            .test_on_check_out(true)
            .build(manager)
            .expect("Could not build connection pool");

        // run migrations
        let mut connection = db_pool.get().unwrap();
        connection
            .run_pending_migrations(MIGRATIONS)
            .expect("migrations could not run");

        let (tx, _) = watch::channel(vec![]);
        let pubkey_channel = Arc::new(Mutex::new(tx));
        let (tx, _) = watch::channel(vec![]);
        let secret_channel = Arc::new(Mutex::new(tx));
        let (tx, _) = watch::channel(vec![]);
        let auth_channel = Arc::new(Mutex::new(tx));
        let server_keys = Keys::generate();
        let xpriv = ExtendedPrivKey::new_master(bitcoin::Network::Testnet, &[]).unwrap();

        State {
            db_pool,
            pubkey_channel,
            secret_channel,
            auth_channel,
            server_keys,
            xpriv,
            auth: Arc::new(
                crate::auth::Nip98Config::new(
                    TEST_PUBLIC_URL,
                    &allowed.iter().map(|p| p.to_string()).collect::<Vec<_>>(),
                )
                .unwrap(),
            ),
        }
    }

    const TEST_PUBLIC_URL: &str = "http://localhost:3000";

    fn request(
        method: &str,
        path: &str,
        auth: Option<String>,
        body: Option<String>,
    ) -> Request<Body> {
        let mut b = Request::builder().method(method).uri(path);
        if let Some(a) = auth {
            b = b.header(header::AUTHORIZATION, a);
        }
        if body.is_some() {
            b = b.header(header::CONTENT_TYPE, "application/json");
        }
        b.body(body.map(Body::from).unwrap_or_else(Body::empty))
            .unwrap()
    }

    fn signed(keys: &Keys, method: HttpMethod, path: &str, body: Option<&str>) -> String {
        crate::auth::test_support::header(
            keys,
            method,
            &format!("{TEST_PUBLIC_URL}{path}"),
            body.map(str::as_bytes),
            Timestamp::now(),
        )
    }

    async fn body_string(res: Response) -> String {
        let bytes = hyper::body::to_bytes(res.into_body()).await.unwrap();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    /// Mutation paths are POST-only and refuse anything without a valid
    /// NIP-98 header, before any handler or DB code runs.
    #[tokio::test]
    async fn router_rejects_get_and_unauthenticated_mutations() {
        let app = crate::build_router(init_state());

        let signer = Keys::generate();
        let app_allowing = crate::build_router(init_state_allowing(&[signer.public_key()]));
        for path in [
            format!("/delete-user/{PUBKEY}"),
            format!("/delete-user/{PUBKEY}/{}", urlencoding::encode("⚡")),
            format!("/delete-subscription/{PUBKEY}/{PUBKEY2}"),
            "/migrate-emojis".to_string(),
            "/wallet-auth".to_string(),
        ] {
            // The auth layer sits in front of method routing, so an
            // unauthenticated GET is refused there; an authenticated GET is
            // then refused by the router. Either way nothing runs.
            let res = app
                .clone()
                .oneshot(request("GET", &path, None, None))
                .await
                .unwrap();
            assert_eq!(res.status(), StatusCode::UNAUTHORIZED, "GET {path}");

            let res = app_allowing
                .clone()
                .oneshot(request(
                    "GET",
                    &path,
                    Some(signed(&signer, HttpMethod::GET, &path, None)),
                    None,
                ))
                .await
                .unwrap();
            assert_eq!(
                res.status(),
                StatusCode::METHOD_NOT_ALLOWED,
                "authenticated GET {path}"
            );

            let res = app
                .clone()
                .oneshot(request("POST", &path, None, None))
                .await
                .unwrap();
            assert_eq!(
                res.status(),
                StatusCode::UNAUTHORIZED,
                "POST {path} without header"
            );
        }

        let body = format!(r#"{{"npub":"{PUBKEY}","amount_sats":21,"nwc":"{NWC}"}}"#);
        let res = app
            .clone()
            .oneshot(request("POST", "/set-user", None, Some(body.clone())))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

        let res = app
            .clone()
            .oneshot(request(
                "POST",
                "/set-user",
                Some("Bearer nope".into()),
                Some(body),
            ))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

        // Reads stay open.
        let res = app
            .oneshot(request("GET", &format!("/get-user/{PUBKEY}"), None, None))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
    }

    /// A correctly signed, allowlisted request may only touch the signer's
    /// own config; the same request aimed at another npub is forbidden.
    #[tokio::test]
    async fn router_enforces_ownership_and_allowlist() {
        let owner = Keys::generate();
        let stranger = Keys::generate();
        let state = init_state_allowing(&[owner.public_key()]);
        clear_database(&state);
        let app = crate::build_router(state);
        let me = owner.public_key();

        // Allowlisted key, resource belongs to someone else -> 403.
        let path = format!("/delete-user/{PUBKEY2}");
        let res = app
            .clone()
            .oneshot(request(
                "POST",
                &path,
                Some(signed(&owner, HttpMethod::POST, &path, None)),
                None,
            ))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::FORBIDDEN);

        // Valid signature but key not on the allowlist -> 403 before ownership.
        let path = format!("/delete-user/{}", stranger.public_key());
        let res = app
            .clone()
            .oneshot(request(
                "POST",
                &path,
                Some(signed(&stranger, HttpMethod::POST, &path, None)),
                None,
            ))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::FORBIDDEN);

        // Owner creates their config end to end through the router.
        let body = format!(r#"{{"npub":"{me}","amount_sats":21,"nwc":"{NWC}","emoji":"⚡"}}"#);
        let res = app
            .clone()
            .oneshot(request(
                "POST",
                "/set-user",
                Some(signed(&owner, HttpMethod::POST, "/set-user", Some(&body))),
                Some(body.clone()),
            ))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK, "{}", body_string(res).await);

        // Same body, header signed for a body of a different amount -> 401.
        let other =
            format!(r#"{{"npub":"{me}","amount_sats":1000000,"nwc":"{NWC}","emoji":"⚡"}}"#);
        let res = app
            .clone()
            .oneshot(request(
                "POST",
                "/set-user",
                Some(signed(&owner, HttpMethod::POST, "/set-user", Some(&other))),
                Some(body.clone()),
            ))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

        // Owner signs for their own npub but the JSON claims another npub -> 403.
        let spoof =
            format!(r#"{{"npub":"{PUBKEY2}","amount_sats":21,"nwc":"{NWC}","emoji":"⚡"}}"#);
        let res = app
            .clone()
            .oneshot(request(
                "POST",
                "/set-user",
                Some(signed(&owner, HttpMethod::POST, "/set-user", Some(&spoof))),
                Some(spoof),
            ))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::FORBIDDEN);

        // The stored config is readable and never echoes the NWC.
        let emoji = urlencoding::encode("⚡");
        let res = app
            .clone()
            .oneshot(request(
                "GET",
                &format!("/get-user/{me}/{emoji}"),
                None,
                None,
            ))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let text = body_string(res).await;
        assert!(text.contains("\"amount_sats\":21"), "{text}");
        assert!(!text.contains("secret="), "{text}");

        // Owner deletes their own config -> 200 and the config is gone.
        let path = format!("/delete-user/{me}/{emoji}");
        let res = app
            .clone()
            .oneshot(request(
                "POST",
                &path,
                Some(signed(&owner, HttpMethod::POST, &path, None)),
                None,
            ))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let res = app
            .oneshot(request(
                "GET",
                &format!("/get-user/{me}/{emoji}"),
                None,
                None,
            ))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::NOT_FOUND);
    }

    /// Every handler behind the auth layer that addresses a resource by npub
    /// must refuse an allowlisted key that is not that npub. One assertion
    /// per handler so removing any single `require_owner` call goes red.
    #[tokio::test]
    async fn router_every_owner_guard_is_enforced() {
        let owner = Keys::generate();
        let state = init_state_allowing(&[owner.public_key()]);
        clear_database(&state);
        let app = crate::build_router(state);
        let emoji = urlencoding::encode("⚡");

        // Body-less handlers: the victim npub is in the path.
        for path in [
            format!("/delete-user/{PUBKEY2}/{emoji}"),
            format!("/delete-subscription/{PUBKEY2}/{PUBKEY}"),
            format!("/delete-user/{PUBKEY2}"),
        ] {
            let res = app
                .clone()
                .oneshot(request(
                    "POST",
                    &path,
                    Some(signed(&owner, HttpMethod::POST, &path, None)),
                    None,
                ))
                .await
                .unwrap();
            assert_eq!(res.status(), StatusCode::FORBIDDEN, "POST {path}");
        }

        // Body handlers: the victim npub is in the JSON.
        let bodies = [
            (
                "/set-user",
                format!(r#"{{"npub":"{PUBKEY2}","amount_sats":21,"nwc":"{NWC}","emoji":"⚡"}}"#),
            ),
            (
                "/create-subscription",
                format!(
                    r#"{{"npub":"{PUBKEY2}","to_npub":"{PUBKEY}","amount_sats":21,"time_period":"day","nwc":"{NWC}"}}"#
                ),
            ),
        ];
        for (path, body) in bodies {
            let res = app
                .clone()
                .oneshot(request(
                    "POST",
                    path,
                    Some(signed(&owner, HttpMethod::POST, path, Some(&body))),
                    Some(body.clone()),
                ))
                .await
                .unwrap();
            assert_eq!(res.status(), StatusCode::FORBIDDEN, "POST {path} {body}");
        }

        // Nothing above may have written anything.
        let res = app
            .oneshot(request("GET", &format!("/get-user/{PUBKEY2}"), None, None))
            .await
            .unwrap();
        let text = body_string(res).await;
        assert!(text.contains(r#""zaps":[]"#), "{text}");
        assert!(text.contains(r#""subscriptions":[]"#), "{text}");
    }

    /// `/wallet-auth` creates state (DB row, derived key, relay filter) and is
    /// therefore POST-only behind the auth layer. Through the real router: no
    /// header -> 401, bad JSON -> 400 with no row written, valid -> 200 with
    /// the new key both in the response and on the listener channel.
    #[tokio::test]
    async fn router_wallet_auth_is_authenticated_and_bounded() {
        let owner = Keys::generate();
        let state = init_state_allowing(&[owner.public_key()]);
        clear_database(&state);
        let mut rx = state.auth_channel.lock().await.subscribe();
        let app = crate::build_router(state.clone());
        let rows = || -> i64 {
            use diesel::QueryDsl;
            crate::models::schema::wallet_auth::table
                .count()
                .get_result(&mut state.db_pool.get().unwrap())
                .unwrap()
        };
        let rows_before = rows();

        let res = app
            .clone()
            .oneshot(request("POST", "/wallet-auth", None, None))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

        let bad = r#"{"amount":"not a number"}"#.to_string();
        let res = app
            .clone()
            .oneshot(request(
                "POST",
                "/wallet-auth",
                Some(signed(&owner, HttpMethod::POST, "/wallet-auth", Some(&bad))),
                Some(bad),
            ))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
        assert!(
            !rx.has_changed().unwrap(),
            "bad params must not create a key"
        );
        assert_eq!(rows(), rows_before, "bad params must not insert a row");

        // No body: no budget.
        let res = app
            .clone()
            .oneshot(request(
                "POST",
                "/wallet-auth",
                Some(signed(&owner, HttpMethod::POST, "/wallet-auth", None)),
                None,
            ))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let text = body_string(res).await;
        let v: Value = serde_json::from_str(&text).unwrap();
        let id1 = PublicKey::from_str(v["id"].as_str().unwrap()).unwrap();
        assert!(v["uri"]
            .as_str()
            .unwrap()
            .starts_with("nostr+walletauth://"));
        assert!(!v["uri"].as_str().unwrap().contains("budget"), "{text}");
        assert!(rx.has_changed().unwrap());
        assert_eq!(rx.borrow_and_update().as_slice(), &[id1]);

        // Budget + identity in the body.
        let body = format!(r#"{{"time_period":"day","amount":1000,"identity":"{PUBKEY2}"}}"#);
        let res = app
            .clone()
            .oneshot(request(
                "POST",
                "/wallet-auth",
                Some(signed(
                    &owner,
                    HttpMethod::POST,
                    "/wallet-auth",
                    Some(&body),
                )),
                Some(body),
            ))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let v: Value = serde_json::from_str(&body_string(res).await).unwrap();
        let id2 = PublicKey::from_str(v["id"].as_str().unwrap()).unwrap();
        assert_ne!(id1, id2);
        assert!(v["uri"].as_str().unwrap().contains("budget=1000%2Fday"));
        assert!(v["uri"].as_str().unwrap().contains(PUBKEY2));
        assert_eq!(rx.borrow_and_update().as_slice(), &[id1, id2]);
        assert_eq!(rows(), rows_before + 2);

        // The pending key is checkable by anyone but not yet linked.
        let res = app
            .oneshot(request(
                "GET",
                &format!("/check-wallet-auth?id={id2}"),
                None,
                None,
            ))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);

        clear_database(&state);
    }

    #[test]
    fn pending_auth_list_dedupes_and_caps() {
        let mut list: Vec<PublicKey> = Vec::new();
        let first = Keys::generate().public_key();
        assert!(push_pending_auth(&mut list, first));
        assert!(!push_pending_auth(&mut list, first), "duplicate is a no-op");
        assert_eq!(list.len(), 1);

        while list.len() < MAX_PENDING_WALLET_AUTHS {
            assert!(push_pending_auth(&mut list, Keys::generate().public_key()));
        }
        assert_eq!(list[0], first);

        // One over the cap evicts the oldest, never grows past the cap.
        let newest = Keys::generate().public_key();
        assert!(push_pending_auth(&mut list, newest));
        assert_eq!(list.len(), MAX_PENDING_WALLET_AUTHS);
        assert!(!list.contains(&first));
        assert_eq!(*list.last().unwrap(), newest);
    }

    #[test]
    fn debug_output_never_contains_nwc_secret() {
        let nwc = NostrWalletConnectURI::from_str(NWC).unwrap();
        let secret_hex = nwc.secret.display_secret().to_string();

        let zap = SetUserConfig {
            npub: PublicKey::from_str(
                "e1ff3bfdd4e40315959b08b4fcc8245eaa514637e1d4ec2ae166b743341be1af",
            )
            .unwrap(),
            amount_sats: 21,
            nwc: Some(nwc.clone()),
            auth_id: None,
            emoji: None,
            donations: None,
        };
        let out = format!("{zap:?}");
        assert!(out.contains("<redacted>"), "{out}");
        assert!(!out.contains(&secret_hex), "{out}");
        assert!(!out.contains("secret="), "{out}");

        let sub = CreateUserSubscription {
            npub: zap.npub,
            to_npub: zap.npub,
            amount_sats: 21,
            time_period: SubscriptionPeriod::Day,
            nwc: Some(nwc),
            auth_id: None,
        };
        let out = format!("{sub:?}");
        assert!(out.contains("<redacted>"), "{out}");
        assert!(!out.contains(&secret_hex), "{out}");
        assert!(!out.contains("secret="), "{out}");
    }

    fn clear_database(state: &State) {
        let conn = &mut state.db_pool.get().unwrap();

        conn.transaction::<_, anyhow::Error, _>(|conn| {
            diesel::delete(crate::models::schema::zap_events::table).execute(conn)?;
            diesel::delete(crate::models::schema::donations::table).execute(conn)?;
            diesel::delete(crate::models::schema::subscription_configs::table).execute(conn)?;
            diesel::delete(crate::models::schema::zap_configs::table).execute(conn)?;
            diesel::delete(crate::models::schema::users::table).execute(conn)?;
            Ok(())
        })
        .unwrap();
    }

    #[tokio::test]
    async fn test_create_config() {
        let state = init_state();
        clear_database(&state);

        let npub = PublicKey::from_str(PUBKEY).unwrap();
        let nwc = NostrWalletConnectURI::from_str(NWC).unwrap();

        let payload = SetUserConfig {
            npub,
            amount_sats: 21,
            nwc: Some(nwc),
            auth_id: None,
            emoji: None,
            donations: None,
        };

        let current = set_user_config_impl(payload, &state).await.unwrap();

        let configs = get_user_configs_impl(npub, &state).unwrap();
        let configs = configs.zaps;

        assert_eq!(current.zaps, configs);
        assert_eq!(configs.len(), 1);
        assert_eq!(configs[0].npub, npub);
        assert_eq!(configs[0].amount_sats, 21);
        assert_eq!(configs[0].emoji(), "⚡");
        assert!(configs[0].donations.is_none());

        clear_database(&state);
    }

    #[tokio::test]
    async fn test_create_config_with_auth() {
        let state = init_state();
        clear_database(&state);

        let npub = PublicKey::from_str(PUBKEY).unwrap();

        let uri = wallet_auth_impl(&state, None).await.unwrap();

        // set dummy pubkey
        WalletAuth::add_user_data(
            &mut state.db_pool.get().unwrap(),
            uri.public_key,
            npub,
            None,
        )
        .unwrap();

        let payload = SetUserConfig {
            npub,
            amount_sats: 21,
            nwc: None,
            auth_id: Some(uri.public_key),
            emoji: None,
            donations: None,
        };

        let current = set_user_config_impl(payload, &state).await.unwrap();
        assert_eq!(current.zaps.len(), 1);

        clear_database(&state);
    }

    #[tokio::test]
    async fn test_create_config_overwrite_with_auth() {
        let state = init_state();
        clear_database(&state);

        let npub = PublicKey::from_str(PUBKEY).unwrap();

        // set using nwc first
        let nwc = NostrWalletConnectURI::from_str(NWC).unwrap();
        let payload = SetUserConfig {
            npub,
            amount_sats: 21,
            nwc: Some(nwc),
            auth_id: None,
            emoji: None,
            donations: None,
        };
        let current = set_user_config_impl(payload, &state).await.unwrap();
        assert_eq!(current.zaps.len(), 1);

        let uri = wallet_auth_impl(&state, None).await.unwrap();

        // set dummy pubkey
        WalletAuth::add_user_data(
            &mut state.db_pool.get().unwrap(),
            uri.public_key,
            npub,
            None,
        )
        .unwrap();

        let payload = SetUserConfig {
            npub,
            amount_sats: 21,
            nwc: None,
            auth_id: Some(uri.public_key),
            emoji: None,
            donations: None,
        };

        let current = set_user_config_impl(payload, &state).await.unwrap();
        assert_eq!(current.zaps.len(), 1);

        clear_database(&state);
    }

    #[tokio::test]
    async fn test_create_config_emojis() {
        let state = init_state();
        clear_database(&state);

        let npub = PublicKey::from_str(PUBKEY).unwrap();
        let nwc = NostrWalletConnectURI::from_str(NWC).unwrap();

        let emojis = ["⚡️", "🤙", "👍", "❤️", "🫂"];

        for emoji in emojis {
            let payload = SetUserConfig {
                npub,
                amount_sats: 21,
                nwc: Some(nwc.clone()),
                auth_id: None,
                emoji: Some(emoji.to_string()),
                donations: None,
            };

            set_user_config_impl(payload, &state).await.unwrap();
        }

        clear_database(&state);
    }

    #[tokio::test]
    async fn test_create_subscription() {
        let state = init_state();
        clear_database(&state);

        let npub = PublicKey::from_str(PUBKEY).unwrap();
        let to_npub = PublicKey::from_str(PUBKEY2).unwrap();

        let nwc = NostrWalletConnectURI::from_str(NWC).unwrap();

        let payload = CreateUserSubscription {
            npub,
            to_npub,
            amount_sats: 21,
            time_period: SubscriptionPeriod::Day,
            nwc: Some(nwc),
            auth_id: None,
        };

        let current = create_user_subscription_impl(payload, &state)
            .await
            .unwrap();

        let mut conn = state.db_pool.get().unwrap();
        let configs = get_user_subscriptions_impl(&mut conn, npub).unwrap();

        assert_eq!(current.subscriptions, configs);
        assert_eq!(configs.len(), 1);
        assert_eq!(configs[0].npub, npub);
        assert_eq!(configs[0].to_npub, to_npub);
        assert_eq!(configs[0].amount_sats, 21);
        assert_eq!(configs[0].time_period, SubscriptionPeriod::Day);

        clear_database(&state);
    }

    #[tokio::test]
    async fn test_create_subscription_overwrite_with_auth() {
        let state = init_state();
        clear_database(&state);

        let npub = PublicKey::from_str(PUBKEY).unwrap();
        let to_npub = PublicKey::from_str(PUBKEY2).unwrap();

        let nwc = NostrWalletConnectURI::from_str(NWC).unwrap();

        let payload = CreateUserSubscription {
            npub,
            to_npub,
            amount_sats: 21,
            time_period: SubscriptionPeriod::Day,
            nwc: Some(nwc),
            auth_id: None,
        };

        let current = create_user_subscription_impl(payload, &state)
            .await
            .unwrap();
        assert_eq!(current.subscriptions.len(), 1);

        let mut conn = state.db_pool.get().unwrap();
        let configs = get_user_subscriptions_impl(&mut conn, npub).unwrap();
        assert_eq!(configs.len(), 1);

        let uri = wallet_auth_impl(&state, None).await.unwrap();

        // set dummy pubkey
        WalletAuth::add_user_data(
            &mut state.db_pool.get().unwrap(),
            uri.public_key,
            npub,
            None,
        )
        .unwrap();

        let payload = CreateUserSubscription {
            npub,
            to_npub,
            amount_sats: 21,
            time_period: SubscriptionPeriod::Day,
            nwc: None,
            auth_id: Some(uri.public_key),
        };

        let current = create_user_subscription_impl(payload, &state)
            .await
            .unwrap();
        assert_eq!(current.subscriptions.len(), 1);

        clear_database(&state);
    }

    #[tokio::test]
    async fn test_delete_zap_config() {
        let state = init_state();
        clear_database(&state);

        let npub = PublicKey::from_str(PUBKEY).unwrap();
        let nwc = NostrWalletConnectURI::from_str(NWC).unwrap();
        let emoji = "⚡";

        let payload = SetUserConfig {
            npub,
            amount_sats: 21,
            nwc: Some(nwc),
            auth_id: None,
            emoji: None,
            donations: None,
        };

        let current = set_user_config_impl(payload, &state).await.unwrap();

        let configs = get_user_configs_impl(npub, &state).unwrap();
        let configs = configs.zaps;

        assert_eq!(current.zaps, configs);
        assert_eq!(configs.len(), 1);
        assert_eq!(configs[0].npub, npub);
        assert_eq!(configs[0].amount_sats, 21);
        assert_eq!(configs[0].emoji(), emoji);
        assert!(configs[0].donations.is_none());

        let mut conn = state.db_pool.get().unwrap();
        crate::models::delete_user_config(&mut conn, npub, emoji).unwrap();

        let configs = get_user_configs_impl(npub, &state).unwrap();
        assert_eq!(configs.zaps.len(), 0);

        clear_database(&state);
    }

    #[tokio::test]
    async fn test_delete_subscription() {
        let state = init_state();
        clear_database(&state);

        let npub = PublicKey::from_str(PUBKEY).unwrap();
        let to_npub = PublicKey::from_str(PUBKEY2).unwrap();

        let nwc = NostrWalletConnectURI::from_str(NWC).unwrap();

        let payload = CreateUserSubscription {
            npub,
            to_npub,
            amount_sats: 21,
            time_period: SubscriptionPeriod::Hour,
            nwc: Some(nwc),
            auth_id: None,
        };

        let current = create_user_subscription_impl(payload, &state)
            .await
            .unwrap();

        let mut conn = state.db_pool.get().unwrap();
        let configs = get_user_subscriptions_impl(&mut conn, npub).unwrap();

        assert_eq!(current.subscriptions, configs);
        assert_eq!(configs.len(), 1);
        assert_eq!(configs[0].npub, npub);
        assert_eq!(configs[0].to_npub, to_npub);
        assert_eq!(configs[0].amount_sats, 21);
        assert_eq!(configs[0].time_period, SubscriptionPeriod::Hour);

        crate::models::delete_user_subscription(&mut conn, npub, to_npub).unwrap();

        let subs = get_user_subscriptions_impl(&mut conn, npub).unwrap();
        assert_eq!(subs.len(), 0);

        clear_database(&state);
    }

    #[tokio::test]
    async fn test_delete_user() {
        let state = init_state();
        clear_database(&state);

        let npub = PublicKey::from_str(PUBKEY).unwrap();
        let to_npub = PublicKey::from_str(PUBKEY2).unwrap();

        let nwc = NostrWalletConnectURI::from_str(NWC).unwrap();

        let payload = CreateUserSubscription {
            npub,
            to_npub,
            amount_sats: 21,
            time_period: SubscriptionPeriod::Year,
            nwc: Some(nwc.clone()),
            auth_id: None,
        };

        let current = create_user_subscription_impl(payload, &state)
            .await
            .unwrap();

        let mut conn = state.db_pool.get().unwrap();
        let configs = get_user_subscriptions_impl(&mut conn, npub).unwrap();

        assert_eq!(current.subscriptions, configs);
        assert_eq!(configs.len(), 1);
        assert_eq!(configs[0].npub, npub);
        assert_eq!(configs[0].to_npub, to_npub);
        assert_eq!(configs[0].amount_sats, 21);
        assert_eq!(configs[0].time_period, SubscriptionPeriod::Year);

        let emojis = ["⚡️", "🤙", "👍", "❤️", "🫂"];

        for emoji in emojis {
            let payload = SetUserConfig {
                npub,
                amount_sats: 21,
                nwc: Some(nwc.clone()),
                auth_id: None,
                emoji: Some(emoji.to_string()),
                donations: None,
            };

            set_user_config_impl(payload, &state).await.unwrap();
        }

        crate::models::delete_user(&mut conn, npub).unwrap();

        let configs = get_user_configs_impl(npub, &state).unwrap();
        assert_eq!(configs.zaps.len(), 0);
        assert_eq!(configs.subscriptions.len(), 0);

        clear_database(&state);
    }
}
