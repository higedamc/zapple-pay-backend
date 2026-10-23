use crate::models::subscription_config::SubscriptionConfig;
use crate::models::wallet_auth::WalletAuth;
use crate::models::zap_config::ZapConfig;
use crate::models::zap_event::ZapEvent;
use crate::models::zap_event_to_subscription_config::ZapEventToSubscriptionConfig;
use crate::models::zap_event_to_zap_config::ZapEventToZapConfig;
use crate::models::ConfigType;
use crate::nip49::NIP49Confirmation;
use crate::profile_handler::{get_user_lnurl, pay_to_lnurl};
use crate::utils::map_emoji;
use crate::{utils, LnUrlCacheResult, DEFAULT_AUTH_RELAY};
use anyhow::anyhow;
use bitcoin::bip32::{ChildNumber, Xpriv};
use bitcoin::hashes::Hash;
use diesel::r2d2::{ConnectionManager, Pool};
use diesel::{Connection, PgConnection};
use lnurl::lnurl::LnUrl;
use lnurl::pay::PayResponse;
use lnurl::{AsyncClient, Builder};
use log::*;
use nostr::hashes::sha256;
use nostr::key::PublicKey;
use nostr::nips::nip04::decrypt;
use nostr::nips::nip47::{ErrorCode, Method, NIP47Error, Response, ResponseResult};
use nostr::{
    Alphabet, Event, EventId, Filter, Keys, Kind, RelayUrl, SecretKey, SingleLetterTag,
    SubscriptionId, Tag, TagKind, TagStandard, Tags, Timestamp, SECP256K1,
};
use nostr_sdk::{Client, RelayPoolNotification};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch::Receiver;
use tokio::sync::Mutex;

/// NWA confirmation events (NIP-47 wallet auth), addressable, `d` = app pubkey.
const NWA_KIND: Kind = Kind::Custom(33194);

/// Fixed id for the NWA confirmation subscription. A REQ with an existing id
/// replaces that subscription on the relay, so updating the pending-key list
/// never stacks subscriptions.
const NWA_SUBSCRIPTION: &str = "zapple-pay-nwa";

const KINDS: [Kind; 5] = [
    Kind::Reaction,
    Kind::TextNote,
    Kind::LiveEventMessage,
    Kind::WalletConnectResponse,
    NWA_KIND,
];

fn check_event(event: &Event) -> bool {
    KINDS.contains(&event.kind)
        && event.tags.iter().any(|tag| {
            matches!(
                tag.as_standardized(),
                Some(TagStandard::PublicKey {
                    uppercase: false,
                    ..
                }) | Some(TagStandard::Identifier(_))
            )
        })
}

/// The last `e` tag, i.e. the note a reaction or reply addresses (NIP-10).
fn last_event_tag(tags: &Tags) -> Option<EventId> {
    tags.iter()
        .rev()
        .find_map(|tag| match tag.as_standardized() {
            Some(TagStandard::Event { event_id, .. }) => Some(*event_id),
            _ => None,
        })
}

/// The last lowercase `p` tag, i.e. the author being reacted to.
fn last_pubkey_tag(tags: &Tags) -> Option<PublicKey> {
    tags.iter()
        .rev()
        .find_map(|tag| match tag.as_standardized() {
            Some(TagStandard::PublicKey {
                public_key,
                uppercase: false,
                ..
            }) => Some(*public_key),
            _ => None,
        })
}

fn nwa_filter(auth_keys: &[PublicKey]) -> Filter {
    Filter::new()
        .kind(NWA_KIND)
        .identifiers(auth_keys.iter().map(|k| k.to_string()))
}

/// Update the NWA confirmation filter under the fixed id on the live
/// connection. A REQ with an existing id replaces that subscription on the
/// relay; an empty pending list drops it instead of sending an empty `#d`.
/// `auth_keys` is capped at `MAX_PENDING_WALLET_AUTHS`, so it always fits
/// one filter. A relay that is disconnected at this moment keeps its previous
/// NWA filter until the next update or the hourly restart.
async fn update_nwa_subscription(
    client: &Client,
    id: &SubscriptionId,
    auth_keys: &[PublicKey],
) -> anyhow::Result<()> {
    if auth_keys.is_empty() {
        client.unsubscribe(id).await;
        return Ok(());
    }
    let out = client
        .subscribe_with_id(id.clone(), nwa_filter(auth_keys), None)
        .await?;
    if !out.failed.is_empty() {
        warn!("NWA subscription update not delivered to: {:?}", out.failed);
    }
    Ok(())
}

pub async fn start_listener(
    mut relays: Vec<String>,
    db_pool: Pool<ConnectionManager<PgConnection>>,
    mut pubkey_receiver: Receiver<Vec<PublicKey>>,
    mut secret_receiver: Receiver<Vec<PublicKey>>,
    mut auth_receiver: Receiver<Vec<PublicKey>>,
    keys: Keys,
    xpriv: Xpriv,
    lnurl_cache: Arc<Mutex<HashMap<PublicKey, LnUrlCacheResult>>>,
    pay_cache: Arc<Mutex<HashMap<LnUrl, PayResponse>>>,
) -> anyhow::Result<()> {
    debug!("Using relays: {:?}", relays);
    let lnurl_client = Builder::default().build_async()?;

    loop {
        let client = Client::new(keys.clone());

        let mut conn = db_pool.get()?;
        let nwc_relays = ZapConfig::get_nwc_relays(&mut conn)?;
        drop(conn);
        relays.extend(nwc_relays.into_keys().map(|r| r.to_string()));
        relays.push(DEFAULT_AUTH_RELAY.to_string());
        relays.sort();
        relays.dedup();

        let tagged: Vec<PublicKey> = secret_receiver.borrow().clone();
        let authors: Vec<PublicKey> = pubkey_receiver.borrow().clone();

        let auth_keys: Vec<PublicKey> = auth_receiver.borrow().clone();

        let now = Timestamp::now();

        // filters for reactions
        let mut filters: Vec<Filter> = authors
            .chunks(250)
            .map(|keys| {
                Filter::new()
                    .kinds(KINDS.to_vec())
                    .authors(keys.to_vec())
                    .since(now)
            })
            .collect();

        // filters for responses
        filters.extend(tagged.chunks(250).map(|keys| {
            Filter::new()
                .kind(Kind::WalletConnectResponse)
                .pubkeys(keys.to_vec())
                .since(now)
        }));

        // Register every subscription with the pool *before* adding relays.
        // A relay added afterwards inherits them and sends the REQs itself on
        // every (re)connect, so a relay that is down at startup or drops
        // later still ends up subscribed. (Subscribing after `connect()`
        // would only reach relays whose socket is already up: the pool
        // remembers a REQ per relay only once it was sent successfully.)
        // One subscription per filter: the SDK no longer batches filters
        // into a single REQ.
        let pool = client.pool();
        for (i, filter) in filters.into_iter().enumerate() {
            pool.save_subscription(SubscriptionId::new(format!("zapple-pay-{i}")), vec![filter])
                .await;
        }
        let nwa_id = SubscriptionId::new(NWA_SUBSCRIPTION);
        if !auth_keys.is_empty() {
            pool.save_subscription(nwa_id.clone(), vec![nwa_filter(&auth_keys)])
                .await;
        }

        for relay in relays.iter() {
            if relay.is_empty() {
                continue;
            }
            if relay.contains("localhost") {
                continue;
            }
            client.add_relay(relay.as_str()).await?;
        }
        client.connect().await;

        info!("Listening for events...");

        let mut notifications = client.notifications();
        loop {
            tokio::select! {
                Ok(notification) = notifications.recv() => {
                    match notification {
                        RelayPoolNotification::Event { event, .. } => {
                            if check_event(&event) {
                                tokio::spawn({
                                    let db_pool = db_pool.clone();
                                    let lnurl_client = lnurl_client.clone();
                                    let keys = keys.clone();
                                    let lnurl_cache = lnurl_cache.clone();
                                    let pay_cache = pay_cache.clone();
                                    async move {
                                        let fut = handle_event(
                                            &db_pool,
                                            &lnurl_client,
                                            *event,
                                            &keys,
                                            xpriv,
                                            lnurl_cache.clone(),
                                            pay_cache.clone(),
                                        );

                                        match tokio::time::timeout(Duration::from_secs(30), fut).await {
                                            Ok(Ok(_)) => {}
                                            Ok(Err(e)) => error!("Error: {e}"),
                                            Err(_) => error!("Timeout"),
                                        }
                                    }
                                });
                            }
                        }
                        RelayPoolNotification::Shutdown => {
                            warn!("Relay pool shutdown");
                            break;
                        }
                        RelayPoolNotification::Message { .. } => {}
                    }
                }
                _ = pubkey_receiver.changed() => {
                    break;
                }
                _ = secret_receiver.changed() => {
                    break;
                }
                _ = auth_receiver.changed() => {
                    let auth_keys: Vec<PublicKey> = auth_receiver.borrow().clone();
                    if let Err(e) = update_nwa_subscription(&client, &nwa_id, &auth_keys).await {
                        // Reconnect: the outer loop rebuilds every subscription
                        // from the receivers' current state.
                        warn!("NWA subscription update failed, reconnecting: {e}");
                        break;
                    }
                }
            }
        }

        client.disconnect().await;
    }
}

async fn handle_event(
    db_pool: &Pool<ConnectionManager<PgConnection>>,
    lnurl_client: &AsyncClient,
    event: Event,
    keys: &Keys,
    xpriv: Xpriv,
    lnurl_cache: Arc<Mutex<HashMap<PublicKey, LnUrlCacheResult>>>,
    pay_cache: Arc<Mutex<HashMap<LnUrl, PayResponse>>>,
) -> anyhow::Result<()> {
    event.verify()?;

    match event.kind {
        kind if kind == NWA_KIND => handle_auth_response(db_pool, xpriv, event).await,
        Kind::WalletConnectResponse => handle_nwc_response(db_pool, event).await,
        Kind::TextNote | Kind::Reaction => {
            handle_reaction(
                db_pool,
                lnurl_client,
                event,
                keys,
                xpriv,
                lnurl_cache,
                pay_cache,
            )
            .await
        }
        Kind::LiveEventMessage => {
            handle_live_chat(
                db_pool,
                lnurl_client,
                event,
                keys,
                xpriv,
                lnurl_cache,
                pay_cache,
            )
            .await
        }
        Kind::Metadata => Ok(()),
        kind => Err(anyhow!("Invalid event kind, got: {kind:?}")),
    }
}

// struct for handling alby not sending result type
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseNoType {
    /// Request Method
    pub result_type: Option<String>,
    /// NIP47 Error
    pub error: Option<NIP47Error>,
    /// NIP47 Result
    pub result: Option<Value>,
}

impl ResponseNoType {
    pub fn into_response(mut self) -> anyhow::Result<Response> {
        if self
            .result_type
            .as_ref()
            .filter(|s| !s.is_empty())
            .is_none()
        {
            self.result_type = Some("pay_invoice".to_string());
        }
        let json = json!(self);
        let res: Response = serde_json::from_value(json)?;
        Ok(res)
    }
}

async fn handle_auth_response(
    db_pool: &Pool<ConnectionManager<PgConnection>>,
    xpriv: Xpriv,
    event: Event,
) -> anyhow::Result<()> {
    trace!("Received auth response: {}", event.id);

    let d_tag = event
        .tags
        .iter()
        .find_map(|tag| match tag.as_standardized() {
            Some(TagStandard::Identifier(pk)) => PublicKey::from_str(pk).ok(),
            _ => None,
        });
    let d_tag = match d_tag {
        Some(pk) => pk,
        None => return Err(anyhow!("No d tag found")),
    };

    let mut conn = db_pool.get()?;
    let Some(auth) = WalletAuth::get_by_pubkey(&mut conn, d_tag)? else {
        return Err(anyhow!("No auth found"));
    };
    if auth.user_pubkey().is_some() {
        return Err(anyhow!("Auth already has user_pubkey"));
    }

    let secret: SecretKey = xpriv
        .derive_priv(
            SECP256K1,
            &[ChildNumber::from_hardened_idx(auth.index as u32).unwrap()],
        )
        .unwrap()
        .private_key
        .into();
    let content = decrypt(&secret, &event.pubkey, &event.content)?;
    let confirmation: NIP49Confirmation = serde_json::from_str(&content)?;

    if !confirmation.commands.contains(&Method::PayInvoice) {
        return Err(anyhow!("Invalid confirmation, missing pay_invoice"));
    }
    if confirmation.secret != utils::calculate_nwa_secret(xpriv, auth.pubkey()) {
        return Err(anyhow!("Invalid secret"));
    }

    // The wallet's preferred relay is stored verbatim and later fed to
    // RelayUrl::parse; keep only values that will parse so the payment
    // loops never meet an unusable string.
    let relay = confirmation.relay.filter(|r| match RelayUrl::parse(r) {
        Ok(_) => true,
        Err(e) => {
            warn!("ignoring unusable relay in NWA confirmation: {e}");
            false
        }
    });
    WalletAuth::add_user_data(&mut conn, d_tag, event.pubkey, relay)?;

    info!("Successfully registered with Nostr Wallet Auth");

    Ok(())
}

async fn handle_nwc_response(
    db_pool: &Pool<ConnectionManager<PgConnection>>,
    event: Event,
) -> anyhow::Result<()> {
    trace!("Received nwc response: {}", event.id);

    let event_id = last_event_tag(&event.tags).ok_or(anyhow!("No e tag found"))?;

    let mut conn = db_pool.get()?;

    let Some(zap_event) = ZapEvent::find_by_event_id(&mut conn, event_id)? else {
        return Ok(());
    };

    let content = decrypt(&zap_event.secret_key(), &event.pubkey, &event.content)?;
    let response: ResponseNoType = serde_json::from_str(&content).map_err(|e| {
        error!("Error parsing response: {content}");
        e
    })?;
    let response = response.into_response()?;

    if response.result_type != Method::PayInvoice {
        return Ok(());
    }

    if let Some(e) = response.error {
        // this means the user deleted it from alby, safe to delete from db
        if matches!(e.code, ErrorCode::Unauthorized)
            && e.message == "The public key does not have a wallet connected."
        {
            let mut conn = db_pool.get()?;
            conn.transaction::<_, anyhow::Error, _>(|conn| {
                let event_opt = ZapEvent::delete_by_event_id(conn, event_id)?;

                if let Some(event) = event_opt {
                    match event.config_type() {
                        ConfigType::Zap => {
                            if let Some(to) =
                                ZapEventToZapConfig::find_by_zap_event_id(conn, event.id)?
                            {
                                ZapConfig::delete_by_id(conn, to.zap_config_id)?;
                                info!("Deleted user's zap config");
                            }
                        }
                        ConfigType::Subscription => {
                            if let Some(to) =
                                ZapEventToSubscriptionConfig::find_by_zap_event_id(conn, event.id)?
                            {
                                SubscriptionConfig::delete_by_id(conn, to.subscription_config_id)?;
                                info!("Deleted user's subscription config");
                            }
                        }
                    }
                }

                Ok(())
            })?;
        }

        return Err(anyhow!(
            "Received error, code: {:?}, message: {}",
            e.code,
            e.message
        ));
    }

    if let Some(ResponseResult::PayInvoice(res)) = response.result {
        let preimage: [u8; 32] = hex::decode(&res.preimage)?
            .try_into()
            .map_err(|_| anyhow!("Invalid preimage length"))?;

        if sha256::Hash::hash(&preimage).to_string() == zap_event.payment_hash {
            debug!("Payment successful: {}", zap_event.payment_hash);
            ZapEvent::mark_zap_paid(&mut conn, event_id, event.created_at)?;
        } else {
            return Err(anyhow!("Invalid preimage"));
        }
    }

    Ok(())
}

async fn handle_live_chat(
    db_pool: &Pool<ConnectionManager<PgConnection>>,
    lnurl_client: &AsyncClient,
    event: Event,
    keys: &Keys,
    xpriv: Xpriv,
    lnurl_cache: Arc<Mutex<HashMap<PublicKey, LnUrlCacheResult>>>,
    pay_cache: Arc<Mutex<HashMap<LnUrl, PayResponse>>>,
) -> anyhow::Result<()> {
    let event_id = last_event_tag(&event.tags);
    let p_tag = last_pubkey_tag(&event.tags);

    // if no p tag we are zapping the streamer, need to get pubkey from a tag
    let (user_key, a_tag) = match p_tag {
        Some(p) => (p, None),
        None => {
            let a_tag: Option<Tag> = event
                .tags
                .iter()
                .rev()
                .find(|t| {
                    t.kind() == TagKind::SingleLetter(SingleLetterTag::lowercase(Alphabet::A))
                })
                .cloned();
            let user_key = a_tag.as_ref().and_then(|tag| {
                let kpi: Vec<&str> = tag.as_slice().get(1)?.split(':').collect();
                let kind = Kind::from_str(kpi.first()?).ok();
                let pk = PublicKey::from_str(kpi.get(1)?).ok();

                if kind.is_some_and(|k| k.as_u16() == 30311) {
                    pk
                } else {
                    None
                }
            });

            match user_key {
                Some(pk) => (pk, a_tag),
                None => return Err(anyhow!("No a tag found")),
            }
        }
    };

    pay_user(
        user_key,
        event_id,
        a_tag,
        db_pool,
        lnurl_client,
        event,
        keys,
        xpriv,
        lnurl_cache,
        pay_cache,
    )
    .await
}

async fn handle_reaction(
    db_pool: &Pool<ConnectionManager<PgConnection>>,
    lnurl_client: &AsyncClient,
    event: Event,
    keys: &Keys,
    xpriv: Xpriv,
    lnurl_cache: Arc<Mutex<HashMap<PublicKey, LnUrlCacheResult>>>,
    pay_cache: Arc<Mutex<HashMap<LnUrl, PayResponse>>>,
) -> anyhow::Result<()> {
    let event_id = last_event_tag(&event.tags);
    let p_tag = last_pubkey_tag(&event.tags);

    let p_tag = match p_tag {
        None => return Err(anyhow!("No p tag found")),
        Some(p) => p,
    };

    pay_user(
        p_tag,
        event_id,
        None,
        db_pool,
        lnurl_client,
        event,
        keys,
        xpriv,
        lnurl_cache,
        pay_cache,
    )
    .await
}

async fn pay_user(
    user_key: PublicKey,
    event_id: Option<EventId>,
    a_tag: Option<Tag>,
    db_pool: &Pool<ConnectionManager<PgConnection>>,
    lnurl_client: &AsyncClient,
    event: Event,
    keys: &Keys,
    xpriv: Xpriv,
    lnurl_cache: Arc<Mutex<HashMap<PublicKey, LnUrlCacheResult>>>,
    pay_cache: Arc<Mutex<HashMap<LnUrl, PayResponse>>>,
) -> anyhow::Result<()> {
    let content = if event.kind == Kind::Reaction {
        map_emoji(&event.content).unwrap_or(&event.content)
    } else {
        &event.content
    };

    let mut conn = db_pool.get()?;
    if let Some(user) = crate::models::get_user_zap_config(&mut conn, event.pubkey, content)? {
        debug!(
            "Received reaction: {} {} {}",
            event.id, event.content, event.pubkey
        );

        let (user_nwc_key, relay) = if let Some(auth_index) = user.zap_config.auth_index {
            let (key, relay) = WalletAuth::get_user_data(&mut conn, auth_index)?
                .ok_or(anyhow!("No user pubkey found"))?;
            (Some(key), relay)
        } else {
            (None, None)
        };

        let nwc = user.zap_config.nwc(xpriv, user_nwc_key, relay.as_deref());

        let lnurl = get_user_lnurl(user_key, &lnurl_cache, lnurl_client).await?;

        // pay to lnurl
        let sent = pay_to_lnurl(
            keys,
            event.pubkey,
            Some(user_key),
            event_id,
            a_tag,
            lnurl,
            lnurl_client,
            user.zap_config.amount_msats(),
            nwc.clone(),
            &pay_cache,
            None,
        )
        .await?;
        // pay donations too
        let mut futs = vec![];
        for donation in user.donations {
            let (lnurl, to_user) = match donation.lnurl() {
                Some(lnurl) => ((lnurl, None), None),
                None => {
                    let npub = donation.npub().unwrap();
                    let lnurl = get_user_lnurl(npub, &lnurl_cache, lnurl_client).await?;

                    (lnurl, Some(npub))
                }
            };

            futs.push(pay_to_lnurl(
                keys,
                event.pubkey,
                to_user,
                None,
                None,
                lnurl,
                lnurl_client,
                donation.amount_msats(),
                nwc.clone(),
                &pay_cache,
                None,
            ));
        }
        futures::future::join_all(futs).await;

        // save to db
        conn.transaction::<_, anyhow::Error, _>(|conn| {
            let event = ZapEvent::create_zap_event(
                conn,
                &user_key,
                &event.pubkey,
                ConfigType::Zap,
                user.zap_config.amount,
                nwc.secret,
                sent.payment_hash,
                sent.event_id,
            )?;

            ZapEventToZapConfig::new(conn, event.id, user.zap_config.id)?;

            Ok(())
        })?;

        info!(
            "Successful reaction: {} {} {}",
            event.id, event.content, event.pubkey
        );
    } else {
        if log_enabled!(Level::Debug) {
            let truncated: String = content.chars().take(5).collect();
            // if we truncated, add ...
            if content != truncated {
                debug!("Config not found: {} {truncated}…", event.pubkey)
            } else {
                debug!("Config not found: {} {truncated}", event.pubkey)
            };
        }

        return Ok(());
    }

    Ok(())
}

#[cfg(test)]
mod test {
    use super::ResponseNoType;
    use nostr::nips::nip47::{ErrorCode, Method, ResponseResult};
    use nostr::JsonUtil;

    /// Wire compatibility of NWC response parsing, which now goes through the
    /// nostr crate's custom `Response` deserializer: Alby omits `result_type`
    /// on pay_invoice replies, and error replies carry `result: null`.
    #[test]
    fn nwc_response_parsing_survives_missing_result_type_and_errors() {
        let alby: ResponseNoType =
            serde_json::from_str(r#"{"result":{"preimage":"00ff"},"error":null}"#).unwrap();
        let res = alby.into_response().unwrap();
        assert_eq!(res.result_type, Method::PayInvoice);
        assert!(res.error.is_none());
        match res.result {
            Some(ResponseResult::PayInvoice(p)) => assert_eq!(p.preimage, "00ff"),
            other => panic!("unexpected result: {other:?}"),
        }

        let err: ResponseNoType = serde_json::from_str(
            r#"{"result_type":"pay_invoice","error":{"code":"UNAUTHORIZED","message":"The public key does not have a wallet connected."},"result":null}"#,
        )
        .unwrap();
        let res = err.into_response().unwrap();
        assert_eq!(res.result_type, Method::PayInvoice);
        assert!(res.result.is_none());
        let e = res.error.unwrap();
        assert!(matches!(e.code, ErrorCode::Unauthorized));
        assert_eq!(
            e.message,
            "The public key does not have a wallet connected."
        );

        // A reply for another method is parsed but not treated as a payment.
        let other: ResponseNoType =
            serde_json::from_str(r#"{"result_type":"get_balance","result":{"balance":1000}}"#)
                .unwrap();
        let res = other.into_response().unwrap();
        assert_ne!(res.result_type, Method::PayInvoice);
    }

    #[test]
    fn test_check_event() {
        let event = nostr::Event::from_json("{\"content\":\"NZEQvjoWGaWiNH7acJ5dnX24yJcPJIW7t1q3nQhVOlG8OWdNvXpf8LU1oi/Nwaq2SDHLVfKozWeO2PqhWZPOmUY66benQqLim0uzsc/6xTwsIPIhStIS+BReRWGGl+0+?iv=6lbXMUOWN3qr1yMn2rlalg==\",\"created_at\":1709993795,\"id\":\"02dceaaffacdafb02baf936a4dc88cb1ee55cbf60285eb956269509300a17a19\",\"kind\":33194,\"pubkey\":\"6068cf95000cdd712c1dff283a6c863a4b12c14f94cc0985347b7a0cda3cebf2\",\"sig\":\"e9dc03abf83e5373f97d43099ba97c231dbf693e0fb180c08cf8116c85482bea4217095035db5cec0b809813c8d8f552ca57ff806c21478158c45316125f1782\",\"tags\":[[\"d\",\"a2a483c521c94f9903dde4192ec7f15861c1b935f894eee215274255cfe9dad7\"]]}").unwrap();

        assert!(event.verify().is_ok());
        assert!(super::check_event(&event));
        assert_eq!(event.kind, super::NWA_KIND);
        assert_eq!(event.kind.as_u16(), 33194);
    }
}
