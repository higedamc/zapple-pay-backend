use crate::LnUrlCacheResult;
use anyhow::anyhow;
use bitcoin::hashes::Hash;
use lightning_invoice::Bolt11Invoice;
use lnurl::lightning_address::LightningAddress;
use lnurl::lnurl::LnUrl;
use lnurl::pay::PayResponse;
use lnurl::LnUrlResponse::LnUrlPayResponse;
use lnurl::{AsyncClient, Builder};
use log::*;
use nostr::nips::nip47::{
    Method, NostrWalletConnectURI, PayInvoiceRequest, Request, RequestParams,
};
use nostr::prelude::ToBech32;
use nostr::{
    Event, EventBuilder, EventId, JsonUtil, Keys, Kind, Metadata, PublicKey, RelayUrl, Tag,
    TagStandard, Timestamp,
};
use nostr_sdk::Client;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::str::FromStr;
use std::time::Duration;
use tokio::sync::Mutex;

pub struct SentInvoice {
    pub payment_hash: [u8; 32],
    pub event_id: EventId,
}

pub async fn get_user_lnurl(
    user_key: PublicKey,
    lnurl_cache: &Mutex<HashMap<PublicKey, LnUrlCacheResult>>,
    lnurl_client: &AsyncClient,
) -> anyhow::Result<(LnUrl, Option<LnUrl>)> {
    let (cache_result, _timestamp) = {
        let cache = lnurl_cache.lock().await;
        let cache = cache.get(&user_key);
        match cache {
            None => (None, None),
            Some(either) => match either {
                LnUrlCacheResult::LnUrl((lnurl, timestamp)) => {
                    // if we got the lnurl more than 24 hours ago, return None
                    if Timestamp::now().as_secs() - timestamp > 60 * 60 * 24 {
                        (None, None)
                    } else {
                        (Some((lnurl.clone(), None)), None)
                    }
                }
                LnUrlCacheResult::MultipleLnUrl((lnurl, lnurl2, timestamp)) => {
                    // if we got the lnurl more than 24 hours ago, return None
                    if Timestamp::now().as_secs() - timestamp > 60 * 60 * 24 {
                        (None, None)
                    } else {
                        (Some((lnurl.clone(), Some(lnurl2.clone()))), None)
                    }
                }
                LnUrlCacheResult::Timestamp(timestamp) => (None, Some(*timestamp)),
            },
        }
    };
    let lnurl = match cache_result {
        Some(lnurl) => lnurl,
        None => {
            debug!("No lnurl in cache, fetching...");

            let metadata = get_nostr_profile(lnurl_client, user_key).await?;

            let mut lnurl: Option<LnUrl> = None;
            let mut lnurl2: Option<LnUrl> = None;

            // try parse lightning address
            let lud16 = metadata
                .lud16
                .and_then(|s| LightningAddress::from_str(&s).ok());
            if let Some(lnaddr) = lud16 {
                lnurl = Some(lnaddr.lnurl());
            }

            // try parse lnurl pay
            let lud06 = metadata.lud06.and_then(|s| LnUrl::from_str(&s).ok());
            if let Some(url) = lud06 {
                if lnurl.is_some() {
                    lnurl2 = Some(url);
                } else {
                    lnurl = Some(url);
                }
            }

            // handle None case
            let lnurl: LnUrl = match lnurl {
                None => {
                    let mut cache = lnurl_cache.lock().await;
                    cache.insert(
                        user_key,
                        LnUrlCacheResult::Timestamp(Timestamp::now().as_secs()),
                    );

                    return Err(anyhow!("Profile has no lnurl or lightning address"));
                }
                Some(lnurl) => lnurl,
            };

            let mut cache = lnurl_cache.lock().await;
            let now = Timestamp::now().as_secs();

            match lnurl2.as_ref() {
                None => cache.insert(user_key, LnUrlCacheResult::LnUrl((lnurl.clone(), now))),
                Some(lnurl2) => cache.insert(
                    user_key,
                    LnUrlCacheResult::MultipleLnUrl((lnurl.clone(), lnurl2.clone(), now)),
                ),
            };

            (lnurl, lnurl2)
        }
    };

    Ok(lnurl)
}

async fn get_invoice_from_lnurl(
    keys: &Keys,
    from_user: PublicKey,
    to_user: Option<PublicKey>,
    event_id: Option<EventId>,
    a_tag: Option<Tag>,
    lnurl: &LnUrl,
    lnurl_client: &AsyncClient,
    amount_msats: u64,
    pay_cache: &Mutex<HashMap<LnUrl, PayResponse>>,
) -> anyhow::Result<Bolt11Invoice> {
    let pay = {
        let cache_result = {
            let cache = pay_cache.lock().await;
            cache.get(lnurl).cloned()
        };
        match cache_result {
            Some(pay) => pay,
            None => {
                debug!("No pay in cache, fetching...");
                let resp = if lnurl.url.contains(".onion") {
                    let client = Builder::default().proxy("127.0.0.1:9050").build_async()?;
                    tokio::time::timeout(Duration::from_secs(30), client.make_request(&lnurl.url))
                        .await?
                } else {
                    tokio::time::timeout(
                        Duration::from_secs(30),
                        lnurl_client.make_request(&lnurl.url),
                    )
                    .await?
                };

                if let Ok(LnUrlPayResponse(pay)) = resp {
                    // don't cache voltage or coinos lnurls, they change everytime
                    if !lnurl.url.contains("vlt.ge") && !lnurl.url.contains("coinos.io") {
                        let mut cache = pay_cache.lock().await;
                        cache.insert(lnurl.clone(), pay.clone());
                    }
                    pay
                } else {
                    return Err(anyhow::anyhow!("Invalid lnurl response"));
                }
            }
        }
    };

    let zap_request = match to_user {
        None => None,
        Some(to_user) => {
            let mut tags = vec![
                Tag::public_key(to_user),
                Tag::from_standardized(TagStandard::Amount {
                    millisats: amount_msats,
                    bolt11: None,
                }),
                Tag::from_standardized(TagStandard::Lnurl(lnurl.to_string())),
                Tag::relays(RelayUrl::parse("wss://relay.damus.io").ok()),
            ];
            if let Some(event_id) = event_id {
                tags.push(Tag::event(event_id));
            }
            if let Some(a_tag) = a_tag {
                tags.push(a_tag);
            }
            let content = format!("From: nostr:{}", from_user.to_bech32().unwrap());
            EventBuilder::new(Kind::ZapRequest, content)
                .tags(tags)
                .sign_with_keys(keys)
                .ok()
        }
    };

    let invoice = {
        let res = {
            tokio::time::timeout(
                Duration::from_secs(30),
                lnurl_client.get_invoice(
                    &pay,
                    amount_msats,
                    zap_request.as_ref().map(|e| e.as_json()),
                    None,
                ),
            )
            .await?
        };

        let invoice_str = match res {
            Ok(inv) => inv.pr,
            Err(_) => {
                tokio::time::timeout(
                    Duration::from_secs(30),
                    lnurl_client.get_invoice(
                        &pay,
                        amount_msats,
                        zap_request.map(|e| urlencoding::encode(&e.as_json()).to_string()),
                        None,
                    ),
                )
                .await??
                .pr
            }
        };

        Bolt11Invoice::from_str(&invoice_str)?
    };

    if !invoice
        .amount_milli_satoshis()
        .is_some_and(|a| a == amount_msats)
    {
        return Err(anyhow::anyhow!(
            "Got invoice with invalid amount expected: {amount_msats} msats got: {:?} msats",
            invoice.amount_milli_satoshis()
        ));
    }

    Ok(invoice)
}

pub async fn pay_to_lnurl(
    keys: &Keys,
    from_user: PublicKey,
    to_user: Option<PublicKey>,
    event_id: Option<EventId>,
    a_tag: Option<Tag>,
    lnurl: (LnUrl, Option<LnUrl>),
    lnurl_client: &AsyncClient,
    amount_msats: u64,
    nwc: NostrWalletConnectURI,
    pay_cache: &Mutex<HashMap<LnUrl, PayResponse>>,
    client: Option<Client>,
) -> anyhow::Result<SentInvoice> {
    let invoice = match get_invoice_from_lnurl(
        keys,
        from_user,
        to_user,
        event_id,
        a_tag.clone(),
        &lnurl.0,
        lnurl_client,
        amount_msats,
        pay_cache,
    )
    .await
    {
        Ok(invoice) => invoice,
        Err(e) => match lnurl.1 {
            None => {
                return Err(anyhow!(
                    "Error getting invoice from lnurl ({}): {e}",
                    lnurl.0.url
                ));
            }
            Some(lnurl) => {
                get_invoice_from_lnurl(
                    keys,
                    from_user,
                    to_user,
                    event_id,
                    a_tag,
                    &lnurl,
                    lnurl_client,
                    amount_msats,
                    pay_cache,
                )
                .await?
            }
        },
    };

    let event = create_nwc_request(&nwc, invoice.to_string())?;

    let sent = SentInvoice {
        payment_hash: invoice.payment_hash().to_byte_array(),
        event_id: event.id,
    };

    let relay_url = crate::utils::nwc_relay(&nwc);
    match client {
        Some(client) => {
            client.send_event(&event).await?;
        }
        None => {
            let keys = Keys::new(nwc.secret.clone());
            let client = Client::new(keys);

            client.add_relay(&relay_url).await?;
            client.connect().await;

            client.send_event(&event).await?;
            client.disconnect().await;
        }
    };

    debug!("Sent event to {relay_url}");
    Ok(sent)
}

/// Build the NIP-47 `pay_invoice` request event, NIP-04 encrypted to the
/// wallet service and signed with the connection secret (as upstream did).
fn create_nwc_request(nwc: &NostrWalletConnectURI, invoice: String) -> anyhow::Result<Event> {
    let req = Request {
        method: Method::PayInvoice,
        params: RequestParams::PayInvoice(PayInvoiceRequest {
            id: None,
            invoice,
            amount: None,
        }),
    };

    Ok(req.to_event(nwc)?)
}

async fn get_nostr_profile(
    lnurl_client: &AsyncClient,
    pubkey: PublicKey,
) -> anyhow::Result<Metadata> {
    let body = json!(["user_profile", { "pubkey": pubkey.to_string() } ]);
    let data: Vec<Value> = lnurl_client
        .client
        .post("https://cache2.primal.net/api")
        .header("Content-Type", "application/json")
        .body(body.to_string())
        .send()
        .await?
        .json()
        .await?;

    if let Some(json) = data.first().cloned() {
        let event: Event = serde_json::from_value(json)?;
        if event.kind != Kind::Metadata {
            anyhow::bail!("Did not find user's profile");
        }

        let metadata: Metadata = serde_json::from_str(&event.content)?;
        return Ok(metadata);
    }

    Err(anyhow!("No data for user's profile"))
}
