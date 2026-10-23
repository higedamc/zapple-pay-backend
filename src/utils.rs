use crate::DEFAULT_AUTH_RELAY;
use bitcoin::bip32::Xpriv;
use bitcoin::hashes::{sha256, Hash};
use lazy_static::lazy_static;
use nostr::nips::nip47::NostrWalletConnectURI;
use nostr::{PublicKey, RelayUrl};
use regex::Regex;

lazy_static! {
    static ref LN_REG: Regex =
        Regex::new(r"^\u{26A1}[\u{FE00}-\u{FE0F}]?$").expect("Invalid regex");
}

pub fn map_emoji(emoji: &str) -> Option<&str> {
    match emoji {
        "❤" | "+" | "" => Some("❤️"),
        "⚡️" => Some("⚡"),
        str => {
            if LN_REG.is_match(str) {
                Some("⚡")
            } else {
                None
            }
        }
    }
}

/// Calculate the NWA secret from the xpriv and the public key
pub(crate) fn calculate_nwa_secret(xpriv: Xpriv, public_key: PublicKey) -> String {
    let mut bytes = xpriv.private_key.secret_bytes().to_vec();
    bytes.extend_from_slice(public_key.as_bytes());

    let hash = sha256::Hash::hash(&bytes);

    let mut str = hash.to_string();
    // Truncate to 16 characters, we don't need the full hash
    // and it keeps the QR code smaller
    str.truncate(16);
    str
}

/// The relay an NWC connection is driven over. A NIP-47 URI may list several
/// relays; this service has always used the first one, and falls back to the
/// default auth relay if the list is empty. Alby's legacy internal hostname is
/// remapped to its public relay, as upstream did.
pub(crate) fn nwc_relay(nwc: &NostrWalletConnectURI) -> RelayUrl {
    let url = nwc.relays.first().cloned().unwrap_or_else(|| {
        RelayUrl::parse(DEFAULT_AUTH_RELAY).expect("default auth relay is a valid relay url")
    });
    let legacy_alby = RelayUrl::parse("ws://alby-mainnet-nostr-relay/v1").ok();
    if legacy_alby.is_some_and(|alby| alby == url) {
        RelayUrl::parse("wss://relay.getalby.com/v1").expect("valid relay url")
    } else {
        url
    }
}

/// The relay to drive an NWA-linked wallet over: the relay the wallet named in
/// its confirmation, or the default auth relay when it named none or something
/// that is not a `ws(s)://` URL. The stored string comes from the wallet
/// service verbatim, so it must never be able to panic the payment loops.
pub(crate) fn relay_or_default(relay: Option<&str>) -> RelayUrl {
    match relay.map(RelayUrl::parse) {
        Some(Ok(url)) => url,
        Some(Err(e)) => {
            log::warn!("stored wallet relay is not a usable relay url, using default: {e}");
            RelayUrl::parse(DEFAULT_AUTH_RELAY).expect("default auth relay is a valid relay url")
        }
        None => {
            RelayUrl::parse(DEFAULT_AUTH_RELAY).expect("default auth relay is a valid relay url")
        }
    }
}
