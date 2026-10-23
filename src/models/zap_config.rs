use crate::models::schema::zap_configs::dsl;
use crate::utils::map_emoji;
use bitcoin::bip32::{ChildNumber, Xpriv};
use diesel::prelude::*;
use nostr::prelude::NostrWalletConnectURI;
use nostr::SecretKey;
use nostr::{PublicKey, RelayUrl, SECP256K1};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::str::FromStr;

use super::schema::users;
use super::schema::zap_configs;

#[derive(
    Associations,
    Queryable,
    Insertable,
    Identifiable,
    AsChangeset,
    Serialize,
    Deserialize,
    Clone,
    PartialEq,
)]
#[diesel(primary_key(id))]
#[diesel(belongs_to(crate::models::user::User, foreign_key = user_id))]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct ZapConfig {
    pub id: i32,
    pub user_id: i32,
    pub emoji: String,
    pub amount: i32,
    #[serde(skip_serializing)]
    nwc: Option<String>,
    created_at: chrono::NaiveDateTime,
    pub auth_index: Option<i32>,
}

/// Manual `Debug` with the NWC field redacted. `nwc` here is the raw
/// connection string (wallet spend authority) as a plain `String`, so a derived
/// `Debug` would print the secret verbatim. Nothing formats this struct with
/// `{:?}` today; the impl exists so that can never become a leak.
impl std::fmt::Debug for ZapConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ZapConfig")
            .field("id", &self.id)
            .field("user_id", &self.user_id)
            .field("emoji", &self.emoji)
            .field("amount", &self.amount)
            .field("nwc", &self.nwc.as_ref().map(|_| "<redacted>"))
            .field("created_at", &self.created_at)
            .field("auth_index", &self.auth_index)
            .finish()
    }
}

#[derive(Insertable, AsChangeset)]
#[diesel(table_name = zap_configs)]
#[diesel(treat_none_as_null = true)]
pub struct NewZapConfig<'a> {
    pub user_id: i32,
    pub emoji: &'a str,
    pub amount: i32,
    pub nwc: Option<String>,
    pub auth_index: Option<i32>,
}

impl ZapConfig {
    pub fn nwc(
        &self,
        xpriv: Xpriv,
        user_public_key: Option<PublicKey>,
        relay: Option<&str>,
    ) -> NostrWalletConnectURI {
        match (self.nwc.as_deref(), self.auth_index) {
            (Some(str), None) => NostrWalletConnectURI::from_str(str).unwrap(),
            (None, Some(index)) => {
                let secret = xpriv
                    .derive_priv(
                        SECP256K1,
                        &[ChildNumber::from_hardened_idx(index as u32).unwrap()],
                    )
                    .unwrap()
                    .private_key;

                NostrWalletConnectURI::new(
                    user_public_key.expect("Missing user public key from database"),
                    vec![crate::utils::relay_or_default(relay)],
                    secret.into(),
                    None,
                )
            }
            _ => panic!("Invalid ZapConfig"),
        }
    }

    pub fn amount_msats(&self) -> u64 {
        (self.amount * 1_000) as u64
    }

    pub fn get_config_count(conn: &mut PgConnection) -> anyhow::Result<i64> {
        let count = zap_configs::table.count().get_result(conn)?;
        Ok(count)
    }

    pub fn get_nwc_secrets(conn: &mut PgConnection) -> anyhow::Result<Vec<SecretKey>> {
        let strings: Vec<Option<String>> = zap_configs::table
            .select(zap_configs::nwc)
            .filter(zap_configs::nwc.is_not_null())
            .distinct()
            .load(conn)?;
        let mut secrets: Vec<SecretKey> = strings
            .into_iter()
            .flatten()
            .filter_map(|s| NostrWalletConnectURI::from_str(&s).ok())
            .map(|nwc| nwc.secret)
            .collect();

        secrets.sort_by_key(|s| s.secret_bytes());
        secrets.dedup();

        Ok(secrets)
    }

    pub fn get_nwc_relays(conn: &mut PgConnection) -> anyhow::Result<HashMap<RelayUrl, usize>> {
        let strings: Vec<Option<String>> = zap_configs::table
            .select(zap_configs::nwc)
            .filter(zap_configs::nwc.is_not_null())
            .distinct()
            .load(conn)?;
        let relays: Vec<RelayUrl> = strings
            .into_iter()
            .flatten()
            .filter_map(|s| NostrWalletConnectURI::from_str(&s).ok())
            .map(|nwc| crate::utils::nwc_relay(&nwc))
            .filter(|u| !u.to_string().contains("mutinywallet")) // these are dead/old
            .collect();

        // count the relays
        let mut counts = HashMap::with_capacity(relays.len());
        for relay in relays {
            counts.entry(relay).and_modify(|c| *c += 1).or_insert(1);
        }

        Ok(counts)
    }

    pub fn get_by_pubkey(conn: &mut PgConnection, pubkey: &PublicKey) -> anyhow::Result<Vec<Self>> {
        let configs = zap_configs::table
            .inner_join(users::table)
            .filter(users::npub.eq(pubkey.to_string()))
            .select(dsl::zap_configs::all_columns())
            .load::<Self>(conn)?;

        Ok(configs)
    }

    pub fn get_by_pubkey_and_emoji(
        conn: &mut PgConnection,
        pubkey: &PublicKey,
        emoji: &str,
    ) -> anyhow::Result<Option<Self>> {
        let table = zap_configs::table
            .filter(zap_configs::emoji.eq(emoji))
            .or_filter(zap_configs::emoji.eq(emoji));

        Ok(table
            .inner_join(users::table)
            .filter(users::npub.eq(pubkey.to_string()))
            .select(dsl::zap_configs::all_columns())
            .first::<Self>(conn)
            .optional()?)
    }

    pub fn delete_by_id(conn: &mut PgConnection, id: i32) -> anyhow::Result<usize> {
        let count =
            diesel::delete(zap_configs::table.filter(zap_configs::id.eq(id))).execute(conn)?;
        Ok(count)
    }

    pub fn migrate_emojis(conn: &mut PgConnection) -> anyhow::Result<usize> {
        conn.transaction(|conn| {
            let all = zap_configs::table.load::<Self>(conn)?;

            let mut count: usize = 0;
            for z in all {
                if let Some(emoji) = map_emoji(&z.emoji) {
                    if emoji != z.emoji {
                        let updated = diesel::update(zap_configs::table)
                            .filter(zap_configs::id.eq(z.id))
                            .set(zap_configs::emoji.eq(emoji))
                            .execute(conn)?;

                        if updated > 1 {
                            anyhow::bail!("Updated more rows than expected: {updated}");
                        }

                        count += updated;
                    }
                }
            }

            Ok(count)
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;

    const NWC: &str = "nostr+walletconnect://246be70a7e4966f138e9e48401f33c32a1c428bbfb7aab42e3946beb8bc15e7c?relay=wss%3A%2F%2Frelay.damus.io%2F&secret=23ea701003500d852ba2756460099217f839e1fbc9665e493b56bd2d5912e31b";

    #[test]
    fn debug_output_never_contains_nwc() {
        let config = ZapConfig {
            id: 1,
            user_id: 1,
            emoji: "⚡".to_string(),
            amount: 21,
            nwc: Some(NWC.to_string()),
            created_at: chrono::NaiveDateTime::default(),
            auth_index: None,
        };
        let out = format!("{config:?}");
        assert!(out.contains("<redacted>"), "{out}");
        assert!(!out.contains("secret="), "{out}");
        assert!(!out.contains("nostr+walletconnect"), "{out}");
    }

    /// A relay string the wallet sent that is not a `ws(s)://` URL must not
    /// panic the payment path; the default auth relay is used instead.
    #[test]
    fn nwa_nwc_with_unparseable_relay_falls_back_to_default() {
        let xpriv = bitcoin::bip32::Xpriv::new_master(bitcoin::Network::Bitcoin, &[0; 32]).unwrap();
        let config = ZapConfig {
            id: 1,
            user_id: 1,
            emoji: "⚡".to_string(),
            amount: 21,
            nwc: None,
            created_at: chrono::NaiveDateTime::default(),
            auth_index: Some(3),
        };
        let user = PublicKey::from_slice(&[2; 32]).unwrap();
        let nwc = config.nwc(xpriv, Some(user), Some("https://not-a-relay.example/x"));
        assert_eq!(nwc.public_key, user);
        assert_eq!(
            nwc.relays,
            vec![RelayUrl::parse(crate::DEFAULT_AUTH_RELAY).unwrap()]
        );
        let kept = config.nwc(xpriv, Some(user), Some("wss://wallet.example/"));
        assert_eq!(
            kept.relays,
            vec![RelayUrl::parse("wss://wallet.example/").unwrap()]
        );
    }

    /// Wire-side twin of the Debug test: the raw NWC string must never be
    /// serialized, even if a handler one day returns the model directly.
    #[test]
    fn serialized_json_never_contains_nwc() {
        let config = ZapConfig {
            id: 1,
            user_id: 1,
            emoji: "⚡".to_string(),
            amount: 21,
            nwc: Some(NWC.to_string()),
            created_at: chrono::NaiveDateTime::default(),
            auth_index: None,
        };
        let out = serde_json::to_string(&config).unwrap();
        assert!(!out.contains("nwc"), "{out}");
        assert!(!out.contains("secret="), "{out}");
        assert!(!out.contains("nostr+walletconnect"), "{out}");
        assert!(out.contains("\"amount\":21"), "{out}");
    }
}
