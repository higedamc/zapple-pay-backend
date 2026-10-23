use bitcoin::bip32::{ChildNumber, Xpriv};
use diesel::prelude::*;
use nostr::key::PublicKey;
use nostr::SECP256K1;
use serde::{Deserialize, Serialize};
use std::str::FromStr;

use super::schema::wallet_auth;

/// Upper bound on the number of not-yet-linked NWA keys the listener watches
/// at once. Every pending key becomes an identifier in the relay filter, so
/// an unbounded list lets one client grow the subscription until the relay
/// rejects the whole REQ, zap filters included. 250 is the per-filter chunk
/// size used for the other filters, so the pending set is always one filter.
pub const MAX_PENDING_WALLET_AUTHS: usize = 250;

#[derive(
    Queryable,
    Insertable,
    Identifiable,
    AsChangeset,
    Serialize,
    Deserialize,
    Debug,
    Clone,
    PartialEq,
)]
#[diesel(primary_key(index))]
#[diesel(check_for_backend(diesel::pg::Pg))]
#[diesel(table_name = wallet_auth)]
pub struct WalletAuth {
    pub index: i32,
    pubkey: String,
    user_pubkey: Option<String>,
    created_at: chrono::NaiveDateTime,
    relay: Option<String>,
}

#[derive(Insertable, Serialize, Deserialize, Debug, Clone, PartialEq)]
#[diesel(table_name = wallet_auth)]
struct NewWalletAuth {
    pubkey: String,
}

#[derive(QueryableByName)]
struct NextId {
    #[diesel(sql_type = diesel::sql_types::Int4)]
    new_id: i32,
}

impl WalletAuth {
    pub fn pubkey(&self) -> PublicKey {
        PublicKey::from_str(&self.pubkey).expect("invalid pubkey")
    }

    pub fn user_pubkey(&self) -> Option<PublicKey> {
        self.user_pubkey
            .as_deref()
            .map(|s| PublicKey::from_str(s).expect("invalid user_pubkey"))
    }

    pub fn create(conn: &mut PgConnection, xpriv: Xpriv) -> anyhow::Result<Self> {
        conn.transaction(|conn| {
            // Get the next value from the sequence
            let query =
                "SELECT nextval(pg_get_serial_sequence('wallet_auth', 'index'))::int4 as new_id";
            let next_index: Vec<NextId> = diesel::sql_query(query).load(conn)?;
            let next_index = next_index[0].new_id;

            // Derive the pubkey for the next index
            let (derived_pubkey, _) = xpriv
                .derive_priv(
                    SECP256K1,
                    &[ChildNumber::from_hardened_idx(next_index as u32).unwrap()],
                )
                .unwrap()
                .private_key
                .x_only_public_key(SECP256K1);

            // Now, you can insert the row with the reserved `index`, and the derived values
            let result = diesel::insert_into(wallet_auth::table)
                .values((
                    wallet_auth::index.eq(next_index),
                    wallet_auth::pubkey.eq(derived_pubkey.to_string()),
                ))
                .get_result(conn)?;

            Ok(result)
        })
    }

    pub fn add_user_data(
        conn: &mut PgConnection,
        pubkey: PublicKey,
        user_pubkey: PublicKey,
        relay: Option<String>,
    ) -> anyhow::Result<()> {
        diesel::update(wallet_auth::table)
            .filter(wallet_auth::pubkey.eq(pubkey.to_string()))
            .set((
                wallet_auth::user_pubkey.eq(user_pubkey.to_string()),
                wallet_auth::relay.eq(relay),
            ))
            .execute(conn)?;

        Ok(())
    }

    /// Returns the index of the wallet_auth entry for the given pubkey
    /// Also verifies that user_pubkey is set so that we don't link to a wallet_auth entry that
    /// hasn't been claimed yet
    pub fn get_index_by_pubkey(
        conn: &mut PgConnection,
        pubkey: PublicKey,
    ) -> Result<Option<i32>, diesel::result::Error> {
        let id = wallet_auth::table
            .select(wallet_auth::index)
            .filter(wallet_auth::pubkey.eq(pubkey.to_string()))
            .filter(wallet_auth::user_pubkey.is_not_null())
            .first(conn)
            .optional()?;

        Ok(id)
    }

    pub fn get_by_pubkey(
        conn: &mut PgConnection,
        pubkey: PublicKey,
    ) -> Result<Option<WalletAuth>, diesel::result::Error> {
        let id = wallet_auth::table
            .select(wallet_auth::all_columns)
            .filter(wallet_auth::pubkey.eq(pubkey.to_string()))
            .first(conn)
            .optional()?;

        Ok(id)
    }

    pub fn get_user_data(
        conn: &mut PgConnection,
        index: i32,
    ) -> anyhow::Result<Option<(PublicKey, Option<String>)>> {
        let (user_pubkey, relay) = wallet_auth::table
            .select((wallet_auth::user_pubkey, wallet_auth::relay))
            .filter(wallet_auth::index.eq(index))
            .first::<(Option<String>, Option<String>)>(conn)?;

        Ok(user_pubkey.map(|pubkey| {
            (
                PublicKey::from_str(&pubkey).expect("invalid user_pubkey"),
                relay,
            )
        }))
    }

    /// Pending (not yet linked) NWA keys the listener should watch at startup:
    /// the ones created within the last day. Upstream had this bound inverted
    /// (`lt`), so a restart between `/wallet-auth` and the wallet's kind 33194
    /// reply re-watched only abandoned keys and silently dropped every live
    /// one; `/check-wallet-auth` then polled forever.
    pub fn get_unlinked(conn: &mut PgConnection) -> anyhow::Result<Vec<PublicKey>> {
        let unlinked = wallet_auth::table
            .select(wallet_auth::pubkey)
            .filter(wallet_auth::user_pubkey.is_null())
            .filter(
                wallet_auth::created_at
                    .gt(chrono::Utc::now().naive_utc() - chrono::Duration::days(1)),
            )
            .order(wallet_auth::created_at.desc())
            .limit(MAX_PENDING_WALLET_AUTHS as i64)
            .load::<String>(conn)?;

        // Newest N selected above; hand them back oldest-first so the list
        // has the same shape `push_pending_auth` maintains at runtime
        // (push at the tail, evict from the head).
        let unlinked = unlinked
            .into_iter()
            .rev()
            .filter_map(|s| PublicKey::from_str(&s).ok())
            .collect();

        Ok(unlinked)
    }

    pub fn get_pubkeys(conn: &mut PgConnection) -> anyhow::Result<Vec<PublicKey>> {
        let pubkeys = wallet_auth::table
            .select(wallet_auth::pubkey)
            .filter(wallet_auth::user_pubkey.is_not_null())
            .load::<String>(conn)?;

        let pubkeys = pubkeys
            .into_iter()
            .filter_map(|s| PublicKey::from_str(&s).ok())
            .collect();

        Ok(pubkeys)
    }
}

#[cfg(test)]
mod test {
    use crate::models::wallet_auth::WalletAuth;
    use crate::models::MIGRATIONS;
    use bitcoin::bip32::Xpriv;
    use diesel::r2d2::{ConnectionManager, Pool};
    use diesel::{Connection, PgConnection, RunQueryDsl};
    use diesel_migrations::MigrationHarness;
    use nostr::key::PublicKey;
    use std::str::FromStr;

    const PUBKEY: &str = "e1ff3bfdd4e40315959b08b4fcc8245eaa514637e1d4ec2ae166b743341be1af";

    fn init_db() -> Pool<ConnectionManager<PgConnection>> {
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

        db_pool
    }

    fn clear_database(conn: &mut PgConnection) {
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

    /// The startup seed for the listener's pending-auth list: fresh unlinked
    /// keys only (created within the last day), bounded to the newest
    /// `MAX_PENDING_WALLET_AUTHS` and returned oldest-first, matching the
    /// runtime list shape. Stale and already-linked rows are excluded.
    /// Flipping the bound back to `lt` makes the stale row the only hit.
    #[tokio::test]
    async fn test_get_unlinked_is_fresh_bounded_and_oldest_first() {
        use crate::models::schema::wallet_auth;
        use crate::models::wallet_auth::MAX_PENDING_WALLET_AUTHS;
        use diesel::{ExpressionMethods, QueryDsl};

        let db_pool = init_db();
        let conn = &mut db_pool.get().unwrap();
        let xpriv = Xpriv::new_master(bitcoin::Network::Testnet, &[]).unwrap();

        // Start from an empty table: other tests leave fresh unlinked rows
        // behind, which this query is now supposed to see.
        clear_database(conn);
        diesel::delete(wallet_auth::table).execute(conn).unwrap();
        assert!(WalletAuth::get_unlinked(conn).unwrap().is_empty());

        let now = chrono::Utc::now().naive_utc();
        let set_created_at = |conn: &mut PgConnection, index: i32, at: chrono::NaiveDateTime| {
            diesel::update(wallet_auth::table.filter(wallet_auth::index.eq(index)))
                .set(wallet_auth::created_at.eq(at))
                .execute(conn)
                .unwrap();
        };

        // Abandoned: unlinked but two days old -> not re-watched.
        let stale = WalletAuth::create(conn, xpriv).unwrap();
        set_created_at(conn, stale.index, now - chrono::Duration::days(2));
        assert!(WalletAuth::get_unlinked(conn).unwrap().is_empty());

        // Linked: fresh but already has a user -> nothing to wait for.
        let linked = WalletAuth::create(conn, xpriv).unwrap();
        let user = PublicKey::from_str(PUBKEY).unwrap();
        WalletAuth::add_user_data(conn, linked.pubkey(), user, None).unwrap();
        assert!(WalletAuth::get_unlinked(conn).unwrap().is_empty());

        // Live: MAX + 2 fresh unlinked rows one second apart, newest last.
        let extra = 2;
        let base = now - chrono::Duration::hours(1);
        let mut created: Vec<PublicKey> = Vec::new();
        for i in 0..(MAX_PENDING_WALLET_AUTHS + extra) {
            let auth = WalletAuth::create(conn, xpriv).unwrap();
            set_created_at(conn, auth.index, base + chrono::Duration::seconds(i as i64));
            created.push(auth.pubkey());
        }

        let unlinked = WalletAuth::get_unlinked(conn).unwrap();
        assert_eq!(unlinked.len(), MAX_PENDING_WALLET_AUTHS);
        // The two oldest fell off the cap; the rest come back oldest-first.
        assert_eq!(unlinked.as_slice(), &created[extra..]);
        assert!(!unlinked.contains(&stale.pubkey()));
        assert!(!unlinked.contains(&linked.pubkey()));

        diesel::delete(wallet_auth::table).execute(conn).unwrap();
    }

    #[tokio::test]
    async fn test_get_user_data() {
        let db_pool = init_db();
        let conn = &mut db_pool.get().unwrap();
        clear_database(conn);

        let xpriv = Xpriv::new_master(bitcoin::Network::Bitcoin, &[]).unwrap();
        let wallet_auth = WalletAuth::create(conn, xpriv).unwrap();

        let pubkey = wallet_auth.pubkey();

        let user_data = WalletAuth::get_user_data(conn, wallet_auth.index).unwrap();
        assert_eq!(user_data, None);

        let user_pubkey = PublicKey::from_str(PUBKEY).unwrap();
        WalletAuth::add_user_data(conn, pubkey, user_pubkey, None).unwrap();

        let user_data = WalletAuth::get_user_data(conn, wallet_auth.index)
            .unwrap()
            .unwrap();
        assert_eq!(user_data.0, user_pubkey);
        assert_eq!(user_data.1, None);

        let auth = WalletAuth::get_by_pubkey(conn, pubkey).unwrap().unwrap();

        assert_eq!(auth.user_pubkey(), Some(user_pubkey));

        clear_database(conn);
    }

    #[tokio::test]
    async fn test_get_user_data_with_relay() {
        let db_pool = init_db();
        let conn = &mut db_pool.get().unwrap();
        clear_database(conn);

        let xpriv = Xpriv::new_master(bitcoin::Network::Bitcoin, &[]).unwrap();
        let wallet_auth = WalletAuth::create(conn, xpriv).unwrap();

        let pubkey = wallet_auth.pubkey();

        let user_data = WalletAuth::get_user_data(conn, wallet_auth.index).unwrap();
        assert_eq!(user_data, None);

        let user_pubkey = PublicKey::from_str(PUBKEY).unwrap();
        let relay = Some("wss://relay.damus.io/".to_string());
        WalletAuth::add_user_data(conn, pubkey, user_pubkey, relay.clone()).unwrap();

        let user_data = WalletAuth::get_user_data(conn, wallet_auth.index)
            .unwrap()
            .unwrap();
        assert_eq!(user_data.0, user_pubkey);
        assert_eq!(user_data.1, relay);

        let auth = WalletAuth::get_by_pubkey(conn, pubkey).unwrap().unwrap();

        assert_eq!(auth.user_pubkey(), Some(user_pubkey));

        clear_database(conn);
    }
}
