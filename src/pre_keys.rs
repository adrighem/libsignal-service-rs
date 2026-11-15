use std::convert::TryFrom;

use crate::{
    timestamp::TimestampExt as _,
    utils::{serde_base64, serde_identity_key},
};
use async_trait::async_trait;
use libsignal_protocol::{
    error::SignalProtocolError, kem, GenericSignedPreKey, IdentityKey,
    IdentityKeyPair, IdentityKeyStore, KeyPair, KyberPreKeyId,
    KyberPreKeyRecord, KyberPreKeyStore, PreKeyId, PreKeyRecord, PreKeyStore,
    SignedPreKeyId, SignedPreKeyRecord, SignedPreKeyStore, Timestamp,
};

use rand::{CryptoRng, Rng};
use serde::{Deserialize, Serialize};
use tracing::Instrument;

#[async_trait(?Send)]
/// Additional methods for the Kyber pre key store
///
/// Analogue of Android's ServiceKyberPreKeyStore
pub trait KyberPreKeyStoreExt: KyberPreKeyStore {
    async fn store_last_resort_kyber_pre_key(
        &mut self,
        kyber_prekey_id: KyberPreKeyId,
        record: &KyberPreKeyRecord,
    ) -> Result<(), SignalProtocolError>;

    async fn load_last_resort_kyber_pre_keys(
        &self,
    ) -> Result<Vec<KyberPreKeyRecord>, SignalProtocolError>;

    async fn remove_kyber_pre_key(
        &mut self,
        kyber_prekey_id: KyberPreKeyId,
    ) -> Result<(), SignalProtocolError>;

    /// Analogous to markAllOneTimeKyberPreKeysStaleIfNecessary
    async fn mark_all_one_time_kyber_pre_keys_stale_if_necessary(
        &mut self,
        stale_time: chrono::DateTime<chrono::Utc>,
    ) -> Result<(), SignalProtocolError>;

    /// Analogue of deleteAllStaleOneTimeKyberPreKeys
    async fn delete_all_stale_one_time_kyber_pre_keys(
        &mut self,
        threshold: chrono::DateTime<chrono::Utc>,
        min_count: usize,
    ) -> Result<(), SignalProtocolError>;
}

/// Stores the ID of keys published ahead of time
///
/// <https://signal.org/docs/specifications/x3dh/>
#[async_trait(?Send)]
pub trait PreKeysStore:
    PreKeyStore
    + IdentityKeyStore
    + SignedPreKeyStore
    + KyberPreKeyStore
    + KyberPreKeyStoreExt
{
    /// ID of the next pre key
    async fn next_pre_key_id(&self) -> Result<u32, SignalProtocolError>;

    /// ID of the next signed pre key
    async fn next_signed_pre_key_id(&self) -> Result<u32, SignalProtocolError>;

    /// ID of the next PQ pre key
    async fn next_pq_pre_key_id(&self) -> Result<u32, SignalProtocolError>;

    /// number of signed pre-keys we currently have in store
    async fn signed_pre_keys_count(&self)
        -> Result<usize, SignalProtocolError>;

    /// number of kyber pre-keys we currently have in store
    async fn kyber_pre_keys_count(
        &self,
        last_resort: bool,
    ) -> Result<usize, SignalProtocolError>;

    async fn signed_prekey_id(
        &self,
    ) -> Result<Option<SignedPreKeyId>, SignalProtocolError>;

    async fn last_resort_kyber_prekey_id(
        &self,
    ) -> Result<Option<KyberPreKeyId>, SignalProtocolError>;

    /// Save many pre keys at once.
    ///
    /// Stores backed by a database should override this to write in a single
    /// transaction.
    async fn save_pre_keys(
        &mut self,
        records: &[(PreKeyId, PreKeyRecord)],
    ) -> Result<(), SignalProtocolError> {
        for (id, record) in records {
            self.save_pre_key(*id, record).await?;
        }
        Ok(())
    }

    /// Save many Kyber pre keys at once. See [`Self::save_pre_keys`].
    async fn save_kyber_pre_keys(
        &mut self,
        records: &[(KyberPreKeyId, KyberPreKeyRecord)],
    ) -> Result<(), SignalProtocolError> {
        for (id, record) in records {
            self.save_kyber_pre_key(*id, record).await?;
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PreKeyEntity {
    pub key_id: u32,
    #[serde(with = "serde_base64")]
    pub public_key: Vec<u8>,
}

impl TryFrom<PreKeyRecord> for PreKeyEntity {
    type Error = SignalProtocolError;

    fn try_from(key: PreKeyRecord) -> Result<Self, Self::Error> {
        Ok(PreKeyEntity {
            key_id: key.id()?.into(),
            public_key: key.key_pair()?.public_key.serialize().to_vec(),
        })
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SignedPreKeyEntity {
    pub key_id: u32,
    #[serde(with = "serde_base64")]
    pub public_key: Vec<u8>,
    #[serde(with = "serde_base64")]
    pub signature: Vec<u8>,
}

impl TryFrom<&'_ SignedPreKeyRecord> for SignedPreKeyEntity {
    type Error = SignalProtocolError;

    fn try_from(key: &'_ SignedPreKeyRecord) -> Result<Self, Self::Error> {
        Ok(SignedPreKeyEntity {
            key_id: key.id()?.into(),
            public_key: key.key_pair()?.public_key.serialize().to_vec(),
            signature: key.signature()?.to_vec(),
        })
    }
}

impl TryFrom<SignedPreKeyRecord> for SignedPreKeyEntity {
    type Error = SignalProtocolError;

    fn try_from(key: SignedPreKeyRecord) -> Result<Self, Self::Error> {
        SignedPreKeyEntity::try_from(&key)
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KyberPreKeyEntity {
    pub key_id: u32,
    #[serde(with = "serde_base64")]
    pub public_key: Vec<u8>,
    #[serde(with = "serde_base64")]
    pub signature: Vec<u8>,
}

impl TryFrom<&'_ KyberPreKeyRecord> for KyberPreKeyEntity {
    type Error = SignalProtocolError;

    fn try_from(key: &'_ KyberPreKeyRecord) -> Result<Self, Self::Error> {
        Ok(KyberPreKeyEntity {
            key_id: key.id()?.into(),
            public_key: key.key_pair()?.public_key.serialize().to_vec(),
            signature: key.signature()?,
        })
    }
}

impl TryFrom<KyberPreKeyRecord> for KyberPreKeyEntity {
    type Error = SignalProtocolError;

    fn try_from(key: KyberPreKeyRecord) -> Result<Self, Self::Error> {
        KyberPreKeyEntity::try_from(&key)
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PreKeyState {
    pub pre_keys: Vec<PreKeyEntity>,
    pub signed_pre_key: SignedPreKeyEntity,
    #[serde(with = "serde_identity_key")]
    pub identity_key: IdentityKey,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pq_last_resort_key: Option<KyberPreKeyEntity>,
    pub pq_pre_keys: Vec<KyberPreKeyEntity>,
}

pub(crate) const PRE_KEY_MINIMUM: u32 = 10;
pub(crate) const PRE_KEY_BATCH_SIZE: u32 = 100;
pub(crate) const PRE_KEY_MEDIUM_MAX_VALUE: u32 = 0xFFFFFF;

pub(crate) async fn replenish_pre_keys<R: Rng + CryptoRng, P: PreKeysStore>(
    protocol_store: &mut P,
    csprng: &mut R,
    identity_key_pair: &IdentityKeyPair,
    use_last_resort_key: bool,
    pre_key_count: u32,
    kyber_pre_key_count: u32,
) -> Result<
    (
        Vec<PreKeyRecord>,
        SignedPreKeyRecord,
        Vec<KyberPreKeyRecord>,
        Option<KyberPreKeyRecord>,
    ),
    SignalProtocolError,
> {
    let pre_keys_offset_id = protocol_store.next_pre_key_id().await?;
    let next_signed_pre_key_id =
        protocol_store.next_signed_pre_key_id().await?;
    let pq_pre_keys_offset_id = protocol_store.next_pq_pre_key_id().await?;

    let span = tracing::span!(tracing::Level::DEBUG, "Generating pre keys");

    let mut pre_keys = vec![];
    let mut pq_pre_keys = vec![];

    // EC keys
    for i in 0..pre_key_count {
        let key_pair = KeyPair::generate(csprng);
        let pre_key_id =
            (((pre_keys_offset_id + i) % (PRE_KEY_MEDIUM_MAX_VALUE - 1)) + 1)
                .into();
        pre_keys.push(PreKeyRecord::new(pre_key_id, &key_pair));
    }
    let records = pre_keys
        .iter()
        .map(|record| Ok((record.id()?, record.clone())))
        .collect::<Result<Vec<_>, SignalProtocolError>>()?;
    protocol_store
        .save_pre_keys(&records)
        .instrument(tracing::trace_span!(parent: &span, "save pre keys"))
        .await?;
    // TODO: Shouldn't this also remove the previous pre-keys from storage?
    //       I think we might want to update the storage, and then sync the storage to the
    //       server.

    // Kyber keys
    for i in 0..kyber_pre_key_count {
        let pre_key_id = (((pq_pre_keys_offset_id + i)
            % (PRE_KEY_MEDIUM_MAX_VALUE - 1))
            + 1)
        .into();
        pq_pre_keys.push(KyberPreKeyRecord::generate(
            kem::KeyType::Kyber1024,
            pre_key_id,
            identity_key_pair.private_key(),
        )?);
    }
    let records = pq_pre_keys
        .iter()
        .map(|record| Ok((record.id()?, record.clone())))
        .collect::<Result<Vec<_>, SignalProtocolError>>()?;
    protocol_store
        .save_kyber_pre_keys(&records)
        .instrument(tracing::trace_span!(parent: &span, "save kyber pre keys"))
        .await?;
    // TODO: Shouldn't this also remove the previous pre-keys from storage?
    //       I think we might want to update the storage, and then sync the storage to the
    //       server.

    // Generate and store the next signed prekey
    let signed_pre_key_pair = KeyPair::generate(csprng);
    let signed_pre_key_public = signed_pre_key_pair.public_key;
    let signed_pre_key_signature = identity_key_pair
        .private_key()
        .calculate_signature(&signed_pre_key_public.serialize(), csprng)?;

    let signed_prekey_record = SignedPreKeyRecord::new(
        next_signed_pre_key_id.into(),
        Timestamp::now(),
        &signed_pre_key_pair,
        &signed_pre_key_signature,
    );

    protocol_store
                .save_signed_pre_key(
                    next_signed_pre_key_id.into(),
                    &signed_prekey_record,
                )
                    .instrument(tracing::trace_span!(parent: &span, "save signed pre key", signed_pre_key_id = ?next_signed_pre_key_id)).await?;

    let pq_last_resort_key = if use_last_resort_key {
        let pre_key_id = (((pq_pre_keys_offset_id + kyber_pre_key_count)
            % (PRE_KEY_MEDIUM_MAX_VALUE - 1))
            + 1)
        .into();

        if !pq_pre_keys.is_empty() {
            assert_eq!(
                u32::from(pq_pre_keys.last().unwrap().id()?) + 1,
                u32::from(pre_key_id)
            );
        }

        let pre_key_record = KyberPreKeyRecord::generate(
            kem::KeyType::Kyber1024,
            pre_key_id,
            identity_key_pair.private_key(),
        )?;
        protocol_store
                    .store_last_resort_kyber_pre_key(pre_key_id, &pre_key_record)
                    .instrument(tracing::trace_span!(parent: &span, "save last resort kyber pre key", ?pre_key_id)).await?;
        // TODO: Shouldn't this also remove the previous pre-keys from storage?
        //       I think we might want to update the storage, and then sync the storage to the
        //       server.

        Some(pre_key_record)
    } else {
        None
    };

    Ok((
        pre_keys,
        signed_prekey_record,
        pq_pre_keys,
        pq_last_resort_key,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use libsignal_protocol::{
        Direction, IdentityChange, InMemKyberPreKeyStore, InMemPreKeyStore,
        ProtocolAddress, PublicKey,
    };

    // Only the pre key halves work; the rest is required by the trait bounds.
    #[derive(Default)]
    struct TestStore {
        pre_keys: InMemPreKeyStore,
        kyber_pre_keys: InMemKyberPreKeyStore,
    }

    #[async_trait(?Send)]
    impl PreKeyStore for TestStore {
        async fn get_pre_key(
            &self,
            id: PreKeyId,
        ) -> Result<PreKeyRecord, SignalProtocolError> {
            self.pre_keys.get_pre_key(id).await
        }

        async fn save_pre_key(
            &mut self,
            id: PreKeyId,
            record: &PreKeyRecord,
        ) -> Result<(), SignalProtocolError> {
            self.pre_keys.save_pre_key(id, record).await
        }

        async fn remove_pre_key(
            &mut self,
            id: PreKeyId,
        ) -> Result<(), SignalProtocolError> {
            self.pre_keys.remove_pre_key(id).await
        }
    }

    #[async_trait(?Send)]
    impl KyberPreKeyStore for TestStore {
        async fn get_kyber_pre_key(
            &self,
            id: KyberPreKeyId,
        ) -> Result<KyberPreKeyRecord, SignalProtocolError> {
            self.kyber_pre_keys.get_kyber_pre_key(id).await
        }

        async fn save_kyber_pre_key(
            &mut self,
            id: KyberPreKeyId,
            record: &KyberPreKeyRecord,
        ) -> Result<(), SignalProtocolError> {
            self.kyber_pre_keys.save_kyber_pre_key(id, record).await
        }

        async fn mark_kyber_pre_key_used(
            &mut self,
            _id: KyberPreKeyId,
            _ec_id: SignedPreKeyId,
            _base_key: &PublicKey,
        ) -> Result<(), SignalProtocolError> {
            unimplemented!()
        }
    }

    #[async_trait(?Send)]
    impl SignedPreKeyStore for TestStore {
        async fn get_signed_pre_key(
            &self,
            _id: SignedPreKeyId,
        ) -> Result<SignedPreKeyRecord, SignalProtocolError> {
            unimplemented!()
        }

        async fn save_signed_pre_key(
            &mut self,
            _id: SignedPreKeyId,
            _record: &SignedPreKeyRecord,
        ) -> Result<(), SignalProtocolError> {
            unimplemented!()
        }
    }

    #[async_trait(?Send)]
    impl IdentityKeyStore for TestStore {
        async fn get_identity_key_pair(
            &self,
        ) -> Result<IdentityKeyPair, SignalProtocolError> {
            unimplemented!()
        }

        async fn get_local_registration_id(
            &self,
        ) -> Result<u32, SignalProtocolError> {
            unimplemented!()
        }

        async fn save_identity(
            &mut self,
            _address: &ProtocolAddress,
            _identity: &IdentityKey,
        ) -> Result<IdentityChange, SignalProtocolError> {
            unimplemented!()
        }

        async fn is_trusted_identity(
            &self,
            _address: &ProtocolAddress,
            _identity: &IdentityKey,
            _direction: Direction,
        ) -> Result<bool, SignalProtocolError> {
            unimplemented!()
        }

        async fn get_identity(
            &self,
            _address: &ProtocolAddress,
        ) -> Result<Option<IdentityKey>, SignalProtocolError> {
            unimplemented!()
        }
    }

    #[async_trait(?Send)]
    impl KyberPreKeyStoreExt for TestStore {
        async fn store_last_resort_kyber_pre_key(
            &mut self,
            _id: KyberPreKeyId,
            _record: &KyberPreKeyRecord,
        ) -> Result<(), SignalProtocolError> {
            unimplemented!()
        }

        async fn load_last_resort_kyber_pre_keys(
            &self,
        ) -> Result<Vec<KyberPreKeyRecord>, SignalProtocolError> {
            unimplemented!()
        }

        async fn remove_kyber_pre_key(
            &mut self,
            _id: KyberPreKeyId,
        ) -> Result<(), SignalProtocolError> {
            unimplemented!()
        }

        async fn mark_all_one_time_kyber_pre_keys_stale_if_necessary(
            &mut self,
            _stale_time: chrono::DateTime<chrono::Utc>,
        ) -> Result<(), SignalProtocolError> {
            unimplemented!()
        }

        async fn delete_all_stale_one_time_kyber_pre_keys(
            &mut self,
            _threshold: chrono::DateTime<chrono::Utc>,
            _min_count: usize,
        ) -> Result<(), SignalProtocolError> {
            unimplemented!()
        }
    }

    #[async_trait(?Send)]
    impl PreKeysStore for TestStore {
        async fn next_pre_key_id(&self) -> Result<u32, SignalProtocolError> {
            unimplemented!()
        }

        async fn next_signed_pre_key_id(
            &self,
        ) -> Result<u32, SignalProtocolError> {
            unimplemented!()
        }

        async fn next_pq_pre_key_id(&self) -> Result<u32, SignalProtocolError> {
            unimplemented!()
        }

        async fn signed_pre_keys_count(
            &self,
        ) -> Result<usize, SignalProtocolError> {
            unimplemented!()
        }

        async fn kyber_pre_keys_count(
            &self,
            _last_resort: bool,
        ) -> Result<usize, SignalProtocolError> {
            unimplemented!()
        }

        async fn signed_prekey_id(
            &self,
        ) -> Result<Option<SignedPreKeyId>, SignalProtocolError> {
            unimplemented!()
        }

        async fn last_resort_kyber_prekey_id(
            &self,
        ) -> Result<Option<KyberPreKeyId>, SignalProtocolError> {
            unimplemented!()
        }
    }

    #[tokio::test]
    async fn default_batch_saves_store_every_record() {
        let mut rng = rand::rng();
        let identity = IdentityKeyPair::generate(&mut rng);
        let mut store = TestStore::default();

        let pre_keys: Vec<_> = (1..=5u32)
            .map(|i| {
                let id = PreKeyId::from(i);
                (id, PreKeyRecord::new(id, &KeyPair::generate(&mut rng)))
            })
            .collect();
        let kyber_pre_keys: Vec<_> = (1..=5u32)
            .map(|i| {
                let id = KyberPreKeyId::from(i);
                let record = KyberPreKeyRecord::generate(
                    kem::KeyType::Kyber1024,
                    id,
                    identity.private_key(),
                )
                .unwrap();
                (id, record)
            })
            .collect();

        store.save_pre_keys(&[]).await.unwrap();
        store.save_kyber_pre_keys(&[]).await.unwrap();
        store.save_pre_keys(&pre_keys).await.unwrap();
        store.save_kyber_pre_keys(&kyber_pre_keys).await.unwrap();

        for (id, record) in &pre_keys {
            let stored = store.get_pre_key(*id).await.unwrap();
            assert_eq!(
                stored.serialize().unwrap(),
                record.serialize().unwrap()
            );
        }
        for (id, record) in &kyber_pre_keys {
            let stored = store.get_kyber_pre_key(*id).await.unwrap();
            assert_eq!(
                stored.serialize().unwrap(),
                record.serialize().unwrap()
            );
        }
    }
}
