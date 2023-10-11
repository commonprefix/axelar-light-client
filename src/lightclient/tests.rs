#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use cosmwasm_std::testing::mock_env;
    use cosmwasm_std::Timestamp;
    use ssz_rs::Bitvector;

    use crate::{
        lightclient::error::ConsensusError,
        lightclient::helpers::test_helpers::{get_bootstrap, get_config, get_update},
        lightclient::types::{primitives::U64, BLSPubKey, SignatureBytes},
        lightclient::{self, types::primitives::ByteVector, LightClient},
    };

    fn init_lightclient() -> LightClient {
        let bootstrap = get_bootstrap();
        let config = get_config();
        let mut env = mock_env();
        env.block.time = Timestamp::from_seconds(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        );

        let mut client = LightClient::new(&config, None, &env);
        let res = client.bootstrap(bootstrap);
        if let Err(e) = res {
            panic!("Error bootstrapping: {}", e);
        }

        return client;
    }

    #[test]
    fn test_verify_update_insufficient_participation_error() {
        let lightclient = init_lightclient();

        let mut update = get_update(862);
        update.sync_aggregate.sync_committee_bits = Bitvector::default();

        let err = lightclient.verify_update(&update).unwrap_err();

        assert_eq!(
            err.to_string(),
            lightclient::ConsensusError::InsufficientParticipation.to_string()
        );
    }

    #[test]
    fn test_verify_update_time_error() {
        let lightclient = init_lightclient();

        let mut update = get_update(862);
        update.signature_slot = U64::from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
                + 12,
        );
        let mut err = lightclient.verify_update(&update).unwrap_err();

        assert_eq!(
            err.to_string(),
            lightclient::ConsensusError::InvalidTimestamp.to_string()
        );

        update = get_update(862);
        update.signature_slot = update.attested_header.beacon.slot;
        err = lightclient.verify_update(&update).unwrap_err();

        assert_eq!(
            err.to_string(),
            lightclient::ConsensusError::InvalidTimestamp.to_string()
        );

        update = get_update(862);
        update.attested_header.beacon.slot =
            U64::from(update.finalized_header.beacon.slot.as_u64() - 1);
        err = lightclient.verify_update(&update).unwrap_err();

        assert_eq!(
            err.to_string(),
            lightclient::ConsensusError::InvalidTimestamp.to_string()
        );
    }

    #[test]
    fn test_verify_update_period_error() {
        let mut lightclient = init_lightclient();
        // current period is 862, without a sync committee
        let mut update = get_update(863);

        let mut err = lightclient.verify_update(&update).unwrap_err();

        assert_eq!(
            err.to_string(),
            lightclient::ConsensusError::InvalidPeriod.to_string()
        );

        // properly sync with period 862, store sync committee
        update = get_update(862);
        lightclient.apply_update(&update).unwrap();

        // update was applied
        assert!(lightclient.state.next_sync_committee.is_some());

        // update period > current period + 1
        update = get_update(864);
        err = lightclient.verify_update(&update).unwrap_err();

        assert_eq!(
            err.to_string(),
            lightclient::ConsensusError::InvalidPeriod.to_string()
        );
    }

    #[test]
    fn test_verify_update_relevance_error() {
        let mut lightclient = init_lightclient();
        let mut update = get_update(862);
        lightclient.apply_update(&update).unwrap();

        update.attested_header.beacon.slot = lightclient.state.finalized_header.slot;
        update.finalized_header.beacon.slot = lightclient.state.finalized_header.slot;
        assert!(lightclient.state.next_sync_committee.is_some());
        let mut err = lightclient.verify_update(&update).unwrap_err();
        assert_eq!(
            err.to_string(),
            lightclient::ConsensusError::NotRelevant.to_string()
        );

        update = get_update(862);
        update.attested_header.beacon.slot =
            U64::from(lightclient.state.finalized_header.slot.as_u64() - (256 * 32));
        update.finalized_header.beacon.slot =
            U64::from(lightclient.state.finalized_header.slot.as_u64() - (256 * 32) - 1); // subtracting 1 for a regression bug
        lightclient.state.next_sync_committee = None;
        err = lightclient.verify_update(&update).unwrap_err();
        assert_eq!(
            err.to_string(),
            lightclient::ConsensusError::NotRelevant.to_string()
        );
    }

    #[test]
    fn test_verify_update_finaliy_proof() {
        let lightclient = init_lightclient();
        let mut update = get_update(862);

        update.attested_header.beacon.state_root = ByteVector::default();
        let mut err = lightclient.verify_update(&update).unwrap_err();
        assert_eq!(
            err.to_string(),
            lightclient::ConsensusError::InvalidFinalityProof.to_string()
        );

        update = get_update(862);
        update.finalized_header.beacon.state_root = ByteVector::default();
        err = lightclient.verify_update(&update).unwrap_err();
        assert_eq!(
            err.to_string(),
            lightclient::ConsensusError::InvalidFinalityProof.to_string()
        );
    }

    #[test]
    fn test_verify_update_invalid_committee() {
        let lightclient = init_lightclient();

        let mut update = get_update(862);
        update.next_sync_committee.pubkeys[0] = BLSPubKey::default();
        let err = lightclient.verify_update(&update).unwrap_err();

        assert_eq!(
            err.to_string(),
            lightclient::ConsensusError::InvalidNextSyncCommitteeProof.to_string()
        );
    }

    #[test]
    fn test_verify_update_invalid_sig() {
        let lightclient = init_lightclient();

        let mut update = get_update(862);
        update.sync_aggregate.sync_committee_signature = SignatureBytes::default();

        let err = lightclient.verify_update(&update).err().unwrap();
        assert_eq!(
            err.to_string(),
            ConsensusError::InvalidSignature.to_string()
        );
    }

    #[test]
    fn test_verify_update() {
        let lightclient = init_lightclient();

        let update = get_update(862);
        let res = lightclient.verify_update(&update);
        assert!(res.is_ok());
    }

    #[test]
    fn test_apply_update() {
        let mut lightclient = init_lightclient();
        let update = get_update(862);
        let res = lightclient.verify_update(&update);
        assert!(res.is_ok());

        let res = lightclient.apply_update(&update);
        assert!(res.is_ok());
        assert_eq!(
            lightclient.state.finalized_header, update.finalized_header.beacon,
            "finalized_header should be set after applying update"
        );
        assert_eq!(
            lightclient.state.next_sync_committee.unwrap(),
            update.next_sync_committee,
            "next_sync_committee should be set after applying update"
        );
    }

    #[test]
    fn test_multiple_updates() {
        let mut lightclient = init_lightclient();
        let update = get_update(862);
        let res = lightclient.apply_update(&update);
        assert!(res.is_ok());
        assert_eq!(
            lightclient.state.finalized_header, update.finalized_header.beacon,
            "finalized_header should be set after applying first update"
        );

        let update = get_update(863);
        let res = lightclient.apply_update(&update);
        assert!(res.is_ok());
        assert_eq!(
            lightclient.state.finalized_header, update.finalized_header.beacon,
            "finalized_header should be set after applying second update"
        );
    }
}
