#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use cosmwasm_std::testing::mock_env;
    use cosmwasm_std::Timestamp;

    use crate::{
        lightclient::error::ConsensusError,
        lightclient::helpers::test_helpers::{get_bootstrap, get_config, get_update},
        lightclient::types::{BLSPubKey, Header, SignatureBytes},
        lightclient::{self, LightClient},
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
    fn test_verify_update_invalid_finality() {
        let lightclient = init_lightclient();

        let mut update = get_update(862);
        update.finalized_header.beacon = Header::default();

        let err = lightclient.verify_update(&update).err().unwrap();
        assert_eq!(
            err.to_string(),
            ConsensusError::InvalidFinalityProof.to_string()
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
    fn test_verify_finality_invalid_finality() {
        let lightclient = init_lightclient();

        let mut update = get_update(862);
        update.finalized_header.beacon = Header::default();

        let err = lightclient.verify_update(&update).err().unwrap();
        assert_eq!(
            err.to_string(),
            ConsensusError::InvalidFinalityProof.to_string()
        );
    }

    #[test]
    fn test_verify_finality_invalid_sig() {
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
    fn test_invalid_period() {
        let lightclient = init_lightclient();

        let update = get_update(863);
        let err = lightclient.verify_update(&update).err().unwrap();

        assert_eq!(
            err.to_string(),
            ConsensusError::InvalidPeriod.to_string(),
            "should error on invalid period"
        );
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
