#[cfg(test)]
pub mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use crate::lightclient::helpers::is_proof_valid;
    use crate::{
        lightclient::error::ConsensusError,
        lightclient::LightClient,
        lightclient::{self},
        lightclient::{
            helpers::test_helpers::{get_bootstrap, get_config, get_update},
            Verification,
        },
    };
    use cosmwasm_std::testing::mock_env;
    use cosmwasm_std::Timestamp;
    use types::consensus::Bootstrap;
    use types::lightclient::LightClientState;
    use types::ssz_rs::{Bitvector, Node};
    use types::sync_committee_rs::constants::Bytes32;
    use types::sync_committee_rs::{
        consensus_types::BeaconBlockHeader,
        constants::{BlsPublicKey, BlsSignature},
    };

    pub fn init_lightclient(bootstrap: Option<Bootstrap>) -> LightClient {
        let bootstrap = if bootstrap.is_some() {
            bootstrap.unwrap()
        } else {
            get_bootstrap()
        };
        let config = get_config();
        let mut env = mock_env();
        env.block.time = Timestamp::from_seconds(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        );

        let mut client = LightClient::new(&config, None, &env);
        let res = client.bootstrap(&bootstrap);
        if let Err(e) = res {
            panic!("Error bootstrapping: {}", e);
        }

        client
    }

    #[test]
    fn test_is_proof_valid() {
        let mut update = get_update(862);

        // success
        assert!(is_proof_valid(
            &update.attested_header.beacon.state_root,
            &mut update.finalized_header.beacon,
            &update.finality_branch,
            6,
            41
        ));

        // change depth, fail
        assert!(!is_proof_valid(
            &update.attested_header.beacon.state_root,
            &mut update.finalized_header.beacon,
            &update.finality_branch,
            5,
            41
        ));

        // change index, fail
        assert!(!is_proof_valid(
            &update.attested_header.beacon.state_root,
            &mut update.finalized_header.beacon,
            &update.finality_branch,
            6,
            40
        ));

        // tamper with the state root, fail
        let mut invalid_update = update.clone();
        invalid_update.attested_header.beacon.state_root.0[0] = 0;
        assert!(!is_proof_valid(
            &invalid_update.attested_header.beacon.state_root,
            &mut invalid_update.finalized_header.beacon,
            &invalid_update.finality_branch,
            6,
            40
        ));

        // tamper with the body of the finalized header, fail
        let mut invalid_update = update.clone();
        invalid_update.finalized_header.beacon.body_root.0[0] = 0;
        assert!(!is_proof_valid(
            &invalid_update.attested_header.beacon.state_root,
            &mut invalid_update.finalized_header.beacon,
            &invalid_update.finality_branch,
            6,
            40
        ));

        // tamper with the proof, fail
        let mut invalid_update = update.clone();
        invalid_update.finality_branch[0] = Bytes32::default();
        assert!(!is_proof_valid(
            &invalid_update.attested_header.beacon.state_root,
            &mut invalid_update.finalized_header.beacon,
            &invalid_update.finality_branch,
            6,
            40
        ));
    }

    #[test]
    fn test_verify_update_participation() {
        let lightclient = init_lightclient(None);

        let mut update = get_update(862);
        update.sync_aggregate.sync_committee_bits = Bitvector::default();

        let err = update.verify(&lightclient).unwrap_err();

        assert_eq!(
            err.to_string(),
            lightclient::ConsensusError::InsufficientParticipation.to_string()
        );
    }

    #[test]
    fn test_verify_update_time() {
        let lightclient = init_lightclient(None);

        let mut update = get_update(862);
        update.signature_slot = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 12;
        let mut err = update.verify(&lightclient).unwrap_err();

        assert_eq!(
            err.to_string(),
            lightclient::ConsensusError::InvalidTimestamp.to_string()
        );

        update = get_update(862);
        update.signature_slot = update.attested_header.beacon.slot;
        err = update.verify(&lightclient).unwrap_err();

        assert_eq!(
            err.to_string(),
            lightclient::ConsensusError::InvalidTimestamp.to_string()
        );

        update = get_update(862);
        update.finalized_header.beacon.slot = update.attested_header.beacon.slot + 1;
        err = update.verify(&lightclient).unwrap_err();

        assert_eq!(
            err.to_string(),
            lightclient::ConsensusError::InvalidTimestamp.to_string()
        );
    }

    #[test]
    fn test_verify_update_period() {
        let mut lightclient = init_lightclient(None);
        // current period is 862, without a sync committee
        let mut update = get_update(863);

        let mut err = update.verify(&lightclient).unwrap_err();

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
        err = update.verify(&lightclient).unwrap_err();

        assert_eq!(
            err.to_string(),
            lightclient::ConsensusError::InvalidPeriod.to_string()
        );
    }

    #[test]
    fn test_verify_update_relevance() {
        let mut lightclient = init_lightclient(None);
        let mut update = get_update(862);
        lightclient.apply_update(&update).unwrap();

        update.attested_header.beacon.slot = lightclient.state.update_slot;
        update.finalized_header.beacon.slot = lightclient.state.update_slot;
        assert!(lightclient.state.next_sync_committee.is_some());
        let mut err = update.verify(&lightclient).unwrap_err();
        assert_eq!(
            err.to_string(),
            lightclient::ConsensusError::NotRelevant.to_string()
        );

        update = get_update(862);
        update.attested_header.beacon.slot = lightclient.state.update_slot - (256 * 32);
        update.finalized_header.beacon.slot = lightclient.state.update_slot - (256 * 32) - 1; // subtracting 1 for a regression bug
        lightclient.state.next_sync_committee = None;
        err = update.verify(&lightclient).unwrap_err();
        assert_eq!(
            err.to_string(),
            lightclient::ConsensusError::NotRelevant.to_string()
        );
    }

    #[test]
    fn test_verify_update_finality_proof() {
        let lightclient = init_lightclient(None);
        let mut update = get_update(862);

        update.finality_branch = vec![];
        let mut err = update.verify(&lightclient).unwrap_err();
        assert_eq!(
            err.to_string(),
            lightclient::ConsensusError::InvalidFinalityProof.to_string()
        );

        update = get_update(862);
        update.finalized_header.beacon.state_root = Node::default();
        err = update.verify(&lightclient).unwrap_err();
        assert_eq!(
            err.to_string(),
            lightclient::ConsensusError::InvalidFinalityProof.to_string()
        );
    }

    #[test]
    fn test_verify_update_invalid_committee() {
        let lightclient = init_lightclient(None);

        let mut update = get_update(862);
        update.next_sync_committee.public_keys[0] = BlsPublicKey::default();
        let err = update.verify(&lightclient).unwrap_err();

        assert_eq!(
            err.to_string(),
            lightclient::ConsensusError::InvalidNextSyncCommitteeProof.to_string()
        );
    }

    #[test]
    fn test_verify_update_invalid_sig() {
        let lightclient = init_lightclient(None);

        let mut update = get_update(862);
        update.sync_aggregate.sync_committee_signature = BlsSignature::default();

        let err = update.verify(&lightclient).err().unwrap();
        assert_eq!(
            err.to_string(),
            ConsensusError::InvalidSignature.to_string()
        );
    }

    #[test]
    fn test_verify_update() {
        let lightclient = init_lightclient(None);

        let update = get_update(862);
        let res = update.verify(&lightclient);
        assert!(res.is_ok());
    }

    #[test]
    fn test_bootstrap_state() {
        let lightclient = init_lightclient(None);
        let bootstrap = get_bootstrap();

        let mut update = get_update(862);
        update.finalized_header.beacon = BeaconBlockHeader::default();

        let err = update.verify(&lightclient);
        assert!(err.is_err());

        assert_eq!(
            lightclient.state,
            LightClientState {
                update_slot: bootstrap.header.beacon.slot,
                current_sync_committee: bootstrap.current_sync_committee,
                next_sync_committee: None,
            }
        );
    }

    #[test]
    fn test_apply_first_update() {
        let mut lightclient = init_lightclient(None);
        let update = get_update(862);
        let bootstrap = get_bootstrap();
        let res = update.verify(&lightclient);
        assert!(res.is_ok());

        let res = lightclient.apply_update(&update);
        assert!(res.is_ok());
        assert_eq!(
            lightclient.state.update_slot, update.finalized_header.beacon.slot,
            "finalized_header should be set after applying update"
        );
        assert_eq!(
            lightclient.state.current_sync_committee, bootstrap.current_sync_committee,
            "current_sync_committee should be unchanged"
        );
        assert_eq!(
            lightclient.state.next_sync_committee.unwrap(),
            update.next_sync_committee,
            "next_sync_committee should be set after applying update"
        );
    }

    #[test]
    fn test_apply_next_period_update() {
        let mut lightclient = init_lightclient(None);

        let mut res;
        res = lightclient.apply_update(&get_update(862));
        assert!(res.is_ok());
        let state_before_update = lightclient.state.clone();

        let update = get_update(863);
        res = lightclient.apply_update(&update);
        assert!(res.is_ok());

        assert_eq!(
            lightclient.state.update_slot, update.finalized_header.beacon.slot,
            "update_slot should be set after applying update"
        );
        assert_eq!(
            lightclient.state.current_sync_committee,
            state_before_update.next_sync_committee.unwrap(),
            "current_sync_committee was updated with previous next_sync_committee"
        );
        assert_eq!(
            lightclient.state.next_sync_committee.clone().unwrap(),
            update.next_sync_committee,
            "next_sync_committee was updated"
        );
    }

    #[test]
    #[ignore]
    fn test_apply_same_period_update() {
        let mut lightclient = init_lightclient(None);
        let update = get_update(862);

        let mut res;
        res = lightclient.apply_update(&update);
        assert!(res.is_ok());
        let state_before_update = lightclient.state.clone();

        // TODO: FIXME
        // update.finalized_header.beacon.slot =
        //     U64::from(update.finalized_header.beacon.slot.as_u64() + 1);
        res = lightclient.apply_update(&update);
        assert!(res.is_ok());

        assert_ne!(
            lightclient.state.update_slot,
            state_before_update.update_slot,
        );
        assert_eq!(
            lightclient.state.update_slot, update.finalized_header.beacon.slot,
            "update_slot should be set after applying update"
        );
        assert_eq!(
            lightclient.state.current_sync_committee, state_before_update.current_sync_committee,
            "current_sync_committee should be unchanged"
        );
        assert_eq!(
            lightclient.state.next_sync_committee, state_before_update.next_sync_committee,
            "next_sync_committee should be unchanged"
        );
    }

    #[test]
    fn test_multiple_updates() {
        let mut lightclient = init_lightclient(None);
        let update = get_update(862);
        let res = lightclient.apply_update(&update);
        assert!(res.is_ok());
        assert_eq!(
            lightclient.state.update_slot, update.finalized_header.beacon.slot,
            "finalized_header should be set after applying first update"
        );

        let update = get_update(863);
        let res = lightclient.apply_update(&update);
        assert!(res.is_ok());
        assert_eq!(
            lightclient.state.update_slot, update.finalized_header.beacon.slot,
            "finalized_header should be set after applying second update"
        );
    }
}
