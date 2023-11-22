#[cfg(test)]
mod tests {
    use std::{
        fs::File,
        time::{SystemTime, UNIX_EPOCH},
    };

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
    use ssz_rs::Bitvector;
    use types::{
        common::{BLSPubKey, SignatureBytes},
        consensus::BeaconBlockHeader,
        lightclient::{BlockVerificationData, LightClientState},
        primitives::{ByteVector, U64},
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

        client
    }

    #[test]
    fn test_verify_update_participation() {
        let lightclient = init_lightclient();

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
        let lightclient = init_lightclient();

        let mut update = get_update(862);
        update.signature_slot = U64::from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
                + 12,
        );
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
        update.finalized_header.beacon.slot =
            U64::from(u64::from(update.attested_header.beacon.slot) + 1);
        err = update.verify(&lightclient).unwrap_err();

        assert_eq!(
            err.to_string(),
            lightclient::ConsensusError::InvalidTimestamp.to_string()
        );
    }

    #[test]
    fn test_verify_update_period() {
        let mut lightclient = init_lightclient();
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
        let mut lightclient = init_lightclient();
        let mut update = get_update(862);
        lightclient.apply_update(&update).unwrap();

        update.attested_header.beacon.slot = lightclient.state.finalized_header.slot;
        update.finalized_header.beacon.slot = lightclient.state.finalized_header.slot;
        assert!(lightclient.state.next_sync_committee.is_some());
        let mut err = update.verify(&lightclient).unwrap_err();
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
        err = update.verify(&lightclient).unwrap_err();
        assert_eq!(
            err.to_string(),
            lightclient::ConsensusError::NotRelevant.to_string()
        );
    }

    #[test]
    fn test_verify_update_finality_proof() {
        let lightclient = init_lightclient();
        let mut update = get_update(862);

        update.finality_branch = vec![];
        let mut err = update.verify(&lightclient).unwrap_err();
        assert_eq!(
            err.to_string(),
            lightclient::ConsensusError::InvalidFinalityProof.to_string()
        );

        update = get_update(862);
        update.finalized_header.beacon.state_root = ByteVector::default();
        err = update.verify(&lightclient).unwrap_err();
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
        let err = update.verify(&lightclient).unwrap_err();

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

        let err = update.verify(&lightclient).err().unwrap();
        assert_eq!(
            err.to_string(),
            ConsensusError::InvalidSignature.to_string()
        );
    }

    #[test]
    fn test_verify_update() {
        let lightclient = init_lightclient();

        let update = get_update(862);
        let res = update.verify(&lightclient);
        assert!(res.is_ok());
    }

    #[test]
    fn test_bootstrap_state() {
        let lightclient = init_lightclient();
        let bootstrap = get_bootstrap();

        let mut update = get_update(862);
        update.finalized_header.beacon = BeaconBlockHeader::default();

        let err = update.verify(&lightclient);
        assert!(err.is_err());

        assert_eq!(
            lightclient.state,
            LightClientState {
                finalized_header: bootstrap.header.beacon,
                current_sync_committee: bootstrap.current_sync_committee,
                next_sync_committee: None,
                previous_max_active_participants: 0,
                current_max_active_participants: 0
            }
        );
    }

    #[test]
    fn test_apply_first_update() {
        let mut lightclient = init_lightclient();
        let update = get_update(862);
        let bootstrap = get_bootstrap();
        let res = update.verify(&lightclient);
        assert!(res.is_ok());

        let res = lightclient.apply_update(&update);
        assert!(res.is_ok());
        assert_eq!(
            lightclient.state.finalized_header, update.finalized_header.beacon,
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
        assert_eq!(
            lightclient.state.previous_max_active_participants, 0,
            "previous_max_active_participants should be unchanged"
        );
        assert_eq!(
            lightclient.state.current_max_active_participants, 511,
            "current_max_active_participants should be unchanged"
        );
    }

    #[test]
    fn test_apply_next_period_update() {
        let mut lightclient = init_lightclient();

        let mut res;
        res = lightclient.apply_update(&get_update(862));
        assert!(res.is_ok());
        let state_before_update = lightclient.state.clone();

        let update = get_update(863);
        res = lightclient.apply_update(&update);
        assert!(res.is_ok());

        assert_eq!(
            lightclient.state.finalized_header, update.finalized_header.beacon,
            "finalized_header should be set after applying update"
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
        assert_eq!(
            lightclient.state.previous_max_active_participants,
            u64::max(
                state_before_update.current_max_active_participants,
                lightclient.get_bits(&update.sync_aggregate.sync_committee_bits),
            ),
            "previous_max_active_participants should be unchanged"
        );
        assert_eq!(
            lightclient.state.current_max_active_participants, 0,
            "current_max_active_participants should be unchanged"
        );
    }

    #[test]
    #[ignore]
    fn test_apply_same_period_update() {
        let mut lightclient = init_lightclient();
        let mut update = get_update(862);

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
            lightclient.state.finalized_header,
            state_before_update.finalized_header,
        );
        assert_eq!(
            lightclient.state.finalized_header, update.finalized_header.beacon,
            "finalized_header should be set after applying update"
        );
        assert_eq!(
            lightclient.state.current_sync_committee, state_before_update.current_sync_committee,
            "current_sync_committee should be unchanged"
        );
        assert_eq!(
            lightclient.state.next_sync_committee, state_before_update.next_sync_committee,
            "next_sync_committee should be unchanged"
        );
        assert_eq!(
            lightclient.state.previous_max_active_participants,
            state_before_update.previous_max_active_participants,
            "previous_max_active_participants should be unchanged"
        );
        assert_eq!(
            lightclient.state.current_max_active_participants,
            state_before_update.current_max_active_participants,
            "current_max_active_participants should be unchanged"
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

    #[test]
    fn test_verify_block_directly() {
        let mut lightclient = init_lightclient();
        let bootstrap = get_bootstrap();

        let update = get_update(862);
        let res = lightclient.apply_update(&update);
        assert!(res.is_ok());

        let file: File = File::open("testdata/verification/7061552-7061553.json").unwrap();
        let data: BlockVerificationData = serde_json::from_reader(file).unwrap();
        let sync_committee = bootstrap.current_sync_committee;

        assert!(lightclient.verify_block(
            &sync_committee,
            &data.target_block,
            &data.intermediate_chain,
            &data.sync_aggregate,
            data.sig_slot.into(),
        ));
    }

    #[test]
    fn test_verify_block_with_intermediate_block() {
        let mut lightclient = init_lightclient();
        let bootstrap = get_bootstrap();

        let update = get_update(862);
        let res = lightclient.apply_update(&update);
        assert!(res.is_ok());

        let file: File = File::open("testdata/verification/7061551-7061553.json").unwrap();
        let data: BlockVerificationData = serde_json::from_reader(file).unwrap();
        let sync_committee = bootstrap.current_sync_committee;

        assert!(lightclient.verify_block(
            &sync_committee,
            &data.target_block,
            &data.intermediate_chain,
            &data.sync_aggregate,
            data.sig_slot.into(),
        ));
    }

    #[test]
    fn test_verify_block_with_intermediate_chain() {
        let mut lightclient = init_lightclient();
        let bootstrap = get_bootstrap();

        let update = get_update(862);
        let res = lightclient.apply_update(&update);
        assert!(res.is_ok());

        let file: File = File::open("testdata/verification/7061551-7061555.json").unwrap();
        let data: BlockVerificationData = serde_json::from_reader(file).unwrap();
        let sync_committee = bootstrap.current_sync_committee;

        assert!(lightclient.verify_block(
            &sync_committee,
            &data.target_block,
            &data.intermediate_chain,
            &data.sync_aggregate,
            data.sig_slot.into(),
        ));
    }
}
