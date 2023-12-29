use types::lightclient::{CrossChainId, Hash};

pub type VerificationResult = Vec<(ContentVariantId, String)>;
#[derive(serde::Serialize, serde::Deserialize)]
pub enum ContentVariantId {
    CrossChainId(CrossChainId),
    OperatorsHash(Hash),
}
