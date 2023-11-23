extern crate alloc;
use alloc::collections::BTreeSet;
use sha2::{Digest, Sha256};
use ssz_rs::{
    field_inspect::FieldsIterMut, ElementsType, GeneralizedIndex, MerkleizationError, Merkleized,
    Node, SimpleSerialize, SszReflect, SszTypeClass,
};

/// Generates a proof for potentially multiple elements in an SszObject.
pub fn generate_proof<T: SimpleSerialize + SszReflect>(
    data: &mut T,
    indices: &[usize],
) -> Result<Vec<Node>, MerkleizationError> {
    // first merklize the data, return a virtual tree that maps the generalized index to the node
    // next calculate the required proof indices for given indices to prove.
    // return the nodes for those proof indices.
    let type_class = data.ssz_type_class();
    let leaves = match type_class {
        SszTypeClass::Basic
        | SszTypeClass::Union
        | SszTypeClass::Bits(_)
        | SszTypeClass::Elements(_) => Err(MerkleizationError::CannotMerkleize)?,
        SszTypeClass::Container => {
            let fields = data
                .as_mut_field_inspectable()
                .expect("SszTypeClass is a container; qed");
            let mut leaves = vec![];

            for (i, (j, field)) in FieldsIterMut::new(fields).enumerate() {
                let leaf = field.hash_tree_root()?;
                println!("i: {:?}, j: {:?}, leaf: {:?}", i, j, leaf);
                leaves.push(leaf);
            }

            leaves
        }
    };

    let virtual_tree = merkleize_to_virtual_tree(leaves);
    let indices = indices
        .into_iter()
        .cloned()
        .map(GeneralizedIndex)
        .collect::<Vec<_>>();
    let proof_indices = get_helper_indices(&indices);
    let mut proof = Vec::new();

    for GeneralizedIndex(index) in proof_indices {
        if index <= virtual_tree.len() {
            proof.push(virtual_tree[index].clone())
        }
    }

    Ok(proof)
}

pub fn merkleize_to_virtual_tree(leaves: Vec<Node>) -> Vec<Node> {
    let mut hasher = Sha256::new();
    let leaves_len = leaves.len();
    let bottom_len = leaves_len.next_power_of_two();
    let padding = bottom_len - leaves_len;
    let mut out = (0..bottom_len)
        .map(|_| Node::default())
        .chain(leaves.into_iter())
        .chain((0..padding).map(|_| Node::default()))
        .collect::<Vec<_>>();

    for i in (0..bottom_len).rev() {
        hasher.update(&out[i * 2]);
        hasher.update(&out[i * 2 + 1]);
        out[i] = hasher
            .finalize_reset()
            .as_slice()
            .try_into()
            .expect("SHA256 digest size is 32; qed");
    }

    out
}

fn get_helper_indices(indices: &[GeneralizedIndex]) -> Vec<GeneralizedIndex> {
    let mut all_helper_indices = BTreeSet::new();
    let mut all_path_indices = BTreeSet::new();

    for index in indices {
        all_helper_indices.extend(get_branch_indices(index).iter());
        all_path_indices.extend(get_path_indices(index).iter());
    }

    let mut all_branch_indices = all_helper_indices
        .difference(&all_path_indices)
        .cloned()
        .collect::<Vec<_>>();
    all_branch_indices.sort_by(|a: &GeneralizedIndex, b: &GeneralizedIndex| b.cmp(a));
    all_branch_indices
}

fn get_branch_indices(tree_index: &GeneralizedIndex) -> Vec<GeneralizedIndex> {
    let mut focus = tree_index.sibling();
    let mut result = vec![focus.clone()];
    while focus.0 > 1 {
        focus = focus.parent().sibling();
        result.push(focus.clone());
    }
    result.truncate(result.len() - 1);
    result
}

fn get_path_indices(tree_index: &GeneralizedIndex) -> Vec<GeneralizedIndex> {
    let mut focus = *tree_index;
    let mut result = vec![focus.clone()];
    while focus.0 > 1 {
        focus = focus.parent();
        result.push(focus.clone());
    }
    result.truncate(result.len() - 1);
    result
}
