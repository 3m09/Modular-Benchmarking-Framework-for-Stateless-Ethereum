//! The relation proved by the zkVM: Keccak/RLP hexary MPT membership.

use serde::{Deserialize, Serialize};
use tiny_keccak::{Hasher, Keccak};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Lookup {
    pub root: [u8; 32],
    pub key: Vec<u8>,
    pub value: Vec<u8>,
    pub nodes: Vec<Vec<u8>>, // private witness; never committed to the journal
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Statement {
    pub root: [u8; 32],
    pub key: Vec<u8>,
    pub value: Vec<u8>,
}

impl Lookup {
    pub fn statement(&self) -> Statement {
        Statement {
            root: self.root,
            key: self.key.clone(),
            value: self.value.clone(),
        }
    }
}

fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut hash = [0u8; 32];
    let mut hasher = Keccak::v256();
    hasher.update(data);
    hasher.finalize(&mut hash);
    hash
}

#[derive(Clone, Copy)]
struct Item {
    start: usize,
    payload: usize,
    end: usize,
    list: bool,
}

impl Item {
    fn bytes<'a>(&self, data: &'a [u8]) -> &'a [u8] {
        &data[self.payload..self.end]
    }

    fn encoded<'a>(&self, data: &'a [u8]) -> &'a [u8] {
        &data[self.start..self.end]
    }
}

fn length(data: &[u8], start: usize, n: usize) -> Option<usize> {
    if n == 0 || n > 4 || start.checked_add(n)? > data.len() || data[start] == 0 {
        return None;
    }
    let mut len = 0usize;
    for &byte in &data[start..start + n] {
        len = len.checked_mul(256)?.checked_add(byte as usize)?;
    }
    (len > 55).then_some(len)
}

fn parse(data: &[u8], start: usize, depth: usize) -> Option<Item> {
    if depth > 64 {
        return None;
    }
    let tag = *data.get(start)?;
    let (payload, len, list) = match tag {
        0..=127 => (start, 1, false),
        128..=183 => (start + 1, (tag - 128) as usize, false),
        184..=191 => {
            let n = (tag - 183) as usize;
            (start.checked_add(1 + n)?, length(data, start + 1, n)?, false)
        }
        192..=247 => (start + 1, (tag - 192) as usize, true),
        _ => {
            let n = (tag - 247) as usize;
            (start.checked_add(1 + n)?, length(data, start + 1, n)?, true)
        }
    };
    let end = payload.checked_add(len)?;
    if end > data.len() || (tag == 129 && data[payload] < 128) {
        return None;
    }
    if list {
        let mut pos = payload;
        while pos < end {
            let child = parse(data, pos, depth + 1)?;
            if child.end > end {
                return None;
            }
            pos = child.end;
        }
        if pos != end {
            return None;
        }
    }
    Some(Item { start, payload, end, list })
}

fn children(data: &[u8], item: Item) -> Option<Vec<Item>> {
    if !item.list {
        return None;
    }
    let mut pos = item.payload;
    let mut result = Vec::new();
    while pos < item.end {
        let child = parse(data, pos, 1)?;
        if child.end > item.end || result.len() == 17 {
            return None;
        }
        result.push(child);
        pos = child.end;
    }
    Some(result)
}

fn valid_child(data: &[u8], item: Item) -> bool {
    if !item.list {
        return matches!(item.bytes(data).len(), 0 | 32);
    }
    item.encoded(data).len() < 32
        && children(data, item).is_some_and(|items| matches!(items.len(), 2 | 17))
}

fn child_matches(data: &[u8], reference: Item, next: &[u8]) -> bool {
    if next.len() < 32 {
        reference.list && reference.encoded(data) == next
    } else {
        !reference.list
            && reference.bytes(data).len() == 32
            && reference.bytes(data) == keccak256(next)
    }
}

fn nibbles(bytes: &[u8]) -> Vec<u8> {
    bytes.iter().flat_map(|b| [b >> 4, b & 15]).collect()
}

fn compact_path(bytes: &[u8]) -> Option<(Vec<u8>, bool)> {
    let (&first, rest) = bytes.split_first()?;
    let flag = first >> 4;
    if flag > 3 || (flag & 1 == 0 && first & 15 != 0) {
        return None;
    }
    let mut path = Vec::with_capacity(bytes.len() * 2);
    if flag & 1 != 0 {
        path.push(first & 15);
    }
    path.extend(nibbles(rest));
    Some((path, flag & 2 != 0))
}

/// Verify one *complete* membership path. The root is always a 32-byte hash.
pub fn verify_membership(root: &[u8; 32], key: &[u8], value: &[u8], nodes: &[Vec<u8>]) -> bool {
    let Some(first) = nodes.first() else { return false; };
    if keccak256(first) != *root {
        return false;
    }
    let path = nibbles(key);
    let mut key_pos = 0usize;
    for (index, node) in nodes.iter().enumerate() {
        let Some(outer) = parse(node, 0, 0) else { return false; };
        if !outer.list || outer.end != node.len() {
            return false;
        }
        let Some(items) = children(node, outer) else { return false; };
        let last = index + 1 == nodes.len();
        if items.len() == 17 {
            if items[..16].iter().any(|&item| !valid_child(node, item)) || items[16].list {
                return false;
            }
            if key_pos == path.len() {
                return last && !items[16].bytes(node).is_empty() && items[16].bytes(node) == value;
            }
            let choice = path[key_pos] as usize;
            if last || !child_matches(node, items[choice], &nodes[index + 1]) {
                return false;
            }
            key_pos += 1;
        } else if items.len() == 2 && !items[0].list {
            let Some((part, leaf)) = compact_path(items[0].bytes(node)) else { return false; };
            if !path[key_pos..].starts_with(&part) {
                return false;
            }
            key_pos += part.len();
            if leaf {
                return last && key_pos == path.len() && !items[1].list && items[1].bytes(node) == value;
            }
            if part.is_empty()
                || !valid_child(node, items[1])
                || last
                || !child_matches(node, items[1], &nodes[index + 1])
            {
                return false;
            }
        } else {
            return false;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn leaf_and_tampering() {
        let node = vec![201, 130, 32, 171, 133, 118, 97, 108, 117, 101];
        let root = keccak256(&node);
        assert!(verify_membership(&root, &[171], b"value", &[node.clone()]));
        assert!(!verify_membership(&root, &[172], b"value", &[node.clone()]));
        assert!(!verify_membership(&root, &[171], b"wrong", &[node.clone()]));
        assert!(!verify_membership(&[0; 32], &[171], b"value", &[node]));
    }

    #[test]
    fn inline_extension_and_branch() {
        let extension = vec![213, 26, 211, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128,
            128, 194, 32, 118, 128, 128, 128, 128, 128];
        let branch = extension[2..].to_vec();
        let leaf = vec![194, 32, 118];
        let root = keccak256(&extension);
        assert!(verify_membership(&root, &[171], b"v", &[extension, branch, leaf]));
    }

    #[test]
    fn hashed_branch_child() {
        let value = vec![120u8; 64];
        let mut leaf = vec![248, 67, 48, 184, 64];
        leaf.extend(&value);
        let mut branch = vec![241];
        branch.extend([128u8; 11]);
        branch.push(160);
        branch.extend(keccak256(&leaf));
        branch.extend([128u8; 5]);
        let root = keccak256(&branch);
        assert!(verify_membership(&root, &[176], &value, &[branch.clone(), leaf]));
        assert!(!verify_membership(&root, &[177], &value, &[branch]));
    }

    #[test]
    fn rejects_noncanonical_rlp() {
        let node = vec![0xc3, 0x81, 0x20, 0x80];
        let root = keccak256(&node);
        assert!(!verify_membership(&root, &[], b"", &[node]));
    }

    #[test]
    fn repository_tree_extension_branch_leaf() {
        // Generated by tree.merkle_tree.MerklePatriciaTrie for ab/ac keys.
        let nodes = [
            "e21aa0cd95314ee3ffbad70e5797f8aff40a736bed1143a50c4aaffb18b75066030182",
            "f8518080808080808080808080a0a66051538e04c60a1f0939b98b11c1255bb9b2386432b5cb5c5a139c113f51efa08d594d902f2a879e3bc8bcbb0d88433e93dbaf12ba5000f793a4144d60f6327b80808080",
            "f84420b84176616c756576616c756576616c756576616c756576616c756576616c756576616c756576616c756576616c756576616c756576616c756576616c756576616c7565",
        ]
        .map(|n| hex::decode(n).unwrap());
        let root: [u8; 32] = hex::decode(
            "4605a15c243c64b00ae3046ab4bdf74dc7727ca797f8cd6a5741f908a82bb145",
        )
        .unwrap()
        .try_into()
        .unwrap();
        assert!(verify_membership(&root, &[0xab], &b"value".repeat(13), &nodes));
        assert!(!verify_membership(&root, &[0xac], &b"value".repeat(13), &nodes));
    }
}
