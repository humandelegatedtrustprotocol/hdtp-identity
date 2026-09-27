//! The state `decide` reads: what the host holds (its keys, its pins, what it has forgotten and
//! where contacts used to live) and what it answers. Plain data; the host supplies it and applies
//! the effects `decide` returns.
use super::{active, Wire};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Deserialize, Clone)]
pub struct HeldKey {
    pub kid: String,
    pub leaf: String,
    pub pkcs8: String,
    #[serde(default)]
    pub current: bool,
}

/// Written by hand so `pkcs8` cannot be printed. `PrivateKey` and `PublicKey` deliberately derive no
/// `Debug`; a derive here undid that, and any `{:?}`, `expect` message or panic payload that touched a
/// `HeldKey` printed a host's LEAF PRIVATE KEY. The rest is public and worth keeping debuggable.
impl std::fmt::Debug for HeldKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HeldKey")
            .field("kid", &self.kid)
            .field("leaf", &self.leaf)
            .field("pkcs8", &"<redacted>")
            .field("current", &self.current)
            .finish()
    }
}

#[derive(Deserialize, Clone, Debug)]
pub struct Pin {
    pub root: String,
    pub endpoint: String,
    pub leaf: String,
    #[serde(default = "active")]
    pub state: String,
    /// The fingerprint of `leaf`'s key, when the host keeps it — see `pin_holding`.
    #[serde(default)]
    pub leaf_fingerprint: Option<String>,
}

#[derive(Deserialize, Clone, Debug)]
pub struct Tombstone {
    pub root: String,
    pub leaf: String,
    pub at: String,
}

#[derive(Deserialize, Clone, Debug)]
pub struct FormerEndpoint {
    pub root: String,
    pub endpoint: String,
    pub at: String,
}

fn auto() -> String {
    "auto".into()
}

#[derive(Deserialize, Clone, Debug)]
pub struct NodeState {
    pub endpoint: String,
    #[serde(default = "auto")]
    pub accept_new_hosts: String,
    #[serde(default)]
    pub chain: Vec<String>,
    #[serde(default)]
    pub keys: Vec<HeldKey>,
    #[serde(default)]
    pub former: Vec<String>,
    #[serde(default)]
    pub sibling_kids: Vec<String>,
    #[serde(default)]
    pub pins: Vec<Pin>,
    #[serde(default)]
    pub tombstones: Vec<Tombstone>,
    #[serde(default)]
    pub former_endpoints: Vec<FormerEndpoint>,
    #[serde(default)]
    pub seen: Vec<String>,
}

#[derive(Deserialize, Clone, Debug)]
pub struct DecideInput {
    pub now: String,
    pub envelope: Wire,
    pub node: NodeState,
}

#[derive(Serialize, Debug)]
pub struct DecideOutput {
    pub result: Value,
    pub effects: Vec<Value>,
}
