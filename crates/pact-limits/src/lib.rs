//! PACT SPEC §12's per-caller call budgets, decided in one place: layer 2 of the two-layer plan
//! (pact-gateway `docs/release/two-layer-limits-2026-09-28.md`), the check that runs after an
//! envelope is opened and the caller is known.
//!
//! Everything here is a pure function of its arguments. There is no I/O: the counters live in a
//! [`StateStore`] the host implements (the cloud's `rate_buckets` table, the node sidecar's own
//! store), the clock is the `now` the host passes, and the numbers are a [`Rules`] document the
//! host reads from its configuration. The crate carries no default rule set on purpose: a compiled
//! default is the host's fail-safe, logged when used, and never a second source of truth.
//!
//! The arithmetic is what the cloud's `RateLimiter.take` was (`gateway/src/identity/limits.ts`, the
//! same bytes from pact-cloud 449b273 to b781b53), operation for operation, in IEEE double precision,
//! so the rows the cloud wrote before it moved to this crate (ba68f9c) read the same after.
//! `js/cases/limits-vectors.json`, a fixed record of that TypeScript's decisions over SQLite, holds
//! this crate, the Wasm and the Go port to it.

/// One token bucket: the row it is kept in, its sustained rate in calls a second, and the most calls
/// it holds. A bucket with no row is full.
#[derive(Debug, Clone, PartialEq)]
pub struct Bucket {
    pub key: String,
    pub per_second: f64,
    pub burst: f64,
}

impl Bucket {
    /// `n` calls an hour, all of them available at once: `perHour` of the TypeScript. The rate is
    /// `n / 3600`, computed once, as there.
    pub fn per_hour(key: String, n: f64) -> Bucket {
        Bucket { key, per_second: n / 3600.0, burst: n }
    }
}

/// What a bucket's row holds: the tokens left when it was last charged, and when (milliseconds).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Level {
    pub tokens: f64,
    pub updated_at: i64,
}

/// Where the counters live. `get` of a key never written, or removed, is `None`, which reads as a
/// full bucket; `put` replaces the row.
pub trait StateStore {
    fn get(&self, key: &str) -> Option<Level>;
    fn put(&mut self, key: &str, level: Level);
}

/// A row untouched this long is full whatever it budgets, so a host may delete it: [`Rules::check`]
/// refuses a rule set with a bucket that takes longer than this to refill from empty. The cloud's
/// sweep deletes rows older than this (`rate_buckets`, at most a thousand a minute).
pub const IDLE_MS: i64 = 3_600_000;

/// The numbers of PACT §12's call budgets. Every member is required; none has a default here.
#[derive(Debug, Clone, PartialEq)]
pub struct Rules {
    /// One contact, inbound, and one contact, outbound: the sustained rate…
    pub contact_calls_per_second: f64,
    /// …and how many calls it may make at once.
    pub contact_burst: f64,
    /// The most calls a second one identity is held to from all its contacts together, and sends to
    /// all of them together: what one host serves.
    pub identity_capacity_per_second: f64,
    /// A guest, per proven root and source.
    pub guest_calls_per_hour: f64,
    /// A source alone: a small form answered `chain_required`, which proves no root.
    pub guest_source_calls_per_hour: f64,
    /// Calls out to somebody who is not a contact, per identity.
    pub stranger_calls_out_per_hour: f64,
    /// One integration, per contact (SPEC §5.7).
    pub integration_calls_per_hour: f64,
    /// Every guest together, per identity, charged BEFORE the envelope is opened, keyed on nothing a
    /// caller can rotate.
    pub guest_total_calls_per_hour: f64,
    /// The most requests (`pending_in` rows) an identity holds waiting on its owner.
    pub pending_in_cap: f64,
}

/// The members of a rules document, in the order they are checked.
pub const RULE_MEMBERS: [&str; 9] = [
    "contact_calls_per_second",
    "contact_burst",
    "identity_capacity_per_second",
    "guest_calls_per_hour",
    "guest_source_calls_per_hour",
    "stranger_calls_out_per_hour",
    "integration_calls_per_hour",
    "guest_total_calls_per_hour",
    "pending_in_cap",
];

impl Rules {
    /// The rule set read from its members by name, in [`RULE_MEMBERS`] order.
    pub fn from_members(get: impl Fn(&str) -> f64) -> Rules {
        Rules {
            contact_calls_per_second: get("contact_calls_per_second"),
            contact_burst: get("contact_burst"),
            identity_capacity_per_second: get("identity_capacity_per_second"),
            guest_calls_per_hour: get("guest_calls_per_hour"),
            guest_source_calls_per_hour: get("guest_source_calls_per_hour"),
            stranger_calls_out_per_hour: get("stranger_calls_out_per_hour"),
            integration_calls_per_hour: get("integration_calls_per_hour"),
            guest_total_calls_per_hour: get("guest_total_calls_per_hour"),
            pending_in_cap: get("pending_in_cap"),
        }
    }

    fn member(&self, name: &str) -> f64 {
        match name {
            "contact_calls_per_second" => self.contact_calls_per_second,
            "contact_burst" => self.contact_burst,
            "identity_capacity_per_second" => self.identity_capacity_per_second,
            "guest_calls_per_hour" => self.guest_calls_per_hour,
            "guest_source_calls_per_hour" => self.guest_source_calls_per_hour,
            "stranger_calls_out_per_hour" => self.stranger_calls_out_per_hour,
            "integration_calls_per_hour" => self.integration_calls_per_hour,
            "guest_total_calls_per_hour" => self.guest_total_calls_per_hour,
            _ => self.pending_in_cap,
        }
    }

    /// Whether this rule set can be enforced as written, and the first reason it cannot.
    ///
    /// - Every number is finite. `contact_calls_per_second` is above 0; every other member is at least
    ///   1, since a bucket that never holds a whole call refuses every call forever.
    /// - `pending_in_cap` is a whole number: it counts rows.
    /// - A contact's bucket refills from empty within [`IDLE_MS`] (`contact_burst /
    ///   contact_calls_per_second` at most 3600 s). Every other bucket does by construction (an hourly
    ///   budget refills in an hour; the identity's holds one second of its rate). Without this, a host
    ///   that deletes idle rows would hand a caller a full bucket it had not earned.
    pub fn check(&self) -> Result<(), String> {
        for name in RULE_MEMBERS {
            let v = self.member(name);
            if !v.is_finite() {
                return Err(format!("{name} is a number"));
            }
            if name == "contact_calls_per_second" {
                if v <= 0.0 {
                    return Err(format!("{name} is above 0"));
                }
            } else if v < 1.0 {
                return Err(format!("{name} is at least 1"));
            }
        }
        if self.pending_in_cap.fract() != 0.0 {
            return Err("pending_in_cap is a whole number".into());
        }
        if self.contact_burst / self.contact_calls_per_second > (IDLE_MS / 1000) as f64 {
            return Err(
                "contact_burst / contact_calls_per_second is at most 3600: a contact's bucket refills within the hour an idle row is kept"
                    .into(),
            );
        }
        Ok(())
    }

    /// The identity's aggregate rate: its contact cap times the per-contact rate, at most what one
    /// host serves, and never below one call a second (`identityPerSecond`).
    pub fn identity_per_second(&self, contact_cap: f64) -> f64 {
        f64::max(1.0, f64::min(contact_cap * self.contact_calls_per_second, self.identity_capacity_per_second))
    }
}

/// What a call is charged to. The keys and the order of the buckets are the TypeScript's, so a row
/// the cloud's `rate_buckets` holds today reads the same after the swap.
#[derive(Debug, Clone, PartialEq)]
pub enum Charge {
    /// An active contact calling in: its own bucket, then the identity's aggregate.
    ContactIn { root: String, contact_cap: f64 },
    /// Anybody else calling in (a guest, a pending or blocked root): by the root the envelope proved
    /// and the source it came from. `addressed` is whether the edge gave an address; `source` is the
    /// host's name for it (the cloud's is a salted hash, and the empty address has one too).
    GuestIn { root: Option<String>, source: String, addressed: bool },
    /// Every guest together, before the envelope is opened.
    GuestTotal,
    /// A call out to an active contact: its bucket, then the identity's outbound aggregate.
    ContactOut { root: String, contact_cap: f64 },
    /// A call out to anybody who is not an active contact, or one that starts or answers a
    /// relationship.
    StrangerOut,
    /// A call to one integration by one contact.
    Integration { integration: String, contact: String },
    /// A request from a stranger, while the identity holds `held` requests already.
    PendingIn { held: f64 },
}

impl Charge {
    /// The buckets a call is charged to, in order. A count quota has none.
    pub fn buckets(&self, rules: &Rules) -> Vec<Bucket> {
        let contact = |key: String| Bucket { key, per_second: rules.contact_calls_per_second, burst: rules.contact_burst };
        let identity = |key: &str, cap: f64| {
            let r = rules.identity_per_second(cap);
            Bucket { key: key.to_string(), per_second: r, burst: r }
        };
        match self {
            Charge::ContactIn { root, contact_cap } => vec![contact(format!("contact:{root}")), identity("identity", *contact_cap)],
            Charge::GuestIn { root, source, addressed } => match root.as_deref().filter(|r| !r.is_empty()) {
                None => vec![Bucket::per_hour(format!("source:{source}"), rules.guest_source_calls_per_hour)],
                Some(r) if *addressed => vec![Bucket::per_hour(format!("guest:{r}:{source}"), rules.guest_calls_per_hour)],
                Some(r) => vec![Bucket::per_hour(format!("guest:{r}"), rules.guest_calls_per_hour)],
            },
            Charge::GuestTotal => vec![Bucket::per_hour("guest-total".into(), rules.guest_total_calls_per_hour)],
            Charge::ContactOut { root, contact_cap } => {
                vec![contact(format!("out:contact:{root}")), identity("out:identity", *contact_cap)]
            }
            Charge::StrangerOut => vec![Bucket::per_hour("out:stranger".into(), rules.stranger_calls_out_per_hour)],
            Charge::Integration { integration, contact } => {
                vec![Bucket::per_hour(format!("integration:{integration}:{contact}"), rules.integration_calls_per_hour)]
            }
            Charge::PendingIn { .. } => Vec::new(),
        }
    }
}

/// The answer: the call is let through, or refused with the bucket that refused it.
#[derive(Debug, Clone, PartialEq)]
pub enum Decision {
    Allow,
    /// `retry_after` is the whole seconds, at least 1, until every bucket that refused holds a call
    /// again; `None` for a count quota, which no wait refills. `which` is the key of the bucket that
    /// needs longest (the first of equals, in charge order), or `pending_in`.
    Refuse {
        retry_after: Option<u64>,
        which: String,
    },
}

/// Charges one call to every bucket of `charge`, or to none of them: a refusal spends nothing, so a
/// contact refused by the identity's aggregate keeps its own burst.
///
/// A bucket holds at most its burst, refills at its rate, and starts full. Its level is read from its
/// row as `min(burst, tokens + elapsed × rate)`, `elapsed` the seconds since the row was written and
/// never negative (a clock that went back refills nothing, and the row is written with the earlier
/// time). Every level is read before any row is written, so a key named twice in one charge is
/// spent once.
pub fn decide(rules: &Rules, charge: &Charge, now: i64, store: &mut impl StateStore) -> Decision {
    if let Charge::PendingIn { held } = charge {
        return if *held >= rules.pending_in_cap {
            Decision::Refuse { retry_after: None, which: "pending_in".into() }
        } else {
            Decision::Allow
        };
    }
    let buckets = charge.buckets(rules);
    let levels: Vec<f64> = buckets
        .iter()
        .map(|b| match store.get(&b.key) {
            None => b.burst,
            Some(row) => {
                let elapsed = (now - row.updated_at).max(0) as f64 / 1000.0;
                f64::min(b.burst, row.tokens + elapsed * b.per_second)
            }
        })
        .collect();
    let mut retry_after = 0.0;
    let mut which = "";
    for (b, level) in buckets.iter().zip(&levels) {
        if *level >= 1.0 {
            continue;
        }
        let wait = f64::max(1.0, ((1.0 - level) / b.per_second).ceil());
        if wait > retry_after {
            retry_after = wait;
            which = &b.key;
        }
    }
    if retry_after > 0.0 {
        return Decision::Refuse { retry_after: Some(retry_after as u64), which: which.to_string() };
    }
    for (b, level) in buckets.iter().zip(&levels) {
        store.put(&b.key, Level { tokens: level - 1.0, updated_at: now });
    }
    Decision::Allow
}

/// A store in memory, in the order rows were first written: the contract function's state, and the
/// tests'.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct MemoryStore {
    pub rows: Vec<(String, Level)>,
}

impl StateStore for MemoryStore {
    fn get(&self, key: &str) -> Option<Level> {
        self.rows.iter().find(|(k, _)| k == key).map(|(_, l)| *l)
    }
    fn put(&mut self, key: &str, level: Level) {
        match self.rows.iter_mut().find(|(k, _)| k == key) {
            Some((_, l)) => *l = level,
            None => self.rows.push((key.to_string(), level)),
        }
    }
}

impl MemoryStore {
    /// Deletes every row idle for longer than [`IDLE_MS`]: what a host's sweep may do at any time
    /// without changing a decision, when the rules pass [`Rules::check`].
    pub fn sweep(&mut self, now: i64) {
        self.rows.retain(|(_, l)| l.updated_at >= now - IDLE_MS);
    }
}

#[cfg(test)]
mod tests;
