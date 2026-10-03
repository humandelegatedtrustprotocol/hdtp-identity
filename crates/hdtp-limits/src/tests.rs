//! The decision's properties, over generated sequences as well as chosen ones. The equivalence with
//! the cloud's TypeScript is `tests/vectors.rs`.
use super::*;

/// Arbitrary numbers, chosen to be unlike HDTP's defaults so a test cannot pass by agreeing with
/// them by accident. The guest total and the pending cap have no approved numbers yet.
fn rules() -> Rules {
    Rules {
        contact_calls_per_second: 2.0,
        contact_burst: 5.0,
        identity_capacity_per_second: 7.0,
        guest_calls_per_hour: 3.0,
        guest_source_calls_per_hour: 4.0,
        stranger_calls_out_per_hour: 6.0,
        integration_calls_per_hour: 8.0,
        guest_total_calls_per_hour: 9.0,
        pending_in_cap: 2.0,
    }
}

/// splitmix64: a generator with no dependency, so a failing seed can be named and rerun.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

fn every_charge(cap: f64) -> Vec<Charge> {
    vec![
        Charge::ContactIn { root: "sha256:A".into(), contact_cap: cap },
        Charge::GuestIn { root: Some("sha256:G".into()), source: "s1".into(), addressed: true },
        Charge::GuestIn { root: Some("sha256:G".into()), source: "s1".into(), addressed: false },
        Charge::GuestIn { root: None, source: "s1".into(), addressed: true },
        Charge::GuestTotal,
        Charge::ContactOut { root: "sha256:A".into(), contact_cap: cap },
        Charge::StrangerOut,
        Charge::Integration { integration: "i1".into(), contact: "sha256:A".into() },
    ]
}

#[test]
fn a_fresh_key_is_let_through() {
    for charge in every_charge(3.0) {
        let mut store = MemoryStore::default();
        assert_eq!(decide(&rules(), &charge, 1_000, &mut store), Decision::Allow, "{charge:?}");
        assert_eq!(store.rows.len(), charge.buckets(&rules()).len(), "{charge:?} wrote a row per bucket");
    }
    assert_eq!(decide(&rules(), &Charge::PendingIn { held: 0.0 }, 1_000, &mut MemoryStore::default()), Decision::Allow);
}

#[test]
fn every_rule_refuses_once_its_burst_is_spent_and_names_its_bucket() {
    // One bucket per charge, alone, so the one that refuses is the one the rule names.
    let r = rules();
    let cases: Vec<(Charge, &str, f64)> = vec![
        (
            Charge::GuestIn { root: Some("sha256:G".into()), source: "s1".into(), addressed: true },
            "guest:sha256:G:s1",
            r.guest_calls_per_hour,
        ),
        (
            Charge::GuestIn { root: Some("sha256:G".into()), source: "s1".into(), addressed: false },
            "guest:sha256:G",
            r.guest_calls_per_hour,
        ),
        (Charge::GuestIn { root: Some(String::new()), source: "s1".into(), addressed: true }, "source:s1", r.guest_source_calls_per_hour),
        (Charge::GuestIn { root: None, source: "s1".into(), addressed: false }, "source:s1", r.guest_source_calls_per_hour),
        (Charge::GuestTotal, "guest-total", r.guest_total_calls_per_hour),
        (Charge::StrangerOut, "out:stranger", r.stranger_calls_out_per_hour),
        (
            Charge::Integration { integration: "i1".into(), contact: "sha256:A".into() },
            "integration:i1:sha256:A",
            r.integration_calls_per_hour,
        ),
    ];
    for (charge, key, burst) in cases {
        let mut store = MemoryStore::default();
        for i in 0..burst as i64 {
            assert_eq!(decide(&r, &charge, 5_000, &mut store), Decision::Allow, "{key}: call {i} of its burst");
        }
        // An hourly bucket of n refills one call in 3600/n seconds.
        let want = (3600.0 / burst).ceil() as u64;
        assert_eq!(decide(&r, &charge, 5_000, &mut store), Decision::Refuse { retry_after: Some(want), which: key.into() }, "{key}");
    }
    // The contact's own bucket (5 at 2/s), with the identity's aggregate roomy enough not to refuse.
    let mut store = MemoryStore::default();
    let charge = Charge::ContactIn { root: "sha256:A".into(), contact_cap: 100.0 };
    for _ in 0..5 {
        assert_eq!(decide(&r, &charge, 0, &mut store), Decision::Allow);
    }
    assert_eq!(decide(&r, &charge, 0, &mut store), Decision::Refuse { retry_after: Some(1), which: "contact:sha256:A".into() });
    let charge = Charge::ContactOut { root: "sha256:A".into(), contact_cap: 100.0 };
    for _ in 0..5 {
        assert_eq!(decide(&r, &charge, 0, &mut store), Decision::Allow);
    }
    assert_eq!(decide(&r, &charge, 0, &mut store), Decision::Refuse { retry_after: Some(1), which: "out:contact:sha256:A".into() });
}

#[test]
fn the_identity_aggregate_refuses_a_contact_that_still_has_its_own_burst_and_spends_nothing() {
    // A cap of 2 contacts at 2/s: the identity holds 4 a second, fewer than one contact's burst of 5.
    let r = rules();
    let mut store = MemoryStore::default();
    for n in 0..4 {
        let charge = Charge::ContactIn { root: format!("sha256:{n}"), contact_cap: 2.0 };
        assert_eq!(decide(&r, &charge, 0, &mut store), Decision::Allow);
    }
    let before = store.clone();
    let charge = Charge::ContactIn { root: "sha256:new".into(), contact_cap: 2.0 };
    assert_eq!(decide(&r, &charge, 0, &mut store), Decision::Refuse { retry_after: Some(1), which: "identity".into() });
    assert_eq!(store, before, "a refusal writes nothing, so the refused contact keeps its own burst");
    // Out, the same with its own key.
    for n in 0..4 {
        assert_eq!(decide(&r, &Charge::ContactOut { root: format!("sha256:{n}"), contact_cap: 2.0 }, 0, &mut store), Decision::Allow);
    }
    let out = Charge::ContactOut { root: "sha256:new".into(), contact_cap: 2.0 };
    assert_eq!(decide(&r, &out, 0, &mut store), Decision::Refuse { retry_after: Some(1), which: "out:identity".into() });
}

#[test]
fn the_identity_rate_is_the_cap_times_the_contact_rate_at_most_the_capacity_and_at_least_one() {
    let r = rules();
    assert_eq!(r.identity_per_second(3.0), 6.0);
    assert_eq!(r.identity_per_second(1_000.0), 7.0, "capped at identity_capacity_per_second");
    assert_eq!(r.identity_per_second(0.0), 1.0, "never below one call a second");
}

#[test]
fn the_pending_cap_refuses_at_the_cap_with_no_wait_that_would_refill_it() {
    let r = rules();
    let mut store = MemoryStore::default();
    assert_eq!(decide(&r, &Charge::PendingIn { held: 1.0 }, 0, &mut store), Decision::Allow);
    assert_eq!(
        decide(&r, &Charge::PendingIn { held: 2.0 }, 0, &mut store),
        Decision::Refuse { retry_after: None, which: "pending_in".into() }
    );
    assert_eq!(
        decide(&r, &Charge::PendingIn { held: 3.0 }, 0, &mut store),
        Decision::Refuse { retry_after: None, which: "pending_in".into() }
    );
    assert!(store.rows.is_empty(), "a count quota keeps no row");
}

#[test]
fn retry_after_is_the_wait_to_within_a_rounding_second() {
    // Over generated sequences: whenever a call is refused with retry_after n, the same call n + 1
    // seconds later is let through, and n - 2 seconds later (n > 2) is still refused. Between those,
    // the answer is the rounding's. The TypeScript's arithmetic (`limits.ts`, which this reproduces,
    // and which the cloud removed at ba68f9c)
    // computes n from the level when refused and the later level afresh from the row, and the two
    // roundings can part either way:
    //   - short: seed 74, level 0.06666666666666654 at 3 an hour, n = 1120 exactly, and the level
    //     1120 s on is 0.9999999999999999, so the call is refused once more, with retry_after 1;
    //   - long: seed 188, a wait a rounding error over a whole second is ceiled up to the next one,
    //     and the call is let through a second before retry_after said.
    // Both are counted, so the test says when its generator stops reaching them.
    let r = rules();
    let (mut short, mut long) = (0, 0);
    for seed in 0..200u64 {
        let mut rng = Rng(seed);
        let mut store = MemoryStore::default();
        let mut now = 0i64;
        let charges = every_charge(1.0 + rng.below(4) as f64);
        for _ in 0..300 {
            now += rng.below(1_500) as i64;
            let charge = &charges[rng.below(charges.len() as u64) as usize];
            if let Decision::Refuse { retry_after: Some(n), which } = decide(&r, charge, now, &mut store) {
                assert!(n >= 1, "seed {seed}: retry_after {n}");
                let n = n as i64;
                let at = |secs: i64| decide(&r, charge, now + secs * 1000, &mut store.clone());
                assert_eq!(at(n + 1), Decision::Allow, "seed {seed}: {which} after {n} + 1 s");
                if n > 2 {
                    assert!(matches!(at(n - 2), Decision::Refuse { .. }), "seed {seed}: {which} let through two seconds early");
                }
                if at(n) != Decision::Allow {
                    assert_eq!(at(n), Decision::Refuse { retry_after: Some(1), which: which.clone() }, "seed {seed}: {which} after {n} s");
                    short += 1;
                }
                if n > 1 && at(n - 1) == Decision::Allow {
                    long += 1;
                }
            }
        }
    }
    assert!(short > 0 && long > 0, "the rounding cases this test describes were not reached (short {short}, long {long})");
}

#[test]
fn a_bucket_never_holds_more_than_its_burst_and_refills_at_its_rate() {
    let r = rules();
    let charge = Charge::StrangerOut; // 6 an hour: one call every 600 s
    let mut store = MemoryStore::default();
    for _ in 0..6 {
        assert_eq!(decide(&r, &charge, 0, &mut store), Decision::Allow);
    }
    assert!(matches!(decide(&r, &charge, 599_000, &mut store), Decision::Refuse { retry_after: Some(1), .. }));
    assert_eq!(decide(&r, &charge, 600_000, &mut store), Decision::Allow);
    // A day idle is still only a burst.
    let mut store = MemoryStore::default();
    assert_eq!(decide(&r, &charge, 0, &mut store), Decision::Allow);
    for _ in 0..6 {
        assert_eq!(decide(&r, &charge, 86_400_000, &mut store), Decision::Allow);
    }
    assert!(matches!(decide(&r, &charge, 86_400_000, &mut store), Decision::Refuse { .. }));
}

#[test]
fn a_clock_that_goes_back_refills_nothing_and_writes_the_earlier_time() {
    let r = rules();
    let mut store = MemoryStore::default();
    let charge = Charge::StrangerOut;
    assert_eq!(decide(&r, &charge, 10_000, &mut store), Decision::Allow);
    assert_eq!(decide(&r, &charge, 5_000, &mut store), Decision::Allow);
    assert_eq!(store.get("out:stranger"), Some(Level { tokens: 4.0, updated_at: 5_000 }));
}

#[test]
fn deleting_idle_rows_changes_no_decision_under_rules_that_pass_the_check() {
    // What lets a host sweep: the same sequence, swept after every call and never swept, decides alike.
    let mut r = rules();
    r.contact_burst = 7_200.0; // 3600 s from empty at 2/s: the slowest a contact's bucket may be
    r.check().unwrap();
    for seed in 0..100u64 {
        let mut rng = Rng(seed);
        let (mut kept, mut swept) = (MemoryStore::default(), MemoryStore::default());
        let mut now = 0i64;
        let charges = every_charge(2.0);
        for step in 0..400 {
            // Mostly short gaps, sometimes an hour and a millisecond or more: every idle row goes.
            now += if rng.below(10) == 0 { IDLE_MS + 1 + rng.below(5_000) as i64 } else { rng.below(2_000) as i64 };
            let charge = &charges[rng.below(charges.len() as u64) as usize];
            let a = decide(&r, charge, now, &mut kept);
            let b = decide(&r, charge, now, &mut swept);
            swept.sweep(now);
            assert_eq!(a, b, "seed {seed} step {step}");
        }
    }
}

#[test]
fn the_check_refuses_every_rule_set_that_cannot_be_enforced_as_written() {
    assert_eq!(rules().check(), Ok(()));
    let with = |f: fn(&mut Rules)| {
        let mut r = rules();
        f(&mut r);
        r.check().unwrap_err()
    };
    assert_eq!(with(|r| r.contact_calls_per_second = 0.0), "contact_calls_per_second is above 0");
    assert_eq!(with(|r| r.contact_burst = 0.5), "contact_burst is at least 1");
    assert_eq!(with(|r| r.identity_capacity_per_second = f64::NAN), "identity_capacity_per_second is a number");
    assert_eq!(with(|r| r.guest_calls_per_hour = 0.0), "guest_calls_per_hour is at least 1");
    assert_eq!(with(|r| r.guest_source_calls_per_hour = -1.0), "guest_source_calls_per_hour is at least 1");
    assert_eq!(with(|r| r.stranger_calls_out_per_hour = 0.0), "stranger_calls_out_per_hour is at least 1");
    assert_eq!(with(|r| r.integration_calls_per_hour = f64::INFINITY), "integration_calls_per_hour is a number");
    assert_eq!(with(|r| r.guest_total_calls_per_hour = 0.0), "guest_total_calls_per_hour is at least 1");
    assert_eq!(with(|r| r.pending_in_cap = 0.0), "pending_in_cap is at least 1");
    assert_eq!(with(|r| r.pending_in_cap = 1.5), "pending_in_cap is a whole number");
    assert!(with(|r| r.contact_burst = 7_201.0).starts_with("contact_burst / contact_calls_per_second is at most 3600"));
}
