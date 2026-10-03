// §6.3 of the contract: the call budgets — a rules document checked, and one call decided.
//
// A fresh key for every kind of charge (the controls that must get through), every rule refusing
// once its bucket is empty, the pending cap, a clock that went back, a stored aggregate over a burst
// that shrank, and every argument that does not read. The sequences that hold the decision to what the
// cloud's TypeScript decided are js/cases/limits-vectors.json, a fixed record of it, replayed by
// js/limits.test.mjs.
import { RawArgs } from '../port.mjs';

export default function limits({ add, expect }) {
  // Arbitrary numbers, unlike HDTP's defaults; the guest total and the pending cap have no approved
  // numbers yet.
  const rules = {
    contact_calls_per_second: 2, contact_burst: 5, identity_capacity_per_second: 7, guest_calls_per_hour: 3,
    guest_source_calls_per_hour: 4, stranger_calls_out_per_hour: 6, integration_calls_per_hour: 8,
    guest_total_calls_per_hour: 9, pending_in_cap: 2,
  };
  const now = 1_790_000_000_123;
  const empty = (key) => ({ [key]: { tokens: 0, updated_at: now } });
  const decide = (charge, state, over = {}) => {
    const args = { rules, charge, now, state, ...over };
    for (const k of Object.keys(args)) if (args[k] === undefined) delete args[k];
    return args;
  };

  // rules_check
  add('limits_rules_check: a document that can be enforced', 'limits_rules_check', { rules });
  expect('limits_rules_check: a document that can be enforced', { ok: true });
  const unenforceable = [
    ['not an object', [1, 2], 'the limits rules are an object'],
    ['a member it does not hold', { ...rules, zeta: 1, alpha: 1 }, 'the limits rules hold contact_calls_per_second, contact_burst, identity_capacity_per_second, guest_calls_per_hour, guest_source_calls_per_hour, stranger_calls_out_per_hour, integration_calls_per_hour, guest_total_calls_per_hour, pending_in_cap, and nothing else: alpha'],
    ['a member missing', { ...rules, pending_in_cap: undefined }, 'pending_in_cap is a number'],
    ['a member that is a string', { ...rules, contact_burst: '5' }, 'contact_burst is a number'],
    ['a contact rate of 0', { ...rules, contact_calls_per_second: 0 }, 'contact_calls_per_second is above 0'],
    ['a burst under one call', { ...rules, contact_burst: 0.5 }, 'contact_burst is at least 1'],
    ['a capacity under one call', { ...rules, identity_capacity_per_second: 0 }, 'identity_capacity_per_second is at least 1'],
    ['a guest budget of 0', { ...rules, guest_calls_per_hour: 0 }, 'guest_calls_per_hour is at least 1'],
    ['a negative source budget', { ...rules, guest_source_calls_per_hour: -4 }, 'guest_source_calls_per_hour is at least 1'],
    ['a stranger budget of 0', { ...rules, stranger_calls_out_per_hour: 0 }, 'stranger_calls_out_per_hour is at least 1'],
    ['an integration budget of 0', { ...rules, integration_calls_per_hour: 0 }, 'integration_calls_per_hour is at least 1'],
    ['a guest total of 0', { ...rules, guest_total_calls_per_hour: 0 }, 'guest_total_calls_per_hour is at least 1'],
    ['a pending cap of 0', { ...rules, pending_in_cap: 0 }, 'pending_in_cap is at least 1'],
    ['a pending cap with a fraction', { ...rules, pending_in_cap: 2.5 }, 'pending_in_cap is a whole number'],
    ['a contact bucket slower than the hour', { ...rules, contact_burst: 7201 }, "contact_burst / contact_calls_per_second is at most 3600: a contact's bucket refills within the hour an idle row is kept"],
  ];
  for (const [what, doc, why] of unenforceable) {
    for (const k of Object.keys(doc)) if (doc[k] === undefined) delete doc[k];
    add(`limits_rules_check: ${what}`, 'limits_rules_check', { rules: doc });
    expect(`limits_rules_check: ${what}`, { ok: false, why });
  }
  add('limits_rules_check with no rules', 'limits_rules_check', {});
  add('limits_rules_check with null rules', 'limits_rules_check', { rules: null });

  // decide: every kind, fresh (the controls) and empty
  const charges = [
    ['a contact in', { kind: 'contact_in', root: 'rA', contact_cap: 100 }, 'contact:rA'],
    ['a contact out', { kind: 'contact_out', root: 'rA', contact_cap: 100 }, 'out:contact:rA'],
    ['a guest with an address', { kind: 'guest_in', root: 'rG', source: 's1', addressed: true }, 'guest:rG:s1'],
    ['a guest with no address', { kind: 'guest_in', root: 'rG', source: 's1', addressed: false }, 'guest:rG'],
    ['a small form, no root', { kind: 'guest_in', root: null, source: 's1', addressed: true }, 'source:s1'],
    ['a small form, an empty root', { kind: 'guest_in', root: '', source: 's1', addressed: false }, 'source:s1'],
    ['the guest total', { kind: 'guest_total' }, 'guest-total'],
    ['a stranger out', { kind: 'stranger_out' }, 'out:stranger'],
    ['an integration', { kind: 'integration', integration: 'i1', contact: 'rA' }, 'integration:i1:rA'],
  ];
  for (const [what, charge, key] of charges) {
    add(`limits_decide: ${what}, fresh`, 'limits_decide', decide(charge));
    expect(`limits_decide: ${what}, fresh`, { allowed: true, retry_after: 0, refused_by: null });
    add(`limits_decide: ${what}, empty`, 'limits_decide', decide(charge, empty(key)));
    expect(`limits_decide: ${what}, empty`, { allowed: false, refused_by: key });
  }
  // The identity's aggregate refuses a contact that still has its own burst: 1 contact × 2/s.
  add('limits_decide: the identity aggregate, empty', 'limits_decide', decide({ kind: 'contact_in', root: 'rA', contact_cap: 1 }, empty('identity')));
  expect('limits_decide: the identity aggregate, empty', { allowed: false, retry_after: 1, refused_by: 'identity' });
  add('limits_decide: the outbound aggregate, empty', 'limits_decide', decide({ kind: 'contact_out', root: 'rA', contact_cap: 1 }, empty('out:identity')));
  expect('limits_decide: the outbound aggregate, empty', { allowed: false, retry_after: 1, refused_by: 'out:identity' });
  // Both buckets empty, and the contact's needs longer (1/2 s against 1/2 s: equal, so the first).
  add('limits_decide: both buckets empty, the first of equals', 'limits_decide', decide({ kind: 'contact_in', root: 'rA', contact_cap: 1 }, { ...empty('contact:rA'), ...empty('identity') }));
  expect('limits_decide: both buckets empty, the first of equals', { allowed: false, retry_after: 1, refused_by: 'contact:rA' });
  add('limits_decide: a contact cap of 0 is still one call a second', 'limits_decide', decide({ kind: 'contact_in', root: 'rA', contact_cap: 0 }));
  add('limits_decide: a contact cap past the capacity', 'limits_decide', decide({ kind: 'contact_out', root: 'rA', contact_cap: 1_000_000 }, { 'out:identity': { tokens: 3.25, updated_at: now - 500 } }));
  // A stored aggregate over a burst the plan has since shrunk reads as the burst.
  add('limits_decide: a row over its burst', 'limits_decide', decide({ kind: 'contact_in', root: 'rA', contact_cap: 1 }, { identity: { tokens: 40, updated_at: now } }));
  // A clock that went back refills nothing, and the row is written with the earlier time.
  add('limits_decide: a clock that went back', 'limits_decide', decide({ kind: 'stranger_out' }, { 'out:stranger': { tokens: 1.5, updated_at: now + 60_000 } }));
  add('limits_decide: a partly refilled bucket', 'limits_decide', decide({ kind: 'stranger_out' }, { 'out:stranger': { tokens: 0.25, updated_at: now - 450_000 } }));
  add('limits_decide: rows for other buckets are left alone', 'limits_decide', decide({ kind: 'stranger_out' }, { ...empty('contact:rZ'), 'out:stranger': { tokens: 2, updated_at: now } }));
  // The pending cap: a count, no row, no wait.
  add('limits_decide: requests under the cap', 'limits_decide', decide({ kind: 'pending_in', held: 1 }));
  expect('limits_decide: requests under the cap', { allowed: true, retry_after: 0, refused_by: null });
  add('limits_decide: requests at the cap', 'limits_decide', decide({ kind: 'pending_in', held: 2 }));
  expect('limits_decide: requests at the cap', { allowed: false, retry_after: null, refused_by: 'pending_in' });

  // Every argument that does not read.
  const bad = [
    ['no rules', { rules: undefined }, 'rules is required'],
    ['rules that cannot be enforced', { rules: { ...rules, contact_burst: 0 } }, 'the limits rules cannot be enforced: contact_burst is at least 1'],
    ['no charge', { charge: undefined }, 'charge is required'],
    ['a charge that is a string', { charge: 'contact_in' }, 'charge is required'],
    ['a charge with no kind', { charge: { root: 'rA' } }, 'charge.kind is required'],
    ['a charge of an unknown kind', { charge: { kind: 'everything' } }, 'charge.kind is one of contact_in, guest_in, guest_total, contact_out, stranger_out, integration, pending_in'],
    ['a charge with a member its kind does not hold', { charge: { kind: 'stranger_out', root: 'rA' } }, 'a stranger_out charge holds kind, and nothing else: root'],
    ['a contact charge with no root', { charge: { kind: 'contact_in', contact_cap: 1 } }, 'charge.root is required'],
    ['a contact charge with an empty root', { charge: { kind: 'contact_out', root: '', contact_cap: 1 } }, 'charge.root is required'],
    ['a contact cap with a fraction', { charge: { kind: 'contact_in', root: 'rA', contact_cap: 1.5 } }, 'charge.contact_cap is a whole number'],
    ['a negative contact cap', { charge: { kind: 'contact_in', root: 'rA', contact_cap: -1 } }, 'charge.contact_cap is a whole number'],
    ['a guest charge whose root is a number', { charge: { kind: 'guest_in', root: 7, source: 's1', addressed: true } }, 'charge.root is a string or null'],
    ['a guest charge with no source', { charge: { kind: 'guest_in', root: 'rG', addressed: true } }, 'charge.source is required'],
    ['a guest charge with no addressed', { charge: { kind: 'guest_in', root: 'rG', source: 's1' } }, 'charge.addressed is required'],
    ['an integration charge with no contact', { charge: { kind: 'integration', integration: 'i1' } }, 'charge.contact is required'],
    ['a pending count that is a string', { charge: { kind: 'pending_in', held: '2' } }, 'charge.held is a whole number'],
    ['no now', { now: undefined }, 'now is required'],
    ['a negative now', { now: -1 }, 'now is a time in milliseconds'],
    ['a now with a fraction', { now: 1000.5 }, 'now is a time in milliseconds'],
    ['a now past 2^53', { now: 2 ** 53 }, 'now is a time in milliseconds'],
    ['a state that is a list', { state: [] }, 'state is an object of rows by bucket'],
    ['a row that is a number', { state: { b: 1, a: { tokens: 1, updated_at: 0 } } }, "the state's row b does not read: a row is an object"],
    ['a row with a member it does not hold', { state: { a: { tokens: 1, updated_at: 0, burst: 5 } } }, "the state's row a does not read: burst"],
    ['a row whose tokens are a string', { state: { a: { tokens: '1', updated_at: 0 } } }, "the state's row a does not read: tokens"],
    ['a row with no updated_at', { state: { a: { tokens: 1 } } }, "the state's row a does not read: updated_at"],
    ['a row whose updated_at has a fraction', { state: { a: { tokens: 1, updated_at: 0.5 } } }, "the state's row a does not read: updated_at"],
  ];
  for (const [what, over, why] of bad) {
    add(`limits_decide with ${what}`, 'limits_decide', decide({ kind: 'stranger_out' }, undefined, over));
    expect(`limits_decide with ${what}`, { error: 'bad_request', why });
  }
  // -0 is not a whole number to the core's reader, which takes it for a float; the Go port read it
  // as 0 and decided. Raw text: JSON.stringify writes -0 as 0.
  add('limits_decide with a now of -0', 'limits_decide', RawArgs.edit(decide({ kind: 'stranger_out' }, undefined, { now: 1234567 }), '"now":1234567', '"now":-0'));
  expect('limits_decide with a now of -0', { error: 'bad_request', why: 'now is a time in milliseconds' });
  add('limits_decide with nothing to work from', 'limits_decide', {});
  expect('limits_decide with nothing to work from', { error: 'bad_request', why: 'rules is required' });

  // limits_buckets: the rows a charge reads, so a host can fetch them before limits_decide (X2). Each
  // answer is held to the key scheme LimitsCharge describes and to rates worked out here from the rules
  // — `n / 3600` an hour's budget, the identity's `max(1, min(cap × contact rate, capacity))` — so
  // neither port's arithmetic is the expectation.
  const perHour = (key, n) => ({ key, per_second: n / 3600, burst: n });
  const identity = (key, cap) => {
    const r = Math.max(1, Math.min(cap * rules.contact_calls_per_second, rules.identity_capacity_per_second));
    return { key, per_second: r, burst: r };
  };
  const contact = (key) => ({ key, per_second: rules.contact_calls_per_second, burst: rules.contact_burst });
  for (const [what, charge, buckets] of [
    ['a contact in', { kind: 'contact_in', root: 'rA', contact_cap: 100 }, [contact('contact:rA'), identity('identity', 100)]],
    ['a contact out', { kind: 'contact_out', root: 'rA', contact_cap: 100 }, [contact('out:contact:rA'), identity('out:identity', 100)]],
    ['a contact in whose cap is 0', { kind: 'contact_in', root: 'rA', contact_cap: 0 }, [contact('contact:rA'), identity('identity', 0)]],
    ['a contact in whose cap is 1', { kind: 'contact_in', root: 'rA', contact_cap: 1 }, [contact('contact:rA'), identity('identity', 1)]],
    ['a guest with an address', { kind: 'guest_in', root: 'rG', source: 's1', addressed: true }, [perHour('guest:rG:s1', rules.guest_calls_per_hour)]],
    ['a guest with no address', { kind: 'guest_in', root: 'rG', source: 's1', addressed: false }, [perHour('guest:rG', rules.guest_calls_per_hour)]],
    ['a small form, no root', { kind: 'guest_in', root: null, source: 's1', addressed: true }, [perHour('source:s1', rules.guest_source_calls_per_hour)]],
    ['a small form, an empty root', { kind: 'guest_in', root: '', source: 's1', addressed: false }, [perHour('source:s1', rules.guest_source_calls_per_hour)]],
    ['the guest total', { kind: 'guest_total' }, [perHour('guest-total', rules.guest_total_calls_per_hour)]],
    ['a stranger out', { kind: 'stranger_out' }, [perHour('out:stranger', rules.stranger_calls_out_per_hour)]],
    ['an integration', { kind: 'integration', integration: 'i1', contact: 'rA' }, [perHour('integration:i1:rA', rules.integration_calls_per_hour)]],
    ['a contact request, a count', { kind: 'pending_in', held: 1 }, []],
  ]) {
    add(`limits_buckets: ${what}`, 'limits_buckets', { rules, charge });
    expect(`limits_buckets: ${what}`, { buckets });
  }
  // The rules and the charge are read as limits_decide reads them, by the same reader, in its words.
  for (const [what, over, why] of bad.filter(([, o]) => 'rules' in o || 'charge' in o)) {
    const args = { rules, charge: { kind: 'stranger_out' }, ...over };
    for (const k of Object.keys(args)) if (args[k] === undefined) delete args[k];
    add(`limits_buckets with ${what}`, 'limits_buckets', args);
    expect(`limits_buckets with ${what}`, { error: 'bad_request', why });
  }
}
