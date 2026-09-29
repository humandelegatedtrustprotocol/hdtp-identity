// The build section: `version`, whose answer describes the port and so is compared by nothing (js/parity.mjs
// leaves it out of the surface). What two ports CAN agree on is the refusal every function shares:
// a member it does not declare, refused before any member is read (CONTRACT §0).
import { RawArgs } from '../port.mjs';

export default function build({ add, expect }) {
  add('version with a member it does not declare', 'version', { not_a_member: 1 });
  expect('version with a member it does not declare', { error: 'bad_request', why: 'version takes no member "not_a_member"' });

  // Arguments one port's JSON parser refuses and the other's reads, refused by every function before
  // anything reads them, in fixed words (R40, S3-2): a number infinite as a double (serde_json
  // refused it in its own words; encoding/json kept its digits and the Go port went on), and
  // containers nested more than 127 deep (serde_json's limit; encoding/json's is 10000). The first in
  // text order is named; the arguments object is the first container. Raw text: JSON.stringify writes
  // 1e400 as null. The controls: the largest double, a number that is merely small, a number in a
  // string, and 127 deep, all of which read.
  const beyond = { error: 'bad_request', why: 'args: a number is outside the range of a double' };
  const deep = { error: 'bad_request', why: 'args: nested more than 127 deep' };
  const nested = (n) => '['.repeat(n) + '1' + ']'.repeat(n);
  const undeclared = { error: 'bad_request', why: 'version takes no member "x"' };
  for (const [what, text, want] of [
    ['a number past the largest double', '{"x":1e400}', beyond],
    ['a negative number past the largest double', '{"x":-1e400}', beyond],
    ['the first number that rounds past the largest double', '{"x":1.7976931348623159e308}', beyond],
    ['the largest double', '{"x":1.7976931348623158e308}', undeclared],
    ['a number too small to be anything but 0', '{"x":1e-400}', undeclared],
    ['a number past the largest double, in a string', '{"x":"1e400"}', undeclared],
    ['containers nested 128 deep', `{"x":${nested(127)}}`, deep],
    ['containers nested 127 deep', `{"x":${nested(126)}}`, undeclared],
    ['a number past the largest double before containers nested 129 deep', `{"x":1e400,"y":${nested(128)}}`, beyond],
    ['containers nested 129 deep before a number past the largest double', `{"y":${nested(128)},"x":1e400}`, deep],
  ]) {
    add(`version with ${what}`, 'version', new RawArgs(text));
    expect(`version with ${what}`, want);
  }
}
