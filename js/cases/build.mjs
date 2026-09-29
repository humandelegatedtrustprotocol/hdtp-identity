// The build section: `version`, whose answer describes the port and so is compared by nothing (js/parity.mjs
// leaves it out of the surface). What two ports CAN agree on is the refusal every function shares:
// a member it does not declare, refused before any member is read (CONTRACT §0).
export default function build({ add, expect }) {
  add('version with a member it does not declare', 'version', { not_a_member: 1 });
  expect('version with a member it does not declare', { error: 'bad_request', why: 'version takes no member "not_a_member"' });
}
