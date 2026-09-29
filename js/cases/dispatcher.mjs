// The dispatcher itself, before any function of the contract is reached: a name nobody defines, and
// arguments that are not an object. Not a contract section — the contract describes functions, and
// these are what a caller gets when it names none of them or hands one no object.
export default function dispatcher({ add, expect }) {
  add('a function nobody defines', 'no_such_function', {});
  // Which is judged first, the name or the arguments (R34).
  add('a function nobody defines, with args that are a list', 'no_such_function', []);
  add('args that are not an object', 'key_info', 'not-an-object');
  add('args that are a list', 'key_info', [1, 2]);
  // `null` reaches both ports as `null` (TC-2): the shims used to make it `{}`, so this case ran
  // key_info({}) and compared "spki is required" under a name that claimed otherwise.
  add('args that are null', 'key_info', null);
  add('args that are a number', 'key_info', 3);
  add('args that are true', 'key_info', true);
  add('args that are an empty list', 'key_info', []);
  expect('args that are null', { error: 'bad_request', why: 'args is a JSON object' });
}
