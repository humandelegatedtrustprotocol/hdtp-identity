// The dispatcher itself, before any function of the contract is reached: a name nobody defines, and
// arguments that are not an object. Not a contract section — the contract describes functions, and
// these are what a caller gets when it names none of them or hands one no object.
import { RawArgs } from '../port.mjs';

export default function dispatcher({ add, expect }) {
  // A name the contract does not have is `unsupported`, whatever the arguments are (CONTRACT §0, and
  // contract/contract.mjs's judge): the name is judged before anything reads them. The core read the
  // arguments first, so a list, `null`, text that does not parse, half a surrogate pair or a number
  // past the largest double beside an unknown name was a `bad_request` about the arguments from it
  // and `unsupported` from the Go port — or, for the last two, a `bad_request` from both (R34). Text
  // that does not parse cannot cross the Go adapter, whose request is one JSON line: both ports' unit
  // tests hold it, and these, to js/boundary-text.json's `unknown_name`.
  const nobody = { error: 'unsupported', why: 'no function named no_such_function' };
  for (const [what, args] of [
    ['', {}],
    [', with args that are a list', []],
    [', with args that are null', null],
    [', with args holding half a surrogate pair', new RawArgs('{"x":"\\ud800"}')],
    [', with args holding a number past the largest double', new RawArgs('{"x":1e400}')],
  ]) {
    add(`a function nobody defines${what}`, 'no_such_function', args);
    expect(`a function nobody defines${what}`, nobody);
  }
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
