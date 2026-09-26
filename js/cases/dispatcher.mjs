// The dispatcher itself, before any function of the contract is reached: a name nobody defines, and
// arguments that are not an object. Not a contract section — the contract describes functions, and
// these are what a caller gets when it names none of them or hands one no object.
export default function dispatcher({ add }) {
  add('a function nobody defines', 'no_such_function', {});
  add('args that are not an object', 'key_info', 'not-an-object');
  add('args that are a list', 'key_info', [1, 2]);
  add('args that are null', 'key_info', null);
}
