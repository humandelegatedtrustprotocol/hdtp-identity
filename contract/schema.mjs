// A JSON Schema validator for exactly the keywords `contract.json` uses, and no others.
//
// The contract is written in JSON Schema 2020-12 so that anybody's stock validator and anybody's
// code generator can read it. This gate does not use a stock validator: `hdtp-identity/js` has no
// dependency of any kind (no lock file, nothing to install before `gate.sh` runs), and one package
// to check forty schemas is not the reason to start. What a hand-written validator must not do is
// IGNORE a keyword it does not implement — a schema would then claim a constraint that nothing
// holds, which is this codebase's recurring defect in a new place. So `compile` walks the whole
// document first and refuses any keyword that is not below, and a `$ref` that points nowhere.
//
//   validate(schema, value, root) -> [] when it holds, else ["<path>: <what is wrong>", …]
//
// Semantics are the specification's for every keyword here: `oneOf` is EXACTLY one, `required` and
// `properties` apply to objects only, `integer` is any number with no fractional part, a `type`
// list is any-of. No stock validator has been run against this one — `js/` has no dependencies and
// nothing to install them with — so the claim this file makes is the narrower one its own tests
// hold: `schema.test.mjs` gives every keyword a value that must fail it and one that must pass,
// and asserts that `compile` refuses a keyword this file does not implement, which is the property
// the whole design rests on.

/** Keywords that say nothing a validator checks. */
const ANNOTATIONS = new Set(['$schema', '$id', '$comment', 'title', 'description', 'examples', '$defs']);
/** Keywords this file enforces. Anything else in a schema is refused by `compile`. */
const ASSERTIONS = new Set([
  '$ref', 'type', 'enum', 'const', 'properties', 'required', 'additionalProperties', 'items', 'minItems', 'maxItems',
  'minimum', 'maximum', 'minLength', 'maxLength', 'pattern', 'oneOf', 'anyOf', 'allOf',
]);
const TYPES = new Set(['object', 'array', 'string', 'integer', 'number', 'boolean', 'null']);

const typeOf = (v) => (v === null ? 'null' : Array.isArray(v) ? 'array' : typeof v);
const isType = (v, t) => (t === 'integer' ? typeof v === 'number' && Number.isInteger(v) : t === 'number' ? typeof v === 'number' : typeOf(v) === t);
const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);

/** `#/$defs/Name`, and nothing more elaborate: the contract has one file and one level of names. */
export function resolve(ref, root) {
  const m = /^#\/\$defs\/([A-Za-z0-9_]+)$/.exec(ref);
  const found = m && root.$defs?.[m[1]];
  if (!found) throw new Error(`$ref ${JSON.stringify(ref)} names nothing in $defs`);
  return found;
}

/**
 * Walks every schema reachable from `schema` and throws on a keyword this file does not enforce, a
 * type it does not know, or a `$ref` that resolves to nothing. Run once over the contract at load.
 */
export function compile(schema, root = schema, at = '#') {
  if (typeof schema === 'boolean') return;
  if (!schema || typeof schema !== 'object' || Array.isArray(schema)) throw new Error(`${at}: a schema is an object or a boolean`);
  for (const [k, v] of Object.entries(schema)) {
    if (ANNOTATIONS.has(k)) {
      if (k === '$defs') for (const [name, s] of Object.entries(v)) compile(s, root, `${at}/$defs/${name}`);
      continue;
    }
    if (!ASSERTIONS.has(k)) throw new Error(`${at}: the keyword ${JSON.stringify(k)} is not one this validator enforces, so the schema may not use it`);
    if (k === '$ref') resolve(v, root);
    if (k === 'type') for (const t of [v].flat()) if (!TYPES.has(t)) throw new Error(`${at}: unknown type ${JSON.stringify(t)}`);
    if (k === 'pattern') new RegExp(v, 'u');
    if (k === 'properties') for (const [name, s] of Object.entries(v)) compile(s, root, `${at}/properties/${name}`);
    if (k === 'required') for (const name of v) if (schema.properties && !(name in schema.properties)) throw new Error(`${at}: requires ${JSON.stringify(name)}, which it does not describe`);
    if (k === 'items' || k === 'additionalProperties') compile(v, root, `${at}/${k}`);
    if (k === 'oneOf' || k === 'anyOf' || k === 'allOf') v.forEach((s, i) => compile(s, root, `${at}/${k}/${i}`));
  }
}

export function validate(schema, value, root = schema, path = '$') {
  if (schema === true) return [];
  if (schema === false) return [`${path}: nothing is allowed here`];
  const out = [];
  if (schema.$ref) out.push(...validate(resolve(schema.$ref, root), value, root, path));
  if (schema.type !== undefined && ![schema.type].flat().some((t) => isType(value, t))) {
    out.push(`${path}: is ${typeOf(value)}, not ${[schema.type].flat().join(' or ')}`);
  }
  if (schema.enum && !schema.enum.some((e) => same(e, value))) out.push(`${path}: ${JSON.stringify(value)} is not one of ${JSON.stringify(schema.enum)}`);
  if ('const' in schema && !same(schema.const, value)) out.push(`${path}: is ${JSON.stringify(value)}, not ${JSON.stringify(schema.const)}`);
  if (typeof value === 'string') {
    // Length is in code points, as the specification counts it, not in UTF-16 units.
    const n = [...value].length;
    if (schema.minLength !== undefined && n < schema.minLength) out.push(`${path}: shorter than ${schema.minLength}`);
    if (schema.maxLength !== undefined && n > schema.maxLength) out.push(`${path}: longer than ${schema.maxLength}`);
    if (schema.pattern !== undefined && !new RegExp(schema.pattern, 'u').test(value)) out.push(`${path}: ${JSON.stringify(value.length > 48 ? `${value.slice(0, 48)}…` : value)} does not match ${schema.pattern}`);
  }
  if (typeof value === 'number') {
    if (schema.minimum !== undefined && value < schema.minimum) out.push(`${path}: below ${schema.minimum}`);
    if (schema.maximum !== undefined && value > schema.maximum) out.push(`${path}: above ${schema.maximum}`);
  }
  if (Array.isArray(value)) {
    if (schema.minItems !== undefined && value.length < schema.minItems) out.push(`${path}: fewer than ${schema.minItems} items`);
    if (schema.maxItems !== undefined && value.length > schema.maxItems) out.push(`${path}: more than ${schema.maxItems} items`);
    if (schema.items !== undefined) value.forEach((v, i) => out.push(...validate(schema.items, v, root, `${path}[${i}]`)));
  }
  if (typeOf(value) === 'object') {
    for (const name of schema.required ?? []) if (!(name in value)) out.push(`${path}: has no member ${JSON.stringify(name)}`);
    for (const [name, v] of Object.entries(value)) {
      if (schema.properties && name in schema.properties) out.push(...validate(schema.properties[name], v, root, `${path}.${name}`));
      else if (schema.additionalProperties !== undefined) {
        const extra = validate(schema.additionalProperties, v, root, `${path}.${name}`);
        if (extra.length) out.push(schema.additionalProperties === false ? `${path}: has a member ${JSON.stringify(name)} the contract does not describe` : extra[0]);
      }
    }
  }
  for (const s of schema.allOf ?? []) out.push(...validate(s, value, root, path));
  if (schema.anyOf && !schema.anyOf.some((s) => validate(s, value, root, path).length === 0)) {
    out.push(`${path}: matches none of its ${schema.anyOf.length} alternatives (${schema.anyOf.map((s) => validate(s, value, root, path)[0]).join(' | ')})`);
  }
  if (schema.oneOf) {
    const verdicts = schema.oneOf.map((s) => validate(s, value, root, path));
    const held = verdicts.filter((v) => v.length === 0).length;
    if (held === 0) out.push(`${path}: matches none of its ${schema.oneOf.length} alternatives (${verdicts.map((v) => v[0]).join(' | ')})`);
    if (held > 1) out.push(`${path}: matches ${held} alternatives where exactly one is allowed`);
  }
  return out;
}
