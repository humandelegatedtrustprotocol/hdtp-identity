// A zip read the way js/parity.mjs needs one: the central directory, entry by entry and duplicates
// included, and an entry's bytes. Test tooling only — the hosts read zips with their own containers
// (Go's archive/zip, the pact CLI's zip crate, the cloud's fflate) — so it reads what the export
// corpus holds (stored and deflated members, no ZIP64) and throws on anything else.
import { inflateRawSync } from 'node:zlib';

const u16 = (b, i) => b.readUInt16LE(i);
const u32 = (b, i) => b.readUInt32LE(i);

/** The central directory: name, stated size, encrypted, mode, and how to read the bytes. */
export function readZip(buf) {
  let eocd = -1;
  for (let i = buf.length - 22; i >= Math.max(0, buf.length - 65557); i--) {
    if (u32(buf, i) === 0x06054b50) { eocd = i; break; }
  }
  if (eocd < 0) throw new Error('not a zip');
  const count = u16(buf, eocd + 10);
  let at = u32(buf, eocd + 16);
  const entries = [];
  for (let k = 0; k < count; k++) {
    if (u32(buf, at) !== 0x02014b50) throw new Error('a central directory entry does not read');
    const madeBy = u16(buf, at + 4), flags = u16(buf, at + 8), method = u16(buf, at + 10);
    const csize = u32(buf, at + 20), size = u32(buf, at + 24);
    const nameLen = u16(buf, at + 28), extraLen = u16(buf, at + 30), commentLen = u16(buf, at + 32);
    const external = u32(buf, at + 38), local = u32(buf, at + 42);
    const name = buf.subarray(at + 46, at + 46 + nameLen).toString('utf8');
    // The mode as both hosts of this repository read it: the external attributes' high half, else
    // an MS-DOS entry's directory bit, else nothing.
    const high = external >>> 16;
    const mode = high !== 0 ? high : (madeBy >> 8) === 0 && (external & 0x10) ? 0o040775 : 0;
    const data = () => {
      const start = local + 30 + u16(buf, local + 26) + u16(buf, local + 28);
      const raw = buf.subarray(start, start + csize);
      if (method === 0) return raw;
      if (method === 8) return inflateRawSync(raw);
      throw new Error(`method ${method}`);
    };
    entries.push({ name, size, encrypted: (flags & 1) === 1, mode, data });
    at += 46 + nameLen + extraLen + commentLen;
  }
  return entries;
}
