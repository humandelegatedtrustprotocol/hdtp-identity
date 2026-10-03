#!/usr/bin/env node
// Builds and serves the PRF stability check — one self-contained page, no build step for whoever
// runs it.
//
//   node prf-check.mjs              build prf-check.built.html and serve it on localhost
//   node prf-check.mjs --build      build only, for hosting it somewhere with a real domain
//   node prf-check.mjs --port 8788  a fixed port, so two browser profiles hit the SAME origin
//
// **The origin has to match on both sides.** A passkey is scoped to its RP ID, so two profiles on
// one machine must reach the same `localhost:PORT`, and two real devices need the same https host —
// `localhost` on two machines is two different origins as far as the passkey is concerned, and would
// answer "no passkey" rather than answering the question.
//
// The wasm is inlined, so the built file works from any static host with nothing beside it.

import { createServer } from 'node:http'
import { readFileSync, writeFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const here = dirname(fileURLToPath(import.meta.url))
const args = process.argv.slice(2)
const port = args.includes('--port') ? Number(args[args.indexOf('--port') + 1]) : 8788
const buildOnly = args.includes('--build')

const STYLE = `
:root { --ink:#1d2126; --muted:#5f6873; --line:#d9dee4; --bg:#fbfbf9; --card:#fff; --accent:#23508f; --bad:#a1282b; --good:#1f6b3a;
  color-scheme: light dark; font-family: system-ui, -apple-system, "Segoe UI", Roboto, sans-serif; }
@media (prefers-color-scheme: dark) { :root { --ink:#e8eaed; --muted:#9aa4b2; --line:#2a2f37; --bg:#14171a; --card:#1b1f24; --accent:#8ab4ff; --bad:#f28b82; --good:#7ee2a8; } }
* { box-sizing: border-box }
body { margin:0; background:var(--bg); color:var(--ink); line-height:1.55 }
main { max-width: 42rem; margin: 0 auto; padding: 2.5rem 1.25rem 4rem; display:flex; flex-direction:column; gap:.9rem }
h1 { font-size:1.5rem; letter-spacing:-.02em; margin:0; text-wrap:balance }
h2 { font-size:1rem; margin:1.2rem 0 .2rem }
.help { color:var(--muted); margin:0; font-size:.94rem }
.row { display:flex; gap:.6rem; flex-wrap:wrap; margin-top:.4rem }
button { font:inherit; font-weight:600; padding:.6rem 1rem; border-radius:8px; border:1px solid var(--accent); background:var(--accent); color:#fff; cursor:pointer }
button.quiet { background:transparent; color:var(--ink); border-color:var(--line) }
button[disabled] { opacity:.5; cursor:default }
code { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size:.86em; overflow-wrap:anywhere }
.big code { font-size:1.15rem; font-weight:600; display:block; padding:.9rem 1rem; background:var(--card); border:1px solid var(--line); border-radius:10px; user-select:all }
.facts { display:grid; grid-template-columns:max-content 1fr; gap:.35rem 1rem; margin:.6rem 0; font-size:.9rem }
.facts dt { color:var(--muted) } .facts dd { margin:0; overflow-wrap:anywhere }
.muted { color:var(--muted) }
.err { color:var(--bad); background:color-mix(in srgb, var(--bad) 10%, transparent); padding:.7rem .9rem; border-radius:8px; margin:0 }
.notice { border:1px solid var(--line); border-left:3px solid var(--good); border-radius:8px; padding:.7rem .9rem; margin:.4rem 0 0; font-size:.92rem }
footer { margin-top:1.6rem; color:var(--muted); font-size:.82rem }
details { border:1px solid var(--line); border-radius:10px; padding:.7rem .9rem; background:var(--card) }
details[open] { padding-bottom:1rem }
summary { cursor:pointer; font-weight:600; font-size:.94rem }
details label { display:flex; flex-direction:column; gap:.25rem; margin-top:.7rem; font-size:.85rem; color:var(--muted) }
details input { font:inherit; font-family:ui-monospace,SFMono-Regular,Menlo,monospace; font-size:.82rem; padding:.45rem .6rem; border:1px solid var(--line); border-radius:7px; background:var(--bg); color:var(--ink) }
[hidden] { display:none !important }
`.trim()

/** The glue's exports become plain declarations, the same way the wallet page inlines it. */
function inlineGlue(text) {
  const out = text.replace(/^export function /gm, 'function ').replace(/^export \{[^}]*\};?\s*$/gm, '')
  if (/^export\b/m.test(out)) throw new Error('prf-check: the glue carries an export form this does not inline')
  return out
}

const template = readFileSync(resolve(here, 'prf-check.html'), 'utf8')
const logic = readFileSync(resolve(here, 'prf-check.js'), 'utf8')
const glue = readFileSync(resolve(here, 'pkg-web/hdtp_identity_wasm.js'), 'utf8')
const wasm = readFileSync(resolve(here, 'pkg-web/hdtp_identity_wasm_bg.wasm'))

const script = `${inlineGlue(glue)}\nconst WASM_B64 = '${wasm.toString('base64')}'\n${logic}`
const html = template.replace('{{STYLE}}', STYLE).replace('{{SCRIPT}}', script)
const out = resolve(here, 'prf-check.built.html')
writeFileSync(out, html)
console.log(`prf-check: built ${out} (${Math.round(html.length / 1024)} KB, self-contained)`)

if (buildOnly) process.exit(0)

const server = createServer((req, res) => {
  res.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' })
  res.end(html)
})

// A port already in use is the one failure that leaves somebody staring at "unreachable" with no
// idea why — the process exits, the terminal scrolls, and the browser says the same thing it says
// when nothing was ever started. Deliberately NOT auto-picking a free port: the whole test depends
// on both profiles reaching the same origin, so a port that quietly changed would break the
// measurement rather than the server.
server.on('error', (e) => {
  if (e.code === 'EADDRINUSE') {
    console.error(`\nprf-check: port ${port} is already taken by something else.`)
    console.error(`  Pick another and use the SAME one in both profiles:  node prf-check.mjs --port 8790\n`)
    process.exit(1)
  }
  throw e
})

server.listen(port, () => {
  console.log('')
  console.log(`  http://localhost:${port}`)
  console.log('')
  console.log('  Leave this running — the page is served from here and nothing is written to disk')
  console.log('  that a browser can open on its own. Ctrl-C ends it.')
  console.log('')
  console.log('  Open that in the FIRST profile and press "Create a passkey here".')
  console.log('  Open the SAME url in the second profile and press "Use a passkey I already have".')
  console.log('  Compare the fingerprints. Identical means that provider is safe to derive from.')
  console.log('')
  console.log('  The url must be identical on both sides — a passkey is scoped to its RP ID, so a')
  console.log('  different port or host answers "no passkey" instead of answering the question.')
})
