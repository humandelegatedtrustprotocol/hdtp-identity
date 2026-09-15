// One test, one browser, its own process.
//
// It needs a wallet with nothing in it — the report it comes from was a person making their first
// identity — and a second `puppeteer.launch` with an unpacked extension inside a process that
// already has one sometimes yields a browser whose extension is loaded but inert. Node's test
// runner gives each FILE its own process, so this lives alone rather than fighting that.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import puppeteer from 'puppeteer-core'
import { EXT, chromePath, visible, textOf, waitScreen, sleep, serviceWorkerTargetId } from './harness.mjs'

const PASS = 'correct horse battery'

test('(1c) a wallet opened on its own survives the worker sleeping: the identity is still made', async () => {
  // The bug a person hit: MV3 stops the worker about thirty seconds after it goes quiet, and the
  // window held the port it was given at load. Typing a name and a passphrase twice takes longer
  // than that, so the button sent on a dead port and answered "Attempting to use a disconnected
  // port object" — with nothing pending, nothing unlocked, and nothing actually wrong.
  //
  // Its own browser, because this is a wallet with no identities yet and no page in sight: the
  // whole point is that making an identity needs nothing but the extension.
  // A bounded launch: on a loaded machine this is where the time goes, and a timeout that names
  // the cause beats a wait that says nothing.
  const solo = await puppeteer.launch({
    timeout: 60_000,
    executablePath: chromePath(),
    headless: true,
    enableExtensions: [EXT],
    args: ['--no-first-run', '--no-default-browser-check'],
  })
  try {
    const sw = await solo.waitForTarget((x) => x.type() === 'service_worker' && x.url().startsWith('chrome-extension://'), { timeout: 20000 })
    const id = new URL(sw.url()).host
    const cdp = await solo.target().createCDPSession()
    const w = await solo.newPage()
    await w.goto(`chrome-extension://${id}/window.html`)
    await w.waitForSelector('#main', { timeout: 10000 })
    // A wallet with nothing in it opens on the create form, which is the screen in the report.
    await waitScreen(w, 's-create')

    // The worker goes away while the person is filling the form, as Chrome does it.
    const targetId = await serviceWorkerTargetId(cdp, id)
    assert.ok(targetId, 'the extension has a service_worker target')
    await cdp.send('Target.closeTarget', { targetId })
    await sleep(300)

    await w.type('#f-create input[name=name]', 'Solo Maker')
    await w.type('#f-create input[name=passphrase]', PASS)
    await w.type('#f-create input[name=again]', PASS)
    await w.click('#f-create input[name=understood]')
    await w.click('#f-create button[type=submit]')

    // No error, and the identity exists: the window reconnected and the worker woke to answer it.
    // Either it failed and says why, or the create screen is behind us — creation is followed by
    // the security-key offer, not by the home screen, which is why this waits on leaving rather
    // than on arriving anywhere in particular.
    await w.waitForFunction(() => {
      const e = document.getElementById('e-create')
      return (e && e.textContent.trim()) || document.getElementById('s-create').hidden
    }, { timeout: 20000 })
    assert.equal(await textOf(w, '#e-create'), '', 'the create form reported no error')
    assert.equal(await visible(w, '#disconnected'), false, 'nothing was lost, so nothing is claimed to be')
    const made = await w.evaluate(() => new Promise((resolve) => {
      const port = chrome.runtime.connect({ name: 'window' })
      port.onMessage.addListener((m) => { if (m.id === 1) resolve(m.result.roots.map((r) => r.cn)) })
      port.postMessage({ id: 1, type: 'state' })
    }))
    assert.ok(made.includes('Solo Maker'), `the wallet holds the identity: ${JSON.stringify(made)}`)
  } finally {
    // Closing waits for Chrome to exit, and a browser whose service-worker target was closed out
    // from under it does not always get there: this test once took thirty-one minutes, all of it
    // here. Ask politely, then insist — the browser has nothing left to save.
    await Promise.race([solo.close(), new Promise((r) => setTimeout(r, 5000))])
    solo.process()?.kill('SIGKILL')
  }
})
