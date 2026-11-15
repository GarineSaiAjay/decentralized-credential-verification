// Drives the standalone verifier page (verifier/index.html) in real Chrome, opened straight from disk.
// Run by scripts/chain-test.sh while the ACVS backend is stopped: the page may only talk to the chain node.
//
//   node e2e/verifier.mjs check <page.html | https://page address> <rpc url> <trust: yes|no> <file>=<verdict>[=<part of a failed check's name>] ...
//   node e2e/verifier.mjs forge <real export.json> <out.json>     (a convincing fake, signed with made-up keys)
import { chromium } from 'playwright-core';
import { generateKeyPairSync, sign, createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';

const [mode, ...args] = process.argv.slice(2);

if (mode === 'forge') {
  // What a forger can do: copy a real file, change the name, and sign everything again with keys of their own.
  const doc = JSON.parse(readFileSync(args[0], 'utf8'));
  const id = doc.id.replace('urn:uuid:', '');
  const content = JSON.parse(doc.hashedContent);
  content.student_name = 'Mallory Forger';
  doc.hashedContent = JSON.stringify(content);
  doc.credentialSubject.studentName = 'Mallory Forger';
  doc.credentialHash = createHash('sha256').update(doc.hashedContent).digest('hex');
  for (const p of doc.proof) {
    const { publicKey, privateKey } = generateKeyPairSync('ed25519');
    const raw = publicKey.export({ type: 'spki', format: 'der' }).subarray(-32).toString('hex');
    p.signedMessage = `ACVS-APPROVAL-v1|${id}|${p.stage}|${doc.credentialHash}`;
    p.verificationMethod = `urn:acvs:ed25519:${raw}`;
    p.proofValue = sign(null, Buffer.from(p.signedMessage), privateKey).toString('hex');
  }
  writeFileSync(args[1], JSON.stringify(doc));
  process.exit(0);
}

const [pagePath, rpc, trust, ...cases] = args;
// A local file, or a published address (the Pages site): the page may then also fetch itself, nothing else.
const pageUrl = /^https?:\/\//.test(pagePath) ? pagePath : pathToFileURL(pagePath).href;
const own = pageUrl.startsWith('http') ? new URL(pageUrl).origin : 'file:';
let fails = 0;
const ok = (m) => console.log('  ok   ' + m), bad = (m) => { fails++; console.log('  FAIL ' + m); };
const browser = await chromium.launch({ channel: 'chrome', headless: true });
try {
  const page = await (await browser.newContext()).newPage();
  // The page must never reach for anything but the chain node (and itself).
  const elsewhere = [];
  page.on('request', (r) => { const u = r.url(); if (!u.startsWith(own) && !u.startsWith(rpc)) elsewhere.push(u); });
  for (const c of cases) {
    const [file, want, failed] = c.split('=');
    const name = file.split('/').pop();
    await page.goto(pageUrl);
    await page.setInputFiles('#file', file);
    await page.locator('#run').waitFor();
    await page.fill('#rpc', rpc);
    if (trust === 'yes' && await page.locator('#trust').isVisible()) await page.check('#trust');
    await page.click('#run');
    await page.locator('#verdict[data-verdict]').waitFor({ timeout: 20000 });
    const got = await page.locator('#verdict').getAttribute('data-verdict');
    const failedChecks = await page.locator('#checks li[data-state=fail]').evaluateAll((els) => els.map((e) => e.dataset.check));
    const note = (await page.locator('#verdict-note').textContent()) ?? '';
    if (got !== want) bad(`${name}: expected ${want}, got ${got} (${note}) failed: ${failedChecks.join('; ')}`);
    else if (failed && !failedChecks.some((f) => f.includes(failed))) bad(`${name}: ${got}, but not because of "${failed}": ${failedChecks.join('; ') || note}`);
    else if (want === 'VALID' && failedChecks.length) bad(`${name}: VALID with failed checks: ${failedChecks.join('; ')}`);
    else ok(`${name}: ${got}${failed ? ` (${failedChecks.find((f) => f.includes(failed))})` : ''}`);
  }
  elsewhere.length ? bad(`the page contacted something other than the chain node: ${elsewhere[0]}`) : ok('the page contacted nothing but the chain node');
} catch (e) {
  bad('verifier check threw: ' + e.message.split('\n')[0]);
} finally {
  await browser.close();
}
process.exit(fails ? 1 : 0);
