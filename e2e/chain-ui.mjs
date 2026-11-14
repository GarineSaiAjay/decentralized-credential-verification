// Checks, in real Chrome against the real server, that the Ledger and Verify pages show the on-chain anchors.
// Run by scripts/chain-test.sh once blocks are anchored to its local chain.
// Usage: PASS=<demo password> CRED=<id of an anchored credential> CHAIN_ID=<id> node e2e/chain-ui.mjs
import { chromium } from 'playwright-core';
const BASE = process.env.BASE || 'http://localhost:3000', PASS = process.env.PASS, CRED = process.env.CRED, CHAIN_ID = process.env.CHAIN_ID;
let fails = 0;
const ok = (m) => console.log('  ok   ' + m), bad = (m) => { fails++; console.log('  FAIL ' + m); };
const check = (m, c) => (c ? ok(m) : bad(m));

const browser = await chromium.launch({ channel: 'chrome', headless: true });
try {
  const page = await (await browser.newContext()).newPage();

  // The public verification page, signed out: what an employer sees.
  await page.goto(`${BASE}/#/verify/${CRED}`);
  await page.getByText('Ledger anchor', { exact: true }).waitFor();
  check('verify page: the credential is VALID', await page.getByText('VALID', { exact: true }).isVisible());
  const row = page.locator('tr', { hasText: 'On-chain anchor' });
  check('verify page: there is an on-chain anchor line', await row.isVisible());
  const link = row.getByRole('link');
  const text = (await link.textContent()) ?? '';
  check(`verify page: it names the chain and the transaction (${text.slice(0, 60)}...)`, text.includes(`on chain ${CHAIN_ID}`) && /transaction 0x[0-9a-f]{16}…/.test(text));
  const href = await link.getAttribute('href');
  check('verify page: it links to the transaction on the explorer', /^https:\/\/explorer\.test\/tx\/0x[0-9a-f]{64}$/.test(href ?? ''));
  check('verify page: the link opens safely in a new tab', (await link.getAttribute('rel')) === 'noopener noreferrer' && (await link.getAttribute('target')) === '_blank');

  // The ledger page, signed in.
  await page.goto(BASE + '/#/login');
  await page.getByLabel('Email').fill('auditor@university.edu');
  await page.getByLabel('Password').fill(PASS);
  await page.getByRole('button', { name: 'Sign in' }).click();
  await page.getByText('auditor@university.edu').first().waitFor();
  await page.goto(BASE + '/#/ledger');
  await page.locator('th', { hasText: 'On-chain' }).waitFor();
  ok('ledger page: there is an On-chain column');
  check('ledger page: it says which chain the blocks are anchored on', await page.getByText(`chain ${CHAIN_ID}, contract`).isVisible());
  check('ledger page: it says every block is anchored', await page.getByText('Every block is anchored.').isVisible());
  const rows = await page.locator('tbody tr').count();
  const anchored = await page.locator('tbody tr a[href^="https://explorer.test/tx/0x"]').count();
  check(`ledger page: every block row links to its transaction (${anchored} of ${rows})`, rows > 0 && anchored === rows);
  check('ledger page: nothing is shown as a mismatch or an incident', (await page.getByText('MISMATCH').count()) === 0 && (await page.getByText(/anchoring has stopped/).count()) === 0);
} catch (e) {
  bad('browser check threw: ' + e.message);
} finally {
  await browser.close();
}
console.log(fails ? `\n${fails} BROWSER CHECK(S) FAILED` : '\nALL ON-CHAIN BROWSER CHECKS PASSED');
process.exit(fails ? 1 : 0);
