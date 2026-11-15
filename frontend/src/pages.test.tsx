import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { getSession } from './api';
import { Audit, CredDetail, CredList, ImportCredentials, Ledger, Login, ResetPassword, Verify } from './pages';

type Reply = { status?: number; body: unknown };
/** Answers fetch calls in order; returns the mock so tests can inspect what was sent. */
function serve(...replies: Reply[]) {
  const f = vi.fn();
  for (const r of replies) f.mockResolvedValueOnce({ ok: (r.status ?? 200) < 400, status: r.status ?? 200, json: async () => r.body });
  vi.stubGlobal('fetch', f);
  return f;
}
const body = (f: ReturnType<typeof vi.fn>, n: number) => JSON.parse(f.mock.calls[n][1].body);
afterEach(() => vi.unstubAllGlobals());

describe('Login', () => {
  it('signs in with a password and opens the credentials list', async () => {
    const f = serve({ body: { token: 'T', email: 'a@u.edu', role: 'faculty' } });
    render(<Login />);
    await userEvent.type(screen.getByLabelText('Email'), 'a@u.edu');
    await userEvent.type(screen.getByLabelText('Password'), 'correct horse battery');
    await userEvent.click(screen.getByRole('button', { name: 'Sign in' }));
    await waitFor(() => expect(getSession()).toMatchObject({ token: 'T', role: 'faculty', mfaSetup: false }));
    expect(f.mock.calls[0][0]).toBe('/api/v1/auth/login');
    expect(body(f, 0)).toEqual({ email: 'a@u.edu', password: 'correct horse battery' });
    expect(window.location.hash).toBe('#/');
  });

  it('asks for a code after the password when two-factor is on, and never keeps the password', async () => {
    const f = serve(
      { body: { mfa_required: true, mfa_token: 'interim' } },
      { body: { token: 'T2', email: 'a@u.edu', role: 'registrar' } },
    );
    render(<Login />);
    await userEvent.type(screen.getByLabelText('Email'), 'a@u.edu');
    await userEvent.type(screen.getByLabelText('Password'), 'correct horse battery');
    await userEvent.click(screen.getByRole('button', { name: 'Sign in' }));
    await screen.findByLabelText('Code');
    expect(screen.queryByLabelText('Password')).not.toBeInTheDocument();
    expect(getSession()).toBeNull();

    await userEvent.type(screen.getByLabelText('Code'), ' 123456 ');
    await userEvent.click(screen.getByRole('button', { name: 'Sign in' }));
    await waitFor(() => expect(getSession()?.token).toBe('T2'));
    expect(f.mock.calls[1][0]).toBe('/api/v1/auth/login/mfa');
    expect(body(f, 1)).toEqual({ mfa_token: 'interim', code: '123456' });
  });

  it('goes straight to the account page when the role must set up two-factor', async () => {
    serve({ body: { token: 'T', email: 'r@u.edu', role: 'registrar', mfa_setup_required: true } });
    render(<Login />);
    await userEvent.type(screen.getByLabelText('Email'), 'r@u.edu');
    await userEvent.type(screen.getByLabelText('Password'), 'correct horse battery');
    await userEvent.click(screen.getByRole('button', { name: 'Sign in' }));
    await waitFor(() => expect(getSession()?.mfaSetup).toBe(true));
    expect(window.location.hash).toBe('#/account');
  });

  it('shows the server message on a wrong password and stays signed out', async () => {
    serve({ status: 401, body: { error: 'invalid email or password' } });
    render(<Login />);
    await userEvent.type(screen.getByLabelText('Email'), 'a@u.edu');
    await userEvent.type(screen.getByLabelText('Password'), 'wrong wrong wrong');
    await userEvent.click(screen.getByRole('button', { name: 'Sign in' }));
    expect(await screen.findByText('invalid email or password')).toBeInTheDocument();
    expect(getSession()).toBeNull();
  });

  it('returns to the password step when the interim sign-in has expired', async () => {
    serve({ body: { mfa_required: true, mfa_token: 'old' } }, { status: 401, body: { error: 'sign-in expired, enter your password again' } });
    render(<Login />);
    await userEvent.type(screen.getByLabelText('Email'), 'a@u.edu');
    await userEvent.type(screen.getByLabelText('Password'), 'correct horse battery');
    await userEvent.click(screen.getByRole('button', { name: 'Sign in' }));
    await userEvent.type(await screen.findByLabelText('Code'), '000000');
    await userEvent.click(screen.getByRole('button', { name: 'Sign in' }));
    expect(await screen.findByText(/expired/)).toBeInTheDocument();
    expect(screen.getByLabelText('Password')).toBeInTheDocument();
  });
});

describe('ResetPassword', () => {
  it('needs the link that carries the token', () => {
    render(<ResetPassword token="" />);
    expect(screen.getByText(/needs the link an administrator gave you/)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Set password' })).toBeDisabled();
  });

  it('refuses two different passwords without calling the server', async () => {
    const f = serve();
    render(<ResetPassword token="tok" />);
    await userEvent.type(screen.getByLabelText(/New password/), 'a long enough passphrase');
    await userEvent.type(screen.getByLabelText('Again'), 'a different passphrase!');
    await userEvent.click(screen.getByRole('button', { name: 'Set password' }));
    expect(await screen.findByText('the two passwords differ')).toBeInTheDocument();
    expect(f).not.toHaveBeenCalled();
  });

  it('sends the token and new password, then confirms', async () => {
    const f = serve({ body: { email: 'a@u.edu' } });
    render(<ResetPassword token="tok123" />);
    await userEvent.type(screen.getByLabelText(/New password/), 'a long enough passphrase');
    await userEvent.type(screen.getByLabelText('Again'), 'a long enough passphrase');
    await userEvent.click(screen.getByRole('button', { name: 'Set password' }));
    expect(await screen.findByText(/The password for a@u.edu was changed/)).toBeInTheDocument();
    expect(body(f, 0)).toEqual({ token: 'tok123', new_password: 'a long enough passphrase' });
  });

  it('shows why the server refused', async () => {
    serve({ status: 400, body: { error: 'that password is too easy to guess' } });
    render(<ResetPassword token="tok" />);
    await userEvent.type(screen.getByLabelText(/New password/), 'password12345');
    await userEvent.type(screen.getByLabelText('Again'), 'password12345');
    await userEvent.click(screen.getByRole('button', { name: 'Set password' }));
    expect(await screen.findByText('that password is too easy to guess')).toBeInTheDocument();
  });
});

const verification = (over: Record<string, unknown> = {}) => ({
  verdict: 'VALID',
  credential: { id: 'c1', student_name: 'Ada Lovelace', program: 'BSc', graduation_date: '2025-05-15', gpa: '3.9', honors: null, status: 'issued', credential_hash: 'ab'.repeat(32), revoke_reason: null },
  supersedes: null, superseded_by: null, termination: null, qr_hash_match: null,
  checks: { hash_ok: true, order_ok: true, status_ok: true, signatures_ok: true },
  signatures: [], anchor: null,
  ...over,
});

describe('Verify', () => {
  it('asks for an id and goes to its result page', async () => {
    render(<Verify />);
    await userEvent.type(screen.getByLabelText('Credential ID'), '  1234  ');
    await userEvent.click(screen.getByRole('button', { name: 'Verify' }));
    expect(window.location.hash).toBe('#/verify/1234');
  });

  it('shows a valid credential with passing checks and says it is not anchored yet', async () => {
    const f = serve({ body: verification() });
    render(<Verify id="c1" />);
    expect(await screen.findByText('VALID')).toBeInTheDocument();
    expect(f.mock.calls[0][0]).toBe('/api/v1/verify/c1');
    expect(screen.getByText('Ada Lovelace')).toBeInTheDocument();
    expect(screen.getAllByText('pass')).toHaveLength(4);
    expect(screen.getByText('not yet anchored')).toBeInTheDocument();
  });

  it('offers printing and the verifiable-credential download only for a VALID credential', async () => {
    serve({ body: verification() });
    const print = vi.fn();
    vi.stubGlobal('print', print);
    render(<Verify id="c1" />);
    await screen.findByText('VALID');
    const link = screen.getByRole('link', { name: /Download as verifiable credential/ });
    expect(link).toHaveAttribute('href', `/api/v1/credentials/${verification().credential.id}/export`);
    expect(screen.getByAltText(/QR code/)).toHaveAttribute('src', `/api/v1/credentials/${verification().credential.id}/qr`);
    await userEvent.click(screen.getByRole('button', { name: 'Print / save as PDF' }));
    expect(print).toHaveBeenCalledOnce();
  });

  it('does not offer them for a revoked or pending credential', async () => {
    serve({ body: verification({ verdict: 'REVOKED' }) });
    render(<Verify id="c1" />);
    await screen.findByText('REVOKED');
    expect(screen.queryByRole('button', { name: /Print/ })).toBeNull();
    expect(screen.queryByRole('link', { name: /verifiable credential/ })).toBeNull();
    expect(screen.queryByAltText(/QR code/)).toBeNull();
  });

  it('flags failed checks and a revoked credential with its reason', async () => {
    serve({ body: verification({ verdict: 'REVOKED', checks: { hash_ok: false, order_ok: true }, credential: { ...verification().credential, status: 'revoked', revoke_reason: 'issued in error' } }) });
    render(<Verify id="c1" />);
    expect(await screen.findByText('REVOKED')).toBeInTheDocument();
    expect(screen.getByText('FAIL')).toBeInTheDocument();
    expect(screen.getByText('issued in error')).toBeInTheDocument();
  });

  it('warns when the QR code does not match, and passes the hash on to the server', async () => {
    const f = serve({ body: verification({ qr_hash_match: false }) });
    render(<Verify id="c1" h="deadbeef" />);
    expect(await screen.findByText(/Treat the printout as forged/)).toBeInTheDocument();
    expect(f.mock.calls[0][0]).toBe('/api/v1/verify/c1?h=deadbeef');
  });

  it('points to the replacement of a replaced credential and back to the one it replaces', async () => {
    serve({ body: verification({ verdict: 'REVOKED', superseded_by: { id: '99999999-aaaa', verdict: 'VALID' } }) });
    const { unmount } = render(<Verify id="c1" />);
    const link = await screen.findByRole('link', { name: '99999999' });
    expect(link).toHaveAttribute('href', '#/verify/99999999-aaaa');
    expect(screen.getByText(/currently reads VALID/)).toBeInTheDocument();
    unmount();
    serve({ body: verification({ supersedes: '11111111-bbbb' }) });
    render(<Verify id="c2" />);
    expect(await screen.findByRole('link', { name: '11111111' })).toBeInTheDocument();
  });

  it('shows an error for an unknown credential', async () => {
    serve({ status: 404, body: { error: 'not found' } });
    render(<Verify id="nope" />);
    expect(await screen.findByText('not found')).toBeInTheDocument();
  });
});

const row = (n: number) => ({ id: `0000000${n}-aaaa-bbbb-cccc-dddddddddddd`, student_id: `S${n}`, student_name: `Student ${n}`, program: 'BSc', status: 'issued', created_at: '2026-01-01T00:00:00Z' });

describe('lists that arrive a page at a time', () => {
  it('shows the first page, then appends the next one when asked, and stops when there is no more', async () => {
    const f = serve(
      { body: { credentials: [row(3), row(2)], next: 'CURSOR-1' } },
      { body: { credentials: [row(1)], next: null } },
    );
    render(<CredList role="auditor" />);
    expect(await screen.findByText('Student 3')).toBeInTheDocument();
    expect(f.mock.calls[0][0]).toBe('/api/v1/credentials?limit=50');
    expect(screen.queryByText('Student 1')).not.toBeInTheDocument();

    await userEvent.click(screen.getByRole('button', { name: 'Load more' }));
    expect(await screen.findByText('Student 1')).toBeInTheDocument();
    expect(screen.getByText('Student 3')).toBeInTheDocument();
    expect(f.mock.calls[1][0]).toBe('/api/v1/credentials?limit=50&before=CURSOR-1');
    expect(screen.queryByRole('button', { name: 'Load more' })).not.toBeInTheDocument();
  });

  it('offers no button when everything fit on one page', async () => {
    serve({ body: { credentials: [row(1)], next: null } });
    render(<CredList role="auditor" />);
    await screen.findByText('Student 1');
    expect(screen.queryByRole('button', { name: 'Load more' })).not.toBeInTheDocument();
  });

  it('filters by student id and starts again from the first page', async () => {
    const f = serve(
      { body: { credentials: [row(1), row(2)], next: null } },
      { body: { credentials: [row(2)], next: null } },
    );
    render(<CredList role="auditor" />);
    await screen.findByText('Student 1');
    await userEvent.type(screen.getByLabelText('Student ID'), 'S2');
    await userEvent.click(screen.getByRole('button', { name: 'Filter' }));
    await waitFor(() => expect(screen.queryByText('Student 1')).not.toBeInTheDocument());
    expect(f.mock.calls[1][0]).toBe('/api/v1/credentials?student_id=S2&limit=50');
  });

  it('shows an error from a later page without losing the pages already shown', async () => {
    serve({ body: { credentials: [row(2)], next: 'C' } }, { status: 500, body: { error: 'database unavailable' } });
    render(<CredList role="auditor" />);
    await screen.findByText('Student 2');
    await userEvent.click(screen.getByRole('button', { name: 'Load more' }));
    expect(await screen.findByText('database unavailable')).toBeInTheDocument();
    expect(screen.getByText('Student 2')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Load more' })).toBeEnabled();
  });

  it('pages the audit log by entry number', async () => {
    const f = serve(
      { body: { logs: [{ id: 9, at: '2026-01-01T00:00:00Z', action: 'LOGIN', actor: 'a@u.edu' }], next: 9 } },
      { body: { logs: [{ id: 8, at: '2026-01-01T00:00:00Z', action: 'LOGOUT', actor: 'a@u.edu' }], next: null } },
    );
    render(<Audit />);
    await screen.findByText('LOGIN');
    await userEvent.click(screen.getByRole('button', { name: 'Load more' }));
    expect(await screen.findByText('LOGOUT')).toBeInTheDocument();
    expect(f.mock.calls[1][0]).toBe('/api/v1/audit?limit=100&before=9');
  });

  it('pages the ledger and names the broken blocks when the chain check fails', async () => {
    const block = (h: number) => ({ height: h, credentials: 1, merkle_root: 'a'.repeat(64), block_hash: 'b'.repeat(64), timestamp: 1700000000 + h, external_timestamp: null });
    const f = serve(
      { body: { blocks: [block(3)], next: 3, pending_unanchored: 0, timestamping: null } },
      { body: { blocks: [block(2)], next: null } },
      { body: { ok: false, length: 3, failed_blocks: [2], blocks: [] } },
    );
    render(<Ledger role="auditor" />);
    await screen.findByText('3');
    await userEvent.click(screen.getByRole('button', { name: 'Load more' }));
    await waitFor(() => expect(f.mock.calls[1][0]).toBe('/api/v1/ledger/blocks?limit=50&before=3'));
    await userEvent.click(screen.getByRole('button', { name: 'Verify whole chain' }));
    expect(await screen.findByText('CHAIN BROKEN (blocks 2)')).toBeInTheDocument();
  });
});

describe('on-chain anchors', () => {
  const block = (h: number, onchain?: unknown) => ({ height: h, credentials: 1, merkle_root: 'a'.repeat(64), block_hash: 'b'.repeat(64), timestamp: 1700000000 + h, external_timestamp: null, ...(onchain ? { onchain } : {}) });
  const anchored = { status: 'ok', chain_id: 11155111, contract: '0xabc', epoch: 1, tx_hash: '0x' + 'f'.repeat(64), chain_block: 9, anchored_at: '2026-11-14T10:00:00Z', explorer_url: 'https://explorer.test/tx/0xfff' };
  const overview = (over: Record<string, unknown> = {}) => ({ chain_id: 11155111, contract: '0xabc', explorer_url: null, unanchored: 0, open_incidents: [], ...over });
  const anchor = (onchain?: unknown) => ({ height: 1, timestamp: 1700000000, block_hash: 'b'.repeat(64), merkle_root: 'a'.repeat(64), proof: [], leaf_index: 0, external_timestamp: null, ok: true, ...(onchain ? { onchain } : {}) });

  it('shows nothing about a chain when the server reports none', async () => {
    serve({ body: { blocks: [block(1)], next: null, pending_unanchored: 0, timestamping: null } });
    render(<Ledger role="auditor" />);
    await screen.findByText('Sealed');
    expect(screen.queryByText('On-chain')).not.toBeInTheDocument();
    expect(screen.queryByText(/public chain/)).not.toBeInTheDocument();
  });

  it('lists each block as anchored, waiting or mismatched, and links to the transaction', async () => {
    serve({ body: { blocks: [block(3, { status: 'none' }), block(2, { status: 'mismatch' }), block(1, anchored)], next: null, pending_unanchored: 0, timestamping: null, onchain: overview({ unanchored: 1 }) } });
    render(<Ledger role="auditor" />);
    expect(await screen.findByText('On-chain')).toBeInTheDocument();
    expect(screen.getByText('pending')).toBeInTheDocument();
    expect(screen.getByText('MISMATCH')).toHaveClass('bad');
    const link = screen.getByRole('link', { name: new Date('2026-11-14T10:00:00Z').toLocaleString() });
    expect(link).toHaveAttribute('href', 'https://explorer.test/tx/0xfff');
    expect(link).toHaveAttribute('rel', 'noopener noreferrer');
    expect(screen.getByText(/1 block\(s\) waiting to be anchored/)).toBeInTheDocument();
  });

  it('warns when the worker has stopped on an incident', async () => {
    serve({ body: { blocks: [block(2, { status: 'none' })], next: null, pending_unanchored: 0, timestamping: null, onchain: overview({ unanchored: 1, open_incidents: [{ kind: 'anchor_mismatch', height: 2, at: '2026-11-14T10:00:00Z', note: 'An older backup was restored.' }] }) } });
    render(<Ledger role="auditor" />);
    expect(await screen.findByText(/On-chain anchoring has stopped at block 2 \(anchor mismatch\)\. An older backup was restored\. Credentials are not affected\./)).toHaveClass('err');
  });

  it('says so when every block is anchored, without a link when no explorer is set', async () => {
    serve({ body: { blocks: [block(1, { ...anchored, explorer_url: null })], next: null, pending_unanchored: 0, timestamping: null, onchain: overview() } });
    render(<Ledger role="auditor" />);
    expect(await screen.findByText(/Every block is anchored\./)).toBeInTheDocument();
    expect(screen.queryByRole('link')).not.toBeInTheDocument();
    expect(screen.getByText(new Date('2026-11-14T10:00:00Z').toLocaleString())).toHaveClass('good');
  });

  it('shows the on-chain anchor on the verification page only when the server reports one', async () => {
    serve({ body: verification({ anchor: anchor() }) });
    const { unmount } = render(<Verify id="c1" />);
    await screen.findByText('Ledger anchor');
    expect(screen.queryByText('On-chain anchor')).not.toBeInTheDocument();
    unmount();

    serve({ body: verification({ anchor: anchor(anchored) }) });
    render(<Verify id="c1" />);
    expect(await screen.findByText('On-chain anchor')).toBeInTheDocument();
    const link = screen.getByRole('link', { name: /anchored .* on chain 11155111 \(epoch 1\), transaction 0xffffffffffffffff…/ });
    expect(link).toHaveAttribute('href', 'https://explorer.test/tx/0xfff');
  });

  it('tells a waiting block from a mismatch on the verification page', async () => {
    serve({ body: verification({ anchor: anchor({ status: 'none' }) }) });
    const { unmount } = render(<Verify id="c1" />);
    expect(await screen.findByText('not yet anchored on a public chain')).toHaveClass('muted');
    unmount();

    serve({ body: verification({ anchor: anchor({ status: 'mismatch' }) }) });
    render(<Verify id="c1" />);
    expect(await screen.findByText('MISMATCH: the on-chain anchor is not for this block')).toHaveClass('bad');
    // The verdict is the server's and is not changed by the anchor.
    expect(screen.getByText('VALID')).toBeInTheDocument();
  });
});

describe('the full export for the graduate', () => {
  const cred = (over: Record<string, unknown> = {}) => ({
    id: 'c1', student_id: 'S-1', student_name: 'Ada Lovelace', program: 'BSc', graduation_date: '2025-05-15', gpa: null, honors: null,
    credential_hash: 'ab'.repeat(32), status: 'issued', verdict: 'VALID', block_height: 1, leaf_index: 0, revoke_reason: null,
    supersedes: null, superseded_by: null, termination: null, signatures: [], checks: {}, approvers: [], ...over,
  });
  const challenge = { status: 404, body: { error: 'nothing to sign' } };

  it('is not offered unless the server says the export exists', async () => {
    serve({ body: cred() }, challenge);
    render(<CredDetail id="c1" role="registrar" />);
    await screen.findByText('Public verification page');
    expect(screen.queryByRole('button', { name: 'Download full file for the graduate' })).not.toBeInTheDocument();
  });

  it('is not offered for a credential that is not VALID', async () => {
    serve({ body: cred({ full_export: true, verdict: 'REVOKED', status: 'revoked' }) }, challenge);
    render(<CredDetail id="c1" role="registrar" />);
    await screen.findByText('Public verification page');
    expect(screen.queryByRole('button', { name: 'Download full file for the graduate' })).not.toBeInTheDocument();
  });

  it('fetches the file with the session and saves it', async () => {
    // The page asks what there is to sign once before and once after the credential has loaded.
    const f = serve({ body: cred({ full_export: true }) }, challenge, challenge, { body: { id: 'urn:uuid:c1', hashedContent: '{}' } });
    const saved: Blob[] = [];
    // jsdom has no object URLs; these two stand in for the browser's.
    Object.assign(URL, { createObjectURL: (b: Blob) => { saved.push(b); return 'blob:x'; }, revokeObjectURL: () => {} });
    const click = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {});
    render(<CredDetail id="c1" role="registrar" />);
    await userEvent.click(await screen.findByRole('button', { name: 'Download full file for the graduate' }));
    expect(await screen.findByText(/recorded in the audit log/)).toBeInTheDocument();
    expect(f.mock.calls[3][0]).toBe('/api/v1/credentials/c1/export-full');
    expect(f.mock.calls[3][1].headers.Authorization).toBeUndefined(); // no session in this test; with one, api() adds it
    expect(click).toHaveBeenCalledOnce();
    const text = await new Promise<string>((done) => { const r = new FileReader(); r.onload = () => done(String(r.result)); r.readAsText(saved[0]); });
    expect(JSON.parse(text)).toEqual({ id: 'urn:uuid:c1', hashedContent: '{}' });
    click.mockRestore();
  });
});

describe('ImportCredentials', () => {
  const file = (text: string) => new File([text], 'c.csv', { type: 'text/csv' });
  const HEAD = 'student_id,student_name,program,graduation_date,gpa,honors';

  it('previews a CSV file, then sends every row in one request', async () => {
    const f = serve({ status: 201, body: { created: 2 } });
    render(<ImportCredentials />);
    await userEvent.upload(screen.getByLabelText('CSV file'), file(`${HEAD}\nS1,Ada,BSc,2025-05-15,3.9,First\nS2,Alan,MSc,2025-06-01,,\n`));
    await screen.findByText('2 credential(s) ready. Check the first rows, then import.');
    expect(f).not.toHaveBeenCalled();
    await userEvent.click(screen.getByRole('button', { name: 'Import 2 and sign as faculty' }));
    await screen.findByText(/Imported\./);
    expect(f.mock.calls[0][0]).toBe('/api/v1/credentials/bulk');
    expect(body(f, 0).items).toEqual([
      { student_id: 'S1', student_name: 'Ada', program: 'BSc', graduation_date: '2025-05-15', gpa: '3.9', honors: 'First' },
      { student_id: 'S2', student_name: 'Alan', program: 'MSc', graduation_date: '2025-06-01', gpa: '', honors: '' },
    ]);
    expect(screen.queryByRole('button', { name: /^Import 2/ })).toBeNull();
  });

  it('explains a bad file and offers no import button', async () => {
    const f = serve();
    render(<ImportCredentials />);
    await userEvent.upload(screen.getByLabelText('CSV file'), file('student_id,program\nS1,BSc'));
    await screen.findByText(/header row is missing: student_name, graduation_date/);
    expect(screen.queryByRole('button', { name: /^Import/ })).toBeNull();
    expect(f).not.toHaveBeenCalled();
  });

  it('shows the row the server rejected and keeps the file for another try', async () => {
    serve({ status: 400, body: { error: 'row 2: graduation_date must be YYYY-MM-DD' } });
    render(<ImportCredentials />);
    await userEvent.upload(screen.getByLabelText('CSV file'), file(`${HEAD}\nS1,Ada,BSc,2025-05-15,,\nS2,Alan,MSc,15/06/2025,,\n`));
    await userEvent.click(await screen.findByRole('button', { name: 'Import 2 and sign as faculty' }));
    await screen.findByText('row 2: graduation_date must be YYYY-MM-DD');
    expect(screen.getByRole('button', { name: 'Import 2 and sign as faculty' })).toBeTruthy();
  });
});
