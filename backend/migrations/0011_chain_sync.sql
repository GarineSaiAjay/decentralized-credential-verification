-- Second part of the optional on-chain layer: publishing revocations and keeping the issuer registry's key
-- list in step with signing_keys. Only the on-chain worker's own tables are touched.

-- The worker can now also refuse a revocation whose signed event does not verify.
ALTER TABLE chain_incidents DROP CONSTRAINT chain_incidents_kind_check;
ALTER TABLE chain_incidents ADD CONSTRAINT chain_incidents_kind_check CHECK (kind IN
    ('anchor_mismatch','block_invalid','height_gap','receipt_not_on_chain','revocation_invalid'));

-- What still waits for the issuer admin's signature, as the worker last saw it: signing-key changes made in
-- ACVS that are not in the on-chain registry yet. One row per chain and contract, rewritten each round (this
-- is the one table of the worker that is a current state and not a log). The backend only reads it.
CREATE TABLE chain_sync_state (
    chain_id            bigint  NOT NULL,
    contract            text    NOT NULL,
    key_changes_pending integer NOT NULL,
    detail              jsonb   NOT NULL,          -- the changes in plain words, and any warnings
    checked_at          timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (chain_id, contract)
);
