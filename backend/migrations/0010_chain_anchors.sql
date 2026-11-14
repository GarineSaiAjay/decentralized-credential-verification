-- Receipts written by the optional on-chain worker (acvs-chain). The backend never writes these tables and
-- works the same when they are empty. They hold no personal data: block-level hashes, ledger positions and
-- public chain references only.
--
-- The smart contract is the source of truth; a row here is a receipt saying "this block (or revocation) was
-- seen on that contract, in that transaction". Rows are keyed by chain and contract, so receipts from an
-- earlier deployment (for example a local test chain) never stand in for the current one.

-- One row per sealed block that has been anchored on-chain.
CREATE TABLE chain_anchors (
    chain_id     bigint NOT NULL,
    contract     text   NOT NULL,                 -- LedgerAnchor address, lower-case 0x...
    block_height bigint NOT NULL REFERENCES blocks(height),
    block_hash   text   NOT NULL,                 -- what the contract holds; must equal blocks.block_hash
    merkle_root  text   NOT NULL,
    leaf_count   integer NOT NULL,
    epoch        bigint NOT NULL,                 -- the contract epoch that anchored it
    tx_hash      text   NOT NULL,
    chain_block  bigint NOT NULL,                 -- chain block holding the transaction
    anchored_at  timestamptz NOT NULL,            -- chain time of that block
    created_at   timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (chain_id, contract, block_height)
);

-- One row per revoked credential whose revocation bit has been set on-chain.
CREATE TABLE chain_revocations (
    chain_id      bigint NOT NULL,
    contract      text   NOT NULL,
    credential_id uuid   NOT NULL REFERENCES credentials(id),
    epoch         bigint NOT NULL,
    block_height  bigint NOT NULL,
    leaf_index    integer NOT NULL,
    tx_hash       text   NOT NULL,
    chain_block   bigint NOT NULL,
    revoked_at    timestamptz NOT NULL,
    created_at    timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (chain_id, contract, credential_id)
);

-- Things the worker refused to act on and a person must look at, for example a block whose on-chain anchor
-- differs from the database. The worker never "repairs" either side; it records the finding once and stops.
CREATE TABLE chain_incidents (
    id           bigserial PRIMARY KEY,
    chain_id     bigint NOT NULL,
    contract     text   NOT NULL,
    kind         text   NOT NULL CHECK (kind IN
        ('anchor_mismatch','block_invalid','height_gap','receipt_not_on_chain')),
    block_height bigint,
    detail       jsonb  NOT NULL,
    fingerprint  text   NOT NULL UNIQUE,          -- the same finding is stored once, however often it is seen
    created_at   timestamptz NOT NULL DEFAULT now()
);

CREATE TRIGGER chain_anchors_append_only     BEFORE UPDATE OR DELETE ON chain_anchors     FOR EACH ROW EXECUTE FUNCTION forbid_mutation();
CREATE TRIGGER chain_revocations_append_only BEFORE UPDATE OR DELETE ON chain_revocations FOR EACH ROW EXECUTE FUNCTION forbid_mutation();
CREATE TRIGGER chain_incidents_append_only   BEFORE UPDATE OR DELETE ON chain_incidents   FOR EACH ROW EXECUTE FUNCTION forbid_mutation();
