-- Undoes 0011. Loses the worker's note of pending key changes (it rewrites it on its next round) and any
-- recorded "revocation_invalid" incidents. Nothing on the chain itself changes. Stop the worker first.
DROP TABLE chain_sync_state;
ALTER TABLE chain_incidents DISABLE TRIGGER USER;
DELETE FROM chain_incidents WHERE kind = 'revocation_invalid';
ALTER TABLE chain_incidents ENABLE TRIGGER USER;
ALTER TABLE chain_incidents DROP CONSTRAINT chain_incidents_kind_check;
ALTER TABLE chain_incidents ADD CONSTRAINT chain_incidents_kind_check CHECK (kind IN
    ('anchor_mismatch','block_invalid','height_gap','receipt_not_on_chain'));
