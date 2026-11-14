-- Undoes 0010. Loses the local receipts of on-chain anchoring. Nothing on the chain itself changes, and the
-- worker (acvs-chain) can rebuild the receipts from the contract if the migration is applied again.
-- Stop the worker first: it cannot run without these tables.
DROP TABLE chain_incidents;
DROP TABLE chain_revocations;
DROP TABLE chain_anchors;
