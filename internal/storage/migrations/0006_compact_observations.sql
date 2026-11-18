-- A digest preserves the duplicate check for discarded structured evidence.
ALTER TABLE events ADD COLUMN evidence_digest BLOB;
