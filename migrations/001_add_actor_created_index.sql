-- Fix 3C: Add composite index for actor_id + created_at DESC
-- This index is critical for the partitioned hash chain query in postgres.go:
--
--   SELECT ... WHERE actor_id = ? ORDER BY created_at DESC, id DESC LIMIT 1
--
-- Without this index, the SELECT ... FOR UPDATE query performs a full table scan
-- under load, causing massive CPU spikes and transaction lock contention.
--
-- This index also benefits the actor-partitioned hash chain verification queries
-- used during non-repudiation audits.

CREATE INDEX IF NOT EXISTS idx_audit_events_actor_created
    ON audit_events (actor_id, created_at DESC);
