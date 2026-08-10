-- A sandbox workload matches no existing principal type: it carries no
-- agent-<id> attribute and cannot be a group member. An environment principal
-- resolves to every workload running it, agent workloads and sandboxes alike,
-- and is the only handle that reaches a sandbox.
--
-- principal_id holds an Environment id for this variant rather than an identity
-- id -- the first principal here that is a configuration resource.
ALTER TYPE private_resource_access_principal_type ADD VALUE IF NOT EXISTS 'environment';

-- Note for the next additive change: the migration runner applies every pending
-- file inside one transaction, and PostgreSQL forbids *using* an enum value in
-- the transaction that added it. Adding a value is fine; a migration that also
-- inserts or compares against it must land in a later batch.
