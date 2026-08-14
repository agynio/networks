-- Mediation is derived from whether any egress rule names the resource; the
-- EgressRules service requests flips and reconciliation re-derives them.
CREATE TYPE private_resource_mediation AS ENUM ('tunnel', 'egress_gateway');

ALTER TABLE private_resources
    ADD COLUMN mediation private_resource_mediation NOT NULL DEFAULT 'tunnel',
    -- OpenZiti service id of private-<id>-upstream-<port>, keyed by intercept
    -- port as a JSON object. Non-empty only while mediation is egress_gateway.
    ADD COLUMN openziti_upstream_service_ids JSONB NOT NULL DEFAULT '{}',
    ADD COLUMN openziti_gateway_dial_policy_id TEXT NOT NULL DEFAULT '';
