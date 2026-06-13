CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TYPE provisioning_state AS ENUM ('active', 'failed', 'removing');
CREATE TYPE tunnel_enrollment_state AS ENUM ('pending', 'enrolled');
CREATE TYPE tunnel_connectivity AS ENUM ('online', 'offline');
CREATE TYPE private_resource_protocol AS ENUM ('tcp', 'http', 'https');
CREATE TYPE private_resource_access_principal_type AS ENUM ('agent', 'user', 'app', 'group');

CREATE TABLE networks (
    id                         UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id            UUID NOT NULL,
    name                       TEXT NOT NULL,
    description                TEXT NOT NULL DEFAULT '',
    provisioning_state         provisioning_state NOT NULL DEFAULT 'active',
    openziti_bind_policy_id    TEXT NOT NULL DEFAULT '',
    created_at                 TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at                 TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (organization_id, name)
);

CREATE INDEX idx_networks_organization_id ON networks (organization_id);

CREATE TABLE tunnel_credentials (
    id                         UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    network_id                 UUID NOT NULL REFERENCES networks(id) ON DELETE CASCADE,
    openziti_identity_id       TEXT NOT NULL DEFAULT '',
    enrollment_jwt_revealed    BOOLEAN NOT NULL DEFAULT FALSE,
    enrollment_jwt_expires_at  TIMESTAMPTZ,
    enrollment_state           tunnel_enrollment_state NOT NULL DEFAULT 'pending',
    connectivity               tunnel_connectivity NOT NULL DEFAULT 'offline',
    provisioning_state         provisioning_state NOT NULL DEFAULT 'active',
    enrolled_at                TIMESTAMPTZ,
    last_seen_at               TIMESTAMPTZ,
    created_at                 TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at                 TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_tunnel_credentials_network_id ON tunnel_credentials (network_id);
CREATE UNIQUE INDEX idx_tunnel_credentials_openziti_identity_id ON tunnel_credentials (openziti_identity_id) WHERE openziti_identity_id <> '';

CREATE TABLE private_resources (
    id                         UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id            UUID NOT NULL,
    network_id                 UUID NOT NULL REFERENCES networks(id) ON DELETE CASCADE,
    name                       TEXT NOT NULL,
    protocol                   private_resource_protocol NOT NULL,
    target_host                TEXT NOT NULL,
    target_ports               INTEGER[] NOT NULL,
    intercept_host             TEXT NOT NULL,
    intercept_ports            INTEGER[] NOT NULL,
    provisioning_state         provisioning_state NOT NULL DEFAULT 'active',
    openziti_service_id        TEXT NOT NULL DEFAULT '',
    created_at                 TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at                 TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK (cardinality(target_ports) > 0),
    CHECK (cardinality(target_ports) = cardinality(intercept_ports)),
    CHECK (0 < ALL(target_ports) AND 65536 > ALL(target_ports)),
    CHECK (0 < ALL(intercept_ports) AND 65536 > ALL(intercept_ports))
);

CREATE INDEX idx_private_resources_organization_id ON private_resources (organization_id);
CREATE INDEX idx_private_resources_network_id ON private_resources (network_id);
CREATE UNIQUE INDEX idx_private_resources_openziti_service_id ON private_resources (openziti_service_id) WHERE openziti_service_id <> '';

CREATE TABLE private_resource_intercept_ports (
    private_resource_id UUID NOT NULL REFERENCES private_resources(id) ON DELETE CASCADE,
    organization_id     UUID NOT NULL,
    intercept_host      TEXT NOT NULL,
    intercept_port      INTEGER NOT NULL CHECK (intercept_port BETWEEN 1 AND 65535),
    PRIMARY KEY (private_resource_id, intercept_port),
    UNIQUE (organization_id, intercept_host, intercept_port)
);

CREATE INDEX idx_private_resource_intercept_ports_resource_id ON private_resource_intercept_ports (private_resource_id);

CREATE TABLE private_resource_accesses (
    id                         UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    private_resource_id        UUID NOT NULL REFERENCES private_resources(id) ON DELETE CASCADE,
    principal_type             private_resource_access_principal_type NOT NULL,
    principal_id               UUID NOT NULL,
    provisioning_state         provisioning_state NOT NULL DEFAULT 'active',
    openziti_dial_policy_id    TEXT NOT NULL DEFAULT '',
    created_at                 TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at                 TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (private_resource_id, principal_type, principal_id)
);

CREATE INDEX idx_private_resource_accesses_resource_id ON private_resource_accesses (private_resource_id);
CREATE INDEX idx_private_resource_accesses_principal ON private_resource_accesses (principal_type, principal_id);
CREATE UNIQUE INDEX idx_private_resource_accesses_openziti_dial_policy_id ON private_resource_accesses (openziti_dial_policy_id) WHERE openziti_dial_policy_id <> '';
