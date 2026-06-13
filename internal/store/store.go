package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Store struct{ pool *pgxpool.Pool }

func New(pool *pgxpool.Pool) *Store { return &Store{pool: pool} }

const networkColumns = `id, organization_id, name, description, provisioning_state, openziti_bind_policy_id, created_at, updated_at`
const tunnelCredentialColumns = `id, network_id, openziti_identity_id, enrollment_jwt_revealed, enrollment_jwt_expires_at, enrollment_state, connectivity, provisioning_state, enrolled_at, last_seen_at, created_at, updated_at`
const privateResourceColumns = `id, organization_id, network_id, name, protocol, target_host, target_ports, intercept_host, intercept_ports, provisioning_state, openziti_service_id, created_at, updated_at`
const privateResourceAccessColumns = `id, private_resource_id, principal_type, principal_id, provisioning_state, openziti_dial_policy_id, created_at, updated_at`

func (s *Store) CreateNetwork(ctx context.Context, input CreateNetworkInput) (Network, error) {
	network, err := scanNetwork(s.pool.QueryRow(ctx,
		fmt.Sprintf(`INSERT INTO networks (id, organization_id, name, description) VALUES ($1, $2, $3, $4) RETURNING %s`, networkColumns),
		input.ID, input.OrganizationID, input.Name, input.Description,
	))
	if err != nil {
		if isUniqueViolation(err) {
			return Network{}, AlreadyExists("network")
		}
		return Network{}, err
	}
	return network, nil
}

func (s *Store) GetNetwork(ctx context.Context, id uuid.UUID) (Network, error) {
	network, err := scanNetwork(s.pool.QueryRow(ctx, fmt.Sprintf(`SELECT %s FROM networks WHERE id = $1`, networkColumns), id))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Network{}, NotFound("network")
		}
		return Network{}, err
	}
	return network, nil
}

func (s *Store) ListNetworks(ctx context.Context, organizationID uuid.UUID, pageSize int32, cursor *PageCursor) ([]Network, *PageCursor, error) {
	return listEntities(ctx, s.pool,
		fmt.Sprintf("SELECT %s FROM networks", networkColumns),
		[]string{"organization_id = $1"}, []any{organizationID}, cursor, pageSize, "networks.id", scanNetwork,
		func(network Network) uuid.UUID { return network.Meta.ID },
	)
}

func (s *Store) UpdateNetwork(ctx context.Context, input UpdateNetworkInput) (Network, error) {
	builder := updateBuilder{}
	if input.Name != nil {
		builder.add("name", *input.Name)
	}
	if input.Description != nil {
		builder.add("description", *input.Description)
	}
	if builder.empty() {
		return s.GetNetwork(ctx, input.ID)
	}
	query, args := builder.build("networks", networkColumns, input.ID)
	network, err := scanNetwork(s.pool.QueryRow(ctx, query, args...))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Network{}, NotFound("network")
		}
		if isUniqueViolation(err) {
			return Network{}, AlreadyExists("network")
		}
		return Network{}, err
	}
	return network, nil
}

func (s *Store) DeleteNetwork(ctx context.Context, id uuid.UUID) error {
	commandTag, err := s.pool.Exec(ctx, `DELETE FROM networks WHERE id = $1`, id)
	if err != nil {
		return err
	}
	if commandTag.RowsAffected() == 0 {
		return NotFound("network")
	}
	return nil
}

func (s *Store) CreateTunnelCredential(ctx context.Context, input CreateTunnelCredentialInput) (TunnelCredential, error) {
	credential, err := scanTunnelCredential(s.pool.QueryRow(ctx,
		fmt.Sprintf(`INSERT INTO tunnel_credentials (id, network_id, openziti_identity_id, enrollment_jwt_revealed, enrollment_jwt_expires_at) VALUES ($1, $2, $3, $4, $5) RETURNING %s`, tunnelCredentialColumns),
		input.ID, input.NetworkID, input.OpenZitiIdentityID, input.EnrollmentJWTRevealed, input.EnrollmentJWTExpiresAt,
	))
	if err != nil {
		if isUniqueViolation(err) {
			return TunnelCredential{}, AlreadyExists("tunnel credential")
		}
		return TunnelCredential{}, err
	}
	return credential, nil
}

func (s *Store) GetTunnelCredential(ctx context.Context, id uuid.UUID) (TunnelCredential, error) {
	credential, err := scanTunnelCredential(s.pool.QueryRow(ctx, fmt.Sprintf(`SELECT %s FROM tunnel_credentials WHERE id = $1`, tunnelCredentialColumns), id))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return TunnelCredential{}, NotFound("tunnel credential")
		}
		return TunnelCredential{}, err
	}
	return credential, nil
}

func (s *Store) CreatePrivateResource(ctx context.Context, input CreatePrivateResourceInput) (PrivateResource, error) {
	var resource PrivateResource
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		created, err := scanPrivateResource(tx.QueryRow(ctx,
			fmt.Sprintf(`INSERT INTO private_resources (id, organization_id, network_id, name, protocol, target_host, target_ports, intercept_host, intercept_ports) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING %s`, privateResourceColumns),
			input.ID, input.OrganizationID, input.NetworkID, input.Name, input.Protocol, input.TargetHost, input.TargetPorts, input.InterceptHost, input.InterceptPorts,
		))
		if err != nil {
			return err
		}
		for _, port := range input.InterceptPorts {
			if _, err := tx.Exec(ctx, `INSERT INTO private_resource_intercept_ports (private_resource_id, organization_id, intercept_host, intercept_port) VALUES ($1, $2, $3, $4)`, input.ID, input.OrganizationID, input.InterceptHost, port); err != nil {
				return err
			}
		}
		resource = created
		return nil
	})
	if err != nil {
		if isUniqueViolation(err) {
			return PrivateResource{}, AlreadyExists("private resource")
		}
		return PrivateResource{}, err
	}
	return resource, nil
}

func (s *Store) GetPrivateResource(ctx context.Context, id uuid.UUID) (PrivateResource, error) {
	resource, err := scanPrivateResource(s.pool.QueryRow(ctx, fmt.Sprintf(`SELECT %s FROM private_resources WHERE id = $1`, privateResourceColumns), id))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return PrivateResource{}, NotFound("private resource")
		}
		return PrivateResource{}, err
	}
	return resource, nil
}

func (s *Store) CreatePrivateResourceAccess(ctx context.Context, input CreatePrivateResourceAccessInput) (PrivateResourceAccess, error) {
	access, err := scanPrivateResourceAccess(s.pool.QueryRow(ctx,
		fmt.Sprintf(`INSERT INTO private_resource_accesses (id, private_resource_id, principal_type, principal_id) VALUES ($1, $2, $3, $4) RETURNING %s`, privateResourceAccessColumns),
		input.ID, input.PrivateResourceID, input.PrincipalType, input.PrincipalID,
	))
	if err != nil {
		if isUniqueViolation(err) {
			return PrivateResourceAccess{}, AlreadyExists("private resource access")
		}
		return PrivateResourceAccess{}, err
	}
	return access, nil
}

func scanNetwork(row pgx.Row) (Network, error) {
	var network Network
	err := row.Scan(&network.Meta.ID, &network.OrganizationID, &network.Name, &network.Description, &network.ProvisioningState, &network.OpenZitiBindPolicyID, &network.Meta.CreatedAt, &network.Meta.UpdatedAt)
	return network, err
}

func scanTunnelCredential(row pgx.Row) (TunnelCredential, error) {
	var credential TunnelCredential
	err := row.Scan(&credential.Meta.ID, &credential.NetworkID, &credential.OpenZitiIdentityID, &credential.EnrollmentJWTRevealed, &credential.EnrollmentJWTExpiresAt, &credential.EnrollmentState, &credential.Connectivity, &credential.ProvisioningState, &credential.EnrolledAt, &credential.LastSeenAt, &credential.Meta.CreatedAt, &credential.Meta.UpdatedAt)
	return credential, err
}

func scanPrivateResource(row pgx.Row) (PrivateResource, error) {
	var resource PrivateResource
	err := row.Scan(&resource.Meta.ID, &resource.OrganizationID, &resource.NetworkID, &resource.Name, &resource.Protocol, &resource.TargetHost, &resource.TargetPorts, &resource.InterceptHost, &resource.InterceptPorts, &resource.ProvisioningState, &resource.OpenZitiServiceID, &resource.Meta.CreatedAt, &resource.Meta.UpdatedAt)
	return resource, err
}

func scanPrivateResourceAccess(row pgx.Row) (PrivateResourceAccess, error) {
	var access PrivateResourceAccess
	err := row.Scan(&access.Meta.ID, &access.PrivateResourceID, &access.PrincipalType, &access.PrincipalID, &access.ProvisioningState, &access.OpenZitiDialPolicyID, &access.Meta.CreatedAt, &access.Meta.UpdatedAt)
	return access, err
}
