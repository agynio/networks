package store

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Store struct{ pool *pgxpool.Pool }

func New(pool *pgxpool.Pool) *Store { return &Store{pool: pool} }

const networkColumns = `id, organization_id, name, description, provisioning_state, openziti_bind_policy_id, created_at, updated_at`
const tunnelCredentialColumns = `tunnel_credentials.id, tunnel_credentials.network_id, networks.organization_id, tunnel_credentials.openziti_identity_id, tunnel_credentials.enrollment_jwt_revealed, tunnel_credentials.enrollment_jwt_expires_at, tunnel_credentials.enrollment_state, tunnel_credentials.connectivity, tunnel_credentials.provisioning_state, tunnel_credentials.enrolled_at, tunnel_credentials.last_seen_at, tunnel_credentials.created_at, tunnel_credentials.updated_at`
const tunnelCredentialInsertColumns = `id, network_id, (SELECT organization_id FROM networks WHERE networks.id = tunnel_credentials.network_id), openziti_identity_id, enrollment_jwt_revealed, enrollment_jwt_expires_at, enrollment_state, connectivity, provisioning_state, enrolled_at, last_seen_at, created_at, updated_at`
const privateResourceColumns = `id, organization_id, network_id, name, protocol, target_host, target_ports, intercept_host, intercept_ports, provisioning_state, openziti_service_id, mediation, openziti_upstream_service_ids, openziti_gateway_dial_policy_id, created_at, updated_at`
const privateResourceAccessColumns = `private_resource_accesses.id, private_resource_accesses.private_resource_id, private_resources.organization_id, private_resources.network_id, private_resource_accesses.principal_type, private_resource_accesses.principal_id, private_resource_accesses.provisioning_state, private_resource_accesses.openziti_dial_policy_id, private_resource_accesses.created_at, private_resource_accesses.updated_at`
const privateResourceAccessInsertColumns = `id, private_resource_id, (SELECT organization_id FROM private_resources WHERE private_resources.id = private_resource_accesses.private_resource_id), (SELECT network_id FROM private_resources WHERE private_resources.id = private_resource_accesses.private_resource_id), principal_type, principal_id, provisioning_state, openziti_dial_policy_id, created_at, updated_at`

func (s *Store) CreateNetwork(ctx context.Context, input CreateNetworkInput) (Network, error) {
	network, err := scanNetwork(s.pool.QueryRow(ctx,
		fmt.Sprintf(`INSERT INTO networks (id, organization_id, name, description, provisioning_state, openziti_bind_policy_id) VALUES ($1, $2, $3, $4, $5, $6) RETURNING %s`, networkColumns),
		input.ID, input.OrganizationID, input.Name, input.Description, normalizeProvisioningState(input.ProvisioningState), input.OpenZitiBindPolicyID,
	))
	if err != nil {
		if isUniqueViolation(err) {
			return Network{}, AlreadyExists("network")
		}
		return Network{}, err
	}
	return network, nil
}

func (s *Store) UpdateNetworkProvisioning(ctx context.Context, id uuid.UUID, state ProvisioningState, openZitiBindPolicyID string) (Network, error) {
	network, err := scanNetwork(s.pool.QueryRow(ctx,
		fmt.Sprintf(`UPDATE networks SET provisioning_state = $1, openziti_bind_policy_id = $2, updated_at = NOW() WHERE id = $3 RETURNING %s`, networkColumns),
		normalizeProvisioningState(state), openZitiBindPolicyID, id,
	))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Network{}, NotFound("network")
		}
		return Network{}, err
	}
	return network, nil
}

func (s *Store) UpdateTunnelCredentialProvisioning(ctx context.Context, id uuid.UUID, state ProvisioningState, openZitiIdentityID string, enrollmentJWTRevealed bool, enrollmentJWTExpiresAt *time.Time) (TunnelCredential, error) {
	credential, err := scanTunnelCredential(s.pool.QueryRow(ctx,
		fmt.Sprintf(`UPDATE tunnel_credentials SET provisioning_state = $1, openziti_identity_id = $2, enrollment_jwt_revealed = $3, enrollment_jwt_expires_at = $4, updated_at = NOW() WHERE id = $5 RETURNING %s`, tunnelCredentialInsertColumns),
		normalizeProvisioningState(state), openZitiIdentityID, enrollmentJWTRevealed, enrollmentJWTExpiresAt, id,
	))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return TunnelCredential{}, NotFound("tunnel credential")
		}
		return TunnelCredential{}, err
	}
	return credential, nil
}

func (s *Store) UpdatePrivateResourceProvisioning(ctx context.Context, id uuid.UUID, state ProvisioningState, openZitiServiceID string) (PrivateResource, error) {
	resource, err := scanPrivateResource(s.pool.QueryRow(ctx,
		fmt.Sprintf(`UPDATE private_resources SET provisioning_state = $1, openziti_service_id = $2, updated_at = NOW() WHERE id = $3 RETURNING %s`, privateResourceColumns),
		normalizeProvisioningState(state), openZitiServiceID, id,
	))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return PrivateResource{}, NotFound("private resource")
		}
		return PrivateResource{}, err
	}
	return resource, nil
}

func (s *Store) UpdatePrivateResourceMediation(ctx context.Context, id uuid.UUID, mediation Mediation, state ProvisioningState, upstreamServiceIDs map[int32]string, gatewayDialPolicyID string) (PrivateResource, error) {
	if upstreamServiceIDs == nil {
		upstreamServiceIDs = map[int32]string{}
	}
	resource, err := scanPrivateResource(s.pool.QueryRow(ctx,
		fmt.Sprintf(`UPDATE private_resources SET mediation = $1, provisioning_state = $2, openziti_upstream_service_ids = $3, openziti_gateway_dial_policy_id = $4, updated_at = NOW() WHERE id = $5 RETURNING %s`, privateResourceColumns),
		mediation, normalizeProvisioningState(state), upstreamServiceIDs, gatewayDialPolicyID, id,
	))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return PrivateResource{}, NotFound("private resource")
		}
		return PrivateResource{}, err
	}
	return resource, nil
}

func (s *Store) UpdatePrivateResourceAccessProvisioning(ctx context.Context, id uuid.UUID, state ProvisioningState, openZitiDialPolicyID string) (PrivateResourceAccess, error) {
	access, err := scanPrivateResourceAccess(s.pool.QueryRow(ctx,
		fmt.Sprintf(`UPDATE private_resource_accesses SET provisioning_state = $1, openziti_dial_policy_id = $2, updated_at = NOW() WHERE id = $3 RETURNING %s`, privateResourceAccessInsertColumns),
		normalizeProvisioningState(state), openZitiDialPolicyID, id,
	))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return PrivateResourceAccess{}, NotFound("private resource access")
		}
		return PrivateResourceAccess{}, err
	}
	return access, nil
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

func (s *Store) ListAllNetworks(ctx context.Context) ([]Network, error) {
	rows, err := s.pool.Query(ctx, fmt.Sprintf(`SELECT %s FROM networks ORDER BY id`, networkColumns))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanRows(rows, scanNetwork)
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
		fmt.Sprintf(`INSERT INTO tunnel_credentials (id, network_id, openziti_identity_id, enrollment_jwt_revealed, enrollment_jwt_expires_at, provisioning_state) VALUES ($1, $2, $3, $4, $5, $6) RETURNING %s`, tunnelCredentialInsertColumns),
		input.ID, input.NetworkID, input.OpenZitiIdentityID, input.EnrollmentJWTRevealed, input.EnrollmentJWTExpiresAt, normalizeProvisioningState(input.ProvisioningState),
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
	credential, err := scanTunnelCredential(s.pool.QueryRow(ctx, fmt.Sprintf(`SELECT %s FROM tunnel_credentials JOIN networks ON networks.id = tunnel_credentials.network_id WHERE tunnel_credentials.id = $1`, tunnelCredentialColumns), id))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return TunnelCredential{}, NotFound("tunnel credential")
		}
		return TunnelCredential{}, err
	}
	return credential, nil
}

func (s *Store) ListTunnelCredentials(ctx context.Context, networkID uuid.UUID, pageSize int32, cursor *PageCursor) ([]TunnelCredential, *PageCursor, error) {
	return listEntities(ctx, s.pool,
		fmt.Sprintf("SELECT %s FROM tunnel_credentials JOIN networks ON networks.id = tunnel_credentials.network_id", tunnelCredentialColumns),
		[]string{"tunnel_credentials.network_id = $1"}, []any{networkID}, cursor, pageSize, "tunnel_credentials.id", scanTunnelCredential,
		func(credential TunnelCredential) uuid.UUID { return credential.Meta.ID },
	)
}

func (s *Store) ListAllTunnelCredentials(ctx context.Context) ([]TunnelCredential, error) {
	return s.ListAllTunnelCredentialsFiltered(ctx, ListTunnelCredentialsFilter{})
}

func (s *Store) ListAllTunnelCredentialsFiltered(ctx context.Context, filter ListTunnelCredentialsFilter) ([]TunnelCredential, error) {
	clauses := []string{}
	args := []any{}
	if filter.NetworkID != nil {
		clauses, args = appendClause(clauses, args, "tunnel_credentials.network_id = $%d", *filter.NetworkID)
	}
	query := fmt.Sprintf(`SELECT %s FROM tunnel_credentials JOIN networks ON networks.id = tunnel_credentials.network_id`, tunnelCredentialColumns)
	if len(clauses) > 0 {
		query += " WHERE " + joinClauses(clauses)
	}
	query += " ORDER BY tunnel_credentials.id"
	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanRows(rows, scanTunnelCredential)
}

func (s *Store) UpdateTunnelCredentialLiveness(ctx context.Context, input UpdateTunnelCredentialLivenessInput) (TunnelCredential, error) {
	credential, err := scanTunnelCredential(s.pool.QueryRow(ctx,
		fmt.Sprintf(`UPDATE tunnel_credentials SET enrollment_state = $1, connectivity = $2, enrolled_at = $3, last_seen_at = $4, updated_at = NOW() WHERE id = $5 RETURNING %s`, tunnelCredentialInsertColumns),
		input.EnrollmentState, input.Connectivity, input.EnrolledAt, input.LastSeenAt, input.ID,
	))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return TunnelCredential{}, NotFound("tunnel credential")
		}
		return TunnelCredential{}, err
	}
	return credential, nil
}

func (s *Store) DeleteTunnelCredential(ctx context.Context, id uuid.UUID) error {
	commandTag, err := s.pool.Exec(ctx, `DELETE FROM tunnel_credentials WHERE id = $1`, id)
	if err != nil {
		return err
	}
	if commandTag.RowsAffected() == 0 {
		return NotFound("tunnel credential")
	}
	return nil
}

func (s *Store) CreatePrivateResource(ctx context.Context, input CreatePrivateResourceInput) (PrivateResource, error) {
	var resource PrivateResource
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		created, err := scanPrivateResource(tx.QueryRow(ctx,
			fmt.Sprintf(`INSERT INTO private_resources (id, organization_id, network_id, name, protocol, target_host, target_ports, intercept_host, intercept_ports, provisioning_state, openziti_service_id) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) RETURNING %s`, privateResourceColumns),
			input.ID, input.OrganizationID, input.NetworkID, input.Name, input.Protocol, input.TargetHost, input.TargetPorts, input.InterceptHost, input.InterceptPorts, normalizeProvisioningState(input.ProvisioningState), input.OpenZitiServiceID,
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

func (s *Store) ListPrivateResources(ctx context.Context, filter ListPrivateResourcesFilter, pageSize int32, cursor *PageCursor) ([]PrivateResource, *PageCursor, error) {
	clauses := []string{}
	args := []any{}
	if filter.OrganizationID != nil {
		clauses, args = appendClause(clauses, args, "organization_id = $%d", *filter.OrganizationID)
	}
	if filter.NetworkID != nil {
		clauses, args = appendClause(clauses, args, "network_id = $%d", *filter.NetworkID)
	}
	return listEntities(ctx, s.pool, fmt.Sprintf("SELECT %s FROM private_resources", privateResourceColumns), clauses, args, cursor, pageSize, "private_resources.id", scanPrivateResource, func(resource PrivateResource) uuid.UUID { return resource.Meta.ID })
}

func (s *Store) ListAllPrivateResources(ctx context.Context) ([]PrivateResource, error) {
	return s.ListAllPrivateResourcesFiltered(ctx, ListPrivateResourcesFilterAll{})
}

func (s *Store) ListAllPrivateResourcesFiltered(ctx context.Context, filter ListPrivateResourcesFilterAll) ([]PrivateResource, error) {
	clauses := []string{}
	args := []any{}
	if filter.NetworkID != nil {
		clauses, args = appendClause(clauses, args, "network_id = $%d", *filter.NetworkID)
	}
	query := fmt.Sprintf(`SELECT %s FROM private_resources`, privateResourceColumns)
	if len(clauses) > 0 {
		query += " WHERE " + joinClauses(clauses)
	}
	query += " ORDER BY id"
	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanRows(rows, scanPrivateResource)
}

func (s *Store) UpdatePrivateResource(ctx context.Context, input UpdatePrivateResourceInput) (PrivateResource, error) {
	var resource PrivateResource
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		builder := updateBuilder{}
		if input.Name != nil {
			builder.add("name", *input.Name)
		}
		if input.Protocol != nil {
			builder.add("protocol", *input.Protocol)
		}
		if input.TargetHost != nil {
			builder.add("target_host", *input.TargetHost)
		}
		if input.InterceptHost != nil {
			builder.add("intercept_host", *input.InterceptHost)
		}
		if input.UpdatePorts {
			builder.add("target_ports", input.TargetPorts)
			builder.add("intercept_ports", input.InterceptPorts)
		}
		if builder.empty() {
			current, err := scanPrivateResource(tx.QueryRow(ctx, fmt.Sprintf(`SELECT %s FROM private_resources WHERE id = $1`, privateResourceColumns), input.ID))
			if err != nil {
				return err
			}
			resource = current
			return nil
		}
		query, args := builder.build("private_resources", privateResourceColumns, input.ID)
		updated, err := scanPrivateResource(tx.QueryRow(ctx, query, args...))
		if err != nil {
			return err
		}
		if input.InterceptHost != nil || input.UpdatePorts {
			if _, err := tx.Exec(ctx, `DELETE FROM private_resource_intercept_ports WHERE private_resource_id = $1`, input.ID); err != nil {
				return err
			}
			for _, port := range updated.InterceptPorts {
				if _, err := tx.Exec(ctx, `INSERT INTO private_resource_intercept_ports (private_resource_id, organization_id, intercept_host, intercept_port) VALUES ($1, $2, $3, $4)`, updated.Meta.ID, updated.OrganizationID, updated.InterceptHost, port); err != nil {
					return err
				}
			}
		}
		resource = updated
		return nil
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return PrivateResource{}, NotFound("private resource")
		}
		if isUniqueViolation(err) {
			return PrivateResource{}, AlreadyExists("private resource")
		}
		return PrivateResource{}, err
	}
	return resource, nil
}

func (s *Store) DeletePrivateResource(ctx context.Context, id uuid.UUID) error {
	commandTag, err := s.pool.Exec(ctx, `DELETE FROM private_resources WHERE id = $1`, id)
	if err != nil {
		return err
	}
	if commandTag.RowsAffected() == 0 {
		return NotFound("private resource")
	}
	return nil
}

func (s *Store) CreatePrivateResourceAccess(ctx context.Context, input CreatePrivateResourceAccessInput) (PrivateResourceAccess, error) {
	access, err := scanPrivateResourceAccess(s.pool.QueryRow(ctx,
		fmt.Sprintf(`INSERT INTO private_resource_accesses (id, private_resource_id, principal_type, principal_id, provisioning_state, openziti_dial_policy_id) VALUES ($1, $2, $3, $4, $5, $6) RETURNING %s`, privateResourceAccessInsertColumns),
		input.ID, input.PrivateResourceID, input.PrincipalType, input.PrincipalID, normalizeProvisioningState(input.ProvisioningState), input.OpenZitiDialPolicyID,
	))
	if err != nil {
		if isUniqueViolation(err) {
			return PrivateResourceAccess{}, AlreadyExists("private resource access")
		}
		return PrivateResourceAccess{}, err
	}
	return access, nil
}

func (s *Store) GetPrivateResourceAccess(ctx context.Context, id uuid.UUID) (PrivateResourceAccess, error) {
	access, err := scanPrivateResourceAccess(s.pool.QueryRow(ctx, fmt.Sprintf(`SELECT %s FROM private_resource_accesses JOIN private_resources ON private_resources.id = private_resource_accesses.private_resource_id WHERE private_resource_accesses.id = $1`, privateResourceAccessColumns), id))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return PrivateResourceAccess{}, NotFound("private resource access")
		}
		return PrivateResourceAccess{}, err
	}
	return access, nil
}

func (s *Store) ListPrivateResourceAccess(ctx context.Context, filter ListPrivateResourceAccessFilter, pageSize int32, cursor *PageCursor) ([]PrivateResourceAccess, *PageCursor, error) {
	clauses := []string{}
	args := []any{}
	if filter.PrivateResourceID != nil {
		clauses, args = appendClause(clauses, args, "private_resource_accesses.private_resource_id = $%d", *filter.PrivateResourceID)
	}
	if filter.NetworkID != nil {
		clauses, args = appendClause(clauses, args, "private_resources.network_id = $%d", *filter.NetworkID)
	}
	if filter.PrincipalType != nil {
		clauses, args = appendClause(clauses, args, "principal_type = $%d", *filter.PrincipalType)
	}
	if filter.PrincipalID != nil {
		clauses, args = appendClause(clauses, args, "principal_id = $%d", *filter.PrincipalID)
	}
	return listEntities(ctx, s.pool, fmt.Sprintf("SELECT %s FROM private_resource_accesses JOIN private_resources ON private_resources.id = private_resource_accesses.private_resource_id", privateResourceAccessColumns), clauses, args, cursor, pageSize, "private_resource_accesses.id", scanPrivateResourceAccess, func(access PrivateResourceAccess) uuid.UUID { return access.Meta.ID })
}

func (s *Store) ListAllPrivateResourceAccess(ctx context.Context) ([]PrivateResourceAccess, error) {
	return s.ListAllPrivateResourceAccessFiltered(ctx, ListPrivateResourceAccessFilterAll{})
}

func (s *Store) ListAllPrivateResourceAccessFiltered(ctx context.Context, filter ListPrivateResourceAccessFilterAll) ([]PrivateResourceAccess, error) {
	clauses := []string{}
	args := []any{}
	if filter.PrivateResourceID != nil {
		clauses, args = appendClause(clauses, args, "private_resource_accesses.private_resource_id = $%d", *filter.PrivateResourceID)
	}
	if filter.NetworkID != nil {
		clauses, args = appendClause(clauses, args, "private_resources.network_id = $%d", *filter.NetworkID)
	}
	query := fmt.Sprintf(`SELECT %s FROM private_resource_accesses JOIN private_resources ON private_resources.id = private_resource_accesses.private_resource_id`, privateResourceAccessColumns)
	if len(clauses) > 0 {
		query += " WHERE " + joinClauses(clauses)
	}
	query += " ORDER BY private_resource_accesses.id"
	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanRows(rows, scanPrivateResourceAccess)
}

func (s *Store) ListPrivateResourceAccessByPrincipals(ctx context.Context, principals []Principal) ([]PrivateResourceAccess, error) {
	if len(principals) == 0 {
		return nil, nil
	}
	clauses := make([]string, 0, len(principals))
	args := make([]any, 0, 2*len(principals))
	for _, principal := range principals {
		clauses = append(clauses, fmt.Sprintf("(private_resource_accesses.principal_type = $%d AND private_resource_accesses.principal_id = $%d)", len(args)+1, len(args)+2))
		args = append(args, principal.Type, principal.ID)
	}
	query := fmt.Sprintf(`SELECT %s FROM private_resource_accesses JOIN private_resources ON private_resources.id = private_resource_accesses.private_resource_id WHERE %s ORDER BY private_resource_accesses.id`, privateResourceAccessColumns, strings.Join(clauses, " OR "))
	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanRows(rows, scanPrivateResourceAccess)
}

func (s *Store) ListPrivateResourcesByIDs(ctx context.Context, ids []uuid.UUID) ([]PrivateResource, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	rows, err := s.pool.Query(ctx, fmt.Sprintf(`SELECT %s FROM private_resources WHERE id = ANY($1) ORDER BY id`, privateResourceColumns), ids)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanRows(rows, scanPrivateResource)
}

func (s *Store) ListPrivateResourceAccessByGroupID(ctx context.Context, groupID uuid.UUID) ([]PrivateResourceAccess, error) {
	rows, err := s.pool.Query(ctx, fmt.Sprintf(`SELECT %s FROM private_resource_accesses JOIN private_resources ON private_resources.id = private_resource_accesses.private_resource_id WHERE principal_type = $1 AND principal_id = $2 ORDER BY private_resource_accesses.id`, privateResourceAccessColumns), PrincipalTypeGroup, groupID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanRows(rows, scanPrivateResourceAccess)
}

func (s *Store) DeletePrivateResourceAccess(ctx context.Context, id uuid.UUID) error {
	commandTag, err := s.pool.Exec(ctx, `DELETE FROM private_resource_accesses WHERE id = $1`, id)
	if err != nil {
		return err
	}
	if commandTag.RowsAffected() == 0 {
		return NotFound("private resource access")
	}
	return nil
}

func normalizeProvisioningState(state ProvisioningState) ProvisioningState {
	if state == "" {
		return ProvisioningStateActive
	}
	return state
}

func scanNetwork(row pgx.Row) (Network, error) {
	var network Network
	err := row.Scan(&network.Meta.ID, &network.OrganizationID, &network.Name, &network.Description, &network.ProvisioningState, &network.OpenZitiBindPolicyID, &network.Meta.CreatedAt, &network.Meta.UpdatedAt)
	return network, err
}

func scanTunnelCredential(row pgx.Row) (TunnelCredential, error) {
	var credential TunnelCredential
	err := row.Scan(&credential.Meta.ID, &credential.NetworkID, &credential.OrganizationID, &credential.OpenZitiIdentityID, &credential.EnrollmentJWTRevealed, &credential.EnrollmentJWTExpiresAt, &credential.EnrollmentState, &credential.Connectivity, &credential.ProvisioningState, &credential.EnrolledAt, &credential.LastSeenAt, &credential.Meta.CreatedAt, &credential.Meta.UpdatedAt)
	return credential, err
}

func scanPrivateResource(row pgx.Row) (PrivateResource, error) {
	var resource PrivateResource
	err := row.Scan(&resource.Meta.ID, &resource.OrganizationID, &resource.NetworkID, &resource.Name, &resource.Protocol, &resource.TargetHost, &resource.TargetPorts, &resource.InterceptHost, &resource.InterceptPorts, &resource.ProvisioningState, &resource.OpenZitiServiceID, &resource.Mediation, &resource.OpenZitiUpstreamServiceIDs, &resource.OpenZitiGatewayDialPolicyID, &resource.Meta.CreatedAt, &resource.Meta.UpdatedAt)
	return resource, err
}

func scanPrivateResourceAccess(row pgx.Row) (PrivateResourceAccess, error) {
	var access PrivateResourceAccess
	err := row.Scan(&access.Meta.ID, &access.PrivateResourceID, &access.OrganizationID, &access.NetworkID, &access.PrincipalType, &access.PrincipalID, &access.ProvisioningState, &access.OpenZitiDialPolicyID, &access.Meta.CreatedAt, &access.Meta.UpdatedAt)
	return access, err
}

type rowScanner[T any] func(pgx.Row) (T, error)

func scanRows[T any](rows pgx.Rows, scanner rowScanner[T]) ([]T, error) {
	values := []T{}
	for rows.Next() {
		value, err := scanner(rows)
		if err != nil {
			return nil, err
		}
		values = append(values, value)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return values, nil
}
