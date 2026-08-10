package store

import (
	"time"

	"github.com/google/uuid"
)

type EntityMeta struct {
	ID        uuid.UUID
	CreatedAt time.Time
	UpdatedAt time.Time
}

type ProvisioningState string

const (
	ProvisioningStateActive   ProvisioningState = "active"
	ProvisioningStateFailed   ProvisioningState = "failed"
	ProvisioningStateRemoving ProvisioningState = "removing"
)

type TunnelEnrollmentState string

const (
	TunnelEnrollmentStatePending  TunnelEnrollmentState = "pending"
	TunnelEnrollmentStateEnrolled TunnelEnrollmentState = "enrolled"
)

type TunnelConnectivity string

const (
	TunnelConnectivityOnline  TunnelConnectivity = "online"
	TunnelConnectivityOffline TunnelConnectivity = "offline"
)

type PrivateResourceProtocol string

const (
	PrivateResourceProtocolTCP   PrivateResourceProtocol = "tcp"
	PrivateResourceProtocolHTTP  PrivateResourceProtocol = "http"
	PrivateResourceProtocolHTTPS PrivateResourceProtocol = "https"
)

type PrincipalType string

const (
	PrincipalTypeAgent PrincipalType = "agent"
	PrincipalTypeUser  PrincipalType = "user"
	PrincipalTypeApp   PrincipalType = "app"
	PrincipalTypeGroup PrincipalType = "group"
	// An Environment, not an identity: it resolves to every workload running
	// it, which is the only handle that reaches a sandbox.
	PrincipalTypeEnvironment PrincipalType = "environment"
)

type Network struct {
	Meta                 EntityMeta
	OrganizationID       uuid.UUID
	Name                 string
	Description          string
	ProvisioningState    ProvisioningState
	OpenZitiBindPolicyID string
}

type TunnelCredential struct {
	Meta                   EntityMeta
	NetworkID              uuid.UUID
	OrganizationID         uuid.UUID
	OpenZitiIdentityID     string
	EnrollmentJWTRevealed  bool
	EnrollmentJWTExpiresAt *time.Time
	EnrollmentState        TunnelEnrollmentState
	Connectivity           TunnelConnectivity
	ProvisioningState      ProvisioningState
	EnrolledAt             *time.Time
	LastSeenAt             *time.Time
}

type PrivateResource struct {
	Meta              EntityMeta
	OrganizationID    uuid.UUID
	NetworkID         uuid.UUID
	Name              string
	Protocol          PrivateResourceProtocol
	TargetHost        string
	TargetPorts       []int32
	InterceptHost     string
	InterceptPorts    []int32
	ProvisioningState ProvisioningState
	OpenZitiServiceID string
}

type PrivateResourceAccess struct {
	Meta                 EntityMeta
	PrivateResourceID    uuid.UUID
	OrganizationID       uuid.UUID
	NetworkID            uuid.UUID
	PrincipalType        PrincipalType
	PrincipalID          uuid.UUID
	ProvisioningState    ProvisioningState
	OpenZitiDialPolicyID string
}

type CreateNetworkInput struct {
	ID                   uuid.UUID
	OrganizationID       uuid.UUID
	Name                 string
	Description          string
	ProvisioningState    ProvisioningState
	OpenZitiBindPolicyID string
}

type UpdateNetworkInput struct {
	ID          uuid.UUID
	Name        *string
	Description *string
}

type CreateTunnelCredentialInput struct {
	ID                     uuid.UUID
	NetworkID              uuid.UUID
	OpenZitiIdentityID     string
	EnrollmentJWTRevealed  bool
	EnrollmentJWTExpiresAt *time.Time
	ProvisioningState      ProvisioningState
}

type CreatePrivateResourceInput struct {
	ID                uuid.UUID
	OrganizationID    uuid.UUID
	NetworkID         uuid.UUID
	Name              string
	Protocol          PrivateResourceProtocol
	TargetHost        string
	TargetPorts       []int32
	InterceptHost     string
	InterceptPorts    []int32
	ProvisioningState ProvisioningState
	OpenZitiServiceID string
}

type UpdatePrivateResourceInput struct {
	ID             uuid.UUID
	Name           *string
	Protocol       *PrivateResourceProtocol
	TargetHost     *string
	TargetPorts    []int32
	InterceptHost  *string
	InterceptPorts []int32
	UpdatePorts    bool
}

type CreatePrivateResourceAccessInput struct {
	ID                   uuid.UUID
	PrivateResourceID    uuid.UUID
	PrincipalType        PrincipalType
	PrincipalID          uuid.UUID
	ProvisioningState    ProvisioningState
	OpenZitiDialPolicyID string
}

type ListPrivateResourcesFilter struct {
	OrganizationID *uuid.UUID
	NetworkID      *uuid.UUID
}

type ListPrivateResourceAccessFilter struct {
	PrivateResourceID *uuid.UUID
	NetworkID         *uuid.UUID
	PrincipalType     *PrincipalType
	PrincipalID       *uuid.UUID
}

type ListTunnelCredentialsFilter struct {
	NetworkID *uuid.UUID
}

type ListPrivateResourcesFilterAll struct {
	NetworkID *uuid.UUID
}

type ListPrivateResourceAccessFilterAll struct {
	PrivateResourceID *uuid.UUID
	NetworkID         *uuid.UUID
}

type UpdateTunnelCredentialLivenessInput struct {
	ID              uuid.UUID
	EnrollmentState TunnelEnrollmentState
	Connectivity    TunnelConnectivity
	EnrolledAt      *time.Time
	LastSeenAt      *time.Time
}
