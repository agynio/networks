package server

import (
	"context"
	"errors"
	"fmt"
	"strings"

	networksv1 "github.com/agynio/networks/.gen/go/agynio/api/networks/v1"
	"github.com/agynio/networks/internal/store"
	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type Store interface {
	CreateNetwork(context.Context, store.CreateNetworkInput) (store.Network, error)
	GetNetwork(context.Context, uuid.UUID) (store.Network, error)
	ListNetworks(context.Context, uuid.UUID, int32, *store.PageCursor) ([]store.Network, *store.PageCursor, error)
	UpdateNetwork(context.Context, store.UpdateNetworkInput) (store.Network, error)
	DeleteNetwork(context.Context, uuid.UUID) error
}

type Server struct{ store Store }

func New(store Store) *Server { return &Server{store: store} }

func (s *Server) CreateNetwork(ctx context.Context, request *networksv1.CreateNetworkRequest) (*networksv1.CreateNetworkResponse, error) {
	organizationID, err := uuid.Parse(request.GetOrganizationId())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "organization_id must be a uuid")
	}
	name := strings.TrimSpace(request.GetName())
	if err := validateName(name); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid name: %v", err)
	}
	network, err := s.store.CreateNetwork(ctx, store.CreateNetworkInput{
		ID:             uuid.New(),
		OrganizationID: organizationID,
		Name:           name,
		Description:    request.GetDescription(),
	})
	if err != nil {
		return nil, toStatus(err)
	}
	return &networksv1.CreateNetworkResponse{Network: convertNetwork(network)}, nil
}

func (s *Server) GetNetwork(ctx context.Context, request *networksv1.GetNetworkRequest) (*networksv1.GetNetworkResponse, error) {
	id, err := uuid.Parse(request.GetId())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "id must be a uuid")
	}
	network, err := s.store.GetNetwork(ctx, id)
	if err != nil {
		return nil, toStatus(err)
	}
	return &networksv1.GetNetworkResponse{Network: convertNetwork(network)}, nil
}

func (s *Server) ListNetworks(ctx context.Context, request *networksv1.ListNetworksRequest) (*networksv1.ListNetworksResponse, error) {
	organizationID, err := uuid.Parse(request.GetOrganizationId())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "organization_id must be a uuid")
	}
	var cursor *store.PageCursor
	if token := request.GetPageToken(); token != "" {
		afterID, err := store.DecodePageToken(token)
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "invalid page_token")
		}
		cursor = &store.PageCursor{AfterID: afterID}
	}
	networks, nextCursor, err := s.store.ListNetworks(ctx, organizationID, request.GetPageSize(), cursor)
	if err != nil {
		return nil, toStatus(err)
	}
	response := &networksv1.ListNetworksResponse{Networks: make([]*networksv1.Network, 0, len(networks))}
	for _, network := range networks {
		response.Networks = append(response.Networks, convertNetwork(network))
	}
	if nextCursor != nil {
		response.NextPageToken = store.EncodePageToken(nextCursor.AfterID)
	}
	return response, nil
}

func (s *Server) UpdateNetwork(ctx context.Context, request *networksv1.UpdateNetworkRequest) (*networksv1.UpdateNetworkResponse, error) {
	id, err := uuid.Parse(request.GetId())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "id must be a uuid")
	}
	input := store.UpdateNetworkInput{ID: id}
	if request.Name != nil {
		name := strings.TrimSpace(request.GetName())
		if err := validateName(name); err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "invalid name: %v", err)
		}
		input.Name = &name
	}
	if request.Description != nil {
		description := request.GetDescription()
		input.Description = &description
	}
	network, err := s.store.UpdateNetwork(ctx, input)
	if err != nil {
		return nil, toStatus(err)
	}
	return &networksv1.UpdateNetworkResponse{Network: convertNetwork(network)}, nil
}

func (s *Server) DeleteNetwork(ctx context.Context, request *networksv1.DeleteNetworkRequest) (*networksv1.DeleteNetworkResponse, error) {
	id, err := uuid.Parse(request.GetId())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "id must be a uuid")
	}
	if err := s.store.DeleteNetwork(ctx, id); err != nil {
		return nil, toStatus(err)
	}
	return &networksv1.DeleteNetworkResponse{}, nil
}

func (s *Server) CreateTunnelCredential(context.Context, *networksv1.CreateTunnelCredentialRequest) (*networksv1.CreateTunnelCredentialResponse, error) {
	return nil, status.Error(codes.Unimplemented, "tunnel credential provisioning is not implemented in this slice")
}

func (s *Server) GetTunnelCredential(context.Context, *networksv1.GetTunnelCredentialRequest) (*networksv1.GetTunnelCredentialResponse, error) {
	return nil, status.Error(codes.Unimplemented, "tunnel credential reads are not implemented in this slice")
}

func (s *Server) ListTunnelCredentials(context.Context, *networksv1.ListTunnelCredentialsRequest) (*networksv1.ListTunnelCredentialsResponse, error) {
	return nil, status.Error(codes.Unimplemented, "tunnel credential listing is not implemented in this slice")
}

func (s *Server) DeleteTunnelCredential(context.Context, *networksv1.DeleteTunnelCredentialRequest) (*networksv1.DeleteTunnelCredentialResponse, error) {
	return nil, status.Error(codes.Unimplemented, "tunnel credential deletion is not implemented in this slice")
}

func (s *Server) CreatePrivateResource(context.Context, *networksv1.CreatePrivateResourceRequest) (*networksv1.CreatePrivateResourceResponse, error) {
	return nil, status.Error(codes.Unimplemented, "private resource provisioning is not implemented in this slice")
}

func (s *Server) GetPrivateResource(context.Context, *networksv1.GetPrivateResourceRequest) (*networksv1.GetPrivateResourceResponse, error) {
	return nil, status.Error(codes.Unimplemented, "private resource reads are not implemented in this slice")
}

func (s *Server) ListPrivateResources(context.Context, *networksv1.ListPrivateResourcesRequest) (*networksv1.ListPrivateResourcesResponse, error) {
	return nil, status.Error(codes.Unimplemented, "private resource listing is not implemented in this slice")
}

func (s *Server) UpdatePrivateResource(context.Context, *networksv1.UpdatePrivateResourceRequest) (*networksv1.UpdatePrivateResourceResponse, error) {
	return nil, status.Error(codes.Unimplemented, "private resource updates are not implemented in this slice")
}

func (s *Server) DeletePrivateResource(context.Context, *networksv1.DeletePrivateResourceRequest) (*networksv1.DeletePrivateResourceResponse, error) {
	return nil, status.Error(codes.Unimplemented, "private resource deletion is not implemented in this slice")
}

func (s *Server) CreatePrivateResourceAccess(context.Context, *networksv1.CreatePrivateResourceAccessRequest) (*networksv1.CreatePrivateResourceAccessResponse, error) {
	return nil, status.Error(codes.Unimplemented, "private resource access provisioning is not implemented in this slice")
}

func (s *Server) DeletePrivateResourceAccess(context.Context, *networksv1.DeletePrivateResourceAccessRequest) (*networksv1.DeletePrivateResourceAccessResponse, error) {
	return nil, status.Error(codes.Unimplemented, "private resource access deletion is not implemented in this slice")
}

func (s *Server) ListPrivateResourceAccess(context.Context, *networksv1.ListPrivateResourceAccessRequest) (*networksv1.ListPrivateResourceAccessResponse, error) {
	return nil, status.Error(codes.Unimplemented, "private resource access listing is not implemented in this slice")
}

func convertNetwork(network store.Network) *networksv1.Network {
	return &networksv1.Network{
		Meta: &networksv1.EntityMeta{
			Id:        network.Meta.ID.String(),
			CreatedAt: timestamppb.New(network.Meta.CreatedAt),
			UpdatedAt: timestamppb.New(network.Meta.UpdatedAt),
		},
		OrganizationId:    network.OrganizationID.String(),
		Name:              network.Name,
		Description:       network.Description,
		ProvisioningState: convertProvisioningState(network.ProvisioningState),
	}
}

func convertProvisioningState(state store.ProvisioningState) networksv1.ProvisioningState {
	switch state {
	case store.ProvisioningStateActive:
		return networksv1.ProvisioningState_PROVISIONING_STATE_ACTIVE
	case store.ProvisioningStateFailed:
		return networksv1.ProvisioningState_PROVISIONING_STATE_FAILED
	case store.ProvisioningStateRemoving:
		return networksv1.ProvisioningState_PROVISIONING_STATE_REMOVING
	default:
		panic(fmt.Sprintf("unexpected provisioning state: %q", state))
	}
}

func toStatus(err error) error {
	var notFound *store.NotFoundError
	if errors.As(err, &notFound) {
		return status.Error(codes.NotFound, notFound.Error())
	}
	var alreadyExists *store.AlreadyExistsError
	if errors.As(err, &alreadyExists) {
		return status.Error(codes.AlreadyExists, alreadyExists.Error())
	}
	return status.Error(codes.Internal, err.Error())
}
