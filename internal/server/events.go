package server

import (
	"context"
	"fmt"
	"log"

	networksv1 "github.com/agynio/networks/.gen/go/agynio/api/networks/v1"
	notificationsv1 "github.com/agynio/networks/.gen/go/agynio/api/notifications/v1"
	"github.com/agynio/networks/internal/store"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
)

const (
	networksEventSource = "networks"

	tunnelOnlineSubject      = "agyn.networks.tunnel.online"
	tunnelOfflineSubject     = "agyn.networks.tunnel.offline"
	accessGrantedSubject     = "agyn.networks.access.granted"
	accessRevokedSubject     = "agyn.networks.access.revoked"
	networksNotificationRoom = "org-%s"
	// Flat, not organization-keyed: the Egress Gateway caches private-target
	// rules with the resource's fields denormalized and cannot enumerate the
	// organizations it serves.
	privateResourcesNotificationRoom = "private_resources"

	networkUpdatedNotification               = "network.updated"
	tunnelCredentialUpdatedNotification      = "tunnel_credential.updated"
	tunnelStatusChangedNotification          = "tunnel_status.changed"
	privateResourceUpdatedNotification       = "private_resource.updated"
	privateResourceAccessUpdatedNotification = "private_resource_access.updated"
)

func (s *Server) publishNetworkUpdated(ctx context.Context, network store.Network) {
	s.publishNotification(ctx, network.OrganizationID, networkUpdatedNotification, map[string]any{
		"network_id": network.Meta.ID.String(),
	})
}

func (s *Server) publishTunnelCredentialUpdated(ctx context.Context, credential store.TunnelCredential) {
	s.publishNotification(ctx, credential.OrganizationID, tunnelCredentialUpdatedNotification, map[string]any{
		"tunnel_credential_id": credential.Meta.ID.String(),
		"network_id":           credential.NetworkID.String(),
	})
}

func (s *Server) publishPrivateResourceUpdated(ctx context.Context, resource store.PrivateResource) {
	s.publishNotificationRooms(ctx,
		[]string{fmt.Sprintf(networksNotificationRoom, resource.OrganizationID.String()), privateResourcesNotificationRoom},
		privateResourceUpdatedNotification, map[string]any{
			"private_resource_id": resource.Meta.ID.String(),
			"network_id":          resource.NetworkID.String(),
		})
}

func (s *Server) publishAccessGranted(ctx context.Context, access store.PrivateResourceAccess) error {
	event := &networksv1.PrivateResourceAccessGrantedEvent{
		PrivateResourceAccessId: access.Meta.ID.String(),
		PrivateResourceId:       access.PrivateResourceID.String(),
		PrincipalType:           convertPrincipalType(access.PrincipalType),
		PrincipalId:             access.PrincipalID.String(),
	}
	if err := s.publishProtoEvent(ctx, accessGrantedSubject, newEventEnvelope(access.Meta.CreatedAt, event), event); err != nil {
		return err
	}
	s.publishPrivateResourceAccessUpdated(ctx, access)
	return nil
}

func (s *Server) publishAccessRevoked(ctx context.Context, access store.PrivateResourceAccess) error {
	event := &networksv1.PrivateResourceAccessRevokedEvent{
		PrivateResourceAccessId: access.Meta.ID.String(),
		PrivateResourceId:       access.PrivateResourceID.String(),
		PrincipalType:           convertPrincipalType(access.PrincipalType),
		PrincipalId:             access.PrincipalID.String(),
	}
	if err := s.publishProtoEvent(ctx, accessRevokedSubject, newEventEnvelope(s.now(), event), event); err != nil {
		return err
	}
	s.publishPrivateResourceAccessUpdated(ctx, access)
	return nil
}

func (s *Server) publishPrivateResourceAccessUpdated(ctx context.Context, access store.PrivateResourceAccess) {
	s.publishNotification(ctx, access.OrganizationID, privateResourceAccessUpdatedNotification, map[string]any{
		"private_resource_access_id": access.Meta.ID.String(),
		"private_resource_id":        access.PrivateResourceID.String(),
		"principal_type":             string(access.PrincipalType),
		"principal_id":               access.PrincipalID.String(),
	})
}

func (s *Server) publishTunnelConnectivity(ctx context.Context, credential store.TunnelCredential) {
	if credential.Connectivity == store.TunnelConnectivityOnline {
		event := &networksv1.TunnelOnlineEvent{TunnelCredentialId: credential.Meta.ID.String(), NetworkId: credential.NetworkID.String()}
		_ = s.publishProtoEvent(ctx, tunnelOnlineSubject, newEventEnvelope(s.now(), event), event)
		s.publishTunnelStatusChanged(ctx, credential)
		return
	}
	event := &networksv1.TunnelOfflineEvent{TunnelCredentialId: credential.Meta.ID.String(), NetworkId: credential.NetworkID.String()}
	_ = s.publishProtoEvent(ctx, tunnelOfflineSubject, newEventEnvelope(s.now(), event), event)
	s.publishTunnelStatusChanged(ctx, credential)
}

func (s *Server) publishTunnelStatusChanged(ctx context.Context, credential store.TunnelCredential) {
	s.publishNotification(ctx, credential.OrganizationID, tunnelStatusChangedNotification, map[string]any{
		"tunnel_credential_id": credential.Meta.ID.String(),
		"network_id":           credential.NetworkID.String(),
		"connectivity":         string(credential.Connectivity),
		"enrollment_state":     string(credential.EnrollmentState),
	})
}

func (s *Server) publishProtoEvent(ctx context.Context, subject string, envelope EventEnvelope, message proto.Message) error {
	if s.eventPublisher == nil {
		return nil
	}
	payload, err := proto.Marshal(message)
	if err != nil {
		panic(fmt.Sprintf("marshal %s: %v", subject, err))
	}
	if err := s.eventPublisher.Publish(ctx, subject, envelope, payload); err != nil {
		log.Printf("publish %s failed: %v", subject, err)
		return err
	}
	return nil
}

func (s *Server) publishNotification(ctx context.Context, organizationID fmt.Stringer, event string, payload map[string]any) {
	s.publishNotificationRooms(ctx, []string{fmt.Sprintf(networksNotificationRoom, organizationID.String())}, event, payload)
}

func (s *Server) publishNotificationRooms(ctx context.Context, rooms []string, event string, payload map[string]any) {
	if s.notificationsClient == nil {
		return
	}
	structPayload, err := structpb.NewStruct(payload)
	if err != nil {
		panic(fmt.Sprintf("notification payload %s: %v", event, err))
	}
	_, err = s.notificationsClient.Publish(ctx, &notificationsv1.PublishRequest{
		Event:   event,
		Rooms:   rooms,
		Payload: structPayload,
		Source:  networksEventSource,
	})
	if err != nil {
		log.Printf("publish notification %s failed: %v", event, err)
	}
}
