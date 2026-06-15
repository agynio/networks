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
	accessGrantedSubject     = "agyn.networks.private_resource_access.granted"
	accessRevokedSubject     = "agyn.networks.private_resource_access.revoked"
	networksNotificationRoom = "org-%s"
)

func (s *Server) publishAccessGranted(ctx context.Context, access store.PrivateResourceAccess) {
	event := &networksv1.PrivateResourceAccessGrantedEvent{
		PrivateResourceAccessId: access.Meta.ID.String(),
		PrivateResourceId:       access.PrivateResourceID.String(),
		PrincipalType:           convertPrincipalType(access.PrincipalType),
		PrincipalId:             access.PrincipalID.String(),
	}
	s.publishProtoEvent(ctx, accessGrantedSubject, eventMessageID(accessGrantedSubject+"-"+access.Meta.ID.String()), event)
	s.publishNotification(ctx, access.OrganizationID, accessGrantedSubject, map[string]any{
		"private_resource_access_id": access.Meta.ID.String(),
		"private_resource_id":        access.PrivateResourceID.String(),
		"principal_type":             string(access.PrincipalType),
		"principal_id":               access.PrincipalID.String(),
	})
}

func (s *Server) publishAccessRevoked(ctx context.Context, access store.PrivateResourceAccess) {
	event := &networksv1.PrivateResourceAccessRevokedEvent{
		PrivateResourceAccessId: access.Meta.ID.String(),
		PrivateResourceId:       access.PrivateResourceID.String(),
		PrincipalType:           convertPrincipalType(access.PrincipalType),
		PrincipalId:             access.PrincipalID.String(),
	}
	s.publishProtoEvent(ctx, accessRevokedSubject, eventMessageID(accessRevokedSubject+"-"+access.Meta.ID.String()), event)
	s.publishNotification(ctx, access.OrganizationID, accessRevokedSubject, map[string]any{
		"private_resource_access_id": access.Meta.ID.String(),
		"private_resource_id":        access.PrivateResourceID.String(),
		"principal_type":             string(access.PrincipalType),
		"principal_id":               access.PrincipalID.String(),
	})
}

func (s *Server) publishTunnelConnectivity(ctx context.Context, credential store.TunnelCredential) {
	if credential.Connectivity == store.TunnelConnectivityOnline {
		event := &networksv1.TunnelOnlineEvent{TunnelCredentialId: credential.Meta.ID.String(), NetworkId: credential.NetworkID.String()}
		s.publishProtoEvent(ctx, tunnelOnlineSubject, eventMessageID(tunnelOnlineSubject+"-"+credential.Meta.ID.String()), event)
		s.publishNotification(ctx, credential.OrganizationID, tunnelOnlineSubject, map[string]any{"tunnel_credential_id": credential.Meta.ID.String(), "network_id": credential.NetworkID.String()})
		return
	}
	event := &networksv1.TunnelOfflineEvent{TunnelCredentialId: credential.Meta.ID.String(), NetworkId: credential.NetworkID.String()}
	s.publishProtoEvent(ctx, tunnelOfflineSubject, eventMessageID(tunnelOfflineSubject+"-"+credential.Meta.ID.String()), event)
	s.publishNotification(ctx, credential.OrganizationID, tunnelOfflineSubject, map[string]any{"tunnel_credential_id": credential.Meta.ID.String(), "network_id": credential.NetworkID.String()})
}

func (s *Server) publishProtoEvent(ctx context.Context, subject string, messageID string, message proto.Message) {
	if s.eventPublisher == nil {
		return
	}
	payload, err := proto.Marshal(message)
	if err != nil {
		panic(fmt.Sprintf("marshal %s: %v", subject, err))
	}
	if err := s.eventPublisher.Publish(ctx, subject, messageID, payload); err != nil {
		log.Printf("publish %s failed: %v", subject, err)
	}
}

func (s *Server) publishNotification(ctx context.Context, organizationID fmt.Stringer, event string, payload map[string]any) {
	if s.notificationsClient == nil {
		return
	}
	structPayload, err := structpb.NewStruct(payload)
	if err != nil {
		panic(fmt.Sprintf("notification payload %s: %v", event, err))
	}
	_, err = s.notificationsClient.Publish(ctx, &notificationsv1.PublishRequest{
		Event:   event,
		Rooms:   []string{fmt.Sprintf(networksNotificationRoom, organizationID.String())},
		Payload: structPayload,
		Source:  networksEventSource,
	})
	if err != nil {
		log.Printf("publish notification %s failed: %v", event, err)
	}
}
