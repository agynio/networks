package server

import (
	"context"
	"time"

	groupsv1 "github.com/agynio/networks/.gen/go/agynio/api/groups/v1"
	"github.com/google/uuid"
	"github.com/nats-io/nats.go"
	"google.golang.org/protobuf/proto"
)

const (
	groupsDeletedSubject = "agyn.groups.group.deleted"
	natsHeaderMessageID  = "Nats-Msg-Id"
	natsHeaderSource     = "Agyn-Source"
)

type EventPublisher = eventPublisher
type NATSConn = *nats.Conn

type NATSPublisher struct{ jetStream nats.JetStreamContext }

func ConnectNATS(url string) (*nats.Conn, error) { return nats.Connect(url) }

func NewNATSPublisher(conn *nats.Conn) (*NATSPublisher, error) {
	jetStream, err := conn.JetStream()
	if err != nil {
		return nil, err
	}
	return &NATSPublisher{jetStream: jetStream}, nil
}

func (p *NATSPublisher) Publish(_ context.Context, subject string, messageID string, payload []byte) error {
	message := nats.NewMsg(subject)
	message.Data = payload
	message.Header.Set(natsHeaderMessageID, messageID)
	message.Header.Set(natsHeaderSource, networksEventSource)
	_, err := p.jetStream.PublishMsg(message)
	return err
}

func (s *Server) SubscribeGroupDeleted(ctx context.Context, conn *nats.Conn) (*nats.Subscription, error) {
	jetStream, err := conn.JetStream()
	if err != nil {
		return nil, err
	}
	return jetStream.Subscribe(groupsDeletedSubject, func(message *nats.Msg) {
		event := &groupsv1.GroupDeletedEvent{}
		if err := proto.Unmarshal(message.Data, event); err != nil {
			return
		}
		if err := s.HandleGroupDeleted(ctx, event); err != nil {
			return
		}
		_ = message.Ack()
	}, nats.Durable("networks-group-deleted"), nats.ManualAck())
}

func eventMessageID(prefix string) string {
	return prefix + "-" + uuid.NewString() + "-" + time.Now().UTC().Format("20060102150405")
}
