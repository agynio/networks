package server

import (
	"context"
	"log"
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
		s.handleGroupDeletedMessage(ctx, message.Data, message.Ack, message.Nak, message.Term)
	}, nats.Durable("networks-group-deleted"), nats.ManualAck())
}

func (s *Server) handleGroupDeletedMessage(ctx context.Context, payload []byte, ack func(...nats.AckOpt) error, nak func(...nats.AckOpt) error, term func(...nats.AckOpt) error) {
	event := &groupsv1.GroupDeletedEvent{}
	if err := proto.Unmarshal(payload, event); err != nil {
		log.Printf("decode %s event failed: %v", groupsDeletedSubject, err)
		if ackErr := term(); ackErr != nil {
			log.Printf("term malformed %s event failed: %v", groupsDeletedSubject, ackErr)
		}
		return
	}
	if event.GetGroupId() == "" {
		log.Printf("decode %s event failed: missing group_id", groupsDeletedSubject)
		if ackErr := term(); ackErr != nil {
			log.Printf("term malformed %s event failed: %v", groupsDeletedSubject, ackErr)
		}
		return
	}
	if err := s.HandleGroupDeleted(ctx, event); err != nil {
		log.Printf("handle %s event failed: %v", groupsDeletedSubject, err)
		if ackErr := nak(); ackErr != nil {
			log.Printf("nak %s event failed: %v", groupsDeletedSubject, ackErr)
		}
		return
	}
	if err := ack(); err != nil {
		log.Printf("ack %s event failed: %v", groupsDeletedSubject, err)
	}
}

func eventMessageID(prefix string) string {
	return prefix + "-" + uuid.NewString() + "-" + time.Now().UTC().Format("20060102150405")
}
