// Package natsbus publishes Aegis domain events to NATS JetStream.
package natsbus

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

// Stream is the JetStream stream that stores Aegis events.
const Stream = "AEGIS_EVENTS"

// Bus is a connected JetStream publisher.
type Bus struct {
	nc *nats.Conn
	js jetstream.JetStream
}

// Credentials authenticate to NATS (empty user: no authentication).
type Credentials struct {
	User     string
	Password string
}

// Connect dials NATS and ensures the event stream exists. Duplicate message
// IDs are dropped by the server for two minutes, which covers relay retries.
func Connect(ctx context.Context, url, name string, creds Credentials) (*Bus, error) {
	opts := []nats.Option{nats.Name(name), nats.MaxReconnects(-1), nats.ReconnectWait(2 * time.Second)}
	if creds.User != "" {
		opts = append(opts, nats.UserInfo(creds.User, creds.Password))
	}
	nc, err := nats.Connect(url, opts...)
	if err != nil {
		return nil, fmt.Errorf("nats connect: %w", err)
	}
	js, err := jetstream.New(nc)
	if err != nil {
		nc.Close()
		return nil, err
	}
	if _, err := js.CreateOrUpdateStream(ctx, jetstream.StreamConfig{
		Name: Stream, Subjects: []string{"aegis.>"}, Storage: jetstream.FileStorage,
		Duplicates: 2 * time.Minute, MaxAge: 7 * 24 * time.Hour,
	}); err != nil {
		nc.Close()
		return nil, fmt.Errorf("ensure stream: %w", err)
	}
	return &Bus{nc: nc, js: js}, nil
}

// Publish sends data and waits for the stream's acknowledgement.
func (b *Bus) Publish(ctx context.Context, subject, msgID string, data []byte) error {
	pctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	_, err := b.js.Publish(pctx, subject, data, jetstream.WithMsgID(msgID))
	if err != nil && ctx.Err() == nil && (b.nc.Status() != nats.CONNECTED || errors.Is(err, context.DeadlineExceeded) ||
		errors.Is(err, nats.ErrNoResponders) || errors.Is(err, nats.ErrTimeout) || errors.Is(err, nats.ErrConnectionClosed) ||
		errors.Is(err, jetstream.ErrNoStreamResponse)) {
		return unavailableError{err}
	}
	return err
}

// unavailableError marks a failure of the broker rather than of the message
// (disconnected, no stream responding, timeout). The outbox relay retries
// these without counting them toward parking.
type unavailableError struct{ err error }

func (e unavailableError) Error() string   { return "broker unavailable: " + e.err.Error() }
func (e unavailableError) Unwrap() error   { return e.err }
func (e unavailableError) Transient() bool { return true }

// JetStream exposes the context for consumers (tests, tools).
func (b *Bus) JetStream() jetstream.JetStream { return b.js }

// Close drains the connection.
func (b *Bus) Close() { _ = b.nc.Drain() }
