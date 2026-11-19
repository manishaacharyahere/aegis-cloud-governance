package natsbus

import (
	"errors"
	"fmt"
	"testing"

	"github.com/nats-io/nats.go"
)

// The outbox relay recognises a broker outage only through this method
// (services/outbox: interface{ Transient() bool }). Renaming it would make
// every outage count toward parking again, so the contract is checked here.
var _ interface{ Transient() bool } = unavailableError{}

func TestUnavailableErrorIsTransientThroughWrapping(t *testing.T) {
	err := fmt.Errorf("publish: %w", unavailableError{nats.ErrNoResponders})
	var tr interface{ Transient() bool }
	if !errors.As(err, &tr) || !tr.Transient() {
		t.Fatal("a wrapped outage is not recognised as transient")
	}
	if !errors.Is(err, nats.ErrNoResponders) {
		t.Fatal("the cause is lost")
	}
}
