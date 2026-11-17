package inventory

import (
	"context"
	"time"
)

// Service is the inventory module's entry point: validate → normalise → persist.
type Service struct {
	store *Store
	now   func() time.Time
}

// NewService returns a Service using store and the real clock.
func NewService(store *Store) *Service {
	return &Service{store: store, now: time.Now}
}

// Import validates, normalises and persists a snapshot.
func (s *Service) Import(ctx context.Context, tenant string, snap Snapshot) (ImportReport, error) {
	if err := Validate(snap, s.now()); err != nil {
		return ImportReport{}, err
	}
	return s.store.Import(ctx, tenant, Normalize(snap))
}

func (s *Service) GetImport(ctx context.Context, tenant, id string) (ImportReport, error) {
	return s.store.GetImport(ctx, tenant, id)
}

func (s *Service) ListResources(ctx context.Context, tenant string, f ListFilter) (ResourcePage, error) {
	return s.store.ListResources(ctx, tenant, f)
}

func (s *Service) GetResource(ctx context.Context, tenant, id string) (ResourceDetail, error) {
	return s.store.GetResource(ctx, tenant, id)
}

// ListAccounts lists the tenant's cloud accounts.
func (s *Service) ListAccounts(ctx context.Context, tenant string) ([]AccountView, error) {
	return s.store.ListAccounts(ctx, tenant)
}

// ResourceTypes lists the tenant's live resource types with counts.
func (s *Service) ResourceTypes(ctx context.Context, tenant string) ([]TypeCount, error) {
	return s.store.ResourceTypes(ctx, tenant)
}
