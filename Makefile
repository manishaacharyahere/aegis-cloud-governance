# Aegis developer commands. On Windows without make, run the commands
# shown in docs/getting-started.md directly.

OPA_IMAGE := openpolicyagent/opa:1.0.0-static

.PHONY: help up down logs test test-go test-web test-ml test-policies lint build

help:
	@grep -E '^[a-z-]+:' Makefile | cut -d: -f1

up:            ## start core services (postgres, nats, opa, api)
	docker compose --profile core up -d --build

down:
	docker compose --profile core down

logs:
	docker compose --profile core logs -f api

test: test-go test-web test-ml test-policies

test-go:
	go vet ./...
	go test -count=1 ./...

test-web:
	cd apps/web && npm run typecheck && npm run lint && npm test

test-ml:
	cd ml && python -m pytest && ruff check .

test-policies:
	docker run --rm -v "$(CURDIR)/policies:/policies:ro" $(OPA_IMAGE) test -v /policies

build:
	go build -o bin/aegis-api ./cmd/aegis-api
	cd apps/web && npm run build
