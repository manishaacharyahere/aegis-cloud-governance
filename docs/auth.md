# Authentication and authorization

## Model

- **Authentication (who):** OIDC ID tokens from any compliant identity provider,
  sent as `Authorization: Bearer <token>`. The API checks:
  - the signature, against the provider's published keys (JWKS);
  - the issuer;
  - the audience (`AEGIS_OIDC_CLIENT_ID`);
  - expiry.

  It accepts RS256, ES256 and EdDSA signatures, and never `none`. The identity is the
  verified email address (lower-cased), or `sub:<subject>` when the email is
  missing or unverified.
- **Authorization (what):** role bindings stored in Aegis, per tenant
  (`role_bindings`). The identity provider proves identity; Aegis decides
  permissions, so no provider-specific group claims are needed.
- **Tenant:** the tenant is still chosen with `X-Aegis-Tenant`. It grants nothing
  by itself: the caller must hold a role in that tenant. An unknown tenant and
  a tenant where the caller has no role return the same `403`, so tenants
  cannot be enumerated.

| Role | Permissions |
|---|---|
| viewer | read |
| analyst | read, operate (imports, scans, evaluations, drift comparison, risk assessment, cost import, recommendations, investigations, propose remediations, request exceptions) |
| approver | read, approve (decide exceptions and remediations, approve drift baselines, release remediations) |
| admin | everything, plus managing role bindings |

Analysts cannot approve and approvers cannot propose. Separation of duties
also holds within a role: nobody can approve their own exception or
remediation, because the recorded actor is now the token's identity.

Every route's permission is listed in one table, `routePermissions` in
[`services/api/auth.go`](../services/api/auth.go). The router refuses to
start if a route is missing from it, and a test fails on stale entries.

## Modes

| `AEGIS_AUTH_MODE` | Use |
|---|---|
| `oidc` | Default in production. Requires `AEGIS_OIDC_ISSUER` (https in production) and `AEGIS_OIDC_CLIENT_ID`. |
| `dev-headers` | Development and tests only: `X-Aegis-Actor` is trusted and every caller has every permission. Refused when `AEGIS_ENV=production`, and logged as a warning at start-up. |

`AEGIS_BOOTSTRAP_ADMINS=a@example.com,b@example.com` grants `admin` in the
bootstrap tenant at start-up (idempotent, audited as `system:bootstrap`), so a
new installation is not locked out. The last admin of a tenant cannot be
removed.

## Endpoints

| Method | Path | Permission |
|---|---|---|
| GET | `/api/v1/me` | any signed-in caller; includes roles in `X-Aegis-Tenant` |
| GET | `/api/v1/me/tenants` | any signed-in caller; the tenants they hold a role in (every tenant in development header mode) |
| GET | `/api/v1/access/bindings` | admin |
| POST / DELETE | `/api/v1/access/bindings` with `{"subject": "...", "role": "..."}` | admin |

## Local identity provider (Dex)

```bash
# .env: AEGIS_AUTH_MODE=oidc  AEGIS_BOOTSTRAP_ADMINS=admin@aegis.local
docker compose --profile core --profile auth up -d
TOKEN=$(scripts/dev-token.sh admin@aegis.local)
curl -H "Authorization: Bearer $TOKEN" -H "X-Aegis-Tenant: demo" http://127.0.0.1:8080/api/v1/me
```

[`infrastructure/auth/dex.yml`](../infrastructure/auth/dex.yml) defines demo
users `admin`, `alice`, `bob`, `carol` and `viewer` `@aegis.local`, all with
the **development-only** password `aegis-dev-only`. It enables the password
grant so scripts can obtain tokens. The issuer `http://dex.localhost:5556/dex`
resolves to 127.0.0.1 in browsers and to the Dex container inside Compose,
so the browser and the API agree on the issuer.

### Running the API from source with Dex

The issuer host `dex.localhost` resolves in browsers and inside Compose, but
not always for programs on the host (Go on Windows, for example). When running
`go run ./cmd/aegis-api` on the host, add `127.0.0.1 dex.localhost` to the hosts
file (`C:\Windows\System32\drivers\etc\hosts` or `/etc/hosts`). Otherwise
every request is refused with `identity_provider_unavailable`.

Dex keeps its signing keys, sessions and refresh tokens in PostgreSQL
(database `dex`), so sign-ins survive a Dex restart. (SQLite was tried first;
it deadlocked on the first refresh-token grant.) `docker compose down -v`
resets everything.

## Verified

The following was run against the running stack with real Dex tokens:

| Request | Result |
|---|---|
| `/me` as the admin | roles `["admin"]` |
| No token, or an altered token | `401` |
| Grant analyst, approver and viewer | `204` |
| Viewer reads resources | `200` |
| Viewer creates an investigation | `403` |
| Analyst creates an investigation while sending `X-Aegis-Actor: admin@aegis.local` | stored with actor `alice@aegis.local` |
| Analyst in another tenant | `403` |
| Removing the last admin | `409` |

The automated tests cover the following:

- **Token verification** against a fake provider that signs real JWTs: valid,
  expired, wrong audience, wrong issuer, wrong key, `alg=none`, and unverified email.
- **Provider outage:** verification fails closed, then recovers once the provider is back.
- **Role enforcement** for every role on representative routes, and a stale-entry check on the permission table.
- **Role bindings** against PostgreSQL: idempotent bootstrap, tenant isolation,
  last-admin protection, and audit events.

## Limitations

- Tokens are verified on every request, but there is no revocation list: a token
  stays valid until it expires (Dex issues 1-hour ID tokens).
- Role lookups query PostgreSQL on each request; there is no cache yet.
- The IaC worker and ML worker are not callers of the API, so they are unaffected.
