# Deploying Aegis

Aegis ships as four container images and one Helm chart, so it runs on any
Kubernetes: EKS, GKE, AKS, a managed cluster elsewhere, or a single VM
running k3s. Every CI run installs the chart on a throwaway cluster and checks
that the deployment works.

| Image (`ghcr.io/manishaacharyahere/aegis-cloud-governance/…`) | What it runs |
|---|---|
| `aegis-api` | The API, plus its `migrate` and `wait-for-schema` steps |
| `aegis-web` | The dashboard, served by Caddy, with the API proxied on the same origin and strict security headers (CSP) |
| `aegis-opa` | OPA with the policies of the same commit baked in |
| `aegis-ml` | The anomaly and forecast worker (a CronJob) |

The images are built for `linux/amd64` and `linux/arm64` by the release
workflow when a `v*` tag is pushed.

## What the chart sets up

- **PostgreSQL** (bundled or your own), with TLS. The API connects as the
  least-privilege `aegis_app` role and never receives the owner password.
  Migrations run in a Job for each release, and API pods wait until the schema
  is current.
- **NATS JetStream** and **OPA**, each authenticated with a generated secret.
- **Secrets.** Database passwords, the OPA and NATS credentials and the
  change-set signing key are generated on install. They are kept on upgrades
  and kept even if the release is deleted.
- **Hardened containers.** Every container runs as non-root with a read-only
  filesystem, no capabilities, and the RuntimeDefault seccomp profile.
- **Network policies.** Everything is denied by default; then only
  web → API → PostgreSQL, NATS and OPA are allowed.
- **Ingress.** `https://<host>/` serves the dashboard. With the bundled Dex,
  `https://<host>/dex` is the sign-in service.
- **Production mode** refuses unsafe settings at install time:
  development header authentication, or OIDC with no identity provider.

## Any Kubernetes cluster

```bash
helm install aegis deploy/helm/aegis -n aegis --create-namespace \
  --set host=aegis.example.com \
  --set api.oidc.issuer=https://login.example.com \
  --set api.bootstrapAdmins={you@example.com}
```

The chart creates a TLS Ingress for `aegis.example.com`. Its certificate
comes from your cluster: for example cert-manager, with
`--set ingress.annotations."cert-manager\.io/cluster-issuer"=letsencrypt`.

**Your own PostgreSQL** (RDS, Cloud SQL, Azure Database). Set
`postgresql.enabled=false` and create a Secret with the URLs, plus
`opa-token`, `nats-password` and `signing-key`, then name it in
`existingSecret`. Create the runtime role once, as the owner:

```sql
CREATE ROLE aegis_app LOGIN PASSWORD '...';
GRANT CONNECT ON DATABASE aegis TO aegis_app;
GRANT USAGE ON SCHEMA public TO aegis_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO aegis_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO aegis_app;
```

The migrations then grant and revoke exactly what the role may do.

## A free public instance

This route costs nothing:

- **Oracle Cloud Always Free:** an Ampere VM with up to 4 cores and 24 GB of
  RAM, free with no time limit.
- **k3s:** a small Kubernetes distribution with an ingress controller built in.
- **cert-manager with Let's Encrypt:** free HTTPS certificates.
- **DuckDNS:** a free hostname.

1. **Create the VM.** Sign up at <https://www.oracle.com/cloud/free/> (a card
   is needed to verify you; Always Free resources are never charged). Create
   an instance with shape `VM.Standard.A1.Flex` (2 OCPU, 12 GB is plenty)
   running Ubuntu 24.04. In its subnet's security list, open TCP 80 and 443.
2. **Get a hostname.** At <https://www.duckdns.org> create, for example,
   `my-aegis.duckdns.org` and point it at the VM's public IP.
3. **Install k3s and cert-manager** on the VM:

   ```bash
   curl -sfL https://get.k3s.io | sh -
   export KUBECONFIG=/etc/rancher/k3s/k3s.yaml
   sudo iptables -I INPUT -p tcp -m multiport --dports 80,443 -j ACCEPT   # Oracle images block them by default
   kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.20.5/cert-manager.yaml
   cat <<'EOF' | kubectl apply -f -
   apiVersion: cert-manager.io/v1
   kind: ClusterIssuer
   metadata: { name: letsencrypt }
   spec:
     acme:
       server: https://acme-v02.api.letsencrypt.org/directory
       email: you@example.com
       privateKeySecretRef: { name: letsencrypt }
       solvers: [{ http01: { ingress: { ingressClassName: traefik } } }]
   EOF
   ```

4. **Allow sign-in with GitHub (free).** On GitHub, go to **Settings →
   Developer settings → OAuth Apps → New**, with homepage
   `https://my-aegis.duckdns.org` and callback
   `https://my-aegis.duckdns.org/dex/callback`.
5. **Install Aegis:**

   ```bash
   git clone https://github.com/manishaacharyahere/aegis-cloud-governance && cd aegis-cloud-governance
   helm install aegis deploy/helm/aegis -n aegis --create-namespace \
     --set host=my-aegis.duckdns.org \
     --set ingress.className=traefik \
     --set ingress.annotations."cert-manager\.io/cluster-issuer"=letsencrypt \
     --set dex.enabled=true \
     --set dex.github.clientId=<client id> --set dex.github.clientSecret=<client secret> \
     --set api.bootstrapAdmins={you@example.com} \
     --set mlWorker.enabled=true
   ```

   GitHub users sign in with their verified email. Only the bootstrap admin
   gets a role; everyone else sees nothing until an admin grants one on the
   Access page. For a public demo, grant `viewer` to the people you invite.
6. **Load data.** Import the sample snapshot from the dashboard, or collect
   your own account ([aws-collector.md](aws-collector.md)) and pass
   `-import https://my-aegis.duckdns.org` with an `AEGIS_TOKEN`.

## Not in the chart yet

- **The IaC scan worker.** It starts each tool in its own locked-down Docker
  container, which needs a Docker daemon. On a VM, run `aegis-worker` next to
  k3s with Docker installed (see getting-started.md). Inside Kubernetes it
  would need a sandboxed runtime such as gVisor or Kata, which is not built
  yet.
- **High availability.** The bundled PostgreSQL and NATS are single
  instances. For production, use a managed PostgreSQL and run more API and
  web replicas.
- **Backups.** Use your provider's database backups, or
  `pg_dump` on a schedule. There is no backup job in the chart yet.
