# Collecting a real AWS account

`aegis-collect` reads an AWS account and produces an `aegis.inventory/v1`
snapshot, the same format the synthetic data uses. Every policy, the risk
graph, drift detection and remediation then work on your real
infrastructure.

It only reads. Every call is a `List*`, `Describe*` or `Get*`, and the AWS
managed policy `SecurityAudit` covers all of them. These read calls cost
nothing, so a Free Tier account is enough.

## What it collects

| AWS | Aegis type | Settings the policies check |
|---|---|---|
| S3 buckets | `storage.bucket` | public access block (all four settings), default encryption, versioning, tags |
| VPCs, subnets | `network.vpc`, `network.subnet` | CIDR, public IP on launch |
| Security groups | `network.security_group` | ingress rules (protocol, ports, IPv4 and IPv6 ranges) |
| EC2 instances | `compute.instance` | type, IMDSv2, monitoring, public IP |
| RDS instances | `database.instance` | public access, storage encryption, multi-AZ, backups |
| IAM roles, customer-managed policies | `identity.role`, `identity.policy` | trusted service, policy statements |
| Application and network load balancers | `network.load_balancer` | internet-facing or internal |
| CloudTrail trails | `logging.trail` | logging on, log file validation, multi-region |

It also records the relationships the risk engine follows: subnet → VPC,
security group → instance, database or load balancer, load balancer →
instance, and policy → role. These are what make attack paths from the
internet visible.

If the credentials cannot read a service or a region, that is reported as a
warning and the rest is still collected.

## One-time setup (free)

1. If you have no AWS account, create one at <https://aws.amazon.com/free>.
   AWS asks for a card to verify you; the read calls Aegis makes are free.
2. Create a read-only user. In the IAM console, go to **Users → Create user**,
   name it `aegis-readonly`, and choose **Attach policies directly** and then
   **SecurityAudit**. Then open **Security credentials → Create access key →
   Command Line Interface**.
3. Store the key locally. Never put it in the repository or a chat:

   ```bash
   aws configure --profile aegis-readonly   # paste the key here; region e.g. ap-south-1
   ```

   With AWS IAM Identity Center (SSO) you can use `aws configure sso` instead.
   The collector uses the standard AWS credential chain, so roles, SSO and
   environment variables all work.

## Collect and import

```bash
# write a snapshot file
go run ./cmd/aegis-collect -profile aegis-readonly -regions ap-south-1,us-east-1 \
  -environment production -out my-account.json

# or import straight into a running Aegis
export AEGIS_TOKEN=$(scripts/dev-token.sh alice@aegis.local)   # OIDC mode
go run ./cmd/aegis-collect -profile aegis-readonly -regions all -import http://127.0.0.1:8080 -tenant demo
```

`-regions all` reads every region enabled for the account. Without
`-regions`, the profile's region is used. S3 and IAM are global and are
always read. The snapshot is validated before it is written or sent, so
problems show up locally with every issue listed.

After importing, run **Evaluate inventory now** on the Compliance page and
**Run assessment** on the Risk page, or wait for the reactor, which
re-evaluates about ten seconds after an import when NATS is running.

## Testing without an account

CI runs the collector against [moto](https://github.com/getmoto/moto), a free
AWS emulator, through the real AWS SDK. The test
`TestCollectorFindsRealMisconfigurations` creates:

- a public bucket and a locked-down bucket;
- a security group open to SSH;
- a public, unencrypted database;
- an admin IAM policy;
- a trail that is not logging.

It collects them, imports the snapshot, and checks that exactly the expected
rules fail. To run it locally:

```bash
docker run -d -p 127.0.0.1:5055:5000 motoserver/moto:5.2.5
AEGIS_TEST_AWS_ENDPOINT=http://127.0.0.1:5055 AEGIS_TEST_DATABASE_URL=... AEGIS_TEST_OPA_URL=... \
  go test -run TestCollector ./tests/integration/
```

## Limits

- **AWS only, and the services above.** KMS keys, Lambda, EKS and
  Organizations are not collected yet.
- **Data sensitivity comes from the `data_classification` tag.** Without it,
  the risk engine estimates sensitivity from the resource name and type.
- **Instance roles are not linked.** An instance profile names a profile, not
  a role, and resolving it needs one more call per profile, so the
  instance → role edge is not recorded yet.
