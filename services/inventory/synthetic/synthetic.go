// Package synthetic generates deterministic, AWS-like inventory snapshots
// with ground-truth labels for every injected misconfiguration, so policy,
// drift and risk engines can be evaluated reproducibly.
//
// All data is fictional. Same Options => byte-identical output.
package synthetic

import (
	"fmt"
	"math/rand/v2"
	"slices"
	"sort"
	"time"

	"github.com/manishaacharyahere/aegis-cloud-governance/services/inventory"
)

// GeneratorVersion changes whenever output for a given seed changes.
const GeneratorVersion = "1.0.0"

// Ground-truth issue labels.
const (
	IssuePublicBucket        = "public_bucket"
	IssueUnencryptedStorage  = "unencrypted_storage"
	IssueUnencryptedDatabase = "unencrypted_database"
	IssuePublicDatabase      = "public_database"
	IssueWildcardIAM         = "wildcard_iam"
	IssueOpenSSH             = "open_ssh"
	IssueMissingTags         = "missing_tags"
	IssueLoggingDisabled     = "logging_disabled"
	IssueUnmanaged           = "unmanaged_resource"
)

// Injection rates (probability per eligible resource).
const (
	ratePublicBucket   = 0.10
	rateUnencrypted    = 0.10
	rateWildcardIAM    = 0.08
	rateOpenSSH        = 0.08
	rateMissingTags    = 0.07
	ratePublicDatabase = 0.05
)

// Options control generation.
type Options struct {
	Seed        uint64
	Resources   int // approximate target; at least the per-environment baseline is always generated
	AccountID   string
	AccountName string
	CapturedAt  time.Time
}

// Dataset is a snapshot plus ground-truth labels (resource ID -> sorted issues).
type Dataset struct {
	Snapshot inventory.Snapshot  `json:"snapshot"`
	Labels   map[string][]string `json:"labels"`
}

var (
	environments = []string{"production", "staging", "development"}
	envWeights   = []float64{0.5, 0.25, 0.25}
	teams        = []string{"payments", "identity", "search", "analytics", "platform", "checkout", "billing", "notifications"}
	regions      = []string{"ap-south-1", "us-east-1", "eu-west-1"}
	instanceSize = []string{"t3.micro", "t3.small", "t3.medium", "m6i.large", "c6i.xlarge"}
	dbEngines    = []string{"postgres", "mysql"}
)

type gen struct {
	rng    *rand.Rand
	res    []inventory.Resource
	labels map[string][]string
	n      map[string]int // per-prefix counters for unique IDs
}

func (g *gen) id(native, name string) string {
	key := native + "." + name
	g.n[key]++
	return fmt.Sprintf("%s.%s_%03d", native, name, g.n[key])
}

func (g *gen) chance(p float64) bool { return g.rng.Float64() < p }

func (g *gen) pick(xs []string) string { return xs[g.rng.IntN(len(xs))] }

func (g *gen) label(id, issue string) {
	if !slices.Contains(g.labels[id], issue) {
		g.labels[id] = append(g.labels[id], issue)
		sort.Strings(g.labels[id])
	}
}

func (g *gen) tags(env, team string, id string) map[string]string {
	if g.chance(rateMissingTags) {
		g.label(id, IssueMissingTags)
		return map[string]string{"environment": env} // owner and cost_center missing
	}
	return map[string]string{"environment": env, "owner": team + "-team", "cost_center": team}
}

func (g *gen) add(r inventory.Resource) { g.res = append(g.res, r) }

// Generate builds a dataset. It panics only on programmer error (invalid options).
func Generate(o Options) Dataset {
	if o.AccountID == "" {
		o.AccountID = "123456789012"
	}
	if o.AccountName == "" {
		o.AccountName = "aegis-synthetic"
	}
	if o.CapturedAt.IsZero() {
		o.CapturedAt = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	}
	g := &gen{
		rng:    rand.New(rand.NewPCG(o.Seed, o.Seed^0x9E3779B97F4A7C15)),
		labels: map[string][]string{},
		n:      map[string]int{},
	}

	type envInfra struct {
		region, vpc, kms, logGroup string
		subnets                    []string
	}
	infra := map[string]envInfra{}
	for i, env := range environments {
		region := regions[i%len(regions)]
		e := envInfra{region: region}
		e.vpc = g.id("aws_vpc", env)
		g.add(inventory.Resource{ResourceID: e.vpc, ResourceType: "aws_vpc", Region: region,
			Tags:          map[string]string{"environment": env, "owner": "platform-team", "cost_center": "platform"},
			Configuration: map[string]any{"cidr_block": fmt.Sprintf("10.%d.0.0/16", i), "enable_dns_support": true}})
		for z := range 3 {
			sn := g.id("aws_subnet", env)
			public := z == 0
			g.add(inventory.Resource{ResourceID: sn, ResourceType: "aws_subnet", Region: region,
				Tags:          map[string]string{"environment": env, "owner": "platform-team", "cost_center": "platform"},
				Configuration: map[string]any{"cidr_block": fmt.Sprintf("10.%d.%d.0/24", i, z), "map_public_ip_on_launch": public},
				Relationships: []inventory.Relationship{{Type: "member_of", TargetID: e.vpc}}})
			e.subnets = append(e.subnets, sn)
		}
		e.kms = g.id("aws_kms_key", env)
		g.add(inventory.Resource{ResourceID: e.kms, ResourceType: "aws_kms_key", Region: region,
			Tags:          map[string]string{"environment": env, "owner": "security-team", "cost_center": "security"},
			Configuration: map[string]any{"enable_key_rotation": true, "deletion_window_in_days": 30}})
		e.logGroup = g.id("aws_cloudwatch_log_group", env)
		g.add(inventory.Resource{ResourceID: e.logGroup, ResourceType: "aws_cloudwatch_log_group", Region: region,
			Tags:          map[string]string{"environment": env, "owner": "platform-team", "cost_center": "platform"},
			Configuration: map[string]any{"retention_in_days": 90}})
		trail := g.id("aws_cloudtrail", env)
		logging := env != "development" || !g.chance(0.5)
		if !logging {
			g.label(trail, IssueLoggingDisabled)
		}
		g.add(inventory.Resource{ResourceID: trail, ResourceType: "aws_cloudtrail", Region: region,
			Tags:          map[string]string{"environment": env, "owner": "security-team", "cost_center": "security"},
			Configuration: map[string]any{"is_multi_region_trail": true, "enable_logging": logging, "log_file_validation": true},
			Relationships: []inventory.Relationship{{Type: "logs_to", TargetID: e.logGroup}}})
		infra[env] = e
	}

	for len(g.res) < o.Resources {
		env := weighted(g.rng, environments, envWeights)
		e := infra[env]
		team := g.pick(teams)

		role := g.id("aws_iam_role", team)
		g.add(inventory.Resource{ResourceID: role, ResourceType: "aws_iam_role",
			Tags:          g.tags(env, team, role),
			Configuration: map[string]any{"assume_role_service": "ec2.amazonaws.com", "max_session_duration": 3600}})

		policy := g.id("aws_iam_policy", team)
		actions, resources := []any{"s3:GetObject", "s3:PutObject"}, []any{"arn:aws:s3:::" + team + "-*"}
		if g.chance(rateWildcardIAM) {
			actions, resources = []any{"*"}, []any{"*"}
			g.label(policy, IssueWildcardIAM)
		}
		g.add(inventory.Resource{ResourceID: policy, ResourceType: "aws_iam_policy",
			Tags: g.tags(env, team, policy),
			Configuration: map[string]any{"statements": []any{map[string]any{
				"effect": "Allow", "actions": actions, "resources": resources}}},
			Relationships: []inventory.Relationship{{Type: "attached_to", TargetID: role}}})

		sg := g.id("aws_security_group", team)
		ingress := []any{map[string]any{"protocol": "tcp", "from_port": 443, "to_port": 443, "cidr_blocks": []any{"10.0.0.0/8"}}}
		if g.chance(rateOpenSSH) {
			ingress = append(ingress, map[string]any{"protocol": "tcp", "from_port": 22, "to_port": 22, "cidr_blocks": []any{"0.0.0.0/0"}})
			g.label(sg, IssueOpenSSH)
		}
		g.add(inventory.Resource{ResourceID: sg, ResourceType: "aws_security_group", Region: e.region,
			Tags: g.tags(env, team, sg), Configuration: map[string]any{"ingress": ingress},
			Relationships: []inventory.Relationship{{Type: "member_of", TargetID: e.vpc}}})

		var instances []string
		for range 1 + g.rng.IntN(3) {
			inst := g.id("aws_instance", team)
			instances = append(instances, inst)
			g.add(inventory.Resource{ResourceID: inst, ResourceType: "aws_instance", Region: e.region,
				Tags: g.tags(env, team, inst),
				Configuration: map[string]any{"instance_type": g.pick(instanceSize), "monitoring": env == "production",
					"ebs_encrypted": true, "imdsv2_required": g.chance(0.85)},
				Relationships: []inventory.Relationship{
					{Type: "member_of", TargetID: e.subnets[1+g.rng.IntN(2)]},
					{Type: "assumes", TargetID: role},
				}})
			// Security group attaches to each instance.
			g.res[indexOf(g.res, sg)].Relationships = append(g.res[indexOf(g.res, sg)].Relationships,
				inventory.Relationship{Type: "attached_to", TargetID: inst})
		}

		bucket := g.id("aws_s3_bucket", team+"_data")
		bcfg := map[string]any{"public_access_block": true, "encryption": "aws:kms", "versioning": env == "production"}
		var brel []inventory.Relationship
		if g.chance(ratePublicBucket) {
			bcfg["public_access_block"] = false
			g.label(bucket, IssuePublicBucket)
		}
		if g.chance(rateUnencrypted) {
			delete(bcfg, "encryption")
			g.label(bucket, IssueUnencryptedStorage)
		} else {
			g.res[indexOf(g.res, e.kms)].Relationships = append(g.res[indexOf(g.res, e.kms)].Relationships,
				inventory.Relationship{Type: "encrypts", TargetID: bucket})
		}
		g.add(inventory.Resource{ResourceID: bucket, ResourceType: "aws_s3_bucket", Region: e.region,
			Tags: g.tags(env, team, bucket), Configuration: bcfg, Relationships: brel})
		for _, inst := range instances {
			g.res[indexOf(g.res, inst)].Relationships = append(g.res[indexOf(g.res, inst)].Relationships,
				inventory.Relationship{Type: "writes_to", TargetID: bucket})
		}

		if g.chance(0.4) {
			lb := g.id("aws_lb", team)
			var rels []inventory.Relationship
			for _, inst := range instances {
				rels = append(rels, inventory.Relationship{Type: "routes_to", TargetID: inst})
			}
			g.add(inventory.Resource{ResourceID: lb, ResourceType: "aws_lb", Region: e.region,
				Tags: g.tags(env, team, lb), Configuration: map[string]any{"internal": false, "load_balancer_type": "application"},
				Relationships: rels})
		}

		if g.chance(0.3) {
			db := g.id("aws_db_instance", team)
			encrypted, public := true, false
			if g.chance(rateUnencrypted) {
				encrypted = false
				g.label(db, IssueUnencryptedDatabase)
			}
			if g.chance(ratePublicDatabase) {
				public = true
				g.label(db, IssuePublicDatabase)
			}
			g.add(inventory.Resource{ResourceID: db, ResourceType: "aws_db_instance", Region: e.region,
				Tags: g.tags(env, team, db),
				Configuration: map[string]any{"engine": g.pick(dbEngines), "instance_class": "db.t3.medium",
					"storage_encrypted": encrypted, "publicly_accessible": public, "backup_retention_period": 7,
					"multi_az": env == "production"},
				Relationships: []inventory.Relationship{{Type: "member_of", TargetID: e.subnets[2]}}})
			for _, inst := range instances {
				g.res[indexOf(g.res, inst)].Relationships = append(g.res[indexOf(g.res, inst)].Relationships,
					inventory.Relationship{Type: "reads_from", TargetID: db})
			}
		}
	}

	return Dataset{
		Snapshot: inventory.Snapshot{
			SchemaVersion: inventory.SchemaV1,
			Source:        "synthetic",
			CapturedAt:    o.CapturedAt.UTC(),
			Account:       inventory.Account{Provider: "aws", ExternalID: o.AccountID, Name: o.AccountName},
			Resources:     g.res,
		},
		Labels: g.labels,
	}
}

// MutateOptions control drift injection for a follow-up snapshot.
type MutateOptions struct {
	Seed       uint64
	Modify     int
	Delete     int
	Add        int
	CapturedAt time.Time // must be after the base snapshot
}

// Mutation is the ground truth of what Mutate changed.
type Mutation struct {
	Modified []string `json:"modified"`
	Deleted  []string `json:"deleted"`
	Added    []string `json:"added"`
}

// Mutate returns a drifted copy of base: modified, deleted and newly added
// (unmanaged, untagged) resources. base is not modified.
func Mutate(base Dataset, o MutateOptions) (Dataset, Mutation) {
	rng := rand.New(rand.NewPCG(o.Seed, o.Seed^0xD1B54A32D192ED03))
	out := Dataset{Snapshot: base.Snapshot, Labels: map[string][]string{}}
	out.Snapshot.CapturedAt = o.CapturedAt.UTC()
	out.Snapshot.Resources = make([]inventory.Resource, len(base.Snapshot.Resources))
	for i, r := range base.Snapshot.Resources {
		out.Snapshot.Resources[i] = cloneResource(r)
	}
	for k, v := range base.Labels {
		out.Labels[k] = slices.Clone(v)
	}

	n := len(out.Snapshot.Resources)
	o.Modify, o.Delete = min(o.Modify, n), min(o.Delete, n-min(o.Modify, n))
	perm := rng.Perm(n)
	var m Mutation

	for _, idx := range perm[:o.Modify] {
		r := &out.Snapshot.Resources[idx]
		switch r.ResourceType {
		case "aws_s3_bucket":
			r.Configuration["public_access_block"] = false
			lbl := append(out.Labels[r.ResourceID], IssuePublicBucket)
			out.Labels[r.ResourceID] = dedupeSorted(lbl)
		case "aws_instance":
			r.Configuration["instance_type"] = "m6i.4xlarge" // cost-related drift
		case "aws_security_group":
			r.Configuration["ingress"] = append(r.Configuration["ingress"].([]any),
				map[string]any{"protocol": "tcp", "from_port": 22, "to_port": 22, "cidr_blocks": []any{"0.0.0.0/0"}})
			out.Labels[r.ResourceID] = dedupeSorted(append(out.Labels[r.ResourceID], IssueOpenSSH))
		default:
			if r.Tags == nil {
				r.Tags = map[string]string{}
			}
			r.Tags["owner"] = "unknown" // tagging drift
		}
		m.Modified = append(m.Modified, r.ResourceID)
	}

	deleted := map[string]bool{}
	for _, idx := range perm[o.Modify : o.Modify+o.Delete] {
		id := out.Snapshot.Resources[idx].ResourceID
		deleted[id] = true
		m.Deleted = append(m.Deleted, id)
		delete(out.Labels, id)
	}
	kept := out.Snapshot.Resources[:0]
	for _, r := range out.Snapshot.Resources {
		if deleted[r.ResourceID] {
			continue
		}
		r.Relationships = slices.DeleteFunc(r.Relationships, func(rel inventory.Relationship) bool { return deleted[rel.TargetID] })
		kept = append(kept, r)
	}
	out.Snapshot.Resources = kept

	region := regions[0]
	for i := range o.Add {
		id := fmt.Sprintf("aws_s3_bucket.unmanaged_%03d", i+1)
		out.Snapshot.Resources = append(out.Snapshot.Resources, inventory.Resource{
			ResourceID: id, ResourceType: "aws_s3_bucket", Region: region,
			Configuration: map[string]any{"public_access_block": rng.Float64() < 0.5, "versioning": false},
		})
		lbl := []string{IssueMissingTags, IssueUnencryptedStorage, IssueUnmanaged}
		if !out.Snapshot.Resources[len(out.Snapshot.Resources)-1].Configuration["public_access_block"].(bool) {
			lbl = append(lbl, IssuePublicBucket)
		}
		out.Labels[id] = dedupeSorted(lbl)
		m.Added = append(m.Added, id)
	}

	sort.Strings(m.Modified)
	sort.Strings(m.Deleted)
	return out, m
}

func weighted(rng *rand.Rand, xs []string, w []float64) string {
	r := rng.Float64()
	for i, p := range w {
		if r < p {
			return xs[i]
		}
		r -= p
	}
	return xs[len(xs)-1]
}

func indexOf(rs []inventory.Resource, id string) int {
	for i := len(rs) - 1; i >= 0; i-- {
		if rs[i].ResourceID == id {
			return i
		}
	}
	panic("synthetic: unknown resource " + id)
}

func cloneResource(r inventory.Resource) inventory.Resource {
	c := r
	if r.Tags != nil {
		c.Tags = make(map[string]string, len(r.Tags))
		for k, v := range r.Tags {
			c.Tags[k] = v
		}
	}
	c.Configuration, _ = deepCopy(r.Configuration).(map[string]any)
	c.Relationships = slices.Clone(r.Relationships)
	return c
}

func deepCopy(v any) any {
	switch t := v.(type) {
	case map[string]any:
		m := make(map[string]any, len(t))
		for k, x := range t {
			m[k] = deepCopy(x)
		}
		return m
	case []any:
		s := make([]any, len(t))
		for i, x := range t {
			s[i] = deepCopy(x)
		}
		return s
	default:
		return v
	}
}

func dedupeSorted(xs []string) []string {
	sort.Strings(xs)
	return slices.Compact(xs)
}
