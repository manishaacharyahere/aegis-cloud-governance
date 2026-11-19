// Package collector reads a live AWS account (read-only) and produces an
// aegis.inventory/v1 snapshot, so every policy, the risk graph and drift work
// on real infrastructure exactly as they do on synthetic data.
//
// Every call is a read (List*, Describe*, Get*); the AWS managed policies
// SecurityAudit or ViewOnlyAccess are enough. A service or region the
// credentials cannot read is reported as a warning and skipped, so a partly
// permitted account still yields a useful snapshot.
package collector

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	elb "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/smithy-go"

	"github.com/manishaacharyahere/aegis-cloud-governance/services/inventory"
)

// The AWS operations the collector uses, one small interface per service
// (defined here, where they are consumed), so tests can fake any of them.
type (
	S3API interface {
		ListBuckets(context.Context, *s3.ListBucketsInput, ...func(*s3.Options)) (*s3.ListBucketsOutput, error)
		GetBucketLocation(context.Context, *s3.GetBucketLocationInput, ...func(*s3.Options)) (*s3.GetBucketLocationOutput, error)
		GetPublicAccessBlock(context.Context, *s3.GetPublicAccessBlockInput, ...func(*s3.Options)) (*s3.GetPublicAccessBlockOutput, error)
		GetBucketEncryption(context.Context, *s3.GetBucketEncryptionInput, ...func(*s3.Options)) (*s3.GetBucketEncryptionOutput, error)
		GetBucketVersioning(context.Context, *s3.GetBucketVersioningInput, ...func(*s3.Options)) (*s3.GetBucketVersioningOutput, error)
		GetBucketTagging(context.Context, *s3.GetBucketTaggingInput, ...func(*s3.Options)) (*s3.GetBucketTaggingOutput, error)
	}
	EC2API interface {
		ec2.DescribeVpcsAPIClient
		ec2.DescribeSubnetsAPIClient
		ec2.DescribeSecurityGroupsAPIClient
		ec2.DescribeInstancesAPIClient
	}
	RDSAPI interface {
		rds.DescribeDBInstancesAPIClient
	}
	IAMAPI interface {
		iam.ListPoliciesAPIClient
		iam.ListRolesAPIClient
		iam.ListEntitiesForPolicyAPIClient
		GetPolicyVersion(context.Context, *iam.GetPolicyVersionInput, ...func(*iam.Options)) (*iam.GetPolicyVersionOutput, error)
	}
	CloudTrailAPI interface {
		DescribeTrails(context.Context, *cloudtrail.DescribeTrailsInput, ...func(*cloudtrail.Options)) (*cloudtrail.DescribeTrailsOutput, error)
		GetTrailStatus(context.Context, *cloudtrail.GetTrailStatusInput, ...func(*cloudtrail.Options)) (*cloudtrail.GetTrailStatusOutput, error)
	}
	ELBAPI interface {
		elb.DescribeLoadBalancersAPIClient
		elb.DescribeTargetGroupsAPIClient
		DescribeTargetHealth(context.Context, *elb.DescribeTargetHealthInput, ...func(*elb.Options)) (*elb.DescribeTargetHealthOutput, error)
	}
)

// Regional holds the clients for one region. A nil client skips that service.
type Regional struct {
	S3         S3API
	EC2        EC2API
	RDS        RDSAPI
	CloudTrail CloudTrailAPI
	ELB        ELBAPI
}

// AWS collects one account.
type AWS struct {
	AccountID   string // 12 digits
	AccountName string
	Environment string   // default for resources without an environment tag
	Regions     []string // regions to read EC2, RDS, ELB and CloudTrail from
	HomeRegion  string   // region for the global S3 and IAM calls (default us-east-1)
	IAM         IAMAPI   // nil skips IAM
	Region      func(region string) Regional
	Now         func() time.Time
}

// Collect reads the account and returns the snapshot and the warnings for
// whatever could not be read.
func (c *AWS) Collect(ctx context.Context) (inventory.Snapshot, []string, error) {
	if c.Region == nil {
		return inventory.Snapshot{}, nil, errors.New("collector: no client factory")
	}
	now := time.Now
	if c.Now != nil {
		now = c.Now
	}
	home := c.HomeRegion
	if home == "" {
		home = "us-east-1"
	}
	b := &builder{env: c.Environment, ids: map[string]int{}}
	b.buckets(ctx, c.Region(home).S3, c.Region)
	b.iam(ctx, c.IAM)
	seenTrails := map[string]bool{}
	for _, r := range c.Regions {
		rc := c.Region(r)
		b.network(ctx, r, rc.EC2)
		b.databases(ctx, r, rc.RDS)
		b.loadBalancers(ctx, r, rc.ELB)
		b.trails(ctx, r, rc.CloudTrail, seenTrails)
	}
	if err := ctx.Err(); err != nil {
		return inventory.Snapshot{}, b.warnings, err
	}
	sort.Slice(b.res, func(i, j int) bool { return b.res[i].ResourceID < b.res[j].ResourceID })
	name := c.AccountName
	if name == "" {
		name = "aws-" + c.AccountID
	}
	return inventory.Snapshot{
		SchemaVersion: inventory.SchemaV1, Source: "aws", CapturedAt: now().UTC().Truncate(time.Second),
		Account:   inventory.Account{Provider: "aws", ExternalID: c.AccountID, Name: name},
		Resources: b.res,
	}, b.warnings, nil
}

// builder accumulates resources and edges; an edge can be added to a
// resource that is created later (security groups attach to instances).
type builder struct {
	env      string
	res      []inventory.Resource
	ids      map[string]int
	warnings []string
}

func (b *builder) warn(what string, err error) {
	b.warnings = append(b.warnings, fmt.Sprintf("%s: %s", what, short(err)))
}

func (b *builder) add(r inventory.Resource) {
	if r.Environment == "" && r.Tags["environment"] == "" && r.Tags["Environment"] == "" {
		r.Environment = b.env
	}
	if len(r.Tags) == 0 {
		r.Tags = nil
	}
	if i, ok := b.ids[r.ResourceID]; ok { // seen in another region's listing
		b.res[i] = r
		return
	}
	b.ids[r.ResourceID] = len(b.res)
	b.res = append(b.res, r)
}

func (b *builder) edge(from, typ, to string) {
	if i, ok := b.ids[from]; ok && from != to {
		for _, e := range b.res[i].Relationships {
			if e.Type == typ && e.TargetID == to {
				return
			}
		}
		b.res[i].Relationships = append(b.res[i].Relationships, inventory.Relationship{Type: typ, TargetID: to})
	}
}

// ------------------------------------------------------------------ S3

func (b *builder) buckets(ctx context.Context, home S3API, region func(string) Regional) {
	if home == nil {
		return
	}
	out, err := home.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		b.warn("s3 ListBuckets", err)
		return
	}
	for _, bk := range out.Buckets {
		name := aws.ToString(bk.Name)
		loc, err := home.GetBucketLocation(ctx, &s3.GetBucketLocationInput{Bucket: &name})
		if err != nil {
			b.warn("s3 "+name+" location", err)
			continue
		}
		reg := bucketRegion(string(loc.LocationConstraint))
		cl := region(reg).S3
		if cl == nil {
			cl = home
		}
		cfg := map[string]any{"public_access_block": false, "versioning": false}
		if pab, err := cl.GetPublicAccessBlock(ctx, &s3.GetPublicAccessBlockInput{Bucket: &name}); err == nil && pab.PublicAccessBlockConfiguration != nil {
			p := pab.PublicAccessBlockConfiguration
			cfg["public_access_block"] = aws.ToBool(p.BlockPublicAcls) && aws.ToBool(p.BlockPublicPolicy) &&
				aws.ToBool(p.IgnorePublicAcls) && aws.ToBool(p.RestrictPublicBuckets)
		} else if err != nil && !isCode(err, "NoSuchPublicAccessBlockConfiguration") {
			b.warn("s3 "+name+" public access block", err)
		}
		if enc, err := cl.GetBucketEncryption(ctx, &s3.GetBucketEncryptionInput{Bucket: &name}); err == nil &&
			enc.ServerSideEncryptionConfiguration != nil && len(enc.ServerSideEncryptionConfiguration.Rules) > 0 {
			if d := enc.ServerSideEncryptionConfiguration.Rules[0].ApplyServerSideEncryptionByDefault; d != nil {
				cfg["encryption"] = string(d.SSEAlgorithm)
			}
		} else if err != nil && !isCode(err, "ServerSideEncryptionConfigurationNotFoundError") {
			b.warn("s3 "+name+" encryption", err)
		}
		if v, err := cl.GetBucketVersioning(ctx, &s3.GetBucketVersioningInput{Bucket: &name}); err == nil {
			cfg["versioning"] = v.Status == "Enabled"
		} else {
			b.warn("s3 "+name+" versioning", err)
		}
		tags := map[string]string{}
		if t, err := cl.GetBucketTagging(ctx, &s3.GetBucketTaggingInput{Bucket: &name}); err == nil {
			for _, tg := range t.TagSet {
				tags[aws.ToString(tg.Key)] = aws.ToString(tg.Value)
			}
		} else if !isCode(err, "NoSuchTagSet") {
			b.warn("s3 "+name+" tags", err)
		}
		b.add(inventory.Resource{ResourceID: "aws_s3_bucket." + name, ResourceType: "aws_s3_bucket", Region: reg, Tags: tags, Configuration: cfg})
	}
}

// bucketRegion maps a GetBucketLocation answer to a region ("" is us-east-1,
// "EU" is the legacy name of eu-west-1).
func bucketRegion(loc string) string {
	switch loc {
	case "":
		return "us-east-1"
	case "EU":
		return "eu-west-1"
	}
	return loc
}

// ------------------------------------------------------------------ IAM

func (b *builder) iam(ctx context.Context, api IAMAPI) {
	if api == nil {
		return
	}
	roles := iam.NewListRolesPaginator(api, &iam.ListRolesInput{})
	for roles.HasMorePages() {
		page, err := roles.NextPage(ctx)
		if err != nil {
			b.warn("iam ListRoles", err)
			break
		}
		for _, r := range page.Roles {
			cfg := map[string]any{"max_session_duration": int(aws.ToInt32(r.MaxSessionDuration))}
			if svc := trustedService(aws.ToString(r.AssumeRolePolicyDocument)); svc != "" {
				cfg["assume_role_service"] = svc
			}
			b.add(inventory.Resource{ResourceID: "aws_iam_role." + aws.ToString(r.RoleName), ResourceType: "aws_iam_role",
				Tags: iamTags(r.Tags), Configuration: cfg})
		}
	}
	// Customer-managed policies only: AWS-managed ones are the same in every account.
	pols := iam.NewListPoliciesPaginator(api, &iam.ListPoliciesInput{Scope: iamtypes.PolicyScopeTypeLocal})
	for pols.HasMorePages() {
		page, err := pols.NextPage(ctx)
		if err != nil {
			b.warn("iam ListPolicies", err)
			break
		}
		for _, p := range page.Policies {
			id := "aws_iam_policy." + aws.ToString(p.PolicyName)
			cfg := map[string]any{"statements": []any{}}
			if v, err := api.GetPolicyVersion(ctx, &iam.GetPolicyVersionInput{PolicyArn: p.Arn, VersionId: p.DefaultVersionId}); err == nil && v.PolicyVersion != nil {
				cfg["statements"] = statements(aws.ToString(v.PolicyVersion.Document))
			} else if err != nil {
				b.warn("iam "+aws.ToString(p.PolicyName)+" document", err)
			}
			b.add(inventory.Resource{ResourceID: id, ResourceType: "aws_iam_policy", Tags: iamTags(p.Tags), Configuration: cfg})
			ents := iam.NewListEntitiesForPolicyPaginator(api, &iam.ListEntitiesForPolicyInput{PolicyArn: p.Arn})
			for ents.HasMorePages() {
				e, err := ents.NextPage(ctx)
				if err != nil {
					b.warn("iam "+aws.ToString(p.PolicyName)+" attachments", err)
					break
				}
				for _, r := range e.PolicyRoles {
					b.edge(id, "attached_to", "aws_iam_role."+aws.ToString(r.RoleName))
				}
			}
		}
	}
}

func iamTags(ts []iamtypes.Tag) map[string]string {
	m := map[string]string{}
	for _, t := range ts {
		m[aws.ToString(t.Key)] = aws.ToString(t.Value)
	}
	return m
}

// policyDoc decodes IAM documents, which are URL-encoded JSON whose Action,
// Resource and Statement may each be a string or a list.
type policyDoc struct {
	Statement oneOrMany[struct {
		Effect    string                     `json:"Effect"`
		Action    oneOrMany[string]          `json:"Action"`
		Resource  oneOrMany[string]          `json:"Resource"`
		Principal map[string]json.RawMessage `json:"Principal"`
	}] `json:"Statement"`
}

type oneOrMany[T any] []T

func (o *oneOrMany[T]) UnmarshalJSON(b []byte) error {
	var many []T
	if err := json.Unmarshal(b, &many); err == nil {
		*o = many
		return nil
	}
	var one T
	if err := json.Unmarshal(b, &one); err != nil {
		return err
	}
	*o = []T{one}
	return nil
}

func decodeDoc(doc string) (policyDoc, bool) {
	if s, err := url.QueryUnescape(doc); err == nil {
		doc = s
	}
	var d policyDoc
	return d, json.Unmarshal([]byte(doc), &d) == nil
}

// statements returns the policy in the inventory shape the policies read:
// [{effect, actions, resources}].
func statements(doc string) []any {
	d, ok := decodeDoc(doc)
	if !ok {
		return []any{}
	}
	out := make([]any, 0, len(d.Statement))
	for _, s := range d.Statement {
		out = append(out, map[string]any{"effect": s.Effect, "actions": strs(s.Action), "resources": strs(s.Resource)})
	}
	return out
}

func strs(v []string) []any {
	out := make([]any, len(v))
	for i, s := range v {
		out[i] = s
	}
	return out
}

// trustedService returns the first AWS service a role's trust policy allows
// (for example "ec2.amazonaws.com"), or "".
func trustedService(doc string) string {
	d, ok := decodeDoc(doc)
	if !ok {
		return ""
	}
	for _, s := range d.Statement {
		var svc oneOrMany[string]
		if raw, ok := s.Principal["Service"]; ok && json.Unmarshal(raw, &svc) == nil && len(svc) > 0 {
			return svc[0]
		}
	}
	return ""
}

// ------------------------------------------------------------ EC2 network

func (b *builder) network(ctx context.Context, region string, api EC2API) {
	if api == nil {
		return
	}
	vpcs := ec2.NewDescribeVpcsPaginator(api, &ec2.DescribeVpcsInput{})
	for vpcs.HasMorePages() {
		page, err := vpcs.NextPage(ctx)
		if err != nil {
			b.warn("ec2 "+region+" DescribeVpcs", err)
			return // the region is not readable at all
		}
		for _, v := range page.Vpcs {
			b.add(inventory.Resource{ResourceID: "aws_vpc." + aws.ToString(v.VpcId), ResourceType: "aws_vpc", Region: region,
				Tags: ec2Tags(v.Tags), Configuration: map[string]any{"cidr_block": aws.ToString(v.CidrBlock), "is_default": aws.ToBool(v.IsDefault)}})
		}
	}
	subnets := ec2.NewDescribeSubnetsPaginator(api, &ec2.DescribeSubnetsInput{})
	for subnets.HasMorePages() {
		page, err := subnets.NextPage(ctx)
		if err != nil {
			b.warn("ec2 "+region+" DescribeSubnets", err)
			break
		}
		for _, s := range page.Subnets {
			id := "aws_subnet." + aws.ToString(s.SubnetId)
			b.add(inventory.Resource{ResourceID: id, ResourceType: "aws_subnet", Region: region, Tags: ec2Tags(s.Tags),
				Configuration: map[string]any{"cidr_block": aws.ToString(s.CidrBlock), "map_public_ip_on_launch": aws.ToBool(s.MapPublicIpOnLaunch)}})
			b.edge(id, "member_of", "aws_vpc."+aws.ToString(s.VpcId))
		}
	}
	sgs := ec2.NewDescribeSecurityGroupsPaginator(api, &ec2.DescribeSecurityGroupsInput{})
	for sgs.HasMorePages() {
		page, err := sgs.NextPage(ctx)
		if err != nil {
			b.warn("ec2 "+region+" DescribeSecurityGroups", err)
			break
		}
		for _, g := range page.SecurityGroups {
			id := "aws_security_group." + aws.ToString(g.GroupId)
			b.add(inventory.Resource{ResourceID: id, ResourceType: "aws_security_group", Region: region, Tags: ec2Tags(g.Tags),
				Configuration: map[string]any{"name": aws.ToString(g.GroupName), "ingress": ingress(g.IpPermissions)}})
			if g.VpcId != nil {
				b.edge(id, "member_of", "aws_vpc."+aws.ToString(g.VpcId))
			}
		}
	}
	insts := ec2.NewDescribeInstancesPaginator(api, &ec2.DescribeInstancesInput{})
	for insts.HasMorePages() {
		page, err := insts.NextPage(ctx)
		if err != nil {
			b.warn("ec2 "+region+" DescribeInstances", err)
			break
		}
		for _, rv := range page.Reservations {
			for _, in := range rv.Instances {
				if in.State != nil && in.State.Name == ec2types.InstanceStateNameTerminated {
					continue
				}
				id := "aws_instance." + aws.ToString(in.InstanceId)
				cfg := map[string]any{"instance_type": string(in.InstanceType), "monitoring": in.Monitoring != nil && in.Monitoring.State == ec2types.MonitoringStateEnabled,
					"imdsv2_required": in.MetadataOptions != nil && in.MetadataOptions.HttpTokens == ec2types.HttpTokensStateRequired,
					"public_ip":       in.PublicIpAddress != nil}
				if in.State != nil {
					cfg["state"] = string(in.State.Name)
				}
				b.add(inventory.Resource{ResourceID: id, ResourceType: "aws_instance", Region: region, Tags: ec2Tags(in.Tags), Configuration: cfg})
				if in.SubnetId != nil {
					b.edge(id, "member_of", "aws_subnet."+aws.ToString(in.SubnetId))
				}
				for _, g := range in.SecurityGroups {
					b.edge("aws_security_group."+aws.ToString(g.GroupId), "attached_to", id)
				}
			}
		}
	}
}

// ingress converts security group rules to the inventory shape:
// [{protocol, from_port, to_port, cidr_blocks, ipv6_cidr_blocks}].
func ingress(perms []ec2types.IpPermission) []any {
	out := []any{}
	for _, p := range perms {
		var v4, v6 []any
		for _, r := range p.IpRanges {
			v4 = append(v4, aws.ToString(r.CidrIp))
		}
		for _, r := range p.Ipv6Ranges {
			v6 = append(v6, aws.ToString(r.CidrIpv6))
		}
		rule := map[string]any{"protocol": aws.ToString(p.IpProtocol), "from_port": int(aws.ToInt32(p.FromPort)), "to_port": int(aws.ToInt32(p.ToPort))}
		if rule["protocol"] == "-1" { // all traffic: AWS omits the ports
			rule["from_port"], rule["to_port"] = 0, 65535
		}
		if len(v4) > 0 {
			rule["cidr_blocks"] = v4
		}
		if len(v6) > 0 {
			rule["ipv6_cidr_blocks"] = v6
		}
		out = append(out, rule)
	}
	return out
}

func ec2Tags(ts []ec2types.Tag) map[string]string {
	m := map[string]string{}
	for _, t := range ts {
		m[aws.ToString(t.Key)] = aws.ToString(t.Value)
	}
	return m
}

// ------------------------------------------------------------------ RDS

func (b *builder) databases(ctx context.Context, region string, api RDSAPI) {
	if api == nil {
		return
	}
	p := rds.NewDescribeDBInstancesPaginator(api, &rds.DescribeDBInstancesInput{})
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if err != nil {
			b.warn("rds "+region+" DescribeDBInstances", err)
			return
		}
		for _, d := range page.DBInstances {
			id := "aws_db_instance." + aws.ToString(d.DBInstanceIdentifier)
			tags := map[string]string{}
			for _, t := range d.TagList {
				tags[aws.ToString(t.Key)] = aws.ToString(t.Value)
			}
			b.add(inventory.Resource{ResourceID: id, ResourceType: "aws_db_instance", Region: region, Tags: tags,
				Configuration: map[string]any{"engine": aws.ToString(d.Engine), "instance_class": aws.ToString(d.DBInstanceClass),
					"multi_az": aws.ToBool(d.MultiAZ), "publicly_accessible": aws.ToBool(d.PubliclyAccessible),
					"storage_encrypted": aws.ToBool(d.StorageEncrypted), "backup_retention_period": int(aws.ToInt32(d.BackupRetentionPeriod))}})
			if d.DBSubnetGroup != nil && len(d.DBSubnetGroup.Subnets) > 0 {
				b.edge(id, "member_of", "aws_subnet."+aws.ToString(d.DBSubnetGroup.Subnets[0].SubnetIdentifier))
			}
			for _, g := range d.VpcSecurityGroups {
				b.edge("aws_security_group."+aws.ToString(g.VpcSecurityGroupId), "attached_to", id)
			}
		}
	}
}

// ---------------------------------------------------------- load balancers

func (b *builder) loadBalancers(ctx context.Context, region string, api ELBAPI) {
	if api == nil {
		return
	}
	lbs := elb.NewDescribeLoadBalancersPaginator(api, &elb.DescribeLoadBalancersInput{})
	byArn := map[string]string{}
	for lbs.HasMorePages() {
		page, err := lbs.NextPage(ctx)
		if err != nil {
			b.warn("elbv2 "+region+" DescribeLoadBalancers", err)
			return
		}
		for _, lb := range page.LoadBalancers {
			id := "aws_lb." + aws.ToString(lb.LoadBalancerName)
			byArn[aws.ToString(lb.LoadBalancerArn)] = id
			b.add(inventory.Resource{ResourceID: id, ResourceType: "aws_lb", Region: region,
				Configuration: map[string]any{"internal": lb.Scheme == "internal", "load_balancer_type": string(lb.Type)}})
			for _, g := range lb.SecurityGroups {
				b.edge("aws_security_group."+g, "attached_to", id)
			}
		}
	}
	tgs := elb.NewDescribeTargetGroupsPaginator(api, &elb.DescribeTargetGroupsInput{})
	for tgs.HasMorePages() {
		page, err := tgs.NextPage(ctx)
		if err != nil {
			b.warn("elbv2 "+region+" DescribeTargetGroups", err)
			return
		}
		for _, tg := range page.TargetGroups {
			if tg.TargetType != "instance" {
				continue
			}
			h, err := api.DescribeTargetHealth(ctx, &elb.DescribeTargetHealthInput{TargetGroupArn: tg.TargetGroupArn})
			if err != nil {
				b.warn("elbv2 "+region+" DescribeTargetHealth", err)
				continue
			}
			for _, arn := range tg.LoadBalancerArns {
				for _, t := range h.TargetHealthDescriptions {
					if t.Target != nil {
						b.edge(byArn[arn], "routes_to", "aws_instance."+aws.ToString(t.Target.Id))
					}
				}
			}
		}
	}
}

// --------------------------------------------------------------- CloudTrail

func (b *builder) trails(ctx context.Context, region string, api CloudTrailAPI, seen map[string]bool) {
	if api == nil {
		return
	}
	out, err := api.DescribeTrails(ctx, &cloudtrail.DescribeTrailsInput{IncludeShadowTrails: aws.Bool(false)})
	if err != nil {
		b.warn("cloudtrail "+region+" DescribeTrails", err)
		return
	}
	for _, t := range out.TrailList {
		arn := aws.ToString(t.TrailARN)
		if seen[arn] {
			continue
		}
		seen[arn] = true
		cfg := map[string]any{"is_multi_region_trail": aws.ToBool(t.IsMultiRegionTrail),
			"log_file_validation": aws.ToBool(t.LogFileValidationEnabled), "enable_logging": false}
		if st, err := api.GetTrailStatus(ctx, &cloudtrail.GetTrailStatusInput{Name: t.TrailARN}); err == nil {
			cfg["enable_logging"] = aws.ToBool(st.IsLogging)
		} else {
			b.warn("cloudtrail "+aws.ToString(t.Name)+" status", err)
		}
		reg := aws.ToString(t.HomeRegion)
		if reg == "" {
			reg = region
		}
		b.add(inventory.Resource{ResourceID: "aws_cloudtrail." + aws.ToString(t.Name), ResourceType: "aws_cloudtrail", Region: reg, Configuration: cfg})
	}
}

// ------------------------------------------------------------------ errors

func isCode(err error, code string) bool {
	var ae smithy.APIError
	return errors.As(err, &ae) && ae.ErrorCode() == code
}

// short keeps the AWS error code and message, without request IDs.
func short(err error) string {
	var ae smithy.APIError
	if errors.As(err, &ae) {
		return ae.ErrorCode() + ": " + ae.ErrorMessage()
	}
	s := err.Error()
	if i := strings.Index(s, ", https response error"); i > 0 {
		s = s[:i]
	}
	return s
}
