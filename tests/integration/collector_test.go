package integration

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"

	"github.com/manishaacharyahere/aegis-cloud-governance/services/collector"
	"github.com/manishaacharyahere/aegis-cloud-governance/services/compliance"
	"github.com/manishaacharyahere/aegis-cloud-governance/services/inventory"
)

// The collector reads a real AWS API (moto, a free AWS emulator, in tests):
// insecure resources created there must come out of Aegis as the matching
// policy violations, and secure ones must not.
func TestCollectorFindsRealMisconfigurations(t *testing.T) {
	endpoint, opaURL := os.Getenv("AEGIS_TEST_AWS_ENDPOINT"), os.Getenv("AEGIS_TEST_OPA_URL")
	if endpoint == "" || opaURL == "" {
		t.Skip("AEGIS_TEST_AWS_ENDPOINT and AEGIS_TEST_OPA_URL not set")
	}
	// Fake credentials; never a developer's real profile.
	dir := t.TempDir()
	t.Setenv("AWS_ACCESS_KEY_ID", "testing")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "testing")
	t.Setenv("AWS_REGION", "us-east-1")
	t.Setenv("AWS_CONFIG_FILE", filepath.Join(dir, "config"))
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", filepath.Join(dir, "credentials"))
	ctx := context.Background()
	if res, err := http.Post(endpoint+"/moto-api/reset", "application/json", nil); err == nil {
		res.Body.Close()
	}
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		t.Fatal(err)
	}
	cfg.BaseEndpoint = aws.String(endpoint)
	seedAWS(t, ctx, cfg)

	c, err := collector.New(ctx, collector.Options{Endpoint: endpoint, Regions: []string{"us-east-1"}, AccountName: "moto", Environment: "production"})
	if err != nil {
		t.Fatal(err)
	}
	snap, warnings, err := c.Collect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, w := range warnings {
		t.Log("collector warning:", w)
	}
	if err := inventory.Validate(snap, snap.CapturedAt); err != nil {
		t.Fatalf("collected snapshot is invalid: %v", err)
	}
	byID := map[string]inventory.Resource{}
	for _, r := range snap.Resources {
		byID[r.ResourceID] = r
	}
	for _, id := range []string{"aws_s3_bucket.aegis-public-data", "aws_s3_bucket.aegis-locked-data", "aws_db_instance.orders",
		"aws_iam_policy.everything", "aws_iam_role.app", "aws_cloudtrail.audit"} {
		if _, ok := byID[id]; !ok {
			t.Errorf("%s was not collected", id)
		}
	}
	if !hasEdge(byID["aws_iam_policy.everything"], "attached_to", "aws_iam_role.app") {
		t.Error("policy attachment edge missing")
	}

	pool, inv := migratedPool(t)
	if _, err := inv.Import(ctx, "demo", "collector", snap); err != nil {
		t.Fatalf("import: %v", err)
	}
	cat, err := compliance.LoadCatalog()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := (&compliance.Service{Pool: pool, Catalog: cat, OPA: testOPA(opaURL)}).EvaluateInventory(ctx, "demo", "tester"); err != nil {
		t.Fatal(err)
	}
	rows, err := pool.Query(ctx, `SELECT rule_id || ' ' || subject FROM compliance_evaluations WHERE result = 'fail'`)
	if err != nil {
		t.Fatal(err)
	}
	failing := map[string]bool{}
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			t.Fatal(err)
		}
		failing[s] = true
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	sg := sgID(t, byID, "ssh-open")
	for _, want := range []string{
		"AEGIS-S3-001 aws_s3_bucket.aegis-public-data",
		"AEGIS-DB-001 aws_db_instance.orders",
		"AEGIS-DB-002 aws_db_instance.orders",
		"AEGIS-IAM-001 aws_iam_policy.everything",
		"AEGIS-NET-001 " + sg,
		"AEGIS-LOG-001 aws_cloudtrail.audit",
	} {
		if !failing[want] {
			t.Errorf("expected failure %q", want)
		}
	}
	for _, unwanted := range []string{"AEGIS-S3-001 aws_s3_bucket.aegis-locked-data", "AEGIS-S3-002 aws_s3_bucket.aegis-locked-data",
		"AEGIS-ENC-001 aws_s3_bucket.aegis-locked-data"} {
		if failing[unwanted] {
			t.Errorf("secure bucket reported: %q", unwanted)
		}
	}
}

func hasEdge(r inventory.Resource, typ, target string) bool {
	for _, e := range r.Relationships {
		if e.Type == typ && e.TargetID == target {
			return true
		}
	}
	return false
}

func sgID(t *testing.T, byID map[string]inventory.Resource, name string) string {
	t.Helper()
	for id, r := range byID {
		if r.ResourceType == "aws_security_group" && r.Configuration["name"] == name {
			return id
		}
	}
	t.Fatalf("security group %s not collected", name)
	return ""
}

// seedAWS creates a small account with known good and bad settings.
func seedAWS(t *testing.T, ctx context.Context, cfg aws.Config) {
	t.Helper()
	must := func(_ any, err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	s3c := s3.NewFromConfig(cfg, func(o *s3.Options) { o.UsePathStyle = true })
	must(s3c.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: aws.String("aegis-public-data")}))
	must(s3c.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: aws.String("aegis-locked-data")}))
	must(s3c.PutPublicAccessBlock(ctx, &s3.PutPublicAccessBlockInput{Bucket: aws.String("aegis-locked-data"),
		PublicAccessBlockConfiguration: &s3types.PublicAccessBlockConfiguration{BlockPublicAcls: aws.Bool(true),
			BlockPublicPolicy: aws.Bool(true), IgnorePublicAcls: aws.Bool(true), RestrictPublicBuckets: aws.Bool(true)}}))
	must(s3c.PutBucketVersioning(ctx, &s3.PutBucketVersioningInput{Bucket: aws.String("aegis-locked-data"),
		VersioningConfiguration: &s3types.VersioningConfiguration{Status: s3types.BucketVersioningStatusEnabled}}))
	must(s3c.PutBucketEncryption(ctx, &s3.PutBucketEncryptionInput{Bucket: aws.String("aegis-locked-data"),
		ServerSideEncryptionConfiguration: &s3types.ServerSideEncryptionConfiguration{Rules: []s3types.ServerSideEncryptionRule{{
			ApplyServerSideEncryptionByDefault: &s3types.ServerSideEncryptionByDefault{SSEAlgorithm: s3types.ServerSideEncryptionAwsKms}}}}}))

	e := ec2.NewFromConfig(cfg)
	vpc, err := e.CreateVpc(ctx, &ec2.CreateVpcInput{CidrBlock: aws.String("10.20.0.0/16")})
	if err != nil {
		t.Fatal(err)
	}
	sub, err := e.CreateSubnet(ctx, &ec2.CreateSubnetInput{VpcId: vpc.Vpc.VpcId, CidrBlock: aws.String("10.20.1.0/24")})
	if err != nil {
		t.Fatal(err)
	}
	sg, err := e.CreateSecurityGroup(ctx, &ec2.CreateSecurityGroupInput{GroupName: aws.String("ssh-open"), Description: aws.String("test"), VpcId: vpc.Vpc.VpcId})
	if err != nil {
		t.Fatal(err)
	}
	must(e.AuthorizeSecurityGroupIngress(ctx, &ec2.AuthorizeSecurityGroupIngressInput{GroupId: sg.GroupId, IpPermissions: []ec2types.IpPermission{{
		IpProtocol: aws.String("tcp"), FromPort: aws.Int32(22), ToPort: aws.Int32(22), IpRanges: []ec2types.IpRange{{CidrIp: aws.String("0.0.0.0/0")}}}}}))
	imgs, err := e.DescribeImages(ctx, &ec2.DescribeImagesInput{})
	if err != nil || len(imgs.Images) == 0 {
		t.Fatalf("no emulator images: %v", err)
	}
	must(e.RunInstances(ctx, &ec2.RunInstancesInput{ImageId: imgs.Images[0].ImageId, MinCount: aws.Int32(1), MaxCount: aws.Int32(1),
		InstanceType: ec2types.InstanceTypeT3Micro, SubnetId: sub.Subnet.SubnetId, SecurityGroupIds: []string{aws.ToString(sg.GroupId)}}))

	must(rds.NewFromConfig(cfg).CreateDBInstance(ctx, &rds.CreateDBInstanceInput{DBInstanceIdentifier: aws.String("orders"),
		DBInstanceClass: aws.String("db.t3.micro"), Engine: aws.String("postgres"), AllocatedStorage: aws.Int32(20),
		MasterUsername: aws.String("app"), MasterUserPassword: aws.String("not-a-real-password-1"),
		PubliclyAccessible: aws.Bool(true), StorageEncrypted: aws.Bool(false)}))

	ic := iam.NewFromConfig(cfg)
	must(ic.CreateRole(ctx, &iam.CreateRoleInput{RoleName: aws.String("app"),
		AssumeRolePolicyDocument: aws.String(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}`)}))
	pol, err := ic.CreatePolicy(ctx, &iam.CreatePolicyInput{PolicyName: aws.String("everything"),
		PolicyDocument: aws.String(`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"*","Resource":"*"}}`)})
	if err != nil {
		t.Fatal(err)
	}
	must(ic.AttachRolePolicy(ctx, &iam.AttachRolePolicyInput{RoleName: aws.String("app"), PolicyArn: pol.Policy.Arn}))

	must(s3c.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: aws.String("aegis-trail-logs")}))
	// Created but never started: logging is off.
	must(cloudtrail.NewFromConfig(cfg).CreateTrail(ctx, &cloudtrail.CreateTrailInput{Name: aws.String("audit"), S3BucketName: aws.String("aegis-trail-logs")}))
}
