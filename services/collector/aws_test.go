package collector

import (
	"context"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/smithy-go"
)

func TestStatementsAcceptEveryDocumentShape(t *testing.T) {
	// IAM returns documents URL-encoded; Statement, Action and Resource may
	// each be a single value or a list.
	single := url.QueryEscape(`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"*","Resource":"*"}}`)
	got := statements(single)
	want := []any{map[string]any{"effect": "Allow", "actions": []any{"*"}, "resources": []any{"*"}}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("single statement: %v", got)
	}
	list := `{"Statement":[{"Effect":"Allow","Action":["s3:GetObject","s3:PutObject"],"Resource":["arn:aws:s3:::b/*"]},{"Effect":"Deny","Action":"*","Resource":"*"}]}`
	if got := statements(list); len(got) != 2 || got[1].(map[string]any)["effect"] != "Deny" {
		t.Errorf("statement list: %v", got)
	}
	if got := statements("not json"); len(got) != 0 {
		t.Errorf("garbage: %v", got)
	}
}

func TestTrustedService(t *testing.T) {
	for doc, want := range map[string]string{
		`{"Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}`:          "ec2.amazonaws.com",
		`{"Statement":[{"Effect":"Allow","Principal":{"Service":["lambda.amazonaws.com","x"]},"Action":"sts:AssumeRole"}]}`: "lambda.amazonaws.com",
		`{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123456789012:root"},"Action":"sts:AssumeRole"}]}`: "",
	} {
		if got := trustedService(doc); got != want {
			t.Errorf("%s -> %q, want %q", doc, got, want)
		}
	}
}

func TestIngressShape(t *testing.T) {
	got := ingress([]ec2types.IpPermission{
		{IpProtocol: aws.String("tcp"), FromPort: aws.Int32(22), ToPort: aws.Int32(22), IpRanges: []ec2types.IpRange{{CidrIp: aws.String("0.0.0.0/0")}}},
		{IpProtocol: aws.String("-1"), Ipv6Ranges: []ec2types.Ipv6Range{{CidrIpv6: aws.String("::/0")}}},
	})
	want := []any{
		map[string]any{"protocol": "tcp", "from_port": 22, "to_port": 22, "cidr_blocks": []any{"0.0.0.0/0"}},
		// All traffic: AWS omits the ports, the policies need the full range.
		map[string]any{"protocol": "-1", "from_port": 0, "to_port": 65535, "ipv6_cidr_blocks": []any{"::/0"}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ingress = %v", got)
	}
}

func TestBucketRegion(t *testing.T) {
	for loc, want := range map[string]string{"": "us-east-1", "EU": "eu-west-1", "ap-south-1": "ap-south-1"} {
		if got := bucketRegion(loc); got != want {
			t.Errorf("%q -> %q", loc, got)
		}
	}
}

// deniedEC2 answers every call with AccessDenied, like a role without EC2 rights.
type deniedEC2 struct{}

var errDenied = &smithy.GenericAPIError{Code: "UnauthorizedOperation", Message: "You are not authorized to perform this operation."}

func (deniedEC2) DescribeVpcs(context.Context, *ec2.DescribeVpcsInput, ...func(*ec2.Options)) (*ec2.DescribeVpcsOutput, error) {
	return nil, errDenied
}
func (deniedEC2) DescribeSubnets(context.Context, *ec2.DescribeSubnetsInput, ...func(*ec2.Options)) (*ec2.DescribeSubnetsOutput, error) {
	return nil, errDenied
}
func (deniedEC2) DescribeSecurityGroups(context.Context, *ec2.DescribeSecurityGroupsInput, ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error) {
	return nil, errDenied
}
func (deniedEC2) DescribeInstances(context.Context, *ec2.DescribeInstancesInput, ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error) {
	return nil, errDenied
}

// A service the credentials cannot read is a warning, not a failure: the
// rest of the account is still collected.
func TestUnreadableServiceIsAWarning(t *testing.T) {
	c := &AWS{AccountID: "123456789012", Regions: []string{"eu-west-1"}, Now: func() time.Time { return time.Unix(0, 0) },
		Region: func(string) Regional { return Regional{EC2: deniedEC2{}} }}
	snap, warnings, err := c.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.Resources) != 0 || len(warnings) != 1 || !strings.Contains(warnings[0], "UnauthorizedOperation") {
		t.Fatalf("resources=%d warnings=%v", len(snap.Resources), warnings)
	}
	if snap.Source != "aws" || snap.Account.Name != "aws-123456789012" {
		t.Errorf("snapshot header: %+v", snap.Account)
	}
}
