package collector

import (
	"context"
	"errors"
	"fmt"
	"sort"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	elb "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// Options select the credentials and scope of a collection.
type Options struct {
	Profile     string   // shared-config profile ("" = the default credential chain)
	Regions     []string // nil: the profile's region; ["all"]: every enabled region
	Endpoint    string   // custom endpoint for every service (an emulator such as moto); "" for AWS
	AccountName string
	Environment string
}

// New builds a collector over real AWS clients. It asks STS which account
// the credentials belong to, so a snapshot is never filed under the wrong one.
func New(ctx context.Context, o Options) (*AWS, error) {
	opts := []func(*config.LoadOptions) error{}
	if o.Profile != "" {
		opts = append(opts, config.WithSharedConfigProfile(o.Profile))
	}
	cfg, err := config.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("load AWS configuration: %w", err)
	}
	if o.Endpoint != "" {
		cfg.BaseEndpoint = aws.String(o.Endpoint)
	}
	home := cfg.Region
	if home == "" {
		home = "us-east-1"
		cfg.Region = home
	}
	id, err := sts.NewFromConfig(cfg).GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return nil, fmt.Errorf("identify the account (sts:GetCallerIdentity): %s", short(err))
	}
	regions := o.Regions
	switch {
	case len(regions) == 0:
		regions = []string{home}
	case len(regions) == 1 && regions[0] == "all":
		out, err := ec2.NewFromConfig(cfg).DescribeRegions(ctx, &ec2.DescribeRegionsInput{})
		if err != nil {
			return nil, fmt.Errorf("list regions: %s", short(err))
		}
		regions = regions[:0]
		for _, r := range out.Regions {
			regions = append(regions, aws.ToString(r.RegionName))
		}
		sort.Strings(regions)
	}
	if len(regions) == 0 {
		return nil, errors.New("no regions to collect")
	}
	inRegion := func(r string) aws.Config { c := cfg.Copy(); c.Region = r; return c }
	return &AWS{
		AccountID: aws.ToString(id.Account), AccountName: o.AccountName, Environment: o.Environment,
		Regions: regions, HomeRegion: home,
		IAM: iam.NewFromConfig(cfg),
		Region: func(r string) Regional {
			c := inRegion(r)
			return Regional{
				S3:         s3.NewFromConfig(c, func(so *s3.Options) { so.UsePathStyle = o.Endpoint != "" }),
				EC2:        ec2.NewFromConfig(c),
				RDS:        rds.NewFromConfig(c),
				CloudTrail: cloudtrail.NewFromConfig(c),
				ELB:        elb.NewFromConfig(c),
			}
		},
	}, nil
}
