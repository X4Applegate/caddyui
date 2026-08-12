package dns

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	awsroute53 "github.com/aws/aws-sdk-go-v2/service/route53"
	"github.com/aws/aws-sdk-go-v2/service/route53/types"
)

const (
	route53DefaultRegion = "us-east-1"
	route53RecordPrefix  = "r53:"
)

// route53API is the small AWS SDK surface used by the provider. Keeping it as
// an interface makes record lifecycle behavior testable without AWS
// credentials or network access.
type route53API interface {
	ListHostedZones(context.Context, *awsroute53.ListHostedZonesInput, ...func(*awsroute53.Options)) (*awsroute53.ListHostedZonesOutput, error)
	ListResourceRecordSets(context.Context, *awsroute53.ListResourceRecordSetsInput, ...func(*awsroute53.Options)) (*awsroute53.ListResourceRecordSetsOutput, error)
	ChangeResourceRecordSets(context.Context, *awsroute53.ChangeResourceRecordSetsInput, ...func(*awsroute53.Options)) (*awsroute53.ChangeResourceRecordSetsOutput, error)
}

// route53Provider manages public Amazon Route 53 hosted zones. Route 53 does
// not assign IDs to record sets, so CaddyUI stores a URL-safe, opaque encoding
// of the complete ResourceRecordSet. AWS requires that exact shape for DELETE,
// including aliases and non-simple routing policies.
type route53Provider struct {
	client route53API
}

func init() {
	Register(Descriptor{
		ID:          Route53,
		DisplayName: "Amazon Route 53",
		DocsAnchor:  "route53",
		Credentials: []CredentialField{
			{
				Key:         "route53_access_key_id",
				Label:       "Access Key ID",
				Help:        "IAM access key with Route 53 list and record-set permissions.",
				Placeholder: "AKIA...",
			},
			{
				Key:         "route53_secret_access_key",
				Label:       "Secret Access Key",
				Help:        "The secret paired with the IAM access key above.",
				Placeholder: "paste secret key here",
				Secret:      true,
			},
			{
				Key:         "route53_session_token",
				Label:       "Session Token",
				Help:        "Only required for temporary STS credentials. Leave blank for ordinary IAM access keys.",
				Placeholder: "optional STS session token",
				Secret:      true,
				Optional:    true,
			},
			{
				Key:         "route53_region",
				Label:       "AWS Region",
				Help:        "Optional for standard Route 53 accounts. Defaults to us-east-1; set the partition-appropriate region for GovCloud or China.",
				Placeholder: route53DefaultRegion,
				Optional:    true,
			},
		},
		Factory: func(creds map[string]string) Provider {
			accessKey := strings.TrimSpace(creds["route53_access_key_id"])
			secretKey := strings.TrimSpace(creds["route53_secret_access_key"])
			if accessKey == "" || secretKey == "" {
				return nil
			}
			region := strings.TrimSpace(creds["route53_region"])
			if region == "" {
				region = route53DefaultRegion
			}
			cfg := aws.Config{
				Region: region,
				Credentials: aws.NewCredentialsCache(credentials.NewStaticCredentialsProvider(
					accessKey,
					secretKey,
					strings.TrimSpace(creds["route53_session_token"]),
				)),
				HTTPClient: &http.Client{Timeout: 15 * time.Second},
			}
			return &route53Provider{client: awsroute53.NewFromConfig(cfg)}
		},
	})
}

func (r *route53Provider) ID() string          { return Route53 }
func (r *route53Provider) DisplayName() string { return "Amazon Route 53" }

func (r *route53Provider) Ping() (string, error) {
	zones, err := r.ListZones()
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("ok (%d public hosted zones accessible)", len(zones)), nil
}

func (r *route53Provider) ListZones() ([]Zone, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	input := &awsroute53.ListHostedZonesInput{MaxItems: aws.Int32(100)}
	var out []Zone
	for {
		page, err := r.client.ListHostedZones(ctx, input)
		if err != nil {
			return nil, fmt.Errorf("route53: list hosted zones: %w", err)
		}
		for _, hosted := range page.HostedZones {
			// Public ACME DNS-01 validation cannot see a private hosted zone.
			// Hiding private zones also avoids ambiguous duplicate zone names in
			// the picker when an account has split-horizon DNS.
			if hosted.Config != nil && hosted.Config.PrivateZone {
				continue
			}
			id := normalizeRoute53ZoneID(aws.ToString(hosted.Id))
			name := normalizeRoute53Name(aws.ToString(hosted.Name))
			if id == "" || name == "" {
				continue
			}
			out = append(out, Zone{ID: id, Name: name})
		}
		if !page.IsTruncated || page.NextMarker == nil {
			break
		}
		input.Marker = page.NextMarker
	}
	return out, nil
}

func (r *route53Provider) CreateRecord(zone Zone, fqdn, content, rtype string, ttl int) (*Record, error) {
	if ttl <= 0 {
		ttl = 300
	}
	set := types.ResourceRecordSet{
		Name: aws.String(normalizeRoute53Name(fqdn)),
		Type: types.RRType(strings.ToUpper(strings.TrimSpace(rtype))),
		TTL:  aws.Int64(int64(ttl)),
		ResourceRecords: []types.ResourceRecord{
			{Value: aws.String(strings.TrimSpace(content))},
		},
	}
	if aws.ToString(set.Name) == "" || set.Type == "" || strings.TrimSpace(content) == "" {
		return nil, fmt.Errorf("route53: record name, type, and content are required")
	}
	if err := r.changeRecord(zone.ID, types.ChangeActionCreate, set); err != nil {
		return nil, err
	}
	id, err := encodeRoute53Record(set)
	if err != nil {
		return nil, err
	}
	return &Record{
		ID:      id,
		Name:    normalizeRoute53Name(fqdn),
		Type:    string(set.Type),
		Content: strings.TrimSpace(content),
		TTL:     ttl,
	}, nil
}

func (r *route53Provider) DeleteRecord(zone Zone, recordID string) error {
	set, err := decodeRoute53Record(recordID)
	if err != nil {
		return err
	}
	// Traffic Flow records must be removed through DeleteTrafficPolicyInstance;
	// deleting only the generated record set leaves a billable orphan.
	if strings.TrimSpace(aws.ToString(set.TrafficPolicyInstanceId)) != "" {
		return fmt.Errorf("route53: refusing to delete a Traffic Flow managed record; remove its traffic policy instance in AWS")
	}
	return r.changeRecord(zone.ID, types.ChangeActionDelete, set)
}

func (r *route53Provider) FindRecord(zone Zone, fqdn string) ([]Record, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	want := normalizeRoute53Name(fqdn)
	input := &awsroute53.ListResourceRecordSetsInput{
		HostedZoneId:    aws.String(normalizeRoute53ZoneID(zone.ID)),
		StartRecordName: aws.String(want),
		MaxItems:        aws.Int32(300),
	}
	var out []Record
	for {
		page, err := r.client.ListResourceRecordSets(ctx, input)
		if err != nil {
			return nil, fmt.Errorf("route53: list records in %s: %w", zone.Name, err)
		}
		for _, set := range page.ResourceRecordSets {
			if !strings.EqualFold(normalizeRoute53Name(aws.ToString(set.Name)), want) {
				// StartRecordName positions the page at the first name >= want;
				// record sets with the same name are contiguous.
				return out, nil
			}
			id, err := encodeRoute53Record(set)
			if err != nil {
				return nil, err
			}
			values := make([]string, 0, len(set.ResourceRecords))
			for _, value := range set.ResourceRecords {
				values = append(values, aws.ToString(value.Value))
			}
			if set.AliasTarget != nil {
				values = append(values, aws.ToString(set.AliasTarget.DNSName))
			}
			out = append(out, Record{
				ID:      id,
				Name:    want,
				Type:    string(set.Type),
				Content: strings.Join(values, ", "),
				TTL:     int(aws.ToInt64(set.TTL)),
			})
		}
		if !page.IsTruncated || page.NextRecordName == nil ||
			!strings.EqualFold(normalizeRoute53Name(aws.ToString(page.NextRecordName)), want) {
			break
		}
		input.StartRecordName = page.NextRecordName
		input.StartRecordType = page.NextRecordType
		input.StartRecordIdentifier = page.NextRecordIdentifier
	}
	return out, nil
}

func (r *route53Provider) changeRecord(zoneID string, action types.ChangeAction, set types.ResourceRecordSet) error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_, err := r.client.ChangeResourceRecordSets(ctx, &awsroute53.ChangeResourceRecordSetsInput{
		HostedZoneId: aws.String(normalizeRoute53ZoneID(zoneID)),
		ChangeBatch: &types.ChangeBatch{Changes: []types.Change{
			{Action: action, ResourceRecordSet: &set},
		}},
	})
	if err != nil {
		return fmt.Errorf("route53: %s record %s in zone %s: %w",
			strings.ToLower(string(action)), normalizeRoute53Name(aws.ToString(set.Name)), zoneID, err)
	}
	return nil
}

func normalizeRoute53Name(name string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
}

func normalizeRoute53ZoneID(id string) string {
	id = strings.TrimSpace(id)
	return strings.TrimPrefix(id, "/hostedzone/")
}

func encodeRoute53Record(set types.ResourceRecordSet) (string, error) {
	body, err := json.Marshal(set)
	if err != nil {
		return "", fmt.Errorf("route53: encode record identifier: %w", err)
	}
	return route53RecordPrefix + base64.RawURLEncoding.EncodeToString(body), nil
}

func decodeRoute53Record(recordID string) (types.ResourceRecordSet, error) {
	var set types.ResourceRecordSet
	if !strings.HasPrefix(recordID, route53RecordPrefix) {
		return set, fmt.Errorf("route53: invalid record identifier")
	}
	body, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(recordID, route53RecordPrefix))
	if err != nil {
		return set, fmt.Errorf("route53: decode record identifier: %w", err)
	}
	if err := json.Unmarshal(body, &set); err != nil {
		return set, fmt.Errorf("route53: decode record identifier: %w", err)
	}
	if strings.TrimSpace(aws.ToString(set.Name)) == "" || set.Type == "" {
		return set, fmt.Errorf("route53: invalid record identifier payload")
	}
	return set, nil
}
