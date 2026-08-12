package dns

import (
	"context"
	"reflect"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsroute53 "github.com/aws/aws-sdk-go-v2/service/route53"
	"github.com/aws/aws-sdk-go-v2/service/route53/types"
)

type fakeRoute53 struct {
	listZonesPages []*awsroute53.ListHostedZonesOutput
	listRecords    *awsroute53.ListResourceRecordSetsOutput
	changes        []*awsroute53.ChangeResourceRecordSetsInput
	zoneCalls      int
}

func (f *fakeRoute53) ListHostedZones(context.Context, *awsroute53.ListHostedZonesInput, ...func(*awsroute53.Options)) (*awsroute53.ListHostedZonesOutput, error) {
	page := f.listZonesPages[f.zoneCalls]
	f.zoneCalls++
	return page, nil
}

func (f *fakeRoute53) ListResourceRecordSets(context.Context, *awsroute53.ListResourceRecordSetsInput, ...func(*awsroute53.Options)) (*awsroute53.ListResourceRecordSetsOutput, error) {
	return f.listRecords, nil
}

func (f *fakeRoute53) ChangeResourceRecordSets(_ context.Context, in *awsroute53.ChangeResourceRecordSetsInput, _ ...func(*awsroute53.Options)) (*awsroute53.ChangeResourceRecordSetsOutput, error) {
	f.changes = append(f.changes, in)
	return &awsroute53.ChangeResourceRecordSetsOutput{}, nil
}

func TestRoute53DescriptorCredentials(t *testing.T) {
	d, ok := Lookup(Route53)
	if !ok || d.DisplayName != "Amazon Route 53" {
		t.Fatalf("Route 53 descriptor = %#v, %v", d, ok)
	}
	creds := map[string]string{
		"route53_access_key_id":     "AKIAEXAMPLE",
		"route53_secret_access_key": "secret",
	}
	if !CredsComplete(Route53, creds) {
		t.Fatal("required access-key pair should be complete without optional region/session token")
	}
	delete(creds, "route53_secret_access_key")
	if CredsComplete(Route53, creds) {
		t.Fatal("missing secret access key should be incomplete")
	}
}

func TestRoute53ListZonesPaginatesAndSkipsPrivateZones(t *testing.T) {
	fake := &fakeRoute53{listZonesPages: []*awsroute53.ListHostedZonesOutput{
		{
			HostedZones: []types.HostedZone{
				{Id: aws.String("/hostedzone/ZPUBLIC1"), Name: aws.String("Example.COM.")},
				{Id: aws.String("/hostedzone/ZPRIVATE"), Name: aws.String("internal.example.com."), Config: &types.HostedZoneConfig{PrivateZone: true}},
			},
			IsTruncated: true,
			NextMarker:  aws.String("next"),
		},
		{
			HostedZones: []types.HostedZone{{Id: aws.String("/hostedzone/ZPUBLIC2"), Name: aws.String("example.net.")}},
		},
	}}
	p := &route53Provider{client: fake}
	zones, err := p.ListZones()
	if err != nil {
		t.Fatal(err)
	}
	want := []Zone{
		{ID: "ZPUBLIC1", Name: "example.com"},
		{ID: "ZPUBLIC2", Name: "example.net"},
	}
	if !reflect.DeepEqual(zones, want) {
		t.Fatalf("zones = %#v, want %#v", zones, want)
	}
}

func TestRoute53CreateAndDeleteRoundTrip(t *testing.T) {
	fake := &fakeRoute53{}
	p := &route53Provider{client: fake}
	zone := Zone{ID: "/hostedzone/Z123", Name: "example.com"}
	record, err := p.CreateRecord(zone, "App.Example.com.", "192.0.2.10", "a", 0)
	if err != nil {
		t.Fatal(err)
	}
	if record.Name != "app.example.com" || record.Type != "A" || record.TTL != 300 {
		t.Fatalf("record = %#v", record)
	}
	if len(fake.changes) != 1 {
		t.Fatalf("create changes = %d, want 1", len(fake.changes))
	}
	created := fake.changes[0].ChangeBatch.Changes[0]
	if created.Action != types.ChangeActionCreate || aws.ToString(created.ResourceRecordSet.Name) != "app.example.com" {
		t.Fatalf("create change = %#v", created)
	}
	if got := aws.ToString(fake.changes[0].HostedZoneId); got != "Z123" {
		t.Fatalf("create hosted zone ID = %q, want Z123", got)
	}
	if err := p.DeleteRecord(zone, record.ID); err != nil {
		t.Fatal(err)
	}
	if len(fake.changes) != 2 {
		t.Fatalf("all changes = %d, want 2", len(fake.changes))
	}
	deleted := fake.changes[1].ChangeBatch.Changes[0]
	if deleted.Action != types.ChangeActionDelete || !reflect.DeepEqual(deleted.ResourceRecordSet, created.ResourceRecordSet) {
		t.Fatalf("delete did not preserve exact record set\ncreated=%#v\ndeleted=%#v", created.ResourceRecordSet, deleted.ResourceRecordSet)
	}
}

func TestRoute53FindRecordPreservesAliasForOverride(t *testing.T) {
	alias := types.ResourceRecordSet{
		Name: aws.String("app.example.com."),
		Type: types.RRTypeA,
		AliasTarget: &types.AliasTarget{
			DNSName:              aws.String("dualstack.example.elb.amazonaws.com."),
			HostedZoneId:         aws.String("ZELB123"),
			EvaluateTargetHealth: true,
		},
	}
	fake := &fakeRoute53{listRecords: &awsroute53.ListResourceRecordSetsOutput{
		ResourceRecordSets: []types.ResourceRecordSet{alias, {Name: aws.String("other.example.com."), Type: types.RRTypeA}},
	}}
	p := &route53Provider{client: fake}
	records, err := p.FindRecord(Zone{ID: "Z123", Name: "example.com"}, "app.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0].Content != "dualstack.example.elb.amazonaws.com." {
		t.Fatalf("records = %#v", records)
	}
	if err := p.DeleteRecord(Zone{ID: "Z123", Name: "example.com"}, records[0].ID); err != nil {
		t.Fatal(err)
	}
	deleted := fake.changes[0].ChangeBatch.Changes[0].ResourceRecordSet
	if !reflect.DeepEqual(*deleted, alias) {
		t.Fatalf("alias delete = %#v, want %#v", *deleted, alias)
	}
}

func TestRoute53RejectsTrafficFlowDelete(t *testing.T) {
	set := types.ResourceRecordSet{
		Name:                    aws.String("app.example.com"),
		Type:                    types.RRTypeA,
		TrafficPolicyInstanceId: aws.String("tp-123"),
	}
	id, err := encodeRoute53Record(set)
	if err != nil {
		t.Fatal(err)
	}
	p := &route53Provider{client: &fakeRoute53{}}
	if err := p.DeleteRecord(Zone{ID: "Z123"}, id); err == nil {
		t.Fatal("Traffic Flow record delete should be refused")
	}
}
