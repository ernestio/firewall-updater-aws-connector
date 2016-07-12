/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"reflect"
	"runtime"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/nats-io/nats"
)

var nc *nats.Conn
var natsErr error

func processEvent(data []byte) (*Event, error) {
	var ev Event
	err := json.Unmarshal(data, &ev)
	return &ev, err
}

func eventHandler(m *nats.Msg) {
	f, err := processEvent(m.Data)
	if err != nil {
		nc.Publish("firewall.update.aws.error", m.Data)
		return
	}

	if f.Valid() == false {
		f.Error(errors.New("Security Group is invalid"))
		return
	}

	err = updateFirewall(f)
	if err != nil {
		f.Error(err)
		return
	}

	f.Complete()
}

func ruleExists(rule *ec2.IpPermission, ruleset []*ec2.IpPermission) bool {
	for _, r := range ruleset {
		if reflect.DeepEqual(*r, *rule) {
			return true
		}
	}
	return false
}

func buildPermissions(rules []rule) []*ec2.IpPermission {
	var perms []*ec2.IpPermission
	for _, rule := range rules {
		p := ec2.IpPermission{
			FromPort:   aws.Int64(rule.FromPort),
			ToPort:     aws.Int64(rule.ToPort),
			IpProtocol: aws.String(rule.Protocol),
		}
		ip := ec2.IpRange{CidrIp: aws.String(rule.IP)}
		p.IpRanges = append(p.IpRanges, &ip)
		perms = append(perms, &p)
	}
	return perms
}

func buildRevokePermissions(old, new []*ec2.IpPermission) []*ec2.IpPermission {
	var revoked []*ec2.IpPermission
	for _, rule := range old {
		if ruleExists(rule, new) != true {
			revoked = append(revoked, rule)
		}
	}
	return revoked
}

func securityGroupByID(svc *ec2.EC2, id string) (*ec2.SecurityGroup, error) {
	f := []*ec2.Filter{
		&ec2.Filter{
			Name:   aws.String("group-id"),
			Values: []*string{aws.String(id)},
		},
	}

	req := ec2.DescribeSecurityGroupsInput{Filters: f}
	resp, err := svc.DescribeSecurityGroups(&req)
	if err != nil {
		return nil, err
	}

	if len(resp.SecurityGroups) != 1 {
		return nil, errors.New("Could not find security group")
	}

	return resp.SecurityGroups[0], nil
}

func removeExistingRules(rules []*ec2.IpPermission, old []*ec2.IpPermission) []*ec2.IpPermission {
	for i, rule := range rules {
		if ruleExists(rule, old) {
			rules = append(rules[:i], rules[i+1:]...)
		}
	}
	return rules
}

func updateFirewall(ev *Event) error {
	creds := credentials.NewStaticCredentials(ev.DatacenterAccessKey, ev.DatacenterAccessToken, "")
	svc := ec2.New(session.New(), &aws.Config{
		Region:      aws.String(ev.DatacenterRegion),
		Credentials: creds,
	})

	sg, err := securityGroupByID(svc, ev.SecurityGroupAWSID)
	if err != nil {
		return err
	}

	newIngressRules := buildPermissions(ev.SecurityGroupRules.Ingress)
	newEgressRules := buildPermissions(ev.SecurityGroupRules.Egress)
	revokeIngressRules := buildRevokePermissions(sg.IpPermissions, newIngressRules)
	revokeEgressRules := buildRevokePermissions(sg.IpPermissionsEgress, newEgressRules)
	newIngressRules = removeExistingRules(newIngressRules, sg.IpPermissions)
	newEgressRules = removeExistingRules(newEgressRules, sg.IpPermissionsEgress)

	// Revoke Ingress
	if len(revokeIngressRules) > 0 {
		iReq := ec2.RevokeSecurityGroupIngressInput{
			GroupId:       aws.String(ev.SecurityGroupAWSID),
			IpPermissions: revokeIngressRules,
		}

		_, err := svc.RevokeSecurityGroupIngress(&iReq)
		if err != nil {
			return err
		}
	}

	// Revoke Egress
	if len(revokeEgressRules) > 0 {
		eReq := ec2.RevokeSecurityGroupEgressInput{
			GroupId:       aws.String(ev.SecurityGroupAWSID),
			IpPermissions: revokeEgressRules,
		}
		_, err := svc.RevokeSecurityGroupEgress(&eReq)
		if err != nil {
			return err
		}
	}

	// Authorize Ingress
	if len(newIngressRules) > 0 {
		iReq := ec2.AuthorizeSecurityGroupIngressInput{
			GroupId:       aws.String(ev.SecurityGroupAWSID),
			IpPermissions: newIngressRules,
		}

		_, err := svc.AuthorizeSecurityGroupIngress(&iReq)
		if err != nil {
			return err
		}
	}

	// Authorize Egress
	if len(newEgressRules) > 0 {
		eReq := ec2.AuthorizeSecurityGroupEgressInput{
			GroupId:       aws.String(ev.SecurityGroupAWSID),
			IpPermissions: newEgressRules,
		}

		_, err := svc.AuthorizeSecurityGroupEgress(&eReq)
		if err != nil {
			return err
		}
	}

	return nil
}

func main() {
	natsURI := os.Getenv("NATS_URI")
	if natsURI == "" {
		natsURI = nats.DefaultURL
	}

	nc, natsErr = nats.Connect(natsURI)
	if natsErr != nil {
		log.Fatal(natsErr)
	}

	fmt.Println("listening for firewall.update.aws")
	nc.Subscribe("firewall.update.aws", eventHandler)

	runtime.Goexit()
}
