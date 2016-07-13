/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package main

import (
	"errors"
	"fmt"
	"log"
	"os"
	"runtime"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/nats-io/nats"
)

var nc *nats.Conn
var natsErr error

func eventHandler(m *nats.Msg) {
	var f Event

	err := f.Process(m.Data)
	if err != nil {
		return
	}

	if err = f.Validate(); err != nil {
		f.Error(err)
		return
	}

	err = updateFirewall(&f)
	if err != nil {
		f.Error(err)
		return
	}

	f.Complete()
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

	// generate the new rulesets
	newIngressRules := buildPermissions(ev.SecurityGroupRules.Ingress)
	newEgressRules := buildPermissions(ev.SecurityGroupRules.Egress)

	// generate the rules to remove
	revokeIngressRules := buildRevokePermissions(sg.IpPermissions, newIngressRules)
	revokeEgressRules := buildRevokePermissions(sg.IpPermissionsEgress, newEgressRules)

	// remove already existing rules from the new ruleset
	newIngressRules = deduplicateRules(newIngressRules, sg.IpPermissions)
	newEgressRules = deduplicateRules(newEgressRules, sg.IpPermissionsEgress)

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
