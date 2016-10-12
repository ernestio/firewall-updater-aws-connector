/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package main

import (
	"reflect"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ec2"
)

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

func deduplicateRules(rules, old []*ec2.IpPermission) []*ec2.IpPermission {
	for i := len(rules) - 1; i >= 0; i-- {
		if ruleExists(rules[i], old) {
			rules = append(rules[:i], rules[i+1:]...)
		}
	}
	return rules
}
