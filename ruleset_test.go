/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package main

import (
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ec2"
	. "github.com/smartystreets/goconvey/convey"
)

var (
	testOldRuleset = []*ec2.IpPermission{
		&ec2.IpPermission{
			IpRanges: []*ec2.IpRange{
				&ec2.IpRange{
					CidrIp: aws.String("10.0.10.100/32"),
				},
			},
			FromPort:   aws.Int64(80),
			ToPort:     aws.Int64(8080),
			IpProtocol: aws.String("tcp"),
		},
		&ec2.IpPermission{
			IpRanges: []*ec2.IpRange{
				&ec2.IpRange{
					CidrIp: aws.String("10.0.0.0/32"),
				},
			},
			FromPort:   aws.Int64(1024),
			ToPort:     aws.Int64(1024),
			IpProtocol: aws.String("tcp"),
		},
	}
	testNewRuleset = []*ec2.IpPermission{
		&ec2.IpPermission{
			IpRanges: []*ec2.IpRange{
				&ec2.IpRange{
					CidrIp: aws.String("10.0.10.100/32"),
				},
			},
			FromPort:   aws.Int64(80),
			ToPort:     aws.Int64(8080),
			IpProtocol: aws.String("tcp"),
		},
	}
)

func TestRuleset(t *testing.T) {
	ev := testEvent
	buildTestRules(&ev)

	Convey("Given an ruleset", t, func() {
		Convey("When mapping to IpPermissions", func() {
			ruleset := buildPermissions(ev.Rules("ingress"))
			Convey("It should produce the correct output", func() {
				So(len(ruleset), ShouldEqual, 1)
				So(*ruleset[0].IpRanges[0].CidrIp, ShouldEqual, "10.0.10.100/32")
				So(*ruleset[0].FromPort, ShouldEqual, 80)
				So(*ruleset[0].ToPort, ShouldEqual, 8080)
				So(*ruleset[0].IpProtocol, ShouldEqual, "tcp")
			})
		})

		Convey("When mapping IpPermissions to revoke", func() {
			revokeRuleset := buildRevokePermissions(testOldRuleset, testNewRuleset)
			Convey("It should produce the correct output", func() {
				So(len(revokeRuleset), ShouldEqual, 1)
				So(*revokeRuleset[0].FromPort, ShouldEqual, 1024)
				So(*revokeRuleset[0].ToPort, ShouldEqual, 1024)
				So(len(revokeRuleset[0].IpRanges), ShouldEqual, 1)
				So(*revokeRuleset[0].IpRanges[0].CidrIp, ShouldEqual, "10.0.0.0/32")
				So(*revokeRuleset[0].IpProtocol, ShouldEqual, "tcp")
			})
		})

		Convey("When deduplicating existing IpPermissions", func() {
			dedupeRuleset := deduplicateRules(testNewRuleset, testOldRuleset)
			Convey("It should produce the correct output", func() {
				So(len(dedupeRuleset), ShouldEqual, 0)
			})
		})

	})
}
