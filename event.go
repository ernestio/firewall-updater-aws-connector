/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package main

import (
	"encoding/json"
	"errors"
	"log"
)

var (
	ErrDatacenterIDInvalid          = errors.New("Datacenter VPC ID invalid")
	ErrDatacenterRegionInvalid      = errors.New("Datacenter Region invalid")
	ErrDatacenterCredentialsInvalid = errors.New("Datacenter credentials invalid")
	ErrSGAWSIDInvalid               = errors.New("Security Group aws id invalid")
	ErrSGNameInvalid                = errors.New("Security Group name invalid")
	ErrSGRulesInvalid               = errors.New("Security Group must contain rules")
	ErrSGRuleTypeInvalid            = errors.New("Security Group rule type invalid")
	ErrSGRuleIPInvalid              = errors.New("Security Group rule ip invalid")
	ErrSGRuleProtocolInvalid        = errors.New("Security Group rule protocol invalid")
	ErrSGRuleFromPortInvalid        = errors.New("Security Group rule from port invalid")
	ErrSGRuleToPortInvalid          = errors.New("Security Group rule to port invalid")
)

type rule struct {
	Type     string `json:"type"`
	IP       string `json:"source_ip"`
	FromPort int64  `json:"source_port"`
	ToPort   int64  `json:"destination_port"`
	Protocol string `json:"protocol"`
}

// Event stores the firewall data
type Event struct {
	UUID                  string `json:"_uuid"`
	BatchID               string `json:"_batch_id"`
	ProviderType          string `json:"_type"`
	DatacenterVPCID       string `json:"datacenter_vpc_id"`
	DatacenterRegion      string `json:"datacenter_region"`
	DatacenterAccessKey   string `json:"datacenter_access_key"`
	DatacenterAccessToken string `json:"datacenter_access_token"`
	NetworkAWSID          string `json:"network_aws_id"`
	SecurityGroupAWSID    string `json:"security_group_aws_id,omitempty"`
	SecurityGroupName     string `json:"name"`
	SecurityGroupRules    []rule `json:"rules"`
	ErrorMessage          string `json:"error,omitempty"`
}

// Rules returns a ruleset that matches a corresponding type
func (ev *Event) Rules(t string) []rule {
	var rules []rule

	for _, rule := range ev.SecurityGroupRules {
		if rule.Type == t {
			rules = append(rules, rule)
		}
	}

	return rules
}

// Validate checks if all criteria are met
func (ev *Event) Validate() error {
	if ev.DatacenterVPCID == "" {
		return ErrDatacenterIDInvalid
	}

	if ev.DatacenterRegion == "" {
		return ErrDatacenterRegionInvalid
	}

	if ev.DatacenterAccessKey == "" || ev.DatacenterAccessToken == "" {
		return ErrDatacenterCredentialsInvalid
	}

	if ev.SecurityGroupAWSID == "" {
		return ErrSGAWSIDInvalid
	}

	if ev.SecurityGroupName == "" {
		return ErrSGNameInvalid
	}

	if len(ev.SecurityGroupRules) < 1 {
		return ErrSGRulesInvalid
	}

	for _, rule := range ev.SecurityGroupRules {
		if rule.Type == "" {
			return ErrSGRuleTypeInvalid
		}
		if rule.IP == "" {
			return ErrSGRuleIPInvalid
		}
		if rule.Protocol == "" {
			return ErrSGRuleProtocolInvalid
		}
		if rule.FromPort < 1 || rule.FromPort > 65535 {
			return ErrSGRuleFromPortInvalid
		}
		if rule.ToPort < 1 || rule.ToPort > 65535 {
			return ErrSGRuleToPortInvalid
		}
	}

	return nil
}

// Process the raw event
func (ev *Event) Process(data []byte) error {
	err := json.Unmarshal(data, &ev)
	if err != nil {
		nc.Publish("firewall.update.aws.error", data)
	}
	return err
}

// Error the request
func (ev *Event) Error(err error) {
	log.Printf("Error: %s", err.Error())
	ev.ErrorMessage = err.Error()

	data, err := json.Marshal(ev)
	if err != nil {
		log.Panic(err)
	}
	nc.Publish("firewall.update.aws.error", data)
}

// Complete the request
func (ev *Event) Complete() {
	data, err := json.Marshal(ev)
	if err != nil {
		ev.Error(err)
	}
	nc.Publish("firewall.update.aws.done", data)
}
