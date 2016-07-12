/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package main

import (
	"encoding/json"
	"log"
)

type rule struct {
	IP       string `json:"ip"`
	FromPort int64  `json:"from_port"`
	ToPort   int64  `json:"to_port"`
	Protocol string `json:"protocol"`
}

// Event stores the network create data
type Event struct {
	ID                    string `json:"id"`
	DatacenterVPCID       string `json:"datacenter_vpc_id"`
	DatacenterRegion      string `json:"datacenter_region"`
	DatacenterAccessKey   string `json:"datacenter_access_key"`
	DatacenterAccessToken string `json:"datacenter_access_token"`
	NetworkAWSID          string `json:"network_aws_id"`
	SecurityGroupAWSID    string `json:"security_group_aws_id,omitempty"`
	SecurityGroupName     string `json:"security_group_name"`
	SecurityGroupRules    struct {
		Ingress []rule `json:"ingress"`
		Egress  []rule `json:"egress"`
	} `json:"security_group_rules"`
	ErrorMessage string `json:"error,omitempty"`
}

// Valid checks if all criteria are met
func (ev *Event) Valid() bool {
	return true
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
