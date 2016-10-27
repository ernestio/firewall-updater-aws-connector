/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package main

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"log"
	"os"
	"testing"
	"time"

	ecc "github.com/ernestio/ernest-config-client"
	"github.com/nats-io/nats"

	. "github.com/smartystreets/goconvey/convey"
)

var (
	testEvent = Event{
		UUID:                  "test",
		BatchID:               "test",
		ProviderType:          "aws",
		VPCID:                 "vpc-0000000",
		DatacenterRegion:      "eu-west-1",
		DatacenterAccessKey:   "key",
		DatacenterAccessToken: "token",
		SecurityGroupAWSID:    "sg-0000000",
		SecurityGroupName:     "test",
	}
)

func waitMsg(ch chan *nats.Msg) (*nats.Msg, error) {
	select {
	case msg := <-ch:
		return msg, nil
	case <-time.After(time.Millisecond * 100):
	}
	return nil, errors.New("timeout")
}

func testSetup() (chan *nats.Msg, chan *nats.Msg) {
	doneChan := make(chan *nats.Msg, 10)
	errChan := make(chan *nats.Msg, 10)

	nc = ecc.NewConfig(os.Getenv("NATS_URI")).Nats()

	nc.ChanSubscribe("firewall.update.aws.done", doneChan)
	nc.ChanSubscribe("firewall.update.aws.error", errChan)

	return doneChan, errChan
}

func buildTestRules(ev *Event) {
	ev.SecurityGroupRules.Ingress = []rule{}
	ev.SecurityGroupRules.Egress = []rule{}

	ev.SecurityGroupRules.Ingress = append(ev.SecurityGroupRules.Ingress, rule{
		IP:       "10.0.10.100/32",
		FromPort: 80,
		ToPort:   8080,
		Protocol: "tcp",
	})

	ev.SecurityGroupRules.Egress = append(ev.SecurityGroupRules.Egress, rule{
		IP:       "8.8.8.8/32",
		FromPort: 80,
		ToPort:   8080,
		Protocol: "tcp",
	})
}

func TestEvent(t *testing.T) {
	completed, errored := testSetup()

	Convey("Given an event", t, func() {
		Convey("With valid fields", func() {
			buildTestRules(&testEvent)
			valid, _ := json.Marshal(testEvent)
			Convey("When processing the event", func() {
				var e Event
				err := e.Process(valid)

				Convey("It should not error", func() {
					So(err, ShouldBeNil)
					msg, timeout := waitMsg(errored)
					So(msg, ShouldBeNil)
					So(timeout, ShouldNotBeNil)
				})

				Convey("It should load the correct values", func() {
					So(e.UUID, ShouldEqual, "test")
					So(e.BatchID, ShouldEqual, "test")
					So(e.ProviderType, ShouldEqual, "aws")
					So(e.VPCID, ShouldEqual, "vpc-0000000")
					So(e.DatacenterRegion, ShouldEqual, "eu-west-1")
					So(e.DatacenterAccessKey, ShouldEqual, "key")
					So(e.DatacenterAccessToken, ShouldEqual, "token")
					So(e.SecurityGroupName, ShouldEqual, "test")
					So(len(e.SecurityGroupRules.Ingress), ShouldEqual, 1)
					So(e.SecurityGroupRules.Ingress[0].IP, ShouldEqual, "10.0.10.100/32")
					So(e.SecurityGroupRules.Ingress[0].FromPort, ShouldEqual, 80)
					So(e.SecurityGroupRules.Ingress[0].ToPort, ShouldEqual, 8080)
					So(e.SecurityGroupRules.Ingress[0].Protocol, ShouldEqual, "tcp")
					So(len(e.SecurityGroupRules.Egress), ShouldEqual, 1)
					So(e.SecurityGroupRules.Egress[0].IP, ShouldEqual, "8.8.8.8/32")
					So(e.SecurityGroupRules.Egress[0].FromPort, ShouldEqual, 80)
					So(e.SecurityGroupRules.Egress[0].ToPort, ShouldEqual, 8080)
					So(e.SecurityGroupRules.Egress[0].Protocol, ShouldEqual, "tcp")
				})
			})

			Convey("When validating the event", func() {
				var e Event
				e.Process(valid)
				err := e.Validate()

				Convey("It should not error", func() {
					So(err, ShouldBeNil)
					msg, timeout := waitMsg(errored)
					So(msg, ShouldBeNil)
					So(timeout, ShouldNotBeNil)
				})
			})

			Convey("When completing the event", func() {
				var e Event
				e.Process(valid)
				e.Complete()
				Convey("It should produce a firewall.update.aws.done event", func() {
					msg, timeout := waitMsg(completed)
					So(msg, ShouldNotBeNil)
					So(string(msg.Data), ShouldEqual, string(valid))
					So(timeout, ShouldBeNil)
					msg, timeout = waitMsg(errored)
					So(msg, ShouldBeNil)
					So(timeout, ShouldNotBeNil)
				})
			})

			Convey("When erroring the event", func() {
				log.SetOutput(ioutil.Discard)
				var e Event
				e.Process(valid)
				e.Error(errors.New("error"))
				Convey("It should produce a firewall.update.aws.error event", func() {
					msg, timeout := waitMsg(errored)
					So(msg, ShouldNotBeNil)
					So(string(msg.Data), ShouldContainSubstring, `"error":"error"`)
					So(timeout, ShouldBeNil)
					msg, timeout = waitMsg(completed)
					So(msg, ShouldBeNil)
					So(timeout, ShouldNotBeNil)
				})
				log.SetOutput(os.Stdout)
			})
		})

		Convey("With no datacenter vpc id", func() {
			testEventInvalid := testEvent
			testEventInvalid.VPCID = ""
			invalid, _ := json.Marshal(testEventInvalid)

			Convey("When validating the event", func() {
				var e Event
				e.Process(invalid)
				err := e.Validate()
				Convey("It should error", func() {
					So(err, ShouldNotBeNil)
					So(err.Error(), ShouldEqual, "Datacenter VPC ID invalid")
				})
			})
		})

		Convey("With no datacenter region", func() {
			testEventInvalid := testEvent
			testEventInvalid.DatacenterRegion = ""
			invalid, _ := json.Marshal(testEventInvalid)

			Convey("When validating the event", func() {
				var e Event
				e.Process(invalid)
				err := e.Validate()
				Convey("It should error", func() {
					So(err, ShouldNotBeNil)
					So(err.Error(), ShouldEqual, "Datacenter Region invalid")
				})
			})
		})

		Convey("With no datacenter access key", func() {
			testEventInvalid := testEvent
			testEventInvalid.DatacenterAccessKey = ""
			invalid, _ := json.Marshal(testEventInvalid)

			Convey("When validating the event", func() {
				var e Event
				e.Process(invalid)
				err := e.Validate()
				Convey("It should error", func() {
					So(err, ShouldNotBeNil)
					So(err.Error(), ShouldEqual, "Datacenter credentials invalid")
				})
			})
		})

		Convey("With no datacenter access token", func() {
			testEventInvalid := testEvent
			testEventInvalid.DatacenterAccessToken = ""
			invalid, _ := json.Marshal(testEventInvalid)

			Convey("When validating the event", func() {
				var e Event
				e.Process(invalid)
				err := e.Validate()
				Convey("It should error", func() {
					So(err, ShouldNotBeNil)
					So(err.Error(), ShouldEqual, "Datacenter credentials invalid")
				})
			})
		})

		Convey("With no security group name", func() {
			testEventInvalid := testEvent
			testEventInvalid.SecurityGroupName = ""
			invalid, _ := json.Marshal(testEventInvalid)

			Convey("When validating the event", func() {
				var e Event
				e.Process(invalid)
				err := e.Validate()
				Convey("It should error", func() {
					So(err, ShouldNotBeNil)
					So(err.Error(), ShouldEqual, "Security Group name invalid")
				})
			})
		})

		Convey("With an empty ruleset", func() {
			testEventInvalid := testEvent
			testEventInvalid.SecurityGroupRules.Ingress = []rule{}
			testEventInvalid.SecurityGroupRules.Egress = []rule{}
			invalid, _ := json.Marshal(testEventInvalid)

			Convey("When validating the event", func() {
				var e Event
				e.Process(invalid)
				err := e.Validate()
				Convey("It should error", func() {
					So(err, ShouldNotBeNil)
					So(err.Error(), ShouldEqual, "Security Group must contain rules")
				})
			})
		})

		Convey("With an invalid ingress rule ip", func() {
			testEventInvalid := testEvent
			buildTestRules(&testEventInvalid)
			testEventInvalid.SecurityGroupRules.Ingress[0].IP = ""
			invalid, _ := json.Marshal(testEventInvalid)

			Convey("When validating the event", func() {
				var e Event
				e.Process(invalid)
				err := e.Validate()
				Convey("It should error", func() {
					So(err, ShouldNotBeNil)
					So(err.Error(), ShouldEqual, "Security Group rule ip invalid")
				})
			})
		})

		Convey("With an invalid ingress rule from port", func() {
			testEventInvalid := testEvent
			buildTestRules(&testEventInvalid)
			testEventInvalid.SecurityGroupRules.Ingress[0].FromPort = 999999
			invalid, _ := json.Marshal(testEventInvalid)

			Convey("When validating the event", func() {
				var e Event
				e.Process(invalid)
				err := e.Validate()
				Convey("It should error", func() {
					So(err, ShouldNotBeNil)
					So(err.Error(), ShouldEqual, "Security Group rule from port invalid")
				})
			})
		})

		Convey("With an invalid ingress rule to port", func() {
			testEventInvalid := testEvent
			buildTestRules(&testEventInvalid)
			testEventInvalid.SecurityGroupRules.Ingress[0].ToPort = -99999
			invalid, _ := json.Marshal(testEventInvalid)

			Convey("When validating the event", func() {
				var e Event
				e.Process(invalid)
				err := e.Validate()
				Convey("It should error", func() {
					So(err, ShouldNotBeNil)
					So(err.Error(), ShouldEqual, "Security Group rule to port invalid")
				})
			})
		})

		Convey("With an invalid ingress rule protocol", func() {
			testEventInvalid := testEvent
			buildTestRules(&testEventInvalid)
			testEventInvalid.SecurityGroupRules.Ingress[0].Protocol = ""
			invalid, _ := json.Marshal(testEventInvalid)

			Convey("When validating the event", func() {
				var e Event
				e.Process(invalid)
				err := e.Validate()
				Convey("It should error", func() {
					So(err, ShouldNotBeNil)
					So(err.Error(), ShouldEqual, "Security Group rule protocol invalid")
				})
			})
		})

		Convey("With an invalid egress rule ip", func() {
			testEventInvalid := testEvent
			buildTestRules(&testEventInvalid)
			testEventInvalid.SecurityGroupRules.Egress[0].IP = ""
			invalid, _ := json.Marshal(testEventInvalid)

			Convey("When validating the event", func() {
				var e Event
				e.Process(invalid)
				err := e.Validate()
				Convey("It should error", func() {
					So(err, ShouldNotBeNil)
					So(err.Error(), ShouldEqual, "Security Group rule ip invalid")
				})
			})
		})

		Convey("With an invalid egress rule from port", func() {
			testEventInvalid := testEvent
			buildTestRules(&testEventInvalid)
			testEventInvalid.SecurityGroupRules.Egress[0].FromPort = 999999
			invalid, _ := json.Marshal(testEventInvalid)

			Convey("When validating the event", func() {
				var e Event
				e.Process(invalid)
				err := e.Validate()
				Convey("It should error", func() {
					So(err, ShouldNotBeNil)
					So(err.Error(), ShouldEqual, "Security Group rule from port invalid")
				})
			})
		})

		Convey("With an invalid egress rule to port", func() {
			testEventInvalid := testEvent
			buildTestRules(&testEventInvalid)
			testEventInvalid.SecurityGroupRules.Egress[0].ToPort = -99999
			invalid, _ := json.Marshal(testEventInvalid)

			Convey("When validating the event", func() {
				var e Event
				e.Process(invalid)
				err := e.Validate()
				Convey("It should error", func() {
					So(err, ShouldNotBeNil)
					So(err.Error(), ShouldEqual, "Security Group rule to port invalid")
				})
			})
		})

		Convey("With an invalid egress rule protocol", func() {
			testEventInvalid := testEvent
			buildTestRules(&testEventInvalid)
			testEventInvalid.SecurityGroupRules.Egress[0].Protocol = ""
			invalid, _ := json.Marshal(testEventInvalid)

			Convey("When validating the event", func() {
				var e Event
				e.Process(invalid)
				err := e.Validate()
				Convey("It should error", func() {
					So(err, ShouldNotBeNil)
					So(err.Error(), ShouldEqual, "Security Group rule protocol invalid")
				})
			})
		})

	})
}
