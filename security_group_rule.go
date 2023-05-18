package main

import (
	"fmt"
	"regexp"
	"strconv"

	"github.com/go-playground/validator/v10"
)

type SecurityGroupRule struct {
	SGRuleType string `json:"security_rule_type" validate:"oneof=ingress egress"`
	Priority   int    `json:"priority" validate:"omitempty,gte=1,lte=100"`
	IPProtocol string `json:"ip_protocol" validate:"required,oneof=tcp udp icmp gre all"`
	PortRange  string `json:"port_range" validate:"required"`
	Policy     string `json:"policy" validate:"oneof=accept drop"`

	AuthorizationObject string `json:"authorization_object,omitempty"`
	CIDR                string `json:"cidr_ip"`
	SGID                string `json:"source_security_group_id"`
	// NIC_Type            string `json:"nic_type,omitempty"`

	Description string `json:"description" validate:"omitempty,gte=1,lte=512"`
}

type SecurityGroupRuleList []SecurityGroupRule

// NewSecurityGroupRule create a SecurityGroupRule
func NewSecurityGroupRule() *SecurityGroupRule {
	return new(SecurityGroupRule)
}

// CheckPortRange check port range format is valid.
func (sgr *SecurityGroupRule) CheckPortRange() (bool, error) {
	portrange := sgr.PortRange
	pattern := `^([-]?[0-9]+)/([-]?[0-9]+)$`
	valid := regexp.MustCompile(pattern)

	if !valid.MatchString(portrange) {
		return false, fmt.Errorf("invalid port range format")
	}

	ports := valid.FindStringSubmatch(portrange)

	min_port, err := strconv.Atoi(ports[1])
	if err != nil {
		return false, fmt.Errorf("min port should be a number")
	}

	max_port, err := strconv.Atoi(ports[2])
	if err != nil {
		return false, fmt.Errorf("max port should be a number")
	}

	// if portocol is tcp or udp, port range can't be -1/-1
	if sgr.IPProtocol == "tcp" || sgr.IPProtocol == "udp" {
		if sgr.PortRange == "-1/-1" {
			return false, fmt.Errorf("invalid port range for %s", sgr.IPProtocol)
		}
		if min_port < 1 || max_port > 65535 {
			return false, fmt.Errorf("port range should be in (1,65535)")
		}
	}

	// if protocol is gre, icmp, or all, port range should be -1/-1
	if sgr.IPProtocol == "gre" || sgr.IPProtocol == "icmp" || sgr.IPProtocol == "all" {
		if sgr.PortRange != "-1/-1" {
			return false, fmt.Errorf("port range should be -1/-1 for protocol %s", sgr.IPProtocol)
		}
	}

	return true, nil
}

// ParseAuthorizationObject check AuthorizationObject is a cidr or a security group id.
// we don't know if security group id is valid or not until run terraform apply.
func (sgr *SecurityGroupRule) ParseAuthorizationObject() (string, error) {

	if isCidr := checkCidr(sgr.AuthorizationObject); !isCidr {
		if isSGID := checkSecurityGroupID(sgr.AuthorizationObject); !isSGID {
			return "Unknown", fmt.Errorf("unknown authorization object")
		}
		return "SGID", nil
	}

	return "CIDR", nil
}

func checkCidr(ipstr string) bool {

	var ip_cidr struct {
		IP string `validate:"cidr|ip"`
	}

	validate := validator.New()

	ip_cidr.IP = ipstr

	if err := validate.Struct(ip_cidr); err != nil {
		return false
	}

	return true
}

func checkSecurityGroupID(sgidstr string) bool {

	pattern := `^sg-[a-z0-9]+$`
	valid := regexp.MustCompile(pattern)

	if !valid.MatchString(sgidstr) {
		return false
	}

	var sgid struct {
		SecurityGroupID string `validate:"startswith=sg-"`
	}

	validate := validator.New()

	sgid.SecurityGroupID = sgidstr

	if err := validate.Struct(sgid); err != nil {
		return false
	}

	return true
}

func (entry *SecurityGroupRule) CSVRecordToSecurityGroupRule(record []string) (*SecurityGroupRule, error) {

	entry.SGRuleType = record[SECURITY_RULE_TYPE]

	priority, err := strconv.Atoi(record[PRIORITY])
	if err != nil {
		fmt.Println("priority should be a number.")
		return nil, err
	}
	entry.Priority = priority

	entry.IPProtocol = record[IP_PROTOCOL]

	entry.PortRange = record[PORT_RANGE]
	if ok, err := entry.CheckPortRange(); !ok {
		return nil, err
	}

	entry.AuthorizationObject = record[AUTHORIZATION_OBJECT]
	if entry.AuthorizationObject == "" {
		fmt.Println("authorization object required")
		return nil, err
	}
	aoType, err := entry.ParseAuthorizationObject()
	if err != nil {
		return nil, err
	}
	switch aoType {
	case "CIDR":
		entry.CIDR = record[AUTHORIZATION_OBJECT]
	case "SGID":
		entry.SGID = record[AUTHORIZATION_OBJECT]
	}
	entry.AuthorizationObject = ""
	// sgrEntry.NIC_Type = "intranet"

	entry.Policy = record[POLICY]

	entry.Description = record[DESCRIPTION]

	validate := validator.New()
	if err := validate.Struct(entry); err != nil {
		fmt.Println("validate error: ", err)
		return nil, err
	}

	return entry, nil
}
