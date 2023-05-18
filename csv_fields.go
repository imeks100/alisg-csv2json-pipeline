package main

// csv ordered filed name, starts with 0
// security_rule_type
// priority
// ip_protocol
// port_range
// authorization_object
// policy
// description
const (
	SECURITY_RULE_TYPE = iota
	PRIORITY
	IP_PROTOCOL
	PORT_RANGE
	AUTHORIZATION_OBJECT
	POLICY
	DESCRIPTION
)
