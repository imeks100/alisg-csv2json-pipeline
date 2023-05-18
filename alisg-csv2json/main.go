package main

import (
	"encoding/csv"
	"encoding/json"
	"flag"
	"io"
	"log"
	"os"
)

// default file name
const (
	SECURITY_GROUP_RULES_CSV_FILE  = "security_group_rules.csv"
	SECURITY_GROUP_RULES_JSON_FILE = "security_group_rules.json"
)

func main() {
	// if parameter is not provide, use default csv file.
	var security_group_rule_csv_file string
	flag.StringVar(&security_group_rule_csv_file, "rule-file", "", "security group rule csv file")
	flag.Parse()

	if security_group_rule_csv_file == "" {
		security_group_rule_csv_file = SECURITY_GROUP_RULES_CSV_FILE
	}

	security_group_rules_file, err := os.Open(security_group_rule_csv_file)
	if err != nil {
		log.Fatalln("open csv file failed ", err)
	}
	defer security_group_rules_file.Close()

	// csv reader
	security_group_rules_csv_reader := csv.NewReader(security_group_rules_file)

	// separate is comma, use # to comment at the begging of a line
	security_group_rules_csv_reader.Comma = ','
	security_group_rules_csv_reader.Comment = '#'

	// security froup rule list that contains security group rule
	var security_group_rule_list SecurityGroupRuleList

	// ignore first line, cause it is table head
	firstLine := true

	for {
		security_group_rule_record, err := security_group_rules_csv_reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Fatal(err)
		}

		if firstLine {
			firstLine = false
			continue
		}

		var securityGroupRuleEntry = NewSecurityGroupRule()

		entry, err := securityGroupRuleEntry.CSVRecordToSecurityGroupRule(security_group_rule_record)
		if err != nil {
			log.Fatalln(err)
		}

		security_group_rule_list = append(security_group_rule_list, *entry)
	}

	var security_group_rules = make(map[string]SecurityGroupRuleList, 1)

	security_group_rules["security_group_rules"] = security_group_rule_list

	// generate json file
	security_group_rules_marshal, err := json.MarshalIndent(security_group_rules, "", "  ")
	if err != nil {
		log.Fatalln("marshal failed: ", err)
	}

	security_group_rule_json_file, err := os.OpenFile(SECURITY_GROUP_RULES_JSON_FILE, os.O_RDWR|os.O_CREATE, 0644)
	if err != nil {
		log.Fatalln("openfile failed, ", err)
	}
	defer security_group_rule_json_file.Close()

	security_group_rule_json_file.Write(security_group_rules_marshal)
}
