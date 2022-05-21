// Copyright 2022 Joshua Brower, Fritz Ifert-Miller. All rights reserved.
//
// Use of this source code is governed by the MIT
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package main

import (
	"encoding/xml"
	"flag"
	"fmt"
	"os"
	"strings"
)

const queryLogic = `
-- Remove Exact Match Paths
first_pass AS (
SELECT p.* FROM processes p
LEFT JOIN proc_filtering pf
ON (LOWER(p.path) = LOWER(pf.rule_content) AND pf.rule_target = 2 AND pf.rule_logic = 2)
WHERE pf.rule_content IS NULL),

-- Remove Exact Match CmdLines
second_pass AS (
SELECT fp.* FROM first_pass fp
LEFT JOIN proc_filtering pf
ON (LOWER(fp.cmdline) = LOWER(pf.rule_content) AND pf.rule_target = 1 AND pf.rule_logic = 2)
WHERE pf.rule_content IS NULL),

-- Remove CmdLines that Begin With...
third_pass AS (
SELECT sp.* FROM second_pass sp 
LEFT JOIN proc_filtering pf 
ON (sp.cmdline LIKE CONCAT(pf.rule_content,'%') 
	AND pf.rule_target = 1 AND pf.rule_logic = 1) 
WHERE pf.rule_content IS NULL),

-- Collect Parent process data
parent_processes AS (
SELECT tp.*, p.cmdline AS parent_cmdline, p.path AS parent_path FROM third_pass tp LEFT JOIN processes p ON tp.parent = p.pid),

-- Remove Exact Match Path Parent Processes
fourth_pass AS (
SELECT p.* FROM parent_processes p
LEFT JOIN proc_filtering pf
ON (LOWER(p.parent_path) = LOWER(pf.rule_content) AND pf.rule_target = 4 AND pf.rule_logic = 2)
WHERE pf.rule_content IS NULL),

-- Remove Exact Match Path Parent Cmdline
fifth_pass AS (
SELECT fps.* FROM fourth_pass fps
LEFT JOIN proc_filtering pf
ON (LOWER(fps.parent_cmdline) = LOWER(pf.rule_content) AND pf.rule_target = 3 AND pf.rule_logic = 2)
WHERE pf.rule_content IS NULL),

-- Remove Parent Cmdlines that begin with
sixth_pass AS (
SELECT fifp.* FROM fifth_pass fifp 
LEFT JOIN proc_filtering pf 
ON (fifp.cmdline LIKE CONCAT(pf.rule_content,'%') 
	AND pf.rule_target = 3 AND pf.rule_logic = 1) 
WHERE pf.rule_content IS NULL)

SELECT * FROM sixth_pass;`

type Sysmon struct {
	XMLName        xml.Name `xml:"Sysmon"`
	EventFiltering struct {
		Text      string `xml:",chardata"`
		RuleGroup struct {
			ProcessCreate struct {
				Text        string `xml:",chardata"`
				Onmatch     string `xml:"onmatch,attr"`
				CommandLine []struct {
					Text       string `xml:",chardata"`
					Condition  string `xml:"condition,attr"`
					RuleTarget string
				} `xml:"CommandLine"`
				Image []struct {
					Text      string `xml:",chardata"`
					Condition string `xml:"condition,attr"`
				} `xml:"Image"`
				IntegrityLevel struct {
					Text      string `xml:",chardata"`
					Condition string `xml:"condition,attr"`
				} `xml:"IntegrityLevel"`
				ParentCommandLine []struct {
					Text      string `xml:",chardata"`
					Condition string `xml:"condition,attr"`
				} `xml:"ParentCommandLine"`
				ParentImage []struct {
					Text      string `xml:",chardata"`
					Condition string `xml:"condition,attr"`
				} `xml:"ParentImage"`
			} `xml:"ProcessCreate"`
		} `xml:"RuleGroup"`
	} `xml:"EventFiltering"`
}

func check(err error, context string) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", context, err)
		os.Exit(1)
	}
}

func main() {
	// Allow sysmon config to be passed via -config flag
	var configPath string
	flag.StringVar(&configPath, "config", "sysmon.xml", "File path to read from")
	flag.Parse()

	data, err := os.ReadFile(configPath)
	check(err, "error reading sysmon config file")

	// Parse sysmon config according to pre-defined structs
	sysmonConfig := &Sysmon{}
	err = xml.Unmarshal(data, &sysmonConfig)
	check(err, "Invalid sysmon config file")

	// Generate Filters
	// TODO - Move this to a function
	var filterElement []string
	var imageIsCount, cmdLineIsCount, CmdLineBWCount, ppImageIsCount, ppCmdLineIsCount, ppCmdLineBWCount int

	// CommandLineIs & Commandline BeginsWith
	for _, p := range sysmonConfig.EventFiltering.RuleGroup.ProcessCreate.CommandLine {
		switch p.Condition {
		case "is":
			// CommandLineIs, Rule Target = 1, Rule Logic = 2
			pattern := fmt.Sprintf("(1,2,'%s')", p.Text)
			filterElement = append(filterElement, pattern)
			imageIsCount++
		case "begin with":
			// CommandLine BeginsWith, Rule Target = 1, Rule Logic = 1
			pattern := fmt.Sprintf("(1,1,'%s')", p.Text)
			filterElement = append(filterElement, pattern)
			CmdLineBWCount++
		}
	}

	// ImageIs, Rule Target = 2, Rule Logic = 2
	for _, p := range sysmonConfig.EventFiltering.RuleGroup.ProcessCreate.Image {
		if p.Condition == "is" {
			pattern := fmt.Sprintf("(2,2,'%s')", p.Text)
			filterElement = append(filterElement, pattern)
			cmdLineIsCount++
		}
	}

	// ParentProcess Image Is, Rule Target = 4, Rule Logic = 2
	for _, p := range sysmonConfig.EventFiltering.RuleGroup.ProcessCreate.ParentImage {
		if p.Condition == "is" {
			pattern := fmt.Sprintf("(4,2,'%s')", p.Text)
			filterElement = append(filterElement, pattern)
			ppImageIsCount++
		}
	}

	// ParentProcess CmdLine Is & Begins With
	for _, p := range sysmonConfig.EventFiltering.RuleGroup.ProcessCreate.ParentCommandLine {
		switch p.Condition {
		case "is":
			// PP CommandLineIs, Rule Target = 3, Rule Logic = 2
			pattern := fmt.Sprintf("(3,2,'%s')", p.Text)
			filterElement = append(filterElement, pattern)
			ppCmdLineIsCount++
		case "begin with":
			// PP CommandLine BeginsWith, Rule Target = 3, Rule Logic = 1
			pattern := fmt.Sprintf("(3,1,'%s')", p.Text)
			filterElement = append(filterElement, pattern)
			ppCmdLineBWCount++
		}
	}

	// Build final filter clause & write out to file
	filterElements := strings.Join(filterElement, ",")
	filterClause := fmt.Sprintf("WITH proc_filtering (rule_target,rule_logic,rule_content) AS (VALUES %s),", filterElements)
	fullQuery := filterClause + queryLogic

	error := os.WriteFile("fullQuery.sql", []byte(fullQuery), 0644)
	check(error, "Not able to writeout file...")

	// Output Results & Summary
	fmt.Printf("\n-== Start Converted Filters -==\n\n")
	fmt.Println(filterClause)
	fmt.Printf("\n-== End Converted Filters -==\n\n")
	fmt.Printf("\n-== Converted Filters ==-\n- Image Is: '%d'\n- CmdLine Is: '%d'\n- CmdLine StartsWith: '%d'\n- Parent Process Image Is: '%d'\n- Parent Process CmdLine Is: '%d'\n- Parent Process CmdLine StartsWith: '%d'",
		imageIsCount, cmdLineIsCount, CmdLineBWCount, ppImageIsCount, ppCmdLineIsCount, ppCmdLineBWCount)
	fmt.Printf("\n\nFull query has been written out to ./fullQuery.sql\n\n\n")

}
