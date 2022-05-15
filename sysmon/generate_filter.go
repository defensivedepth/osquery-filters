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
	"io/ioutil"
	"os"
	"strings"
)

type Sysmon struct {
	XMLName         xml.Name `xml:"Sysmon"`
	Text            string   `xml:",chardata"`
	Schemaversion   string   `xml:"schemaversion,attr"`
	HashAlgorithms  string   `xml:"HashAlgorithms"`
	CheckRevocation string   `xml:"CheckRevocation"`
	EventFiltering  struct {
		Text      string `xml:",chardata"`
		RuleGroup struct {
			Text          string `xml:",chardata"`
			Name          string `xml:"name,attr"`
			GroupRelation string `xml:"groupRelation,attr"`
			ProcessCreate01
		} `xml:"RuleGroup"`
	} `xml:"EventFiltering"`
}

type ProcessCreate01 struct {
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
}

func check(e error) {
	if e != nil {
		panic(e)
	}
}

func main() {
	Query_logic := `

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

	// Allow sysmon config to be passed via -config flag
	fptr := flag.String("config", "sysmon.xml", "File path to read from")
	flag.Parse()
	data, err := ioutil.ReadFile(*fptr)
	if err != nil {
		fmt.Println("File reading error", err)
		return
	}

	// Parse sysmon config according to pre-defined structs
	sysmon_config := &Sysmon{}
	_ = xml.Unmarshal([]byte(data), &sysmon_config)

	// Generate Filters
	// To be moved to function
	Filter_element := make([]string, 0)
	var ImageIs_Count, CmdLineIs_Count, CmdLine_SW_Count, PP_Image_Is_Count, PP_CL_IS_Count, PP_CL_SW_Count int

	for i := range sysmon_config.EventFiltering.RuleGroup.ProcessCreate.CommandLine {
		p := sysmon_config.EventFiltering.RuleGroup.ProcessCreate.CommandLine[i]
		if p.Condition == "is" {
			// CommandLineIs, Rule Target = 1, Rule Logic = 2
			pattern := fmt.Sprintf("(1,2,'%s')", p.Text)
			Filter_element = append(Filter_element, pattern)
			ImageIs_Count++
		} else if p.Condition == "begin with" {
			// CommandLine BeginsWith, Rule Target = 1, Rule Logic = 1
			pattern := fmt.Sprintf("(1,1,'%s')", p.Text)
			Filter_element = append(Filter_element, pattern)
			CmdLine_SW_Count++
		}
	}

	// ImageIs, Rule Target = 2, Rule Logic = 2
	for i := range sysmon_config.EventFiltering.RuleGroup.ProcessCreate.Image {
		p := sysmon_config.EventFiltering.RuleGroup.ProcessCreate.Image[i]
		if p.Condition == "is" {
			pattern := fmt.Sprintf("(2,2,'%s')", p.Text)
			Filter_element = append(Filter_element, pattern)
			CmdLineIs_Count++
		}
	}

	// ParentProcess Image Is, Rule Target = 4, Rule Logic = 2
	for i := range sysmon_config.EventFiltering.RuleGroup.ProcessCreate.ParentImage {
		p := sysmon_config.EventFiltering.RuleGroup.ProcessCreate.ParentImage[i]
		if p.Condition == "is" {
			pattern := fmt.Sprintf("(4,2,'%s')", p.Text)
			Filter_element = append(Filter_element, pattern)
			PP_Image_Is_Count++
		}
	}

	// ParentProcess CmdLine Is & Begins With
	for i := range sysmon_config.EventFiltering.RuleGroup.ProcessCreate.ParentCommandLine {
		p := sysmon_config.EventFiltering.RuleGroup.ProcessCreate.ParentCommandLine[i]
		if p.Condition == "is" {
			// PP CommandLineIs, Rule Target = 3, Rule Logic = 2
			pattern := fmt.Sprintf("(3,2,'%s')", p.Text)
			Filter_element = append(Filter_element, pattern)
			PP_CL_IS_Count++
		} else if p.Condition == "begin with" {
			// PP CommandLine BeginsWith, Rule Target = 3, Rule Logic = 1
			pattern := fmt.Sprintf("(3,1,'%s')", p.Text)
			Filter_element = append(Filter_element, pattern)
			PP_CL_SW_Count++
		}
	}

	// Build final filter clause & write out to file
	Filter_elements := strings.Join(Filter_element, ",")
	Filter_clause := fmt.Sprintf("WITH proc_filtering (rule_target,rule_logic,rule_content) AS (VALUES %s),", Filter_elements)
	Full_query := Filter_clause + Query_logic

	error := os.WriteFile("full_query.sql", []byte(Full_query), 0644)
	check(error)

	// Output Results & Summary to stdout
	fmt.Printf("\n-== Start Converted Filters -==\n\n")
	fmt.Println(Filter_clause)
	fmt.Printf("\n-== End Converted Filters -==\n\n")
	fmt.Printf("\n-== Converted Filters ==-\n- Image_Is: '%d'\n- CmdLine_Is: '%d'\n- CmdLine_StartsWith: '%d'\n- Parent Process Image Is: '%d'\n- Parent Process CmdLine Is: '%d'\n- Parent Process CmdLine StartsWith: '%d'",
		ImageIs_Count, CmdLineIs_Count, CmdLine_SW_Count, PP_Image_Is_Count, PP_CL_IS_Count, PP_CL_SW_Count)
	fmt.Printf("\n\nFull query has been written out to ./full_query.sql\n\n\n")

}
