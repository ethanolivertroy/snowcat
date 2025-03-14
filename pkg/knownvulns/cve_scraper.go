// Copyright 2021-2025 Praetorian Security, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package knownvulns

import (
	"fmt"
	"io"
	"math"
	"net/http"
	"regexp"
	"strconv"
	"strings"
)

// VersionRange represents the range of vulnerable versions.
// Versions are represented as integers using the following formula:
//   major * 100^2 + minor*100^1 + revision*100^0
type VersionRange struct {
	MinVersion uint64
	MaxVersion uint64
}

// MatchesVersion returns true if the given version is within the range.
func (vr *VersionRange) MatchesVersion(version uint64) bool {
	return version <= vr.MaxVersion && version >= vr.MinVersion
}

// IstioCVEData represents a single CVE in Istio.
type IstioCVEData struct {
	AffectedVersions []VersionRange
	DisclosureID     string
	DisclosureURL    string
	DisclosureDate   string
	ImpactScore      string
	RelatedString    string
}

const (
	// BulletinURL is the URL where Istio vulnerabilities are published.
	BulletinURL string = "https://istio.io/latest/news/security/"
)

func convertStringToNumber(versionString string) (uint64, error) {
	versionNumbers := strings.Split(versionString, ".")
	// For now assume we are working with 3 decimals major.minor.revision
	numDecimals := 3
	var versionValue uint64
	for offset, versionNumber := range versionNumbers {
		version, err := strconv.ParseUint(versionNumber, 10, 64)
		if err != nil {
			return 0, err
		}
		multiplier := uint64(math.Pow(10, float64(numDecimals-offset-1)*4))
		versionValue += version * multiplier
	}
	return versionValue, nil
}

func parseAffectedVersions(affectedVersionsString string) []VersionRange {
	affectedVersionStrings := strings.Split(affectedVersionsString, "<br>")
	versionRanges := []VersionRange{}
	for _, affectedVersionString := range affectedVersionStrings {
		if affectedVersionString == "" {
			continue
		}
		if strings.HasPrefix(affectedVersionString, "All releases prior to ") {
			// Handle All releases prior to 1.9.8
			maxVersion, err := convertStringToNumber(strings.Split(affectedVersionString, "All releases prior to ")[1])
			// we want PRIOR to this version, so drop the revision by 1
			maxVersion--
			if err != nil {
				fmt.Println("Found a version string we couldn't convert: " + affectedVersionString)
			}
			vr := VersionRange{
				MinVersion: 0,
				MaxVersion: maxVersion,
			}
			versionRanges = append(versionRanges, vr)
		} else if strings.Contains(affectedVersionString, " to ") {
			// Handle 1.10.0 to 1.10.3
			minVersion, err := convertStringToNumber(strings.Split(affectedVersionString, " to ")[0])
			if err != nil {
				fmt.Println("Found a version string we couldn't convert: " + affectedVersionString)
			}
			maxVersion, err := convertStringToNumber(strings.Split(affectedVersionString, " to ")[1])
			if err != nil {
				fmt.Println("Found a version string we couldn't convert: " + affectedVersionString)
			}
			vr := VersionRange{
				MinVersion: minVersion,
				MaxVersion: maxVersion,
			}
			versionRanges = append(versionRanges, vr)
		} else if strings.HasSuffix(affectedVersionString, "and later") {
			// Ignore CVEs which are applied to ALL versions after a certain point, our auditors check for these issues
			continue
		} else if strings.HasSuffix(affectedVersionString, "patch releases") {
			// Handle edge case of "All 1.8 patch releases"
			minVersion, err := convertStringToNumber(strings.Split(affectedVersionString, " ")[1])
			if err != nil {
				fmt.Println("Found a version string we couldn't convert: " + affectedVersionString)
			}
			maxVersion := minVersion - (minVersion % 10000) + 9999
			vr := VersionRange{
				MinVersion: minVersion,
				MaxVersion: maxVersion,
			}
			versionRanges = append(versionRanges, vr)
		} else {
			// Handle single version number
			version, err := convertStringToNumber(affectedVersionString)
			if err != nil {
				fmt.Println("Found a version string we couldn't convert: " + affectedVersionString)
			}
			vr := VersionRange{
				MinVersion: version,
				MaxVersion: version,
			}
			versionRanges = append(versionRanges, vr)
		}
	}
	return versionRanges
}

func parseBody(body []byte) ([]IstioCVEData, error) {
	cveDataSlice := []IstioCVEData{}

	// First get the table with <table>.*</table>
	r := regexp.MustCompile(`<table>.*</table>`)
	match := r.FindString(string(body))
	if match == "" {
		return nil, fmt.Errorf("Could not find <table>")
	}
	// Next get each row with <tr>.*?</tr>
	r = regexp.MustCompile(`<tr>(.*?)</tr>`)
	matches := r.FindAllStringSubmatch(match, -1)
	for rowNum, stringMatch := range matches {
		// skip the table header
		if rowNum == 0 {
			continue
		}
		// Break it apart by each <td>(.*?)</td>
		tdRegex := regexp.MustCompile(`<td.*?>(.*?)</td>`)

		colMatches := tdRegex.FindAllStringSubmatch(stringMatch[1], -1)

		// e.g. <a href=/latest/news/security/istio-security-2019-001/>ISTIO-SECURITY-2019-001</a>
		linkRegex := regexp.MustCompile(`<a href=(.*?)>(.*?)</a>`)
		discMatches := linkRegex.FindAllStringSubmatch(colMatches[0][1], -1)
		impactMatches := linkRegex.FindAllStringSubmatch(colMatches[3][1], -1)
		affectedVersions := parseAffectedVersions(colMatches[2][1])
		impactScore := colMatches[3][1]
		if colMatches[3][1] == "" {
			impactScore = "N/A"
		}
		if colMatches[3][1] != "N/A" && impactMatches != nil {
			impactScore = impactMatches[0][2]
		}

		data := IstioCVEData{
			AffectedVersions: affectedVersions,
			DisclosureID:     discMatches[0][2],
			DisclosureURL:    "https://istio.io" + discMatches[0][1],
			DisclosureDate:   colMatches[1][1],
			ImpactScore:      impactScore,
			RelatedString:    colMatches[4][1],
		}
		cveDataSlice = append(cveDataSlice, data)
	}
	return cveDataSlice, nil
}

func scrapeCVEs() ([]IstioCVEData, error) {
	resp, err := http.Get(BulletinURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	cveData, err := parseBody(body)
	if err != nil {
		return nil, err
	}
	return cveData, nil
}
