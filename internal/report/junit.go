package report

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
)

type junitFailure struct {
	Message string `xml:"message,attr"`
	Type    string `xml:"type,attr"`
	Body    string `xml:",chardata"`
}

type junitSkipped struct {
	Message string `xml:"message,attr"`
}

type junitCase struct {
	Name      string        `xml:"name,attr"`
	ClassName string        `xml:"classname,attr"`
	Failure   *junitFailure `xml:"failure,omitempty"`
	Skipped   *junitSkipped `xml:"skipped,omitempty"`
}

type junitSuite struct {
	XMLName  xml.Name    `xml:"testsuite"`
	Name     string      `xml:"name,attr"`
	Tests    int         `xml:"tests,attr"`
	Failures int         `xml:"failures,attr"`
	Skipped  int         `xml:"skipped,attr"`
	Cases    []junitCase `xml:"testcase"`
}

// WriteJUnit writes one testsuite "orbit". Each finding is a testcase: a
// failure when not ignored and at or above the threshold, skipped when ignored.
func WriteJUnit(w io.Writer, f []Finding, s Summary) error {
	suite := junitSuite{Name: "orbit"}
	for _, x := range f {
		v, d := x.Vulnerability, x.Dependency
		c := junitCase{Name: fmt.Sprintf("%s@%s: %s", d.Name, d.CurrentVersion, v.OSVID), ClassName: d.ManifestFile}
		switch {
		case x.Ignored:
			c.Skipped = &junitSkipped{Message: x.IgnoreReason}
			suite.Skipped++
		case atOrAbove(v.Severity, s.Threshold):
			msg := fmt.Sprintf("%s: %s", v.Severity, v.Summary)
			body := fmt.Sprintf("%s@%s is affected by %s", d.Name, d.CurrentVersion, v.OSVID)
			if fv := fixedIn(v); fv != "" {
				body += " (fixed in " + fv + ")"
			}
			c.Failure = &junitFailure{Message: msg, Type: string(v.Severity), Body: body}
			suite.Failures++
		}
		suite.Cases = append(suite.Cases, c)
	}
	if len(suite.Cases) == 0 {
		suite.Cases = []junitCase{{Name: "no vulnerabilities found", ClassName: "orbit"}}
	}
	suite.Tests = len(suite.Cases)
	var buf bytes.Buffer
	buf.WriteString(xml.Header)
	enc := xml.NewEncoder(&buf)
	enc.Indent("", "  ")
	if err := enc.Encode(suite); err != nil {
		return err
	}
	buf.WriteString("\n")
	_, err := w.Write(neutraliseXML(buf.Bytes()))
	return err
}
