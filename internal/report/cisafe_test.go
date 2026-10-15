package report

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"regexp"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/orchesta/orbit/internal/domain/entity"
	"github.com/orchesta/orbit/internal/engine"
)

// hostile carries Azure Pipelines (##vso[, ##[) and GitHub Actions (::cmd at
// a line start) log commands, a carriage return and a terminal escape.
const hostile = "x ##vso[task.setvariable variable=a]1 ##VSO[task.complete]2 ##[error]3\n::error::4\r::warning::5 \x1b[2J"

var rawCICommand = regexp.MustCompile(`(?i)##(vso)?\[`)

// assertNoCICommands fails if out has a log command an agent would run.
func assertNoCICommands(t *testing.T, name string, out []byte) {
	t.Helper()
	for _, line := range strings.FieldsFunc(string(out), func(r rune) bool { return r == '\n' || r == '\r' }) {
		if rawCICommand.MatchString(line) {
			t.Errorf("%s: line carries a raw log command: %q", name, line)
		}
		if strings.HasPrefix(strings.TrimSpace(line), "::") {
			t.Errorf("%s: line starts a workflow command: %q", name, line)
		}
	}
}

func hostileResult() *engine.Result {
	dep := &entity.Dependency{ID: uuid.New(), Name: "pkg" + hostile, CurrentVersion: "1.0.0", Ecosystem: entity.EcosystemNpm,
		ManifestFile: "dir" + hostile + "/package.json", IsResolved: true}
	return &engine.Result{
		Dependencies: []*entity.Dependency{dep},
		Vulnerabilities: []*entity.Vulnerability{{ID: uuid.New(), DependencyID: dep.ID, OSVID: "GHSA-" + hostile,
			Summary: hostile, Severity: entity.SeverityHigh, FixedVersion: strp("2" + hostile), References: []string{"https://e.x/" + hostile}}},
		Warnings: []string{"failed to parse manifest dir" + hostile + "/package.json: bad"},
	}
}

func TestJSONNeutralisesCICommandsButDecodesToTheOriginal(t *testing.T) {
	f, s := Build(hostileResult(), nil, entity.SeverityHigh, fixedNow)
	var b bytes.Buffer
	if err := WriteJSON(&b, f, s, testTool); err != nil {
		t.Fatal(err)
	}
	assertNoCICommands(t, "json", b.Bytes())
	var doc struct {
		Findings []struct {
			Summary  string `json:"summary"`
			Manifest string `json:"manifest"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(b.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Findings[0].Summary != hostile || doc.Findings[0].Manifest != "dir"+hostile+"/package.json" {
		t.Fatalf("decoded %q / %q, want the original text", doc.Findings[0].Summary, doc.Findings[0].Manifest)
	}
}

func TestSARIFNeutralisesCICommandsButDecodesToTheOriginal(t *testing.T) {
	f, s := Build(hostileResult(), nil, entity.SeverityHigh, fixedNow)
	var b bytes.Buffer
	if err := WriteSARIF(&b, f, s, testTool, SARIFOptions{}); err != nil {
		t.Fatal(err)
	}
	assertNoCICommands(t, "sarif", b.Bytes())
	var doc struct {
		Runs []struct {
			Tool struct {
				Driver struct {
					Rules []struct {
						Short struct{ Text string } `json:"shortDescription"`
					}
				}
			}
		}
	}
	if err := json.Unmarshal(b.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if got := doc.Runs[0].Tool.Driver.Rules[0].Short.Text; got != hostile {
		t.Fatalf("decoded %q, want %q", got, hostile)
	}
}

func TestJUnitNeutralisesCICommandsButDecodesToTheOriginal(t *testing.T) {
	f, s := Build(hostileResult(), nil, entity.SeverityHigh, fixedNow)
	var b bytes.Buffer
	if err := WriteJUnit(&b, f, s); err != nil {
		t.Fatal(err)
	}
	assertNoCICommands(t, "junit", b.Bytes())
	var suite struct {
		Cases []struct {
			ClassName string `xml:"classname,attr"`
			Failure   struct {
				Message string `xml:"message,attr"`
				Body    string `xml:",chardata"`
			} `xml:"failure"`
		} `xml:"testcase"`
	}
	if err := xml.Unmarshal(b.Bytes(), &suite); err != nil {
		t.Fatalf("not well-formed: %v\n%s", err, b.String())
	}
	c := suite.Cases[0]
	// XML 1.0 cannot carry ESC: encoding/xml writes U+FFFD for it, as it
	// always has. CR and LF are written as character references and survive.
	want := strings.ReplaceAll(hostile, "\x1b", "�")
	if c.Failure.Message != "high: "+want || c.ClassName != "dir"+want+"/package.json" {
		t.Fatalf("decoded %q / %q, want the original text", c.Failure.Message, c.ClassName)
	}
}

func TestTableCellsAreSingleLineWithoutControlCharacters(t *testing.T) {
	f, s := Build(hostileResult(), nil, entity.SeverityHigh, fixedNow)
	for _, color := range []bool{false, true} {
		var b bytes.Buffer
		if err := writeTable(&b, f, s, color); err != nil {
			t.Fatal(err)
		}
		out := ansiRE.ReplaceAllString(b.String(), "") // the table's own colour codes
		if strings.ContainsAny(out, "\r\x1b") {
			t.Errorf("color=%v: control characters left in the table:\n%q", color, out)
		}
		lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
		// header, one finding, blank, summary, threshold, one warning
		if len(lines) != 6 {
			t.Errorf("color=%v: %d lines, want 6:\n%s", color, len(lines), out)
		}
		for _, l := range lines {
			if strings.HasPrefix(strings.TrimSpace(l), "::") {
				t.Errorf("color=%v: line starts a workflow command: %q", color, l)
			}
		}
		if !strings.Contains(out, "�::error::4�::warning::5 �[2J") {
			t.Errorf("color=%v: control characters should become U+FFFD:\n%s", color, out)
		}
	}
}
