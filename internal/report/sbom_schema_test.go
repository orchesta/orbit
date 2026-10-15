package report

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// sbomSchemas maps each vendored schema in testdata/schema to the $id its
// references resolve against, so compiling never touches the network.
//
// Sources (SHA-256 of the file as vendored):
//   - bom-1.6.schema.json, spdx.schema.json, jsf-0.82.schema.json:
//     https://raw.githubusercontent.com/CycloneDX/specification/1.6.2/schema/
//     18f57f7482593bad9f21b4feed09084640cbeff419d62ad5090c5ceccca5b37d,
//     c41917196639055e9f9670811bac23ef777732144f3ff5a2f39686f61580dbe6,
//     8bae002c25e723db7ee1f26afde680ae1a2b1a8f6b4b4b0fd65dc3becb090aae
//     License: Apache-2.0 (CycloneDX/specification).
//   - spdx-2.3.schema.json:
//     https://raw.githubusercontent.com/spdx/spdx-spec/v2.3/schemas/spdx-schema.json
//     239208b7ac287b3cf5d9a9af23f9d69863971102a5e1587a27a398b43490b89b
//     License: CC-BY-3.0, © The Linux Foundation and its contributors (spdx/spdx-spec).
var sbomSchemas = map[string]string{
	"bom-1.6.schema.json":  "http://cyclonedx.org/schema/bom-1.6.schema.json",
	"spdx.schema.json":     "http://cyclonedx.org/schema/spdx.schema.json",
	"jsf-0.82.schema.json": "http://cyclonedx.org/schema/jsf-0.82.schema.json",
	"spdx-2.3.schema.json": "http://spdx.org/rdf/terms/2.3",
}

// checkSchema validates doc against the vendored schema file, with format
// assertions (date-time, iri-reference) switched on.
func checkSchema(file string, doc []byte) error {
	c := jsonschema.NewCompiler()
	c.AssertFormat()
	for name, id := range sbomSchemas {
		f, err := os.Open(filepath.Join("testdata", "schema", name))
		if err != nil {
			return err
		}
		s, err := jsonschema.UnmarshalJSON(f)
		f.Close()
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		if err := c.AddResource(id, s); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
	}
	sch, err := c.Compile(sbomSchemas[file])
	if err != nil {
		return fmt.Errorf("compile %s: %w", file, err)
	}
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(doc))
	if err != nil {
		return err
	}
	return sch.Validate(inst)
}

func validateSchema(t *testing.T, file string, doc []byte) {
	t.Helper()
	if err := checkSchema(file, doc); err != nil {
		t.Errorf("document does not match %s:\n%v", file, err)
	}
}

func TestSchemaValidationCatchesErrors(t *testing.T) {
	// A guard that the validator really runs: a BOM without specVersion
	// and an SPDX document without SPDXID must fail.
	for file, doc := range map[string]string{
		"bom-1.6.schema.json":  `{"bomFormat":"CycloneDX"}`,
		"spdx-2.3.schema.json": `{"spdxVersion":"SPDX-2.3","dataLicense":"CC0-1.0","name":"x","creationInfo":{"created":"2026-01-01T00:00:00Z","creators":["Tool: x"]}}`,
	} {
		var verr *jsonschema.ValidationError
		if err := checkSchema(file, []byte(doc)); !errors.As(err, &verr) {
			t.Errorf("%s: want a validation error, got %v", file, err)
		}
	}
}

func TestCycloneDXMatchesSchema(t *testing.T) {
	f, s := buildSBOMFixture(t)
	var b bytes.Buffer
	if err := WriteCycloneDX(&b, f, s, testTool, sbomOpts); err != nil {
		t.Fatal(err)
	}
	validateSchema(t, "bom-1.6.schema.json", b.Bytes())
}

func TestSPDXMatchesSchema(t *testing.T) {
	f, s := buildSBOMFixture(t)
	var b bytes.Buffer
	if err := WriteSPDX(&b, f, s, testTool, sbomOpts); err != nil {
		t.Fatal(err)
	}
	validateSchema(t, "spdx-2.3.schema.json", b.Bytes())
}
