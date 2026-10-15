package report

import (
	"io"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/orchesta/orbit/internal/spdx"
)

type spdxCreationInfo struct {
	Created  string   `json:"created"`
	Creators []string `json:"creators"`
}

type spdxExternalRef struct {
	ReferenceCategory string `json:"referenceCategory"`
	ReferenceType     string `json:"referenceType"`
	ReferenceLocator  string `json:"referenceLocator"`
}

type spdxPackage struct {
	SPDXID                string            `json:"SPDXID"`
	Name                  string            `json:"name"`
	VersionInfo           string            `json:"versionInfo,omitempty"`
	DownloadLocation      string            `json:"downloadLocation"`
	FilesAnalyzed         bool              `json:"filesAnalyzed"`
	LicenseConcluded      string            `json:"licenseConcluded"`
	LicenseDeclared       string            `json:"licenseDeclared"`
	SourceInfo            string            `json:"sourceInfo,omitempty"`
	PrimaryPackagePurpose string            `json:"primaryPackagePurpose,omitempty"`
	ExternalRefs          []spdxExternalRef `json:"externalRefs,omitempty"`
}

type spdxRelationship struct {
	SPDXElementID      string `json:"spdxElementId"`
	RelationshipType   string `json:"relationshipType"`
	RelatedSPDXElement string `json:"relatedSpdxElement"`
}

type spdxDocument struct {
	SPDXVersion       string             `json:"spdxVersion"`
	DataLicense       string             `json:"dataLicense"`
	SPDXID            string             `json:"SPDXID"`
	Name              string             `json:"name"`
	DocumentNamespace string             `json:"documentNamespace"`
	CreationInfo      spdxCreationInfo   `json:"creationInfo"`
	Packages          []spdxPackage      `json:"packages"`
	Relationships     []spdxRelationship `json:"relationships"`
}

const (
	spdxDocumentID = "SPDXRef-DOCUMENT"
	spdxRootID     = "SPDXRef-Root"
	spdxNoAssert   = "NOASSERTION"
)

// spdxIDUnsafe matches what an SPDX identifier ("SPDXRef-" then letters,
// digits, "." and "-") cannot contain.
var spdxIDUnsafe = regexp.MustCompile(`[^A-Za-z0-9.-]+`)

// spdxIDs hands out unique package identifiers derived from the package.
type spdxIDs map[string]bool

func (ids spdxIDs) next(p *sbomPackage) string {
	base := "SPDXRef-Package-" + strings.Trim(spdxIDUnsafe.ReplaceAllString(
		string(p.Ecosystem)+"-"+p.Name+"-"+nativeVersion(p.Ecosystem, p.Version), "-"), "-")
	id := base
	for n := 2; ids[id]; n++ {
		id = base + "-" + strconv.Itoa(n)
	}
	ids[id] = true
	return id
}

// spdxNamespace is a unique URI for the document: the tool's URI, the
// project name and the serial UUID.
func spdxNamespace(tool ToolInfo, opts SBOMOptions) string {
	base := strings.TrimSuffix(tool.InformationURI, "/")
	if base == "" {
		base = "https://spdx.org/spdxdocs"
	}
	return base + "/spdx/" + url.PathEscape(rootName(opts)) + "-" + opts.Serial.String()
}

// spdxLicense is l in canonical form when it is an SPDX expression of
// listed IDs, "NONE" for NONE, and NOASSERTION otherwise: a LicenseRef or an
// unlisted ID would need an extracted licensing info that orbit cannot fill.
func spdxLicense(l string) string {
	if l == "NONE" {
		return l
	}
	if expr := spdx.NormalizeListed(l); expr != "" {
		return expr
	}
	return spdxNoAssert
}

// WriteSPDX writes an SPDX 2.3 JSON document: the scanned project as the
// described root package and one package per sbomPackage. The project
// DEPENDS_ON its direct runtime dependencies; a direct dev dependency is
// DEV_DEPENDENCY_OF it. Transitive packages have no relationship, because
// the analyzers do not record which package pulled them in. SPDX 2.3 has no
// vulnerability section, so findings are not written; f is unused. Every
// licenseConcluded is NOASSERTION: orbit passes on the declared license and
// does not examine the package.
func WriteSPDX(w io.Writer, _ []Finding, s Summary, tool ToolInfo, opts SBOMOptions) error {
	pkgs, _ := sbomPackages(s.Deps)
	creator := "Tool: " + tool.Name
	if tool.Version != "" {
		creator += "-" + tool.Version
	}
	doc := spdxDocument{
		SPDXVersion: "SPDX-2.3", DataLicense: "CC0-1.0", SPDXID: spdxDocumentID,
		Name: rootName(opts), DocumentNamespace: spdxNamespace(tool, opts),
		CreationInfo: spdxCreationInfo{Created: sbomTime(opts.Now), Creators: []string{creator}},
		Packages: []spdxPackage{{
			SPDXID: spdxRootID, Name: rootName(opts), DownloadLocation: spdxNoAssert,
			LicenseConcluded: spdxNoAssert, LicenseDeclared: spdxNoAssert,
		}},
		Relationships: []spdxRelationship{{spdxDocumentID, "DESCRIBES", spdxRootID}},
	}
	ids := spdxIDs{spdxRootID: true}
	for _, p := range pkgs {
		sp := spdxPackage{
			SPDXID: ids.next(p), Name: p.Name, VersionInfo: nativeVersion(p.Ecosystem, p.Version),
			DownloadLocation: spdxNoAssert, LicenseConcluded: spdxNoAssert, LicenseDeclared: spdxLicense(p.License),
			PrimaryPackagePurpose: "LIBRARY",
		}
		if len(p.Manifests) > 0 {
			sp.SourceInfo = "found in " + strings.Join(p.Manifests, ", ")
		}
		if p.PURL != "" {
			sp.ExternalRefs = []spdxExternalRef{{"PACKAGE-MANAGER", "purl", p.PURL}}
		}
		doc.Packages = append(doc.Packages, sp)
		switch {
		case p.Direct && p.Dev:
			doc.Relationships = append(doc.Relationships, spdxRelationship{sp.SPDXID, "DEV_DEPENDENCY_OF", spdxRootID})
		case p.Direct:
			doc.Relationships = append(doc.Relationships, spdxRelationship{spdxRootID, "DEPENDS_ON", sp.SPDXID})
		}
	}
	return encodeJSON(w, doc)
}
