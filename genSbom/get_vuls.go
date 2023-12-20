package genSbom

import (
	"bytes"
	"fmt"
	"os"
	"path"
	"time"

	"github.com/anchore/grype/grype"
	"github.com/anchore/grype/grype/db"
	"github.com/anchore/grype/grype/match"
	grypePkg "github.com/anchore/grype/grype/pkg"
	cyclonedxPres "github.com/anchore/grype/grype/presenter/cyclonedx"
	"github.com/anchore/grype/grype/presenter/models"

	// "github.com/CycloneDX/cyclonedx-go"

	// "github.com/anchore/grype/grype/presenter/table"

	// syftPkg "github.com/anchore/syft/syft/pkg"

	_ "reflect"

	// "github.com/anchore/syft/syft/format/common/cyclonedxhelpers"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
	"github.com/scylladb/go-set/strset"
)

const (
	grypeDBListingURL string = "https://toolbox-data.anchore.io/grype/databases/listing.json"
	// mavenSearchBaseURL = "https://search.maven.org/solrsearch/select"
)

var localDBFilePath string = path.Join("/tmp/", "grype", "db", "vulnerabilities.db")
var grypeDBConfig db.Config = db.Config{
	DBRootDir:           localDBFilePath,
	ListingURL:          grypeDBListingURL,
	ValidateByHashOnGet: false,
	ValidateAge:         true,
	MaxAllowedBuiltAge:  24 * time.Hour,
}

func GetVuls() {
	fmt.Println("Hello, world!")
	sbomBytes := PrintSBOM(GenSBOM("test-fixture/python/requirements.txt"))
	fmt.Println("-----------------")
	// fmt.Printf(sbomBytes)

	store, _, closer, err := grype.LoadVulnerabilityDB(grypeDBConfig, true)

	if closer != nil {
		defer closer.Close()
	}

	if err != nil {
		panic(err)
	}

	// get vulns (sbom)
	sbomFile, _ := os.CreateTemp("", "")

	_, _ = sbomFile.WriteString(sbomBytes)

	// get vulns (sbom)
	matchesFromSbom, _, _, err := grype.FindVulnerabilities(*store, fmt.Sprintf("sbom:%s", sbomFile.Name()), source.SquashedScope, nil)
	if err != nil {
		panic(err)
	}
	details := make([]match.Detail, 0)
	ids := strset.New()
	for _, m := range matchesFromSbom.Sorted() {
		details = append(details, m.Details...)
		ids.Add(m.Vulnerability.ID)
	}

	fmt.Printf("%s", details)
	// fmt.Printf("%s", matchesFromSbom)
	// fmt.Printf("Found %d vulnerabilities in sbom\n", matchesFromSbom.Count())
}

// tham khao tu: https://github.dev/wolfi-dev/wolfictl/blob/v0.11.0/pkg/scan/finding.go
func GetVuls2(ssbom sbom.SBOM) {
	// ssbom := GenSBOM("test-fixture/python/requirements.txt")
	// sbomBytes := PrintSBOM(sbom)
	syftPkgs := ssbom.Artifacts.Packages
	grypePkgs := grypePkg.FromCollection(syftPkgs, grypePkg.SynthesisConfig{})

	// Load the database
	dbCurator, _ := db.NewCurator(grypeDBConfig)
	dbCurator.ImportFrom(localDBFilePath)
	updated, err := dbCurator.Update()
	if err != nil {
		panic(err)
	}
	if updated {
		fmt.Println("Database updated")
	}
	
	dbStore, _, dbCloser, _ := grype.LoadVulnerabilityDB(grypeDBConfig, true)
	if dbCloser != nil {
		defer dbCloser.Close()
	}

	// Match Vulnerabilities with Packages
	VulMatcher := grype.DefaultVulnerabilityMatcher(*dbStore)
	matchesCollection, _, _ := VulMatcher.FindMatches(grypePkgs, grypePkg.Context{
		Source: &ssbom.Source,
		Distro: ssbom.Artifacts.LinuxDistribution,
	})

	// Present the results
	pb := models.PresenterConfig{
		Matches: *matchesCollection,
		Packages: grypePkgs,
		MetadataProvider: dbStore.MetadataProvider,
		SBOM: &ssbom,
	}

	var buffer bytes.Buffer

	// pres := table.NewPresenter(pb, true)
	pres := cyclonedxPres.NewJSONPresenter(pb)

	err = pres.Present(&buffer)
	if err != nil {
		panic(err)
	}
	
	actual := buffer.String()
	fmt.Printf("%s", actual)
}

// // Present creates a CycloneDX-based reporting
// func (pres *Presenter) Present(output io.Writer) error {
// 	// note: this uses the syft cyclondx helpers to create
// 	// a consistent cyclondx BOM across syft and grype
// 	cyclonedxBOM := cyclonedxhelpers.ToFormatModel(*pres.sbom)

// 	// empty the tool metadata and add grype metadata
// 	cyclonedxBOM.Metadata.Tools = &[]cyclonedx.Tool{
// 		{
// 			Vendor:  "anchore",
// 			Name:    pres.id.Name,
// 			Version: pres.id.Version,
// 		},
// 	}

// 	vulns := make([]cyclonedx.Vulnerability, 0)
// 	for _, m := range pres.results.Sorted() {
// 		v, err := NewVulnerability(m, pres.metadataProvider)
// 		if err != nil {
// 			continue
// 		}
// 		vulns = append(vulns, v)
// 	}
// 	cyclonedxBOM.Vulnerabilities = &vulns
// 	enc := cyclonedx.NewBOMEncoder(output, pres.format)
// 	enc.SetPretty(true)
// 	enc.SetEscapeHTML(false)

// 	return enc.Encode(cyclonedxBOM)
// }
