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
	"github.com/anchore/grype/grype/presenter/table"
	"github.com/anchore/grype/grype/presenter/models"
	// syftPkg "github.com/anchore/syft/syft/pkg"

	_ "reflect"

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
func GetVuls2() {
	ssbom := GenSBOM("test-fixture/python/requirements.txt")
	// sbomBytes := PrintSBOM(sbom)
	syftPkgs := ssbom.Artifacts.Packages
	grypePkgs := grypePkg.FromCollection(syftPkgs, grypePkg.SynthesisConfig{})

	// Load the database
	dbCurator, _ := db.NewCurator(grypeDBConfig)
	dbCurator.ImportFrom(localDBFilePath)
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
	}

	var buffer bytes.Buffer

	pres := table.NewPresenter(pb, true)

	err := pres.Present(&buffer)
	if err != nil {
		panic(err)
	}
	
	actual := buffer.String()
	fmt.Printf("%s", actual)
}
