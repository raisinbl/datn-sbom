package genSbom

import (
	"fmt"
	"os"
	// "main/Get_sbom"
	"github.com/anchore/grype/grype"
	"github.com/anchore/grype/grype/db"
	"github.com/anchore/grype/grype/match"
	// "github.com/anchore/grype/internal"
	// "github.com/anchore/syft/syft/format/spdxjson"
	// "github.com/anchore/syft/syft/format/spdxtagvalue"
	// "github.com/anchore/syft/syft/format/syftjson"
	// syftPkg "github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
	"github.com/scylladb/go-set/strset"
	// "github.com/stretchr/testify/assert"

)


func GetVuls() {
	fmt.Println("Hello, world!")
	sbomBytes := GetSBOM("test-fixture/python/requirements.txt")
	fmt.Println("-----------------")
	fmt.Printf(sbomBytes)

	store, _, closer, err := grype.LoadVulnerabilityDB(db.Config{
		DBRootDir: 	"/home/hung/.cache/grype/db/5",
		ListingURL: "https://toolbox-data.anchore.io/grype/databases/listing.json",
		ValidateByHashOnGet: false,
	}, true)

	if closer != nil {
		defer closer.Close()
	}

	if err != nil {
		panic(err)
	}

	// get vulns (sbom)
	sbomFile, err := os.CreateTemp("", "")

	_, err = sbomFile.WriteString(sbomBytes)

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

	fmt.Printf("Found %d vulnerabilities in sbom\n", matchesFromSbom.Count())
}
