package genSbom

import (
	// "github.com/anchore/syft/syft/pkg/cataloger/python"
	"bytes"
	// "fmt"

	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/format/cyclonedxjson"
	"github.com/anchore/syft/syft/pkg/cataloger"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
)

func GetSBOM(userInput string) string{
	// userInput := "test-fixture/python/requirements.txt"
	detection, err := source.Detect(userInput, source.DefaultDetectConfig())
	if err != nil {
		panic(err)
	}
	theSource, err := detection.NewSource(source.DefaultDetectionSourceConfig())
	if err != nil {
		panic(err)
	}
	// TODO: this would be better with functional options (after/during API refactor)
	c := cataloger.DefaultConfig()
	c.Search.Scope = source.AllLayersScope
	pkgCatalog, relationships, actualDistro, err := syft.CatalogPackages(theSource, c)
	if err != nil {
		panic(err)
	}
	detectedSbom := sbom.SBOM{
		Artifacts: sbom.Artifacts{
			Packages:          pkgCatalog,
			LinuxDistribution: actualDistro,
		},
		Relationships: relationships,
		Source:        theSource.Describe(),
		Descriptor: sbom.Descriptor{
			Name:    "dhung-syft-engine",
			Version: "1.0", // shows up in the output for many different formats
		},
	} 
	cjsonEncoder,err := cyclonedxjson.NewFormatEncoderWithConfig(cyclonedxjson.DefaultEncoderConfig())
	if err != nil {
		panic(err)
	}

	// another way to get return  string json
	var buf bytes.Buffer

	err = cjsonEncoder.Encode(&buf, detectedSbom)
	if err != nil {
		panic(err)
	}
	return buf.String()
	}

// func main(){
// 	fmt.Printf(GetSBOM("test-fixture/python/requirements.txt"))
// }
