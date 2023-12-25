package genSbom

const (
	grypeDBListingURL string = "https://toolbox-data.anchore.io/grype/databases/listing.json"
	// mavenSearchBaseURL = "https://search.maven.org/solrsearch/select"
	CycloneDXJSON 	Format = "cyclonedx-json"
	TableFormat     Format = "table"
	UnknownFormat   Format = "unknown"
)

type Format string

func (f Format) String() string {
	return string(f)
}