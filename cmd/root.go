package cmd

import (
	"fmt"
	"os"

	// "github.com/raisinbl/datn-sbom/genSbom"
	cobra "github.com/spf13/cobra"
	"sigs.k8s.io/release-utils/version"
)
var rootCmd = &cobra.Command{
	Use:   "datn-sbom",
	Short: "SBOM Generator & Utilities",
	Long: `SBOM Generator & Utilities that are used to generate SBOMs and scan for vulnerabilities`,
	Run: func(cmd *cobra.Command, args []string) {
	  // Do Stuff Here
	//   genSbom.GetVuls2()
		cmd.Help()
		fmt.Println(version.GetVersionInfo().GitVersion)
	},
  }
  
func Execute() {
	if err := rootCmd.Execute(); err != nil {
	  fmt.Fprintln(os.Stderr, err)
	  os.Exit(1)
	}
  }

func init() {
	rootCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}

func validatePath(path string) error {
	if _, err := os.Stat(path); err != nil {
		return err
	}
	return nil
}