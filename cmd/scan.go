/*
Copyright © 2023 HUNG NGUYEN DUY <hung.nd.4work@gmail.com>
*/
package cmd

import (
	"fmt"
	"os"

	// "path"

	"github.com/raisinbl/datn-sbom/genSbom"
	"github.com/spf13/cobra"
)

// scanCmd represents the scan command
var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scan for Dependencies and Vulnerabilities",
	Long: `Scaning for Dependencies and Vulnerabilities`,
	// Args: validateNumArgs,
	Run: Scan,	
}

func init() {
	rootCmd.AddCommand(scanCmd)
	scanCmd.Flags().StringP("path", "p", "", "Path to the project")
	scanCmd.Flags().BoolP("vuls", "V", false, "Scan for vulnerabilities")
	scanCmd.Flags().StringP("format", "f", "table", "Output format")
	// scanCmd.Flags().StringP("name", "n", "", "Name of the project")
	// scanCmd.Flags().StringP("version", "v", "", "Version of the project")
}

func Scan(cmd *cobra.Command, args []string) {
	path, err := parseArgs(cmd, args)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	err = validatePath(path)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	format , _ := cmd.Flags().GetString("format");
	// name , _ := cmd.Flags().GetString("name");
	// version , _ := cmd.Flags().GetString("version");

	sbom := genSbom.GenSBOM(path)
	if cmd.Flags().Changed("vuls") {
		genSbom.GetVuls2(sbom, genSbom.Format(format))
	} else {
		fmt.Println(genSbom.PrintSBOM(sbom, genSbom.Format(format)))	
	}
	
}

func parseArgs(cmd *cobra.Command, args []string) (string, error) {
	if len(args) == 1 {
		return args[0], nil
	}

	path, err := cmd.Flags().GetString("path")
	if err != nil {
		return "Not a valid file/directory", err
	}

	return path, nil
}
// func validateNumArgs(cmd *cobra.Command, args []string) error {
// 	if len(args) == 0 {
// 		// in the case that no arguments are given and there is no piped input we want to show the help text and return with a non-0 return code.
// 		if err := cmd.Help(); err != nil {
// 			return fmt.Errorf("unable to display help: %w", err)
// 		}
// 		return fmt.Errorf("a file/directory argument is required")
// 	}

// 	return cobra.MaximumNArgs(1)(cmd, args)
// }