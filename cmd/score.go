// Copyright 2023 Interlynk.io
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package cmd

import (
	"context"
	"fmt"
	"strings"

	"github.com/interlynk-io/sbomqs/pkg/engine"
	"github.com/interlynk-io/sbomqs/pkg/logger"
	"github.com/interlynk-io/sbomqs/pkg/reporter"
	"github.com/samber/lo"

	"github.com/spf13/cobra"
)

var (
	category     string
	feature      string
	reportFormat string
	configPath   string
)

type userCmd struct {
	//input control
	path []string

	//filter control
	category string
	features []string

	//output control
	json     bool
	basic    bool
	detailed bool

	//directory control
	recurse bool

	//debug control
	debug bool

	//config control
	configPath string
}

// scoreCmd represents the score command
var scoreCmd = &cobra.Command{
	Use:          "score",
	Short:        "comprehensive quality score for your sbom",
	SilenceUsage: true,
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) <= 0 {
			return fmt.Errorf("provide a path to an sbom file or directory of sbom files")
		}
		return nil
	},
	RunE: processScore,
}

func processScore(cmd *cobra.Command, args []string) error {
	debug, _ := cmd.Flags().GetBool("debug")
	if debug {
		logger.InitDebugLogger()
	} else {
		logger.InitProdLogger()
	}

	ctx := logger.WithLogger(context.Background())
	uCmd := toUserCmd(cmd, args)

	if err := validateFlags(uCmd); err != nil {
		return err
	}

	engParams := toEngineParams(uCmd)
	return engine.Run(ctx, engParams)
}
func toUserCmd(cmd *cobra.Command, args []string) *userCmd {
	uCmd := &userCmd{}

	//input control
	uCmd.path = append(uCmd.path, args[0:]...)

	//config control
	if configPath == "" {
		uCmd.configPath, _ = cmd.Flags().GetString("configpath")
	} else {
		uCmd.configPath = configPath
	}
	//filter control
	if category == "" {
		uCmd.category, _ = cmd.Flags().GetString("category")
	} else {
		uCmd.category = category
	}

	if feature == "" {
		f, _ := cmd.Flags().GetString("feature")
		uCmd.features = strings.Split(f, ",")
	}

	//output control
	uCmd.json, _ = cmd.Flags().GetBool("json")
	uCmd.basic, _ = cmd.Flags().GetBool("basic")
	uCmd.detailed, _ = cmd.Flags().GetBool("detailed")

	if reportFormat != "" {
		uCmd.json = strings.ToLower(reportFormat) == "json"
		uCmd.basic = strings.ToLower(reportFormat) == "basic"
		uCmd.detailed = strings.ToLower(reportFormat) == "detailed"
	}

	return uCmd
}

func toEngineParams(uCmd *userCmd) *engine.Params {
	return &engine.Params{
		Path:       uCmd.path,
		Category:   uCmd.category,
		Features:   uCmd.features,
		Json:       uCmd.json,
		Basic:      uCmd.basic,
		Detailed:   uCmd.detailed,
		Recurse:    uCmd.recurse,
		Debug:      uCmd.debug,
		ConfigPath: uCmd.configPath,
	}
}

func validateFlags(cmd *userCmd) error {

	for _, path := range cmd.path {
		if err := validatePath(path); err != nil {
			return fmt.Errorf("invalid path: %w", err)
		}
	}

	if cmd.configPath != "" {
		if err := validatePath(cmd.configPath); err != nil {
			return fmt.Errorf("invalid config path: %w", err)
		}
	}

	if len(reportFormat) > 0 && !lo.Contains(reporter.ReportFormats, reportFormat) {
		return fmt.Errorf("invalid report format: %s", reportFormat)
	}

	return nil
}
func init() {
	rootCmd.AddCommand(scoreCmd)

	//Config Control
	scoreCmd.Flags().StringP("configpath", "", "", "scoring based on config path")

	//Filter Control
	scoreCmd.Flags().StringP("category", "c", "", "filter by category")
	scoreCmd.Flags().StringP("feature", "f", "", "filter by feature")

	//Output Control
	scoreCmd.Flags().BoolP("json", "j", false, "results in json")
	scoreCmd.Flags().BoolP("detailed", "d", false, "results in table format, default")
	scoreCmd.Flags().BoolP("basic", "b", false, "results in single line format")
}
