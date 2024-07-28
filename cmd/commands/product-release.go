// Copyright 2024 The Codefresh Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package commands

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/codefresh-io/cli-v2/pkg/util"

	"github.com/codefresh-io/go-sdk/pkg/client"
	platmodel "github.com/codefresh-io/go-sdk/pkg/model/promotion-orchestrator"
	"github.com/spf13/cobra"
)

type (
	productReleaseSlice struct {
		Edges []productReleaseEdge `json:"edges"`
	}

	productReleaseEdge struct {
		Node map[string]any `json:"node"`
	}
)

func NewProductReleaseCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:               "product-release",
		Short:             "Manage product releases of Codefresh account",
		PersistentPreRunE: cfConfig.RequireAuthentication,
		Args:              cobra.NoArgs, // Workaround for subcommand usage errors. See: https://github.com/spf13/cobra/issues/706
		Run: func(cmd *cobra.Command, args []string) {
			cmd.HelpFunc()(cmd, args)
			exit(1)
		},
	}

	cmd.AddCommand(newProductReleaseListCommand())

	return cmd
}

func newProductReleaseListCommand() *cobra.Command {
	var (
		page           int
		pageLimit      int
		productName    string
		statuses       []string
		promotionFlows []string
	)

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List all the pipelines",
		Args:  cobra.NoArgs,
		Example: util.Doc(`
			<BIN> product-release list --product <product>
		`),
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			releaseStatus, err := toProductReleaseStatus(statuses)
			if err != nil {
				return fmt.Errorf("failed to convert status: %w", err)
			}

			filterArgs := platmodel.ProductReleaseFiltersArgs{
				Statuses:       releaseStatus,
				PromotionFlows: promotionFlows,
			}
			return runProductReleaseList(ctx, filterArgs, productName, page, pageLimit)
		},
	}

	cmd.Flags().StringSliceVarP(&statuses, "status", "s", []string{}, "Filter by statuses, comma seperated array RUNNING|SUCCEEDED|SUSPENDED|FAILED")
	cmd.Flags().StringSliceVar(&promotionFlows, "promotion-flows", []string{}, "Filter by promotion flows, comma seperated array")
	cmd.Flags().IntVar(&page, "page", 1, "page number")
	cmd.Flags().IntVar(&pageLimit, "page-limit", 20, "page limit number")
	cmd.Flags().StringVarP(&productName, "product", "p", "", "product")

	return cmd
}

func runProductReleaseList(ctx context.Context, filterArgs platmodel.ProductReleaseFiltersArgs, productName string, page int, pageLimit int) error {
	query := `
query getProductReleasesList(
	$productName: String!
	$filters: ProductReleaseFiltersArgs!
	$pagination: SlicePaginationArgs
) {
	productReleases(productName: $productName, filters: $filters, pagination: $pagination) {
		edges {
			node {
			releaseId
			steps {
				environmentName
				status
			}
			status
			}
		}
	}
}`
	// add pagination - default for now is last 20
	variables := map[string]any{
		"filters":     filterArgs,
		"productName": productName,
		"pagination": platmodel.SlicePaginationArgs{
			First: &pageLimit,
		},
	}

	productReleasesPage, err := client.GraphqlAPI[productReleaseSlice](ctx, cfConfig.NewClient().InternalClient(), query, variables)
	if err != nil {
		return fmt.Errorf("failed to get product releases: %w", err)
	}

	// productReleaseSlice, err := TransformSlice(productReleasesPage)
	if len(productReleasesPage.Edges) == 0 {
		fmt.Println("No product releases found")
		return nil
	}

	nodes := extractNodesFromEdges(productReleasesPage.Edges)
	resJSON, err := json.MarshalIndent(nodes, "", "\t")
	if err != nil {
		return fmt.Errorf("failed to marshal product releases: %w", err)
	}

	fmt.Println(string(resJSON))
	return nil
}

func toProductReleaseStatus(statuses []string) ([]platmodel.ProductReleaseStatus, error) {
	var result []platmodel.ProductReleaseStatus
	for _, statusString := range statuses {
		status := platmodel.ProductReleaseStatus(statusString)
		if !status.IsValid() {
			return nil, fmt.Errorf("invalid product release status: %s", statusString)
		}

		result = append(result, platmodel.ProductReleaseStatus(statusString))
	}

	return result, nil
}

func extractNodesFromEdges(edges []productReleaseEdge) []map[string]any {
	res := []map[string]any{}
	for _, edge := range edges {
		res = append(res, edge.Node)
	}

	return res
}
