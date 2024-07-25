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
	"regexp"
	"strings"

	"github.com/codefresh-io/cli-v2/pkg/util"

	"github.com/codefresh-io/go-sdk/pkg/client"
	platmodel "github.com/codefresh-io/go-sdk/pkg/model/promotion-orchestrator"

	"github.com/spf13/cobra"
)

type (
	Slice struct {
		Edges    []*Edge              `json:"edges"`
		PageInfo *platmodel.SliceInfo `json:"pageInfo"`
	}

	Edge struct {
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

	cmd.AddCommand(NewProductReleaseListCommand())

	return cmd
}

func NewProductReleaseListCommand() *cobra.Command {

	var (
		productName       string
		page              int
		pageLimit         int
		statusList        string
		promotionFlowList string
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

			releaseStatus, err := ToProductReleaseStatus(statusList)
			promotionFlows, err := ToPromotionFlows(promotionFlowList)
			if err != nil {
				return err
			}
			filterArgs := platmodel.ProductReleaseFiltersArgs{
				Statuses:       releaseStatus,
				PromotionFlows: promotionFlows,
			}
			return RunProductReleaseList(ctx, filterArgs, productName, page, pageLimit)
		},
	}

	cmd.Flags().StringVarP(&statusList, "status", "s", "", "Filter by statuses")
	cmd.Flags().StringVar(&promotionFlowList, "promotion-flows", "", "Filter by promotion flows")
	cmd.Flags().IntVar(&page, "page", 1, "page number")
	cmd.Flags().IntVar(&pageLimit, "page-limit", 20, "page limit number")
	cmd.Flags().StringVarP(&productName, "product", "p", "", "product")

	return cmd
}

func RunProductReleaseList(ctx context.Context, filterArgs platmodel.ProductReleaseFiltersArgs, productName string, page int, pageLimit int) error {
	pagination := platmodel.SlicePaginationArgs{
		First: &pageLimit,
	}

	query := `
	query getProductReleasesList(
	  $productName: String!
	  $filters: ProductReleaseFiltersArgs!
	  $pagination: SlicePaginationArgs
	) {
	  productReleases(productName: $productName, filters: $filters, pagination: $pagination) {
		pageInfo {
			hasNextPage
			hasPrevPage
			startCursor
			endCursor
		}
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
	}
  `
	// add pagination - default for now is last 20
	variables := map[string]any{
		"filters":     filterArgs,
		"productName": productName,
		"pagination":  pagination,
	}

	var productReleasesPage map[string]any
	productReleasesPage, err := client.GraphqlAPI[map[string]any](ctx, cfConfig.NewClient().InternalClient(), query, variables)
	if err != nil {
		return err
	}
	productReleaseSlice, err := transformSlice(productReleasesPage)
	if len(productReleaseSlice.Edges) == 0 {
		return fmt.Errorf("no product releases found")
	}
	resJSON, err := json.MarshalIndent(productReleaseSlice.Edges, "", "\t")

	fmt.Println(string(resJSON))
	return nil
}

func mapToSliceInfo(data map[string]interface{}) (*platmodel.SliceInfo, error) {
	startCursor, _ := data["startCursor"].(string)
	endCursor, _ := data["endCursor"].(string)
	hasNextPage, _ := data["hasNextPage"].(bool)
	hasPrevPage, _ := data["hasPrevPage"].(bool)
	return &platmodel.SliceInfo{
		StartCursor: &startCursor,
		EndCursor:   &endCursor,
		HasNextPage: hasNextPage,
		HasPrevPage: hasPrevPage,
	}, nil
}

func transformSlice(data map[string]any) (*Slice, error) {
	edgesInterface, ok := data["edges"].([]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid JSON structure: missing or invalid 'edges' field")
	}

	var edges []*Edge
	for _, edgeInterface := range edgesInterface {
		edgeMap, _ := edgeInterface.(map[string]interface{})
		node, _ := edgeMap["node"].(map[string]interface{})
		edges = append(edges, &Edge{
			Node: node,
		})
	}

	pageInfoData, ok := data["pageInfo"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid JSON structure: missing or invalid 'pageInfo' field")
	}

	pageInfo, err := mapToSliceInfo(pageInfoData)
	if err != nil {
		return nil, err
	}

	return &Slice{
		Edges:    edges,
		PageInfo: pageInfo,
	}, nil
}
func ToProductReleaseStatus(stringStatusList string) ([]platmodel.ProductReleaseStatus, error) {
	if err := assertArrayPattern(stringStatusList, "status"); err != nil {
		return nil, err
	}

	if stringStatusList == "" {
		return nil, nil
	}

	stringStatus := strings.Split(stringStatusList, ",")

	statusMap := map[string]platmodel.ProductReleaseStatus{
		"running":    platmodel.ProductReleaseStatusRunning,
		"failed":     platmodel.ProductReleaseStatusFailed,
		"succeeded":  platmodel.ProductReleaseStatusSucceeded,
		"suspeneded": platmodel.ProductReleaseStatusSuspended,
	}
	var result []platmodel.ProductReleaseStatus
	for _, status := range stringStatus {
		if convertedStatus, ok := statusMap[status]; ok {
			result = append(result, convertedStatus)
		} else {
			return nil, fmt.Errorf("invalid status: %s", status)
		}
	}
	return result, nil
}
func ToPromotionFlows(promotionFlowList string) ([]string, error) {
	if err := assertArrayPattern(promotionFlowList, "promotion-flows"); err != nil {
		return nil, err
	}
	if promotionFlowList == "" {
		return nil, nil
	}
	return strings.Split(promotionFlowList, ","), nil
}

func assertArrayPattern(list string, argName string) error {
	pattern := `^(\w+,)*\w+$`
	match, err := regexp.MatchString(pattern, list)
	if err != nil {
		return err
	}
	if !match {
		return fmt.Errorf("invalid argument %s", argName)
	}
	return nil
}
