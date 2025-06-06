// Copyright 2025 The Codefresh Authors.
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
	"fmt"
	"github.com/codefresh-io/cli-v2/internal/kube"
	"github.com/codefresh-io/cli-v2/internal/log"
	"github.com/codefresh-io/cli-v2/internal/store"
	"github.com/codefresh-io/cli-v2/internal/util"
	"github.com/codefresh-io/cli-v2/internal/util/helm"
	kubeutil "github.com/codefresh-io/cli-v2/internal/util/kube"
	"github.com/codefresh-io/go-sdk/pkg/codefresh"
	"github.com/codefresh-io/go-sdk/pkg/graphql"
	platmodel "github.com/codefresh-io/go-sdk/pkg/model/platform"
	"github.com/spf13/cobra"
	"strings"
)

type (
	ValidateLimitsOptions struct {
		HelmValidateValuesOptions
		failCondition string
		subject       string
	}
)

const (
	failConditionReached  = "reached"
	failConditionExceeded = "exceeded"

	subjectClusters     = "clusters"
	subjectApplications = "applications"
)

func NewAccountCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "account",
		Short: "Account related commands",
		Args:  cobra.NoArgs, // Workaround for subcommand usage errors. See: https://github.com/spf13/cobra/issues/706
		Run: func(cmd *cobra.Command, args []string) {
			cmd.HelpFunc()(cmd, args)
			exit(1)
		},
	}

	cmd.AddCommand(NewValidateLimitsCommand())

	return cmd
}

func NewValidateLimitsCommand() *cobra.Command {
	opts := &ValidateLimitsOptions{}

	cmd := &cobra.Command{
		Use:     "validate-usage",
		Aliases: []string{"vu"},
		Args:    cobra.NoArgs,
		Short:   "Validate usage of account resources",
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			if opts.hook {
				return nil
			}
			return cfConfig.RequireAuthentication(cmd, args)
		},
		Example: util.Doc("<BIN> account validate-usage"),
		PreRun: func(cmd *cobra.Command, _ []string) {
			opts.namespace = cmd.Flag("namespace").Value.String()
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			if opts.hook {
				log.G(ctx).Infof("Running in hook-mode")
			}

			var (
				client codefresh.Codefresh
				err    error
			)
			if opts.hook {
				runtimeToken, _ := kubeutil.GetValueFromSecret(ctx, opts.kubeFactory, opts.namespace, store.Get().CFTokenSecret, "token")
				if runtimeToken != "" {
					log.G(ctx).Infof("Skip hook execution. Runtime already exists.")
					return nil
				}
				client, err = createPlatformClientInRuntime(ctx, &opts.HelmValidateValuesOptions)
				if err != nil {
					return err
				}
			} else {
				client = cfConfig.NewClient()
			}
			user, err := client.GraphQL().User().GetCurrent(cmd.Context())
			if err != nil {
				return err
			}
			if v := user.ActiveAccount.Features.GitopsPlanEnforcement; v == nil || !*v {
				log.G(ctx).Infof("Skip hook execution. GitopsPlanEnforcement feature is disabled.")
				return nil
			}
			payments := client.GraphQL().Payments()
			err = runValidateLimits(cmd.Context(), opts, payments)
			if err != nil {
				return fmt.Errorf("failed validating usage: %w", err)
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&opts.failCondition, "fail-condition", failConditionExceeded, "condition to validate [reached | exceeded]")
	cmd.Flags().StringVar(&opts.subject, "subject", "", "subject to validate [clusters | applications]. All subjects when omitted")
	cmd.Flags().StringVarP(&opts.valuesFile, "values", "f", "", "specify values in a YAML file or a URL")
	cmd.Flags().BoolVar(&opts.hook, "hook", false, "set to true when running inside a helm-hook")
	opts.helm, _ = helm.AddFlags(cmd.Flags())
	opts.kubeFactory = kube.AddFlags(cmd.Flags())

	util.Die(cmd.Flags().MarkHidden("hook"))

	return cmd
}

func runValidateLimits(ctx context.Context, opts *ValidateLimitsOptions, payments graphql.PaymentsAPI) error {
	log.G(ctx).Info("Validating account usage")

	limitsStatus, err := payments.GetLimitsStatus(ctx)
	if err != nil {
		return err
	}

	if limitsStatus.Limits == nil {
		log.G(ctx).Infof("Limits are not defined for account")
		return nil
	}

	err = ValidateGitOpsUsage(*limitsStatus.Usage, *limitsStatus.Limits, opts.failCondition, opts.subject)
	if err != nil {
		return fmt.Errorf("usage validation error: %s", err.Error())
	}

	log.G(ctx).Infof("Successfully validated usage for account")
	return nil
}

// ValidateGitOpsUsage checks whether the usage exceeds or reaches the defined limits.
// - If 'limits' for a field is nil, validation passes for that field.
// - If 'subject' is provided, only that field is checked. Otherwise, all fields are checked.
// - If 'failCondition' is "reached", validation fails if usage == limit.
// - If 'failCondition' is "exceeded", validation fails only if usage > limit.
// - If a field in 'usage' has no corresponding field in 'limits', validation passes for that field.
func ValidateGitOpsUsage(usage platmodel.GitOpsUsage, limits platmodel.GitOpsLimits, failCondition string, subject string) error {
	check := func(usageVal, limitVal *int, name string) error {
		// If usageVal is nil, return an error
		if usageVal == nil {
			return fmt.Errorf("%s usage is missing", name)
		}

		// Skip validation if the limit is not set
		if limitVal == nil {
			return nil
		}

		switch failCondition {
		case failConditionReached:
			if *usageVal >= *limitVal {
				condition := failConditionReached
				if *usageVal > *limitVal {
					condition = failConditionExceeded
				}
				return fmt.Errorf("%s limit %s: usage=%d, limit=%d", name, condition, *usageVal, *limitVal)
			}
		case failConditionExceeded:
			if *usageVal > *limitVal {
				return fmt.Errorf("%s limit exceeded: usage=%d, limit=%d", name, *usageVal, *limitVal)
			}
		default:
			return fmt.Errorf("invalid fail condition")
		}
		log.G().Infof("Limit checking succeeded. condition=%s, subject=%s, usage=%d, limit=%d", failCondition, subject, *usageVal, *limitVal)
		return nil
	}

	subject = strings.ToLower(subject)
	validSubjects := map[string]bool{
		"":                  true,
		subjectApplications: true,
		subjectClusters:     true,
	}

	if !validSubjects[subject] {
		return fmt.Errorf("invalid subject: %s", subject)
	}

	if subject == subjectApplications || subject == "" {
		if err := check(usage.Applications, limits.Applications, subjectApplications); err != nil {
			return err
		}
	}

	if subject == subjectClusters || subject == "" {
		if err := check(usage.Clusters, limits.Clusters, subjectClusters); err != nil {
			return err
		}
	}

	// No validation errors
	return nil
}
