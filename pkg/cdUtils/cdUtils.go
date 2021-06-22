package cdUtils

import (
	"github.com/codefresh-io/cli-v2/pkg/store"

	apstore "github.com/argoproj-labs/argocd-autopilot/pkg/store"
	argocdv1alpha1 "github.com/argoproj/argo-cd/v2/pkg/apis/application/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type (
	CreateAppOptions struct {
		Name        string
		Namespace   string
		RepoURL     string
		Revision    string
		SrcPath     string
		DestServer  string
		NoFinalizer bool
	}
)

func CreateApp(opts *CreateAppOptions) *argocdv1alpha1.Application {
	if opts.DestServer == "" {
		opts.DestServer = apstore.Default.DestServer
	}

	app := &argocdv1alpha1.Application{
		TypeMeta: metav1.TypeMeta{
			Kind:       argocdv1alpha1.ApplicationSchemaGroupVersionKind.Kind,
			APIVersion: argocdv1alpha1.ApplicationSchemaGroupVersionKind.GroupVersion().String(),
		},
		ObjectMeta: metav1.ObjectMeta{
			Namespace: opts.Namespace,
			Name:      opts.Name,
			Labels: map[string]string{
				"app.kubernetes.io/managed-by": store.Get().BinaryName,
				"app.kubernetes.io/name":       opts.Name,
			},
			Finalizers: []string{
				"resources-finalizer.argocd.argoproj.io",
			},
		},
		Spec: argocdv1alpha1.ApplicationSpec{
			Project: "default",
			Source: argocdv1alpha1.ApplicationSource{
				RepoURL:        opts.RepoURL,
				Path:           opts.SrcPath,
				TargetRevision: opts.Revision,
			},
			Destination: argocdv1alpha1.ApplicationDestination{
				Server:    opts.DestServer,
				Namespace: opts.Namespace,
			},
			SyncPolicy: &argocdv1alpha1.SyncPolicy{
				Automated: &argocdv1alpha1.SyncPolicyAutomated{
					SelfHeal:   true,
					Prune:      true,
					AllowEmpty: true,
				},
				SyncOptions: []string{
					"allowEmpty=true",
				},
			},
			IgnoreDifferences: []argocdv1alpha1.ResourceIgnoreDifferences{
				{
					Group: "argoproj.io",
					Kind:  "Application",
					JSONPointers: []string{
						"/status",
					},
				},
			},
		},
	}
	if opts.NoFinalizer {
		app.ObjectMeta.Finalizers = []string{}
	}

	return app
}
