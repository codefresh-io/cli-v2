module github.com/codefresh-io/cli-v2

go 1.16

require (
	github.com/Masterminds/semver/v3 v3.1.1
	github.com/argoproj-labs/applicationset v0.2.0
	github.com/argoproj-labs/argocd-autopilot v0.2.30
	github.com/argoproj/argo-cd/v2 v2.1.9
	github.com/argoproj/argo-events v1.4.0
	github.com/argoproj/argo-workflows/v3 v3.1.6
	github.com/bmizerany/assert v0.0.0-20160611221934-b7ed37b82869 // indirect
	github.com/briandowns/spinner v1.16.0
	github.com/codefresh-io/go-sdk v0.37.8
	github.com/fatih/color v1.12.0
	github.com/ghodss/yaml v1.0.1-0.20190212211648-25d852aebe32
	github.com/go-git/go-billy/v5 v5.3.1
	github.com/go-git/go-git/v5 v5.4.1
	github.com/gobuffalo/packr v1.30.1
	github.com/google/uuid v1.3.0
	github.com/juju/ansiterm v0.0.0-20210929141451-8b71cc96ebdc
	github.com/manifoldco/promptui v0.8.0
	github.com/mattn/go-colorable v0.1.12 // indirect
	github.com/openshift/api v3.9.0+incompatible // indirect
	github.com/rkrmr33/checklist v0.0.5
	github.com/segmentio/backo-go v1.0.0 // indirect
	github.com/sirupsen/logrus v1.8.1
	github.com/spf13/cobra v1.1.3
	github.com/spf13/pflag v1.0.5
	github.com/spf13/viper v1.7.1
	github.com/stretchr/testify v1.7.0
	github.com/xtgo/uuid v0.0.0-20140804021211-a0b114877d4c // indirect
	golang.org/x/crypto v0.0.0-20210817164053-32db794688a5 // indirect
	gopkg.in/segmentio/analytics-go.v3 v3.1.0
	k8s.io/api v0.21.3
	k8s.io/apimachinery v0.21.1
	k8s.io/client-go v11.0.1-0.20190816222228-6d55c1b1f1ca+incompatible
	sigs.k8s.io/kustomize/api v0.8.8
)

replace (
	github.com/argoproj/argo-events => github.com/argoproj/argo-events v0.17.1-0.20210615165534-d403c441bc1d
	github.com/argoproj/gitops-engine => github.com/argoproj/gitops-engine v0.3.1-0.20210709004906-a4c77d5c70fb
	k8s.io/api => k8s.io/api v0.21.1
	k8s.io/apiextensions-apiserver => k8s.io/apiextensions-apiserver v0.21.1
	k8s.io/apimachinery => k8s.io/apimachinery v0.21.1
	k8s.io/apiserver => k8s.io/apiserver v0.21.1
	k8s.io/cli-runtime => k8s.io/cli-runtime v0.21.1
	k8s.io/client-go => k8s.io/client-go v0.21.1
	k8s.io/cloud-provider => k8s.io/cloud-provider v0.21.1
	k8s.io/cluster-bootstrap => k8s.io/cluster-bootstrap v0.21.1
	k8s.io/code-generator => k8s.io/code-generator v0.21.1
	k8s.io/component-base => k8s.io/component-base v0.21.1
	k8s.io/component-helpers => k8s.io/component-helpers v0.21.1
	k8s.io/controller-manager => k8s.io/controller-manager v0.21.1
	k8s.io/cri-api => k8s.io/cri-api v0.21.1
	k8s.io/csi-translation-lib => k8s.io/csi-translation-lib v0.21.1
	k8s.io/kube-aggregator => k8s.io/kube-aggregator v0.21.1
	k8s.io/kube-controller-manager => k8s.io/kube-controller-manager v0.21.1
	k8s.io/kube-proxy => k8s.io/kube-proxy v0.21.1
	k8s.io/kube-scheduler => k8s.io/kube-scheduler v0.21.1
	k8s.io/kubectl => k8s.io/kubectl v0.21.1
	k8s.io/kubelet => k8s.io/kubelet v0.21.1
	k8s.io/kubernetes => k8s.io/kubernetes v1.21.1
	k8s.io/legacy-cloud-providers => k8s.io/legacy-cloud-providers v0.21.1
	k8s.io/metrics => k8s.io/metrics v0.21.1
	k8s.io/mount-utils => k8s.io/mount-utils v0.21.1
	k8s.io/sample-apiserver => k8s.io/sample-apiserver v0.21.1
	sigs.k8s.io/kustomize => sigs.k8s.io/kustomize/v4 v4.1.3
)
