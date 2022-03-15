#!/usr/bin/env bash

# used by the add-cluster-script.yaml
# compares the helm chart version with the kustomization image version to make sure they are identical

BASE_DIRECTORY="manifests/add-cluster"
HELM_CHART="${BASE_DIRECTORY}/helm/Chart.yaml"
KUSTOMIZATION_YAML="${BASE_DIRECTORY}/kustomize/kustomization.yaml"

HELM_VERSION=$(yq ".appVersion" ${HELM_CHART} | tr -d '"')
KUST_VERSION=$(yq '.images | select(.[].name == "quay.io/codefresh/csdp-add-cluster") | .[0].newTag' ${KUSTOMIZATION_YAML} | tr -d '"')
if ! semver-cli equal ${HELM_VERSION} ${KUST_VERSION}; then
  echo "mismatched versions:"
  echo "helm/Chart.yaml appVersion = ${HELM_VERSION}"
  echo "kustomize/kustomization.yaml newTag = ${KUST_VERSION}"
  exit 1
fi

echo "helm and kustomize versions match: ${HELM_VERSION}"
