# required env variables:
# SERVICE_ACCOUNT_NAME (fieldRef)
# CSDP_TOKEN (secret)
# INGRESS_URL (cm)
# CONTEXT_NAME (cm)
# SERVER (cm)
# CSDP_TOKEN_SECRET

echo "ServiceAccount: ${SERVICE_ACCOUNT_NAME}"
echo "Ingress URL: ${INGRESS_URL}"
echo "Context Name: ${CONTEXT_NAME}"
echo "Server: ${SERVER}"

# Path to ServiceAccount token
SERVICEACCOUNT=/var/run/secrets/kubernetes.io/serviceaccount

# Read this Pod's namespace
NAMESPACE=$(cat ${SERVICEACCOUNT}/namespace)

# Reference the internal certificate authority (CA)
CACERT=${SERVICEACCOUNT}/ca.crt

# get ServiceAccount token
SECRET_NAME=$(kubectl get ServiceAccount ${SERVICE_ACCOUNT_NAME} -n ${NAMESPACE} -o jsonpath='{.secrets[0].name}')
echo "Found ServiceAccount secret ${SECRET_NAME}"
BEARER_TOKEN=$(kubectl get secret ${SECRET_NAME} -n ${NAMESPACE} -o jsonpath='{.data.token}' | base64 -d)

# write KUBE_COPNFIG_DATA to local file
CLUSTER_NAME=$(echo ${SERVER} | sed s/'http[s]\?:\/\/'//)
kubectl config set-cluster "${CLUSTER_NAME}" --server=${SERVER} --certificate-authority=${CACERT}
kubectl config set-credentials ${SERVICE_ACCOUNT_NAME} --token ${BEARER_TOKEN}
kubectl config set-context "${CONTEXT_NAME}" --cluster="${CLUSTER_NAME}" --user=${SERVICE_ACCOUNT_NAME}
KUBE_CONFIG_B64=$(kubectl config view --minify --flatten --output json --context="${CONTEXT_NAME}" | base64 -w 0)

STATUS_CODE=$(curl -X POST ${INGRESS_URL}/app-proxy/api/clusters \
  -H 'Content-Type: application/json' \
  -H 'Authorization: '${CSDP_TOKEN}'' \
  -d '{ "name": "'${CONTEXT_NAME}'", "kubeConfig": "'${KUBE_CONFIG_B64}'" }' \
  -skL -o response -w "%{http_code}")
echo "STATUS_CODE: ${STATUS_CODE}"
cat response
echo

if [[ $STATUS_CODE == 000 ]]; then
  echo "error sending request to runtime"
  exit 1
fi

if [[ $STATUS_CODE -ge 300 ]]; then
  echo "error creating cluster in runtime"
  exit $STATUS_CODE
fi

echo "deleting token secret ${CSDP_TOKEN_SECRET}"
kubectl delete secret ${CSDP_TOKEN_SECRET} -n ${NAMESPACE}
