#!/bin/bash
ConfigMapName="${WASM_FILTER_CONFIG_MAP_NAME:-wasm-filter}"
TraceBackendAddress="${WASM_FILTER_TRACE_BACKEND_ADDRESS:-apiclarity-apiclarity.apiclarity.svc.cluster.local}"
BinaryPath="${WASM_FILTER_BINARY_PATH:-bin/release/http-trace-filter.wasm}"
TraceBackendPort="${WASM_FILTER_TRACE_BACKEND_PORT:-9000}"
TraceSamplingPort="${WASM_FILTER_TRACE_SAMPLING_PORT:-9990}"
TraceSamplingEnabled="${TRACE_SAMPLING_ENABLED:-false}"

# patch all the pods under this controller with annotations that mounts the wasm filter from the configmap into the envoy proxy
function patch() {
  local TO_PATCH="$1"
  LIST=$(kubectl -n ${ns} get ${TO_PATCH} -o jsonpath='{.items[*].metadata.name}')
  for item in ${LIST}
  do
    echo "Patching ${TO_PATCH}: ${item}"
    kubectl patch -n ${ns} ${TO_PATCH} ${item} -p '{"spec":{"template":{"metadata":{"annotations":{"sidecar.istio.io/userVolume":"[{\"name\":\"wasmfilters-dir\", \"configMap\": {\"name\": \"wasm-filter\"}}]",
     "sidecar.istio.io/userVolumeMount": "[{\"mountPath\":\"/var/local/lib/wasm-filters\",\"name\":\"wasmfilters-dir\"}]"}}}}}'
  done
}

# read the envoy filter yml and substitute trace backend address and port 
envoyFilter=`cat "envoyFilter.yaml" | sed "s/{{WASM_FILTER_TRACE_BACKEND_ADDRESS}}/$TraceBackendAddress/g" | sed "s/{{WASM_FILTER_TRACE_BACKEND_PORT}}/$TraceBackendPort/g" | sed "s/{{WASM_FILTER_TRACE_SAMPLING_PORT}}/$TraceSamplingPort/g"`

# TODO set plugin config
#if [ "$TraceSamplingEnabled" == "true" ]
#  envoyFilter=`echo $envoyFilter | sed "s/{{PLUGIN_CONFIG}}/{"}/g"`

then
else
fi

echo "Using wasm binary ${BinaryPath}"

for ns in "$@"
do
    echo "Adding envoy wasm filter to all pods in namespace ${ns}"
    ## check if namespace exists
    kubectl get ns ${ns} > /dev/null 2>&1
    if [ $? -ne 0 ]
    then
      echo "Namespace ${ns} was not found, skipping namespace"
      continue
    fi
    ## if configmap already exists in namespace, delete it
    kubectl get cm -n ${ns} ${ConfigMapName} > /dev/null 2>&1
    if [ $? -eq 0 ]
    then
      kubectl delete cm -n ${ns} ${ConfigMapName}
    fi
    ## create configmap with the wasm filter
    kubectl create configmap -n ${ns} ${ConfigMapName} --from-file=${BinaryPath}
    if [ $? -ne 0 ]
    then
      echo "Failed to create configmap from file ${BinaryPath}, aborting"
      exit 1
    fi
    ## add annotations to pods
    patch "deployments"
    patch "statefulsets"
    patch "daemonsets"

    ## apply envoy filter
    echo "$envoyFilter" | kubectl apply -n ${ns} -f -
    if [ $? -ne 0 ]
    then
      echo "Failed to apply envoyFilter.yaml, aborting"
      exit 1
    fi
done
