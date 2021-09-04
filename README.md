# Trace Exporter
## _APIClarity Envoy wasm filter_

Envoy wasm filter that can export http traffic from envoy proxy to any desired backend for analysis.

The exports are a POST request to /publish path, in the format:
```sh
type (
	SCNTelemetry struct {
		RequestID          string       `json:"request_id"`
		Scheme             string       `json:"scheme"`
		DestinationAddress string       `json:"destination_address"`
		SCNTRequest        SCNTRequest  `json:"scnt_request"`
		SCNTResponse       SCNTResponse `json:"scnt_response"`
	}

	SCNTRequest struct {
		Method string `json:"method"`
		Path   string `json:"path"`
		Host   string `json:"host"`
		SCNTCommon
	}

	SCNTResponse struct {
		StatusCode string `json:"status_code"`
		SCNTCommon
	}
	SCNTCommon struct {
		Version       string      `json:"version"`
		Headers       [][2]string `json:"headers"`
		Body          []byte      `json:"body"`
		TruncatedBody bool        `json:"truncated_body"`
	}
)
```
## Configure

you will need to set your backend address in the envoyFilter.yaml.
```sh
    - applyTo: CLUSTER
      match:
        context: SIDECAR_OUTBOUND
      patch:
        operation: ADD
        value: # cluster specification
          name: trace_analyzer
          type: LOGICAL_DNS
          connect_timeout: 0.5s
          lb_policy: ROUND_ROBIN
          load_assignment:
            cluster_name: trace_analyzer
            endpoints:
              - lb_endpoints:
                  - endpoint:
                      address:
                        socket_address:
                          protocol: TCP
                          address: "nats-proxy.portshift.svc.cluster.local"
                          port_value: 1323

```
Change address and port_value to your own.

### Build the filter

```sh
make docker_build
```

This will build the filter into `bin/http-trace-filter.wasm`

### Deploy

```sh
./deploy.sh <list of namespaces seperated by space>
```

This will deploy the filter to all the deployments in the provided namespaces.

This will also create a configmap containing the wasm filter in each namespace, called wasm-filter.  
If you would like to change the name of the configmap, you can set the environment variable WASM_FILTER_CONFIG_MAP_NAME

You might need to restart your pods in order for the filter to be deployed.  
After that you are good to go! 

## Build and deploy locally

Note - In order to build locally you need to have tinygo installed

On Mac:  
```sh
brew tap tinygo-org/tools  
brew install tinygo
```
Then you can run 
```sh
make build
```

In order to deploy the filter manually, you need to perform the following steps:
1. create a configmap containing the wasm binary: 
```sh
kubectl create configmap -n <ns> wasm-filter --from-file=bin/http-trace-filter.wasm
```
2. add the following annotations to any pod you want to send traces from:
```sh
annotations:
    sidecar.istio.io/userVolume: '[{"name":"wasmfilters-dir","configMap": {"name": "wasm-filter"}}]'
    sidecar.istio.io/userVolumeMount: '[{"mountPath":"/var/local/lib/wasm-filters","name":"wasmfilters-dir"}]'
```
3. apply the envoyFilter.yaml in the namespace.
4. you might need to restart the pod.

##
Current proxy-wasm-go-sdk version used is v0.13.0 Which supports istio 1.9.x, 1.10.x 

proxy-wasm-go-sdk depends on TinyGo's WASI (WebAssembly System Interface) target which is introduced in v0.16.0.

See https://github.com/tetratelabs/proxy-wasm-go-sdk for more details

