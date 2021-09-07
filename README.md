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
        SourceAddress      string       'json:"source_address"'
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

In order to set the backend address (where the traces will be sent to) you need to define the following environment variables:
```sh
    WASM_FILTER_TRACE_BACKEND_ADDRESS
    WASM_FILTER_TRACE_BACKEND_PORT

```

### Deploy the filter

```sh
./deploy.sh <list of namespaces seperated by space>
```

This will deploy the filter to all the deployments in the provided namespaces.

This will also create a configmap containing the wasm filter in each namespace, called wasm-filter.  
If you would like to change the name of the configmap, you can set the environment variable WASM_FILTER_CONFIG_MAP_NAME

You might need to restart your pods in order for the filter to be deployed.  
After that you are good to go! 

## Build and deploy your own filter

You can build the filter using docker

```sh
make docker_build
```

If you want to build the filter without using docker you need to have tinygo installed

On Mac:  
```sh
brew tap tinygo-org/tools  
brew install tinygo
```
Then you can run 
```sh
make build
```

The wasm filter binary will be in `bin/http-trace-filter.wasm`

Set the binary path via environment variable

```sh
WASM_FILTER_BINARY_PATH=bin/http-trace-filter.wasm
```

Then you can run the deploy script.

##
Current proxy-wasm-go-sdk version used is v0.13.0 Which supports istio 1.9.x, 1.10.x 

proxy-wasm-go-sdk depends on TinyGo's WASI (WebAssembly System Interface) target which is introduced in v0.16.0.

See https://github.com/tetratelabs/proxy-wasm-go-sdk for more details

