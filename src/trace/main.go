// Copyright © 2021 Cisco Systems, Inc. and its affiliates.
// All rights reserved.
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

package main

import (
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm"
	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm/types"
)

// TODO need to move it to a public repo
type (
	SCNTelemetry struct {
		RequestID            string       `json:"request_id"`
		Scheme               string       `json:"scheme"`
		DestinationAddress   string       `json:"destination_address"`
		DestinationNamespace string       `json:"destination_namespace"`
		SourceAddress        string       `json:"source_address"`
		SCNTRequest          SCNTRequest  `json:"scnt_request"`
		SCNTResponse         SCNTResponse `json:"scnt_response"`
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

func main() {
	proxywasm.SetVMContext(&vmContext{})
}

type vmContext struct {
	types.DefaultVMContext
}

func (*vmContext) NewPluginContext(contextID uint32) types.PluginContext {
	return &pluginContext{}
}

type pluginContext struct {
	types.DefaultPluginContext
	// The server to which the traces will be sent
	serverAddress    string
	scnNATSSubject   string
	scnExampleConfig string
}

func (ctx *pluginContext) NewHttpContext(contextID uint32) types.HttpContext {
	proxywasm.LogDebugf("Called new http context. contextID: %v (we can use the scnExampleConfig here ...)", contextID)
	return &TraceFilterContext{
		contextID:      contextID,
		serverAddress:  ctx.serverAddress,
		scnNATSSubject: ctx.scnNATSSubject,
	}
}

type TraceFilterContext struct {
	types.DefaultHttpContext
	totalRequestBodySize  int
	totalResponseBodySize int
	skipStream            bool
	contextID             uint32
	rootContextID         uint32
	// The server to which the traces will be sent
	serverAddress  string
	scnNATSSubject string
	SCNTelemetry
}

func (ctx *pluginContext) OnPluginStart(pluginConfigurationSize int) types.OnPluginStartStatus {
	data, err := proxywasm.GetPluginConfiguration(pluginConfigurationSize)
	if err != nil {
		proxywasm.LogWarnf("No TraceFilter plugin configuration. Will use defaults")
	}
	ctx.scnExampleConfig = string(data)
	ctx.serverAddress = "trace_analyzer"          // This needs to be read from the configuration
	ctx.scnNATSSubject = "portshift.messaging.io" // This needs to be read from the configuration
	return types.OnPluginStartStatusOK
}

/**
 * override
 */
func (ctx *TraceFilterContext) OnHttpRequestHeaders(numHeaders int, endOfStream bool) types.Action {
	headers, err := proxywasm.GetHttpRequestHeaders()
	if err != nil {
		proxywasm.LogErrorf("Failed to get request headers: %v", err)
		ctx.skipStream = true
		return types.ActionContinue
	}
	proxywasm.LogDebugf("OnHttpRequestHeaders: contextID: %v. rootContextID: %v, endOfStream: %v, numHeaders: %v",
		ctx.contextID, ctx.rootContextID, endOfStream, numHeaders)
	proxywasm.LogDebugf("Request headers: %v", headers)

	var path string
	var host string
	var method string
	var xRequestID string

	if ctx.SCNTelemetry.SCNTRequest.Path == "" {
		path, err = proxywasm.GetHttpRequestHeader(":path")
		if err != nil {
			proxywasm.LogWarnf("Failed to get :path header: %v", err)
		}
		ctx.SCNTelemetry.SCNTRequest.Path = path
	}

	if ctx.SCNTelemetry.SCNTRequest.Host == "" {
		host, err = proxywasm.GetHttpRequestHeader(":authority")
		if err != nil {
			proxywasm.LogWarnf("Failed to get :authority header: %v", err)
		}
		ctx.SCNTelemetry.SCNTRequest.Host = host
		// Host: Header is removed, add it back.
		ctx.SCNTelemetry.SCNTRequest.Headers = append(ctx.SCNTelemetry.SCNTRequest.Headers, [2]string{"host", host})
	}

	if ctx.SCNTelemetry.SCNTRequest.Method == "" {
		method, err = proxywasm.GetHttpRequestHeader(":method")
		if err != nil {
			proxywasm.LogWarnf("Failed to get :method header: %v", err)
		}
		ctx.SCNTelemetry.SCNTRequest.Method = method
	}

	if ctx.SCNTelemetry.RequestID == "" {
		xRequestID, err = proxywasm.GetHttpRequestHeader("x-request-id")
		if err != nil {
			proxywasm.LogWarnf("Failed to get x-request-id header: %v", err)
		}
		ctx.SCNTelemetry.RequestID = xRequestID
	}

	ctx.SCNTelemetry.SCNTRequest.Headers = append(ctx.SCNTelemetry.SCNTRequest.Headers, removeEnvoyPseudoHeaders(headers)...)

	return types.ActionContinue
}

const MaxBodySize = 1000 * 1000

/**
 * override
 */
func (ctx *TraceFilterContext) OnHttpRequestBody(bodySize int, endOfStream bool) types.Action {
	proxywasm.LogDebugf("OnHttpRequestBody: contextID: %v. rootContextID: %v, endOfStream: %v", ctx.contextID, ctx.rootContextID, endOfStream)
	if ctx.shouldShortCircuitOnBody(bodySize, ctx.SCNTelemetry.SCNTRequest.TruncatedBody) {
		return types.ActionContinue
	}
	ctx.totalRequestBodySize += bodySize
	// if body size is too big, dont send it.
	if ctx.totalRequestBodySize > MaxBodySize {
		proxywasm.LogWarnf("Request body size has exceeded the limit of 1MB. Not sending")
		ctx.SCNTelemetry.SCNTRequest.TruncatedBody = true
		// clear body
		ctx.SCNTelemetry.SCNTRequest.Body = []byte{}
		return types.ActionContinue
	}
	body, err := proxywasm.GetHttpRequestBody(0, bodySize)
	if err != nil {
		proxywasm.LogErrorf("Failed to get request body: %v", err)
		ctx.skipStream = true
		return types.ActionContinue
	}
	ctx.SCNTelemetry.SCNTRequest.Body = append(ctx.SCNTelemetry.SCNTRequest.Body, body...)

	return types.ActionContinue
}

/**
 * override
 */
func (ctx *TraceFilterContext) OnHttpResponseHeaders(numHeaders int, endOfStream bool) types.Action {
	proxywasm.LogDebugf("OnHttpResponseHeaders: contextID: %v. rootContextID: %v, endOfStream: %v, numHeaders: %v", ctx.contextID, ctx.rootContextID, endOfStream, numHeaders)
	if ctx.skipStream {
		return types.ActionContinue
	}
	headers, err := proxywasm.GetHttpResponseHeaders()
	if err != nil {
		proxywasm.LogErrorf("Failed to get response headers: %v", err)
		ctx.skipStream = true
		return types.ActionContinue
	}

	proxywasm.LogDebugf("Response headers: %v", headers)

	var statusCode string
	if ctx.SCNTelemetry.SCNTResponse.StatusCode == "" {
		statusCode, err = proxywasm.GetHttpResponseHeader(":status")
		if err != nil {
			proxywasm.LogErrorf("Failed to get status code: %v", err)
		}
		ctx.SCNTelemetry.SCNTResponse.StatusCode = statusCode
	}

	ctx.SCNTelemetry.SCNTResponse.Headers = append(ctx.SCNTelemetry.SCNTResponse.Headers, removeEnvoyPseudoHeaders(headers)...)

	return types.ActionContinue
}

/**
 * override
 */
func (ctx *TraceFilterContext) OnHttpResponseBody(bodySize int, endOfStream bool) types.Action {
	proxywasm.LogDebugf("OnHttpResponseBody: contextID: %v. rootContextID: %v, endOfStream: %v", ctx.contextID, ctx.rootContextID, endOfStream)
	if ctx.shouldShortCircuitOnBody(bodySize, ctx.SCNTelemetry.SCNTResponse.TruncatedBody) {
		return types.ActionContinue
	}

	ctx.totalResponseBodySize += bodySize
	// if body size is too big, dont send it.
	if ctx.totalResponseBodySize > MaxBodySize {
		proxywasm.LogWarnf("Response body size has exceeded the limit of 1MB. Not sending")
		ctx.SCNTelemetry.SCNTResponse.TruncatedBody = true
		// clear body
		ctx.SCNTelemetry.SCNTResponse.Body = []byte{}
		return types.ActionContinue
	}

	body, err := proxywasm.GetHttpResponseBody(0, bodySize)
	if err != nil {
		proxywasm.LogErrorf("Failed to get response body: %v", err)
		ctx.skipStream = true
		return types.ActionContinue
	}
	ctx.SCNTelemetry.SCNTResponse.Body = append(ctx.SCNTelemetry.SCNTResponse.Body, body...)

	return types.ActionContinue
}

func httpCallResponseCallback(numHeaders, bodySize, numTrailers int) {
	proxywasm.LogDebugf("httpCallResponseCallback. numHeaders: %v, bodySize: %v, numTrailers: %v", numHeaders, bodySize, numTrailers)
	headers, err := proxywasm.GetHttpCallResponseHeaders()
	if err != nil {
		proxywasm.LogWarnf("Failed to get http call response headers. %v", err)
		return
	}
	for _, header := range headers {
		if header[0] == ":status" {
			proxywasm.LogDebugf("Got response status from trace server: %v", header[1])
		}
	}
}

/**
 * override
 */
// called when transaction (not necessarily connection) is done
func (ctx *TraceFilterContext) OnHttpStreamDone() {
	// https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/advanced/attributes
	destinationAddress, err := proxywasm.GetProperty([]string{"destination", "address"})
	if err != nil {
		proxywasm.LogError("Failed to get destination address")
		destinationAddress = []byte("")
	}
	sourceAddress, err := proxywasm.GetProperty([]string{"source", "address"})
	if err != nil {
		proxywasm.LogError("Failed to get source address")
		sourceAddress = []byte("")
	}
	ctx.SCNTelemetry.DestinationAddress = string(destinationAddress)
	ctx.SCNTelemetry.SourceAddress = string(sourceAddress)

	ctx.SCNTelemetry.DestinationNamespace = ""
	// catalogue;sock-shop;catalogue;latest;Kubernetes
	dst_workload, err := proxywasm.GetProperty([]string{"upstream_host_metadata", "filter_metadata","istio", "workload"})
	if err == nil {
		s := strings.Split(string(dst_workload), ";")
		if len(s) == 5 {
			ctx.SCNTelemetry.DestinationNamespace = s[1]
		}
	}

	proxywasm.LogDebugf("OnHttpStreamDone: contextID: %v. rootContextID: %v", ctx.contextID, ctx.rootContextID)
	if ctx.skipStream {
		proxywasm.LogError("skipStream was set to true. Not sending telemetry")
		return
	}

	if err := sendAuthPayload(&ctx.SCNTelemetry, ctx.serverAddress, ctx.scnNATSSubject); err != nil {
		proxywasm.LogErrorf("Failed to send payload. %v", err)
	}
}

const jsonPayload string = `{"request_id":"%v","scheme":"%v","destination_address":"%v","destination_namespace":"%v","source_address":"%v","scnt_request":{"method":"%v","path":"%v","host":"%v","version":"%v","headers":%v,"body":"%v","truncated_body":%v},"scnt_response":{"status_code":"%v","version":"%v","headers":%v,"body":"%v","truncated_body": %v}}`

const (
	httpCallTimeoutMs = 15000
)

var emptyTrailers = [][2]string{}

func sendAuthPayload(payload *SCNTelemetry, clusterName string, subject string) error {
	encodedBodyRequest := base64.StdEncoding.EncodeToString(payload.SCNTRequest.Body)
	encodedBodyResponse := base64.StdEncoding.EncodeToString(payload.SCNTResponse.Body)

	body := fmt.Sprintf(jsonPayload,
		payload.RequestID, payload.Scheme,
		payload.DestinationAddress,
		payload.DestinationNamespace,
		payload.SourceAddress,
		payload.SCNTRequest.Method, payload.SCNTRequest.Path, payload.SCNTRequest.Host, payload.SCNTRequest.Version, createJsonHeaders(payload.SCNTRequest.Headers), encodedBodyRequest, payload.SCNTRequest.TruncatedBody,
		payload.SCNTResponse.StatusCode, payload.SCNTResponse.Version, createJsonHeaders(payload.SCNTResponse.Headers), encodedBodyResponse, payload.SCNTResponse.TruncatedBody)

	asHeader := [][2]string{{":method", "POST"}, {":authority", "scn"}, {":path", "/publish"}, {"nats-subject", subject}, {"accept", "*/*"}, {"x-request-id", payload.RequestID}}
	if _, err := proxywasm.DispatchHttpCall(clusterName, asHeader, []byte(body), emptyTrailers,
		httpCallTimeoutMs, httpCallResponseCallback); err != nil {
		proxywasm.LogErrorf("Dispatch httpcall failed. %v", err)
		return err
	}
	return nil
}

func removeEnvoyPseudoHeaders(headers [][2]string) [][2]string {
	var ret [][2]string
	for _, header := range headers {
		if strings.HasPrefix(header[0], ":") || strings.HasPrefix(header[0], "x-envoy-") {
			continue
		}
		ret = append(ret, header)
	}
	return ret
}

func createJsonHeaders(headers [][2]string) string {
	ret := "["

	headersLen := len(headers)

	for i, header := range headers {
		h0 := strings.ReplaceAll(header[0], "\"", "\\\"")
		h1 := strings.ReplaceAll(header[1], "\"", "\\\"")
		if i != headersLen-1 {
			ret += fmt.Sprintf("[\"%v\", \"%v\"],", h0, h1)
		} else {
			ret += fmt.Sprintf("[\"%v\", \"%v\"]", h0, h1)
		}
	}
	ret += "]"
	return ret
}

func (ctx *TraceFilterContext) shouldShortCircuitOnBody(bodySize int, truncatedBody bool) bool {
	if ctx.skipStream {
		return true
	}
	if bodySize == 0 {
		return true
	}
	if truncatedBody {
		return true
	}

	return false
}
