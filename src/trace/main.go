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
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"unsafe"

	"github.com/valyala/fastjson"

	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm"
	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm/types"
)

// This was taken from APIClarity generated telemetry client api.
// We cant import this module from there since it includes package net which is not supported yet by tinygo.
type Telemetry struct {
	DestinationAddress   string    `json:"destinationAddress,omitempty"`
	DestinationNamespace string    `json:"destinationNamespace,omitempty"`
	Request              *Request  `json:"request,omitempty"`
	RequestID            string    `json:"requestID,omitempty"`
	Response             *Response `json:"response,omitempty"`
	Scheme               string    `json:"scheme,omitempty"`
	SourceAddress        string    `json:"sourceAddress,omitempty"`
}

type Request struct {
	Common *Common `json:"common,omitempty"`
	Host   string  `json:"host,omitempty"`
	Method string  `json:"method,omitempty"`
	Path   string  `json:"path,omitempty"`
}

type Response struct {
	Common     *Common `json:"common,omitempty"`
	StatusCode string  `json:"statusCode,omitempty"`
}

type Common struct {
	TruncatedBody bool      `json:"TruncatedBody,omitempty"`
	Body          string    `json:"body,omitempty"`
	Headers       []*Header `json:"headers"`
	Version       string    `json:"version,omitempty"`
	Time          int64     `json:"time,omitempty"`
}

type Header struct {
	Key   string `json:"key,omitempty"`
	Value string `json:"value,omitempty"`
}

type Config struct {
	EnableTraceSampling string  `json:"enable_trace_sampling,omitempty"`
}

var nativeEndian binary.ByteOrder

const tickMilliseconds uint32 = 60000 // 1 Minute

func main() {
	proxywasm.SetVMContext(&vmContext{})
}

type vmContext struct {
	types.DefaultVMContext
}

func (*vmContext) NewPluginContext(contextID uint32) types.PluginContext {
	if err := setEndianness(); err != nil {
		proxywasm.LogErrorf("Failed to set endianness: %v", err)
	}
	return &pluginContext{}
}

type pluginContext struct {
	types.DefaultPluginContext
	// The server to which the traces will be sent
	serverAddress       string
	scnNATSSubject      string
	enableTraceSampling bool
	hostsToTrace        map[string]struct{}
}

func (ctx *pluginContext) NewHttpContext(contextID uint32) types.HttpContext {
	proxywasm.LogDebugf("Called new http context. contextID: %v (we can use the scnExampleConfig here ...)", contextID)

	return &TraceFilterContext{
		contextID:      contextID,
		serverAddress:  ctx.serverAddress,
		scnNATSSubject: ctx.scnNATSSubject,
		hostsToTrace:   ctx.hostsToTrace,
		enableTraceSampling: ctx.enableTraceSampling,
		Telemetry: Telemetry{
			Request: &Request{
				Common: &Common{
					Headers: []*Header{},
				},
			},
			Response: &Response{
				Common: &Common{
					Headers: []*Header{},
				},
			},
		},
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

	Telemetry

	enableTraceSampling bool
	hostsToTrace map[string]struct{}
	isHostFixed  bool
}

func (ctx *pluginContext) OnPluginStart(_ int) types.OnPluginStartStatus {
	data, err := proxywasm.GetPluginConfiguration()
	if err != nil {
		proxywasm.LogWarnf("No TraceFilter plugin configuration. Will use defaults")
	}

	ctx.serverAddress = "trace_analyzer"          // This needs to be read from the configuration
	ctx.scnNATSSubject = "portshift.messaging.io" // This needs to be read from the configuration
	// TODO once we will have more things to configure, we can extract configuration in a better way. for now, since we only have enableTraceSampling configuration, I will just check that value
	ctx.enableTraceSampling = len(data) != 0

	if ctx.enableTraceSampling {
		ctx.callGetHostsToTrace()
		if err := proxywasm.SetTickPeriodMilliSeconds(tickMilliseconds); err != nil {
			proxywasm.LogCriticalf("failed to set tick period: %v", err)
			return types.OnPluginStartStatusFailed
		}
	}

	return types.OnPluginStartStatusOK
}

func (ctx *pluginContext) getHostsToTraceCallBack(_, bodySize, _ int) {
	responseBody, err := proxywasm.GetHttpCallResponseBody(0, bodySize)
	if err != nil {
		proxywasm.LogCriticalf("failed to get response body: %v", err)
		return
	}

	proxywasm.LogDebugf("got response body: %v", string(responseBody))

	hostsToTrace, err := getHostsToTrace(responseBody)
	if err != nil {
		proxywasm.LogCriticalf("failed to extract hosts to trace from body: %v", err)
		return
	}

	ctx.hostsToTrace = hostsToTrace
	proxywasm.LogDebugf("New host list to trace was set")
	//ctx.printHostsToTrace()
}

// getHostsToTrace helper function that received the callback response body (GET /api/hostsToTrace)
// and extract from it the list of hosts to trace
// swagger can be found in https://github.com/apiclarity/trace-sampling-manager/tree/tsm/api // TODO update link
func getHostsToTrace(responseBody []byte) (map[string]struct{}, error) {
	var parser fastjson.Parser

	parsedResponseBody, err := parser.Parse(string(responseBody))
	if err != nil {
		return nil, fmt.Errorf("failed to parse response body: %v", err)
	}

	hosts := parsedResponseBody.GetArray("hosts")

	hostsToTrace := make(map[string]struct{})
	for _, host := range hosts {
		hostsToTrace[string(host.GetStringBytes())] = struct{}{}
	}

	return hostsToTrace, nil
}

func (ctx *pluginContext) OnTick() {
	ctx.callGetHostsToTrace()
}

func (ctx *pluginContext) callGetHostsToTrace() {
	hs := [][2]string{
		{":method", "GET"}, {":authority", "apiclarity"}, {":path", "/api/hostsToTrace"}, {"accept", "*/*"},
	}
	proxywasm.LogDebugf("Retrieving hosts to trace from trace-sampling-manager")
	if _, err := proxywasm.DispatchHttpCall("trace-sampling-manager", hs, nil, emptyTrailers,
		httpCallTimeoutMs, ctx.getHostsToTraceCallBack); err != nil {
		proxywasm.LogCriticalf("dispatch httpcall failed: %v", err)
	}
}

/**
 * override
 */
func (ctx *TraceFilterContext) OnHttpRequestHeaders(numHeaders int, endOfStream bool) types.Action {
	if ctx.skipStream {
		return types.ActionContinue
	}

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

	if ctx.Telemetry.Request.Host == "" {
		host, err = proxywasm.GetHttpRequestHeader(":authority")
		if err != nil {
			proxywasm.LogWarnf("Failed to get :authority header: %v", err)
		}
		ctx.Telemetry.Request.Host = host
		// Host: Header is removed, add it back.
		ctx.Telemetry.Request.Common.Headers = append(ctx.Telemetry.Request.Common.Headers, &Header{
			Key:   "host",
			Value: host,
		})
	}

	// we expect the destination namespace to be empty at that point (we still dont have the upstream data).
	// this will check if the host already contains the namespace data or if it is external, and will fix the host into the correct expected format.
	ctx.Telemetry.Request.Host, ctx.isHostFixed, err = fixHostname(ctx.Telemetry.Request.Host, ctx.Telemetry.DestinationNamespace)
	if err != nil {
		proxywasm.LogErrorf("Failed to get host name and type: %v", err)
	}

	if !ctx.shouldTrace() {
		ctx.skipStream = true
		return types.ActionContinue
	}

	if ctx.Telemetry.Request.Path == "" {
		path, err = proxywasm.GetHttpRequestHeader(":path")
		if err != nil {
			proxywasm.LogWarnf("Failed to get :path header: %v", err)
		}
		ctx.Telemetry.Request.Path = path
	}

	if ctx.Telemetry.Request.Method == "" {
		method, err = proxywasm.GetHttpRequestHeader(":method")
		if err != nil {
			proxywasm.LogWarnf("Failed to get :method header: %v", err)
		}
		ctx.Telemetry.Request.Method = method
	}

	if ctx.Telemetry.RequestID == "" {
		xRequestID, err = proxywasm.GetHttpRequestHeader("x-request-id")
		if err != nil {
			proxywasm.LogWarnf("Failed to get x-request-id header: %v", err)
		}
		ctx.Telemetry.RequestID = xRequestID
	}

	ctx.Telemetry.Request.Common.Headers = append(ctx.Telemetry.Request.Common.Headers, removeEnvoyPseudoHeaders(headers)...)

	return types.ActionContinue
}

const MaxBodySize = 1000 * 1000

/**
 * override
 */
func (ctx *TraceFilterContext) OnHttpRequestBody(bodySize int, endOfStream bool) types.Action {
	proxywasm.LogDebugf("OnHttpRequestBody: contextID: %v. rootContextID: %v, endOfStream: %v", ctx.contextID, ctx.rootContextID, endOfStream)
	if ctx.shouldShortCircuitOnBody(bodySize, ctx.Telemetry.Request.Common.TruncatedBody) {
		return types.ActionContinue
	}
	ctx.totalRequestBodySize += bodySize
	// if body size is too big, dont send it.
	if ctx.totalRequestBodySize > MaxBodySize {
		proxywasm.LogWarnf("Request body size has exceeded the limit of 1MB. Not sending")
		ctx.Telemetry.Request.Common.TruncatedBody = true
		// clear body
		ctx.Telemetry.Request.Common.Body = ""
		return types.ActionContinue
	}
	body, err := proxywasm.GetHttpRequestBody(0, bodySize)
	if err != nil {
		proxywasm.LogErrorf("Failed to get request body: %v", err)
		ctx.skipStream = true
		return types.ActionContinue
	}
	ctx.Telemetry.Request.Common.Body = ctx.Telemetry.Request.Common.Body + string(body)

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
	var err error
	// here we should have the upstream data (namespace)
	ctx.Telemetry.DestinationNamespace, err = ctx.getDestinationNamespace()
	if err != nil {
		proxywasm.LogInfof("Failed to get destination namespace: %v", err)
	}
	// if we did not fix the host name in OnHttpRequestHeaders,do it now with the namespace info
	if !ctx.isHostFixed {
		ctx.Telemetry.Request.Host, ctx.isHostFixed, err = fixHostname(ctx.Telemetry.Request.Host, ctx.Telemetry.DestinationNamespace)
	}

	if !ctx.shouldTrace() {
		ctx.skipStream = true
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
	if ctx.Telemetry.Response.StatusCode == "" {
		statusCode, err = proxywasm.GetHttpResponseHeader(":status")
		if err != nil {
			proxywasm.LogErrorf("Failed to get status code: %v", err)
		}
		ctx.Telemetry.Response.StatusCode = statusCode
	}

	ctx.Telemetry.Response.Common.Headers = append(ctx.Telemetry.Response.Common.Headers, removeEnvoyPseudoHeaders(headers)...)

	return types.ActionContinue
}

/**
 * override
 */
func (ctx *TraceFilterContext) OnHttpResponseBody(bodySize int, endOfStream bool) types.Action {
	proxywasm.LogDebugf("OnHttpResponseBody: contextID: %v. rootContextID: %v, endOfStream: %v", ctx.contextID, ctx.rootContextID, endOfStream)
	if ctx.shouldShortCircuitOnBody(bodySize, ctx.Telemetry.Response.Common.TruncatedBody) {
		return types.ActionContinue
	}

	ctx.totalResponseBodySize += bodySize
	// if body size is too big, dont send it.
	if ctx.totalResponseBodySize > MaxBodySize {
		proxywasm.LogWarnf("Response body size has exceeded the limit of 1MB. Not sending")
		ctx.Telemetry.Response.Common.TruncatedBody = true
		// clear body
		ctx.Telemetry.Response.Common.Body = ""
		return types.ActionContinue
	}

	body, err := proxywasm.GetHttpResponseBody(0, bodySize)
	if err != nil {
		proxywasm.LogErrorf("Failed to get response body: %v", err)
		ctx.skipStream = true
		return types.ActionContinue
	}
	ctx.Telemetry.Response.Common.Body = ctx.Telemetry.Response.Common.Body + string(body)

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

const Millisecond = 1000 * 1000

/**
 * override
 */
// called when transaction (not necessarily connection) is done
func (ctx *TraceFilterContext) OnHttpStreamDone() {
	proxywasm.LogDebugf("OnHttpStreamDone: contextID: %v. rootContextID: %v", ctx.contextID, ctx.rootContextID)
	if ctx.skipStream {
		proxywasm.LogInfof("skipStream was set to true. Not sending telemetry")
		return
	}

	// https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/advanced/attributes
	destinationAddress, err := proxywasm.GetProperty([]string{"destination", "address"})
	if err != nil {
		proxywasm.LogError("Failed to get destination address")
		destinationAddress = []byte("")
	}
	reqTimeNano, err := proxywasm.GetProperty([]string{"request", "time"})
	if err != nil {
		proxywasm.LogError("Failed to get request time")
	}
	reqDurationNano, err := proxywasm.GetProperty([]string{"request", "duration"})
	if err != nil {
		proxywasm.LogError("Failed to get request duration")
	}
	reqTMilli := nativeEndian.Uint64(reqTimeNano) / (Millisecond)
	reqDMilli := nativeEndian.Uint64(reqDurationNano) / (Millisecond)

	ctx.Telemetry.Request.Common.Time = int64(reqTMilli)
	ctx.Telemetry.Response.Common.Time = int64(reqTMilli + reqDMilli)
	sourceAddress, err := proxywasm.GetProperty([]string{"source", "address"})
	if err != nil {
		proxywasm.LogError("Failed to get source address")
		sourceAddress = []byte("")
	}
	ctx.Telemetry.DestinationAddress = string(destinationAddress)
	ctx.Telemetry.SourceAddress = string(sourceAddress)

	if err := sendAuthPayload(&ctx.Telemetry, ctx.serverAddress, ctx.scnNATSSubject); err != nil {
		proxywasm.LogErrorf("Failed to send payload. %v", err)
	}
}

const jsonPayload string = `{"requestID":"%v","scheme":"%v","destinationAddress":"%v","destinationNamespace":"%v","sourceAddress":"%v","request":{"method":"%v","path":"%v","host":"%v","common": {"version":"%v","headers":%v,"body":"%v","TruncatedBody":%v,"time":%v}},"response":{"statusCode":"%v","common": {"version":"%v","headers":%v,"body":"%v","TruncatedBody": %v,"time":%v}}}`

const (
	httpCallTimeoutMs = 15000
)

var emptyTrailers = [][2]string{}

func sendAuthPayload(payload *Telemetry, clusterName string, subject string) error {
	encodedBodyRequest := base64.StdEncoding.EncodeToString([]byte(payload.Request.Common.Body))
	encodedBodyResponse := base64.StdEncoding.EncodeToString([]byte(payload.Response.Common.Body))

	body := fmt.Sprintf(jsonPayload,
		payload.RequestID, payload.Scheme,
		payload.DestinationAddress,
		payload.DestinationNamespace,
		payload.SourceAddress,
		payload.Request.Method, payload.Request.Path, payload.Request.Host, payload.Request.Common.Version, createJsonHeaders(payload.Request.Common.Headers), encodedBodyRequest, payload.Request.Common.TruncatedBody, payload.Request.Common.Time,
		payload.Response.StatusCode, payload.Response.Common.Version, createJsonHeaders(payload.Response.Common.Headers), encodedBodyResponse, payload.Response.Common.TruncatedBody, payload.Response.Common.Time)

	asHeader := [][2]string{{":method", "POST"}, {":authority", "apiclarity"}, {":path", "/api/telemetry"}, {"accept", "*/*"}, {"Content-Type", "application/json"}, {"x-request-id", payload.RequestID}}
	if _, err := proxywasm.DispatchHttpCall(clusterName, asHeader, []byte(body), emptyTrailers,
		httpCallTimeoutMs, httpCallResponseCallback); err != nil {
		proxywasm.LogErrorf("Dispatch httpcall failed. %v", err)
		return err
	}
	return nil
}

func removeEnvoyPseudoHeaders(headers [][2]string) []*Header {
	var ret []*Header
	for _, header := range headers {
		if strings.HasPrefix(header[0], ":") || strings.HasPrefix(header[0], "x-envoy-") {
			continue
		}
		ret = append(ret, &Header{
			Key:   header[0],
			Value: header[1],
		})
	}
	return ret
}

func createJsonHeaders(headers []*Header) string {
	ret := "["

	headersLen := len(headers)

	for i, header := range headers {
		h0 := strings.ReplaceAll(header.Key, "\"", "\\\"")
		h1 := strings.ReplaceAll(header.Value, "\"", "\\\"")
		if i != headersLen-1 {
			ret += fmt.Sprintf("{\"key\": \"%v\",\"value\": \"%v\"},", h0, h1)
		} else {
			ret += fmt.Sprintf("{\"key\": \"%v\",\"value\": \"%v\"}", h0, h1)
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

func (ctx *TraceFilterContext) getDestinationNamespace() (string, error) {
	// catalogue;sock-shop;catalogue;latest;Kubernetes or catalogue;sock-shop;catalogue;latest
	dstWorkload, err := proxywasm.GetProperty([]string{"upstream_host_metadata", "filter_metadata", "istio", "workload"})
	if err != nil {
		return "", fmt.Errorf("failed to get upstream_host_metadata: %v", err)
	}
	s := strings.Split(string(dstWorkload), ";")
	if len(s) == 5 || len(s) == 4 {
		return s[1], nil
	}
	return "", fmt.Errorf("destination namespace was not found")
}

func (ctx *TraceFilterContext) shouldTrace() bool {
	if !ctx.isHostFixed {
		return true
	}
	if !ctx.enableTraceSampling {
		return true
	}

	_, foundInApiToTrace := ctx.hostsToTrace[ctx.Telemetry.Request.Host]
	// check if we should trace all hosts
	_, shouldTraceAll := ctx.hostsToTrace["*"]

	if !foundInApiToTrace && !shouldTraceAll {
		proxywasm.LogDebugf("Host should not be traced. host=%v, foundInApiToTrace=%v, shouldTraceAll=%v",
			ctx.Telemetry.Request.Host, foundInApiToTrace, shouldTraceAll)
		return false
	}
	proxywasm.LogDebugf("Host should be traced. host=%v, foundInApiToTrace=%v, shouldTraceAll=%v",
		ctx.Telemetry.Request.Host, foundInApiToTrace, shouldTraceAll)
	return true
}

//
// fixHostname will return only hostname without scheme and port
// ex. https://example.org:8000 --> example.org. (for external services)
// for internal services:
// if host name ends with one of the known k8s suffixes, they will be removed.
// if host name consists of one word and namespace is empty, the host is returned.
// otherwise, if namespace is not empty, it will be appended to a single word host name.
// this will also return a bool to indicate if the host name has been fixed (true) or still need fixing (adding namespace info)
func fixHostname(host, namespace string) (string, bool, error) {
	if !strings.Contains(host, "://") {
		// need to add scheme to host in order for url.Parse to parse properly
		host = "http://" + host
	}

	parsedHost, err := url.Parse(host)
	if err != nil {
		return "", false, fmt.Errorf("failed to parse host. host=%v: %v", host, err)
	}

	if parsedHost.Hostname() == "" {
		return "", false, fmt.Errorf("hostname is empty. host=%v", host)
	}

	retHost := parsedHost.Hostname()

	if !strings.Contains(retHost, ".") {
		if namespace == "" {
			proxywasm.LogInfo("Got empty namespace in telemetry")
			return retHost, false, nil
		}
		retHost = retHost + "." + namespace
	} else {
		retHost = strings.TrimSuffix(retHost, ".svc.cluster.local")
		retHost = strings.TrimSuffix(retHost, ".svc.cluster")
		retHost = strings.TrimSuffix(retHost, ".svc")
	}

	return retHost, true, nil
}

func setEndianness() error {
	buf := [2]byte{}
	*(*uint16)(unsafe.Pointer(&buf[0])) = uint16(0xABCD)

	switch buf {
	case [2]byte{0xCD, 0xAB}:
		nativeEndian = binary.LittleEndian
	case [2]byte{0xAB, 0xCD}:
		nativeEndian = binary.BigEndian
	default:
		nativeEndian = binary.LittleEndian
		return fmt.Errorf("could not determine native endianness")
	}
	return nil
}
