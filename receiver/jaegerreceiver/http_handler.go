// Adapted github.com/jaegertracing/jaeger@v1.9.0/cmd/collector/app/http_handler.go
// The difference is that this apiHandler object will add the http headers to the thrift
// ctx passed onto the the SubmitBatches() method.
package jaegerreceiver

import (
	"context"
	"fmt"
	"io/ioutil"
	"mime"
	"net/http"
	"time"

	"github.com/apache/thrift/lib/go/thrift"
	"github.com/gorilla/mux"
	"github.com/jaegertracing/jaeger/cmd/collector/app"
	tchanThrift "github.com/uber/tchannel-go/thrift"

	tJaeger "github.com/jaegertracing/jaeger/thrift-gen/jaeger"
)

const (
	// UnableToReadBodyErrFormat is an error message for invalid requests
	UnableToReadBodyErrFormat = "Unable to process request body: %v"
	// ThriftRequestHeadersKey is the key for the thrift request http headers in the context
	ThriftRequestHeadersKey = "thrift-request-headers"
)

var (
	acceptedThriftFormats = map[string]struct{}{
		"application/x-thrift":                 {},
		"application/vnd.apache.thrift.binary": {},
	}
)

// APIHandler handles all HTTP calls to the collector
type apiHandler struct {
	jaegerBatchesHandler app.JaegerBatchesHandler
}

// ThriftRequestHeaders is type def to put headers into the Thrift context
type ThriftRequestHeaders string

// NewAPIHandler returns a new APIHandler
func newAPIHandler(
	jaegerBatchesHandler app.JaegerBatchesHandler,
) *apiHandler {
	return &apiHandler{
		jaegerBatchesHandler: jaegerBatchesHandler,
	}
}

// RegisterRoutes registers routes for this handler on the given router
func (aH *apiHandler) registerRoutes(router *mux.Router) {
	router.HandleFunc("/api/traces", aH.saveSpan).Methods(http.MethodPost)
}

func (aH *apiHandler) saveSpan(w http.ResponseWriter, r *http.Request) {
	bodyBytes, err := ioutil.ReadAll(r.Body)
	r.Body.Close()
	if err != nil {
		http.Error(w, fmt.Sprintf(UnableToReadBodyErrFormat, err), http.StatusInternalServerError)
		return
	}

	contentType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))

	if err != nil {
		http.Error(w, fmt.Sprintf("Cannot parse content type: %v", err), http.StatusBadRequest)
		return
	}

	if _, ok := acceptedThriftFormats[contentType]; !ok {
		http.Error(w, fmt.Sprintf("Unsupported content type: %v", contentType), http.StatusBadRequest)
		return
	}

	tdes := thrift.NewTDeserializer()
	// (NB): We decided to use this struct instead of straight batches to be as consistent with tchannel intake as possible.
	batch := &tJaeger.Batch{}
	if err = tdes.Read(batch, bodyBytes); err != nil {
		http.Error(w, fmt.Sprintf(UnableToReadBodyErrFormat, err), http.StatusBadRequest)
		return
	}

	// Create a context with a timeout and add the request headers to this ctx. Then wrap it around with
	// a thrift context object.
	timeoutCtx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	ctxWithRequestHeaders := context.WithValue(timeoutCtx, ThriftRequestHeaders(ThriftRequestHeadersKey), r.Header)
	ctx := tchanThrift.Wrap(ctxWithRequestHeaders)

	batches := []*tJaeger.Batch{batch}
	if _, err = aH.jaegerBatchesHandler.SubmitBatches(ctx, batches); err != nil {
		http.Error(w, fmt.Sprintf("Cannot submit Jaeger batch: %v", err), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusAccepted)
}
