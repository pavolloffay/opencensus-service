// Package kafkaexporter : Copied from https://github.com/yancl/opencensus-go-exporter-kafka/blob/master/kafka.go
// This exports td.Trace instead of a single Span. The trace will be converted to jaeger proto format in
// kafkajaegerexporterimpl.go
package kafkaexporter

import (
	"context"
	"fmt"
	"github.com/golang/glog"
	"time"

	"github.com/Shopify/sarama"
	"github.com/census-instrumentation/opencensus-service/data"
	"go.opencensus.io/trace"
)

// Options contains options for configuring the exporter.
type Options struct {
	// Brokers is the addresses of the kafka brokers
	// Required
	Brokers []string

	// Topic is the topic of kafka to send spans to
	// Required
	Topic string

	// How long to wait for leader election to occur before retrying.
	MetadataRetryBackOff time.Duration

	// The total number of times to retry a metadata request when the
	// cluster is in the middle of a leader election.
	MetadataRetryMax int

	// OnError is the hook to be called when there is
	// an error uploading the tracing data.
	// If no custom hook is set, errors are logged.
	// Optional.
	OnError func(err error)

	// BundleDelayThreshold determines the max amount of time
	// the exporter can wait before uploading view data to
	// the backend.
	// Optional.
	BundleDelayThreshold time.Duration

	// BundleCountThreshold determines how many view data events
	// can be buffered before batch uploading them to the backend.
	// Optional.
	BundleCountThreshold int

	// DefaultTraceAttributes will be appended to every span that is exported to
	// Kafka Trace.
	DefaultTraceAttributes map[string]interface{}

	// Context allows users to provide a custom context for API calls.
	//
	// This context will be used several times: first, to create Kafka
	// trace and metric clients, and then every time a new batch of traces or
	// stats needs to be uploaded.
	//
	// If unset, context.Background() will be used.
	Context context.Context

	// p as a hook point allows mock for test
	p sarama.AsyncProducer
}

// Exporter is a trace.Exporter
// implementation that uploads data to Kafka.
type Exporter struct {
	traceExporter *traceExporter
}

// NewExporter creates a new Exporter that implements trace.Exporter.
func newKafkaExporter(o Options) (*Exporter, error) {
	if o.Context == nil {
		o.Context = context.Background()
	}

	if o.Brokers == nil {
		return nil, fmt.Errorf("opencensus kafka exporter: broker addrs are empty")
	}

	if o.Topic == "" {
		return nil, fmt.Errorf("opencensus kafka exporter: topic are empty")
	}

	te, err := newTraceExporter(o)
	if err != nil {
		return nil, err
	}

	return &Exporter{
		traceExporter: te,
	}, nil
}

// ExportTrace implements exporterwrapper.ExportTrace
func (e *Exporter) ExportTrace(td data.TraceData) {
	// TODO: Note in our custom implementation we do not support adding default attributes defined in
	// the kafka Options object into the spans.
	e.traceExporter.ExportTrace(td)
}

// TODO: Not supporting adding default trace attributes to spans that go into the kafka queue
func (e *Exporter) sdWithDefaultTraceAttributes(sd *trace.SpanData) *trace.SpanData {
	newSD := *sd
	newSD.Attributes = make(map[string]interface{})
	for k, v := range e.traceExporter.o.DefaultTraceAttributes {
		newSD.Attributes[k] = v
	}
	for k, v := range sd.Attributes {
		newSD.Attributes[k] = v
	}
	return &newSD
}

// Flush waits for exported data to be uploaded.
//
// This is useful if your program is ending and you do not
// want to lose recent stats or spans.
func (e *Exporter) Flush() {
	e.traceExporter.Flush()
}

func (o Options) handleError(err error) {
	if o.OnError != nil {
		o.OnError(err)
		return
	}
	glog.Warningf("Failed to export to Kafka: %v", err)
}
