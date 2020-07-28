// Package kafkaexporter : Copied from https://github.com/yancl/opencensus-go-exporter-kafka/blob/master/trace.go
package kafkaexporter

import (
	"fmt"
	"sync"
	"time"

	"github.com/Shopify/sarama"
	"github.com/census-instrumentation/opencensus-service/data"
	jaegertracetranslator "github.com/census-instrumentation/opencensus-service/translator/trace/jaeger"
	"github.com/golang/glog"
	"github.com/golang/protobuf/proto"
	jaegermodel "github.com/jaegertracing/jaeger/model"
	"google.golang.org/api/support/bundler"
)

// traceExporter is an implementation of trace.Exporter that uploads spans to
// Kafka.
//
type traceExporter struct {
	topic   string
	o       Options
	bundler *bundler.Bundler
	// uploadFn defaults to uploadSpans; it can be replaced for tests.
	uploadFn func(spans []*jaegermodel.Span)
	overflowLogger
	producer sarama.AsyncProducer
}

func newTraceExporter(o Options) (*traceExporter, error) {
	var p sarama.AsyncProducer
	if o.p != nil {
		p = o.p
	} else {
		var err error
		if p, err = newAsyncProducer(o.Brokers, o.MetadataRetryMax, o.MetadataRetryBackOff); err != nil {
			return nil, fmt.Errorf("opencensus kafka exporter: couldn't initialize kafka producer: %v", err)
		}
	}
	return newTraceExporterWithClient(o, p), nil
}

func newAsyncProducer(brokerList []string, metadataRetryMax int, metadataRetryBackOff time.Duration) (sarama.AsyncProducer, error) {
	config := sarama.NewConfig()
	config.Producer.RequiredAcks = sarama.WaitForLocal       // Only wait for the leader to ack
	config.Producer.Compression = sarama.CompressionSnappy   // Compress messages
	config.Producer.Flush.Frequency = 500 * time.Millisecond // Flush batches every 500ms
	if metadataRetryBackOff > 0 {
		config.Metadata.Retry.Backoff = metadataRetryBackOff
	}
	if metadataRetryMax > 0 {
		config.Metadata.Retry.Max = metadataRetryMax
	}

	producer, err := sarama.NewAsyncProducer(brokerList, config)
	if err != nil {
		return nil, fmt.Errorf("Failed to create Sarama kafka producer:%v", err)
	}

	// Note: messages will only be returned here after all retry attempts are exhausted.
	go func() {
		for err := range producer.Errors() {
			glog.Warningf("kafka send message failed:%v", err)
		}
	}()

	return producer, nil
}

func newTraceExporterWithClient(o Options, p sarama.AsyncProducer) *traceExporter {
	e := &traceExporter{
		producer: p,
		o:        o,
		topic:    o.Topic,
	}
	bundler := bundler.NewBundler((*jaegermodel.Span)(nil), func(bundle interface{}) {
		e.uploadFn(bundle.([]*jaegermodel.Span))
	})
	if o.BundleDelayThreshold > 0 {
		bundler.DelayThreshold = o.BundleDelayThreshold
	} else {
		bundler.DelayThreshold = 2 * time.Second
	}
	if o.BundleCountThreshold > 0 {
		bundler.BundleCountThreshold = o.BundleCountThreshold
	} else {
		bundler.BundleCountThreshold = 50
	}
	// The measured "bytes" are not really bytes, see exportReceiver.
	bundler.BundleByteThreshold = bundler.BundleCountThreshold * 200
	bundler.BundleByteLimit = bundler.BundleCountThreshold * 1000
	bundler.BufferedByteLimit = bundler.BundleCountThreshold * 2000

	e.bundler = bundler
	e.uploadFn = e.uploadSpans
	return e
}

func (e *traceExporter) ExportTrace(td data.TraceData) {
	// Convert OC spans to jaeger proto spans
	jaegerBatch, err := jaegertracetranslator.OCProtoToJaegerProto(td)
	if err != nil {
		glog.Warningln(fmt.Sprintf("OpenCensus Kafka exporter. Failed to convert OC Proto to Jaeger Proto: %s", err))
		return
	}

	for _, span := range jaegerBatch.Spans {
		// Add Process object to span
		if span.GetProcess() == nil {
			span.Process = jaegerBatch.GetProcess()
		}

		e.exportSpan(span)
	}
}

func (e *traceExporter) exportSpan(span *jaegermodel.Span) {
	// n is a length heuristic.
	n := 1
	n += len(span.Tags)
	n += len(span.Logs)
	n += len(span.Warnings)
	n += len(span.References)
	err := e.bundler.Add(span, n)
	switch err {
	case nil:
		return
	case bundler.ErrOversizedItem:
		go e.uploadFn([]*jaegermodel.Span{span})
	case bundler.ErrOverflow:
		e.overflowLogger.log()
	default:
		e.o.handleError(err)
	}
}

// Flush waits for exported trace spans to be uploaded.
//
// This is useful if your program is ending and you do not want to lose recent
// spans.
func (e *traceExporter) Flush() {
	e.bundler.Flush()
}

// uploadSpans uploads a set of spans to Kafka.
func (e *traceExporter) uploadSpans(spans []*jaegermodel.Span) {
	for _, span := range spans {
		key := sarama.ByteEncoder(span.TraceID.String())
		data, err := spanToBytes(span)
		if err != nil {
			e.o.handleError(err)
			return
		}

		// send message to kafka
		e.producer.Input() <- &sarama.ProducerMessage{
			Topic: e.topic,
			Key:   key,
			Value: sarama.ByteEncoder(data),
		}
	}
}

func spanToBytes(span *jaegermodel.Span) ([]byte, error) {
	serialized, err := proto.Marshal(span)
	if err != nil {
		return nil, err
	}
	return serialized, nil
}

// overflowLogger ensures that at most one overflow error log message is
// written every 5 seconds.
type overflowLogger struct {
	mu    sync.Mutex
	pause bool
	accum int
}

func (o *overflowLogger) delay() {
	o.pause = true
	time.AfterFunc(5*time.Second, func() {
		o.mu.Lock()
		defer o.mu.Unlock()
		switch {
		case o.accum == 0:
			o.pause = false
		case o.accum == 1:
			glog.Warningln("OpenCensus Kafka exporter: failed to upload span: buffer full")
			o.accum = 0
			o.delay()
		default:
			glog.Warningf("OpenCensus Kafka exporter: failed to upload %d spans: buffer full", o.accum)
			o.accum = 0
			o.delay()
		}
	})
}

func (o *overflowLogger) log() {
	o.mu.Lock()
	defer o.mu.Unlock()
	if !o.pause {
		glog.Warningln("OpenCensus Kafka exporter: failed to upload span: buffer full")
		o.delay()
	} else {
		o.accum++
	}
}
