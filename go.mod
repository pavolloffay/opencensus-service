module github.com/census-instrumentation/opencensus-service

require (
	contrib.go.opencensus.io/exporter/aws v0.0.0-20181029163544-2befc13012d0
	contrib.go.opencensus.io/exporter/jaeger v0.1.1-0.20190430175949-e8b55949d948
	contrib.go.opencensus.io/exporter/ocagent v0.6.0
	contrib.go.opencensus.io/exporter/prometheus v0.1.0
	contrib.go.opencensus.io/exporter/stackdriver v0.12.5
	contrib.go.opencensus.io/exporter/zipkin v0.1.1
	contrib.go.opencensus.io/resource v0.1.2
	github.com/DataDog/datadog-go v2.2.0+incompatible // indirect
	github.com/DataDog/opencensus-go-exporter-datadog v0.0.0-20181026070331-e7c4bd17b329
	github.com/Shopify/sarama v1.19.0
	github.com/VividCortex/gohistogram v1.0.0 // indirect
	github.com/apache/thrift v0.0.0-20161221203622-b2a4d4ae21c7
	github.com/bmizerany/perks v0.0.0-20141205001514-d9a9656a3a4b // indirect
	github.com/census-instrumentation/opencensus-proto v0.2.1
	github.com/codahale/hdrhistogram v0.0.0-20161010025455-3a0bb77429bd // indirect
	github.com/go-kit/kit v0.9.0
	github.com/gogo/googleapis v1.2.0 // indirect
	github.com/golang/glog v0.0.0-20160126235308-23def4e6c14b
	github.com/golang/protobuf v1.3.2
	github.com/google/go-cmp v0.4.0
	github.com/gorilla/mux v1.6.2
	github.com/grpc-ecosystem/grpc-gateway v1.9.5
	github.com/honeycombio/opencensus-exporter v1.0.1
	github.com/inconshreveable/mousetrap v1.0.0 // indirect
	github.com/jaegertracing/jaeger v1.9.0
	github.com/omnition/scribe-go v0.0.0-20190131012523-9e3c68f31124
	github.com/openzipkin/zipkin-go v0.1.6
	github.com/orijtech/prometheus-go-metrics-exporter v0.0.3
	github.com/philhofer/fwd v1.0.0 // indirect
	github.com/pkg/errors v0.8.1
	github.com/prashantv/protectmem v0.0.0-20171002184600-e20412882b3a // indirect
	github.com/prometheus/client_golang v1.4.1
	github.com/prometheus/common v0.9.1
	github.com/prometheus/procfs v0.0.8
	github.com/prometheus/prometheus v0.0.0-20200106144642-d9613e5c466c
	github.com/rs/cors v1.6.0
	github.com/soheilhy/cmux v0.1.4
	github.com/spf13/cast v1.2.0
	github.com/spf13/cobra v0.0.3
	github.com/spf13/viper v1.2.1
	github.com/streadway/quantile v0.0.0-20150917103942-b0c588724d25 // indirect
	github.com/stretchr/testify v1.4.0
	github.com/tinylib/msgp v1.1.0 // indirect
	github.com/uber-go/atomic v1.3.2 // indirect
	github.com/uber/jaeger-client-go v2.16.0+incompatible // indirect
	github.com/uber/jaeger-lib v2.0.0+incompatible
	github.com/uber/tchannel-go v1.10.0
	github.com/wavefronthq/opencensus-exporter v0.0.0-20190506162721-983d7cdaceaf
	github.com/wavefronthq/wavefront-sdk-go v0.9.2
	github.com/yancl/opencensus-go-exporter-kafka v0.0.0-20181029030031-9c471c1bfbeb
	go.opencensus.io v0.22.3
	go.uber.org/atomic v1.3.2 // indirect
	go.uber.org/multierr v1.1.0 // indirect
	go.uber.org/zap v1.9.1
	golang.org/x/lint v0.0.0-20190409202823-959b441ac422
	google.golang.org/api v0.8.0
	google.golang.org/grpc v1.22.1
	gopkg.in/DataDog/dd-trace-go.v1 v1.12.1 // indirect
	gopkg.in/yaml.v2 v2.2.5
)

replace git.apache.org/thrift.git => github.com/apache/thrift v0.12.0

go 1.13
