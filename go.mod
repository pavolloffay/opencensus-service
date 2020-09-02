module github.com/census-instrumentation/opencensus-service

go 1.12

replace k8s.io/client-go v2.0.0-alpha.0.0.20181121191925-a47917edff34+incompatible => k8s.io/client-go v0.0.0-20181121191925-a47917edff34

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
	github.com/PaesslerAG/jsonpath v0.1.1
	github.com/Shopify/sarama v1.19.0
	github.com/Traceableai/iam v0.0.0-20200301184440-cfe1c3c2bb43
	github.com/VividCortex/gohistogram v1.0.0 // indirect
	github.com/antlr/antlr4 v0.0.0-20190518164840-edae2a1c9b4b
	github.com/apache/thrift v0.0.0-20161221203622-b2a4d4ae21c7
	github.com/bmizerany/perks v0.0.0-20141205001514-d9a9656a3a4b // indirect
	github.com/census-instrumentation/opencensus-proto v0.2.1
	github.com/dgrijalva/jwt-go v3.2.0+incompatible
	github.com/go-kit/kit v0.8.0
	github.com/gogo/googleapis v1.2.0 // indirect
	github.com/golang/glog v0.0.0-20160126235308-23def4e6c14b
	github.com/golang/protobuf v1.4.1
	github.com/google/go-cmp v0.5.0
	github.com/google/gofuzz v1.1.0 // indirect
	github.com/gorilla/mux v1.6.2
	github.com/grpc-ecosystem/grpc-gateway v1.13.0
	github.com/honeycombio/opencensus-exporter v1.0.1
	github.com/jaegertracing/jaeger v1.9.0
	github.com/json-iterator/go v1.1.10
	github.com/niemeyer/pretty v0.0.0-20200227124842-a10e7caefd8e // indirect
	github.com/omnition/scribe-go v0.0.0-20190131012523-9e3c68f31124
	github.com/onsi/gomega v1.4.3
	github.com/opentracing/opentracing-go v1.1.0 // indirect
	github.com/openzipkin/zipkin-go v0.1.6
	github.com/orijtech/prometheus-go-metrics-exporter v0.0.3-0.20190313163149-b321c5297f60
	github.com/philhofer/fwd v1.0.0 // indirect
	github.com/pkg/errors v0.8.1
	github.com/prashantv/protectmem v0.0.0-20171002184600-e20412882b3a // indirect
	github.com/prometheus/client_golang v0.9.2
	github.com/prometheus/common v0.0.0-20181126121408-4724e9255275
	github.com/prometheus/procfs v0.0.0-20190117184657-bf6a532e95b1
	github.com/prometheus/prometheus v0.0.0-20190131111325-62e591f928dd
	github.com/rs/cors v1.6.0
	github.com/soheilhy/cmux v0.1.4
	github.com/spf13/cast v1.3.0
	github.com/spf13/cobra v0.0.5
	github.com/spf13/viper v1.3.2
	github.com/streadway/quantile v0.0.0-20150917103942-b0c588724d25 // indirect
	github.com/stretchr/objx v0.2.0 // indirect
	github.com/stretchr/testify v1.6.1
	github.com/tinylib/msgp v1.1.0 // indirect
	github.com/uber-go/atomic v1.3.2 // indirect
	github.com/uber/jaeger-client-go v2.16.0+incompatible // indirect
	github.com/uber/jaeger-lib v2.0.0+incompatible
	github.com/uber/tchannel-go v1.10.0
	github.com/wavefronthq/opencensus-exporter v0.0.0-20190506162721-983d7cdaceaf
	github.com/wavefronthq/wavefront-sdk-go v0.9.2
	go.opencensus.io v0.22.0
	go.uber.org/multierr v1.5.0 // indirect
	go.uber.org/zap v1.10.0
	golang.org/x/crypto v0.0.0-20191205180655-e7c4368fe9dd
	golang.org/x/lint v0.0.0-20190930215403-16217165b5de
	google.golang.org/api v0.7.0
	google.golang.org/grpc v1.27.0
	google.golang.org/protobuf v1.25.0
	gopkg.in/DataDog/dd-trace-go.v1 v1.12.1 // indirect
	gopkg.in/check.v1 v1.0.0-20200227125254-8fa46927fb4f // indirect
	gopkg.in/yaml.v2 v2.2.7
	gopkg.in/yaml.v3 v3.0.0-20200615113413-eeeca48fe776 // indirect
)

replace git.apache.org/thrift.git => github.com/apache/thrift v0.12.0
