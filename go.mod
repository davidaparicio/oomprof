module github.com/parca-dev/oomprof

go 1.23.6

require (
	github.com/KimMachineGun/automemlimit v0.7.3
	github.com/cilium/ebpf v0.19.0
	github.com/containerd/cgroups/v3 v3.0.5
	github.com/elastic/go-freelru v0.16.0
	github.com/google/pprof v0.0.0-20250607225305-033d6d78b36a
	github.com/sirupsen/logrus v1.9.3
	github.com/stretchr/testify v1.10.0
	go.opentelemetry.io/ebpf-profiler v0.0.0-20250519164423-009a07f3803c
)

replace go.opentelemetry.io/ebpf-profiler => github.com/parca-dev/opentelemetry-ebpf-profiler v0.0.0-20250723174028-e4e60d5df998

require (
	github.com/containerd/log v0.1.0 // indirect
	github.com/coreos/go-systemd/v22 v22.5.0 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/godbus/dbus/v5 v5.1.0 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/json-iterator/go v1.1.12 // indirect
	github.com/klauspost/cpuid/v2 v2.2.8 // indirect
	github.com/minio/sha256-simd v1.0.1 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.2 // indirect
	github.com/opencontainers/runtime-spec v1.2.0 // indirect
	github.com/pbnjay/memory v0.0.0-20210728143218-7b4eea64cf58 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/rogpeppe/go-internal v1.13.1 // indirect
	github.com/zeebo/xxh3 v1.0.2 // indirect
	go.opentelemetry.io/collector/consumer v1.35.0 // indirect
	go.opentelemetry.io/collector/consumer/xconsumer v0.129.0 // indirect
	go.opentelemetry.io/collector/pdata v1.35.0 // indirect
	go.opentelemetry.io/collector/pdata/pprofile v0.129.0 // indirect
	go.opentelemetry.io/otel v1.37.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	golang.org/x/arch v0.18.0 // indirect
	golang.org/x/net v0.39.0 // indirect
	golang.org/x/sys v0.33.0 // indirect
	golang.org/x/text v0.24.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20250324211829-b45e905df463 // indirect
	google.golang.org/grpc v1.73.0 // indirect
	google.golang.org/protobuf v1.36.6 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
