default: all

.PHONY: all oompa tests tests-arm64 clean lint generate kernel-tests kernel-tests-quick

AMD64_KERNELS = 5.4.276 5.10.217 5.15.159 6.1.91 6.6.31 6.8.10 6.9.1 6.12.16
ARM64_KERNELS = 6.6.31 6.8.4 6.9.1 6.12.16 6.13.4

GO_TAGS = osusergo,netgo,static_build
GO_ARCH ?= $(shell uname -m | sed 's/x86_64/amd64/g' | sed 's/aarch64/arm64/g')
export GOARCH = $(GO_ARCH)

lint:
	go run github.com/golangci/golangci-lint/cmd/golangci-lint@latest run

clean:
	rm -f oompa *.taux tests/*.taux tests/*.test oomprof/bpf_*.*

generate:
	go generate ./oomprof

oompa: generate
	go build -tags $(GO_TAGS) -ldflags='-extldflags=-static' -o oompa .

tests: generate
	go test -tags $(GO_TAGS) -ldflags='-extldflags=-static' -c -o ./tests/oomprof.test ./oomprof
	go build -tags $(GO_TAGS) -ldflags='-extldflags=-static' -o ./tests/oomer.taux ./tests/oomer
	go build -tags $(GO_TAGS) -ldflags='-extldflags=-static' -o ./tests/gccache.taux ./tests/gccache
	go build -tags $(GO_TAGS) -ldflags='-extldflags=-static' -o ./tests/compile-oom.taux ./tests/compile-oom

cgroup-tests: tests
	cd tests && sudo ./oomprof.test -test.v -test.run TestOOMProf 2>&1 | tee oomprof.log

tests-arm64:
	GOARCH=arm64 go generate ./oomprof
	GOARCH=arm64 go test -tags $(GO_TAGS) -ldflags='-extldflags=-static' -c -o ./tests/oomprof.test ./oomprof
	GOARCH=arm64 go build -tags $(GO_TAGS) -ldflags='-extldflags=-static' -o ./tests/oomer.taux ./tests/oomer
	GOARCH=arm64 go build -tags $(GO_TAGS) -ldflags='-extldflags=-static' -o ./tests/gccache.taux ./tests/gccache
	GOARCH=arm64 go build -tags $(GO_TAGS) -ldflags='-extldflags=-static' -o ./tests/compile-oom.taux ./tests/compile-oom

all: oompa tests

arm64-kernels:
	@DEST=ci-kernels-arm64; \
	mkdir -p $$DEST; \
	for kernel in $(ARM64_KERNELS); do \
		if [ -f $$DEST/$$kernel/boot/vmlinuz ]; then \
			echo "ARM64 kernel $$kernel already exists, skipping..."; \
		else \
			echo "Downloading ARM64 kernel $$kernel..."; \
			echo "FROM ghcr.io/cilium/ci-kernels:$$kernel" | docker buildx build --platform linux/arm64 --quiet --pull --output="$$DEST" -; \
			mkdir -p $$DEST/$$kernel; \
			mv $$DEST/boot/vmlinuz $$DEST/$$kernel/; \
		fi \
	done

amd64-kernels:
	@DEST=ci-kernels-amd64; \
	mkdir -p $$DEST; \
	for kernel in $(AMD64_KERNELS); do \
		if [ -f $$DEST/$$kernel/boot/vmlinuz ]; then \
			echo "AMD64 kernel $$kernel already exists, skipping..."; \
		else \
			echo "Downloading AMD64 kernel $$kernel..."; \
			echo "FROM ghcr.io/cilium/ci-kernels:$$kernel" | docker buildx build --platform linux/amd64 --quiet --pull --output="$$DEST" -; \
			mkdir -p $$DEST/$$kernel; \
			mv $$DEST/boot/vmlinuz $$DEST/$$kernel/; \
		fi \
	done

kernel-tests: amd64-kernels arm64-kernels
	for kernel in $(AMD64_KERNELS); do \
		cd tests && KERN_DIR=../ci-kernels-amd64 ./run-tests.sh $$kernel; \
	done
	for kernel in $(ARM64_KERNELS); do \
		cd tests && QEMU_ARCH=aarch64 KERN_DIR=../ci-kernels-arm64 ./run-tests.sh $$kernel; \
	done

# Quick test with just a couple of kernels
kernel-tests-quick: tests-arm64
	cd tests && QEMU_ARCH=aarch64 KERN_DIR=../ci-kernels-arm64 ./run-tests.sh 6.13.4

