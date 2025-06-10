default: all

AMD64_KERNELS = 5.4.276 5.10.217 5.15.159 6.1.91 6.6.31 6.8.10 6.9.1 6.12.16
ARM64_KERNELS = 6.6.31 6.8.4 6.9.1 6.12.16

GO_TAGS = osusergo,netgo,static_build

all:
	go generate ./oomprof
	go build -tags $(GO_TAGS) -ldflags='-extldflags=-static' -o oompa.taux .
	go test -tags $(GO_TAGS) -ldflags='-extldflags=-static' -c ./oomprof
	go build -tags $(GO_TAGS) -ldflags='-extldflags=-static' -o ./oomer.taux ./test

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
		KERN_DIR=ci-kernels-amd64 ./run-tests.sh $$kernel; \
	done
	for kernel in $(ARM64_KERNELS); do \
		QEMU_ARCH=aarch64 KERN_DIR=ci-kernels-arm64 ./run-tests.sh $$kernel; \
	done
