.PHONY: build-docker build-image build clean

DOCKER_OUTPUT ?= target/docker
# CI passes BuildKit secrets here; local builds need no Guard credentials.
DOCKER_BUILD_FLAGS ?=

# Build bloodhound binary via Docker (works on any OS)
build-docker:
	docker build \
		--platform linux/amd64 \
		-f Dockerfile.build \
		$(DOCKER_BUILD_FLAGS) \
		--output type=local,dest=$(DOCKER_OUTPUT) \
		.

# Build only the toolchain stage (CI cache warming)
build-image:
	docker build \
		--platform linux/amd64 \
		-f Dockerfile.build \
		--target toolchain \
		-t bloodhound-toolchain \
		.

# Native cargo build (Linux only)
build:
	cargo build --package bloodhound --release --target x86_64-unknown-linux-musl

# Clean Docker build output
clean:
	rm -rf $(DOCKER_OUTPUT)
