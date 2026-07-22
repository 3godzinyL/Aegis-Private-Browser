# Aegis Private Browser — developer convenience targets.
# The host-side control plane builds on Linux/macOS/Windows; VM runtime is Linux.

.PHONY: all build test lint fmt clippy deny sbom audit clean daemon cli doc

all: fmt clippy test

build:
	cargo build --workspace

test:
	cargo test --workspace --all-features

fmt:
	cargo fmt --all

fmt-check:
	cargo fmt --all -- --check

clippy:
	cargo clippy --workspace --all-targets -- -D warnings

lint: fmt-check clippy

# Dependency policy: licenses + security advisories (spec Etap 5).
deny:
	cargo deny check

# Software Bill of Materials for a release (spec §10, Etap 5).
sbom:
	cargo cyclonedx --all --format json

audit:
	cargo audit

daemon:
	cargo run -p aegis-daemon

cli:
	cargo run -p aegis-cli -- $(ARGS)

doc:
	cargo doc --workspace --no-deps

clean:
	cargo clean
