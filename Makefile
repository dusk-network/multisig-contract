COMPILER_VERSION=v0.2.0

all: contract

test: contract
	@cargo test --release --manifest-path=tests/Cargo.toml

contract: setup-compiler
	@RUSTFLAGS="-C link-args=-zstack-size=65536" \
	cargo +dusk build \
	  --release \
	  --manifest-path=contract/Cargo.toml \
	  --color=always \
	  -Z build-std=core,alloc \
	  --target wasm64-unknown-unknown
	@mkdir -p build
	@find target/wasm64-unknown-unknown/release -maxdepth 1 -name "*.wasm" \
	    | xargs -I % basename % \
	    | xargs -I % ./scripts/strip.sh \
		target/wasm64-unknown-unknown/release/% \
		build/%

setup-compiler:
	@./scripts/setup-compiler.sh $(COMPILER_VERSION)

clean:
	@cargo clean
	@rm -rf build

.PHONY: all test contract setup-compiler clean
