.PHONY: lint check test build build-release

lint: 
	cargo fmt --all
	rustup component add clippy
	cargo clippy -- -D warnings

check:
	cargo c

test:
	cargo test

build:
	cargo build 

build-release:
	cargo build --release