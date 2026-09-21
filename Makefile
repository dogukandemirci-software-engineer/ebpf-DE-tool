.PHONY: build run check

BPF_TARGET := bpfel-unknown-none

build:
	cargo +nightly build -Z build-std=core --release -p hello-ebpf --target $(BPF_TARGET)
	cargo build --release -p hello

run: build
	sudo ./target/release/hello

check:
	cargo +nightly check -Z build-std=core -p hello-ebpf --target $(BPF_TARGET)
	cargo check -p hello

