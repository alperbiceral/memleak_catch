# Makefile for building and installing memleakcatch

BINARY_NAME=memleak_catch
BINARY_PATH=target/release/$(BINARY_NAME)
INSTALL_PATH=/usr/bin/$(BINARY_NAME)

.PHONY: all build install clean

all: build

build:
	sudo -E cargo build --release --manifest-path memleak_catch/Cargo.toml

install: build
	sudo -E cp $(BINARY_PATH) $(INSTALL_PATH)
	sudo -E chown root:root $(INSTALL_PATH)
	sudo -E chmod u+s $(INSTALL_PATH)
	@echo "Run Command: $(INSTALL_PATH)"

clean:
	sudo -E cargo clean --manifest-path memleak_catch/Cargo.toml