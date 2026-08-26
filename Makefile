# Generic build/install for any Linux/Unix distribution that has a Rust
# toolchain (cargo, rustc). Debian/Ubuntu and Fedora/RHEL/Arch have
# dedicated packaging under debian/ and packaging/ instead -- use this
# Makefile directly only when no distro packaging applies.

PREFIX  ?= /usr/local
DESTDIR ?=

.PHONY: build install uninstall clean test

build:
	cargo build --release

install: build
	install -Dm755 target/release/boringca $(DESTDIR)$(PREFIX)/bin/boringca
	install -Dm644 man/boringca.1 $(DESTDIR)$(PREFIX)/share/man/man1/boringca.1

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/bin/boringca
	rm -f $(DESTDIR)$(PREFIX)/share/man/man1/boringca.1

test: build
	./target/release/boringca --help >/dev/null

clean:
	cargo clean
