# boringca

A tiny command-line tool to quickly create a root Certificate Authority and
issue server/client certificates signed by it -- for local development, home
lab and internal PKI use.

It is intentionally *boring*: no daemon, no database, no network protocol,
and **self-contained** -- certificate generation and signing happen
entirely in-process (via [rcgen](https://github.com/rustls/rcgen), backed
by [ring](https://github.com/briansmith/ring)), with no runtime dependency
on the `openssl` binary or any other external tool. It is **not** a
replacement for a production CA/PKI system (consider
[step-ca](https://smallstep.com/certificates/), easy-rsa or HashiCorp Vault
PKI for that).

Keys are ECDSA P-256 (ring, the crypto backend used, doesn't support RSA
key generation -- P-256 is a good modern default for a "quick CA" tool).

## Usage

The common case needs no subcommand and no options at all:

```console
$ boringca
Generating CA key pair (ECDSA P-256) ...
Generating self-signed CA certificate (CN="BoringCA Root", 3650 days) ...

CA ready in /home/user/.boringca
  key:  /home/user/.boringca/ca.key
  cert: /home/user/.boringca/ca.crt

To trust this CA on Debian/Ubuntu, run:
    sudo cp /home/user/.boringca/ca.crt /usr/local/share/ca-certificates/boringca.crt
    sudo update-ca-certificates

Run 'boringca <name>' to issue a certificate, e.g.:
    boringca nas.lan

$ boringca nas.lan
Generating key pair for 'nas.lan' (ECDSA P-256) ...
Signing certificate with CA (CN="nas.lan", 825 days, EKU=serverAuth) ...

Certificate ready:
  key:  /home/user/.boringca/private/nas.lan.key
  cert: /home/user/.boringca/certs/nas.lan.crt
  SAN:  dns:nas.lan
```

`boringca <name>` also creates the CA automatically the first time it's
run, so on a brand new machine `boringca nas.lan` alone is enough.

For anything beyond the default (multiple SANs, client certs, custom
validity, a non-default CA CN, ...), the same two operations are available
as explicit subcommands with their full set of options:

```console
$ boringca init --cn "Home Lab CA" --days 7300
$ boringca issue nas --san dns:nas.lan,ip:192.168.1.10
$ boringca issue laptop --client --cn "user@laptop"
```

`boringca <name>` is exactly `boringca issue <name>` with every option left
at its default. Run `boringca --help` for the full option list.

### Trusting the CA

Every time the CA is created, boringca prints the `update-ca-certificates`
command to trust it system-wide on Debian/Ubuntu (the target `.crt` name
under `/usr/local/share/ca-certificates/` is derived from the store
directory's name, so certs from different `--dir` stores don't collide).
On other systems, drop `ca.crt` wherever your OS/distribution expects
locally-trusted CAs (e.g. `update-ca-trust` on Fedora/RHEL,
`trust anchor` on Arch), or import it directly into your browser/OS
trust store.

### Store layout

Everything lives under one directory (`--dir`, or `$BORINGCA_HOME`, default
`~/.boringca`):

```
ca.key                  root CA private key   (mode 600)
ca.crt                  root CA certificate
ca.cn                   CA's Common Name (used to reconstruct it when signing)
private/<name>.key      issued certificate's private key   (mode 600)
certs/<name>.crt        issued certificate
```

## Building

boringca is a small Rust binary. Its only dependencies are
[rcgen](https://crates.io/crates/rcgen) (default features: `crypto`,
`pem`, `ring`) and [time](https://crates.io/crates/time), both pinned to
the exact versions packaged in Debian trixie -- no `openssl` (or any other
external tool) is required at runtime, and the resulting binary is fully
self-contained.

Requirements: a Rust toolchain (`cargo`, `rustc`) to build. Nothing else
at runtime.

### Generic (any distribution)

```console
$ cargo build --release
$ install -Dm755 target/release/boringca /usr/local/bin/boringca
```

or simply:

```console
$ cargo install --path .
```

### Debian / Ubuntu

Built entirely offline with the Debian `dh-cargo` buildsystem, against the
`rcgen`/`time` crates already packaged in the archive
(`librust-rcgen-0.13+default-dev`, `librust-time-0.3-dev`):

```console
$ dpkg-buildpackage -us -uc -b
```

Produces `boringca_<version>_<arch>.deb` with no extra runtime
dependencies beyond libc. See [`debian/`](debian/).

### Fedora / RHEL / openSUSE (rpm)

```console
$ rpmbuild -ta boringca-0.1.0.tar.gz
```

using the spec file in [`packaging/rpm/boringca.spec`](packaging/rpm/boringca.spec).
Builds against crates.io (network required at build time).

### Arch Linux

A `PKGBUILD` is provided in
[`packaging/archlinux/PKGBUILD`](packaging/archlinux/PKGBUILD):

```console
$ cd packaging/archlinux && makepkg -si
```

## License

Licensed under either of

 * Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or
   http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or
   http://opensource.org/licenses/MIT)

at your option.
