# boringca

![Rust](https://img.shields.io/badge/rust-%23000000.svg?style=flat&logo=rust&logoColor=white)
![PKI](https://img.shields.io/badge/PKI-certificate--authority-informational)
![TLS](https://img.shields.io/badge/TLS-self--signed-blueviolet)
![Self-hosted](https://img.shields.io/badge/self--hosted-yes-success)
![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)
![GitHub stars](https://img.shields.io/github/stars/fabroce/boringca?style=social)
![GitHub last commit](https://img.shields.io/github/last-commit/fabroce/boringca)
![GitHub issues](https://img.shields.io/github/issues/fabroce/boringca)
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

## Quick start
Just try it with no args and read the output and enjoy !

## Usage

The common case needs no subcommand and no options at all:

```console
$ boringca
Generating CA key pair (ECDSA P-256) ...
Generating self-signed CA certificate (CN="BoringCA Root", 3650 days) ...

CA ready in /home/user/.boringca
  key:  /home/user/.boringca/ca.key
  cert: /home/user/.boringca/ca.crt

To trust this CA system-wide, run:
    boringca install-trust
    boringca uninstall-trust
(it will ask for your password via sudo; see the README for manual steps
 or unsupported distros)

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
$ boringca install-trust
Installing /home/user/.boringca/ca.crt into the system trust store ...
    sudo cp -- /home/user/.boringca/ca.crt /usr/local/share/ca-certificates/boringca-3f9a1c2e.crt
    sudo update-ca-certificates

CA trusted system-wide.

Browser trust stores (best effort, no sudo needed):
  Firefox (/home/user/.mozilla/firefox/xxxxxxxx.default): installed
  Chromium/Chrome (~/.pki/nssdb): installed
```

`boringca <name>` is exactly `boringca issue <name>` and accepts the same
options. Run `boringca --help` (or `boringca <command> --help`) for the
full option list.

A few things `issue` does for you:

- **Subject Alternative Names**: browsers match a server certificate
  against its SANs only, so without `--san` one is derived from the CN --
  `ip:<cn>` for an IP address (`boringca 192.168.1.10`), `dns:<cn>` for a
  host name. A CN that is neither (e.g. `user@laptop`) is refused for a
  server certificate (pass `--san`), and gives no SAN at all for a
  `--client` one.
- **No silent overwrite**: issuing a name that already exists fails
  unless you pass `--force` (e.g. to renew it).
- **Never outlives the CA**: a certificate's validity is capped to the
  CA's own expiry date, with a note when that happens.

### Trusting the CA

Run `boringca install-trust` to add the CA to the system trust store. It
detects which mechanism is present from the distribution's trust anchors
directory (`/usr/local/share/ca-certificates/` + `update-ca-certificates`
on Debian/Ubuntu, `/etc/pki/ca-trust/source/anchors/` + `update-ca-trust`
on Fedora/RHEL, `/etc/pki/trust/anchors/` + `update-ca-certificates` on
openSUSE, or `trust anchor` on Arch) and runs the required steps itself
through `sudo` (or `doas` when there is no `sudo`, or directly when
already root and neither is installed), prompting for a password as
needed. The tools are also looked up in `/usr/sbin` and friends, even when
they aren't in your `$PATH`. The target `.crt` name
in the anchors directory is the store directory's name plus a short hash
of its absolute path (e.g. `boringca-3f9a1c2e.crt`), so certs from
different `--dir` stores never collide, even when their directories share
the same name; the browser entries described below are named the same
way. A copy installed under the plain directory name by an older version
is removed when it holds the same CA.

This is opt-in and explicit by design: `boringca` never touches the
system trust store on its own just because it happens to be run as root
(e.g. via `sudo boringca <name>` for an unrelated reason) -- only
`install-trust` does, and only when you ask for it.

If no known mechanism is found, the system-wide step fails with an error
instead of guessing -- drop `ca.crt` wherever your OS/distribution
expects locally-trusted CAs, or import it directly into your browser/OS
trust store.

`install-trust` also tries, best-effort, to trust the CA in Firefox and
Chromium-based browsers: on Linux these keep their own NSS certificate
databases (a `cert9.db` per Firefox profile -- classic, Snap or Flatpak
install -- and a shared one for Chromium/Chrome under `~/.pki/nssdb`, plus
the Chromium Snap's own) and never consult the system trust
store at all. This part needs `certutil` (Debian/Ubuntu: `libnss3-tools`)
and runs entirely as your user, no `sudo` involved. Unlike the
system-wide step, a failure here (missing `certutil`, no Firefox profile,
...) is reported per browser rather than failing the whole command --
restart the browser afterwards for it to notice the new CA.

To undo it, run `boringca uninstall-trust` (same `--dir` option): it
removes this store's CA from the system trust store (through `sudo`, then
refreshing the bundle) and from the same browser databases, and leaves the
CA itself in its directory -- delete that directory afterwards if you no
longer need it. Entries are found by the store's unique name, so this
still works after the store directory has been deleted (except on Arch,
where p11-kit needs `ca.crt` to find the anchor); entries of other stores
are never touched. Do it before throwing a CA away, or when its key may
have leaked: until then, anything signed with that key is trusted.

### Shell completion

A bash completion script is shipped in
[`completions/boringca.bash`](completions/boringca.bash) (subcommands and
their options, `--dir` completes to directories). The Debian package
installs it automatically (`debian/boringca.bash-completion`), so `<TAB>`
completion works out of the box after `dpkg -i` -- nothing to run or
source by hand.

Outside of the Debian package, copy or symlink the file yourself:

```console
$ sudo cp completions/boringca.bash /usr/share/bash-completion/completions/boringca
```

or source it from your shell startup file:

```console
$ echo 'eval "$(cat /path/to/completions/boringca.bash)"' >> ~/.bashrc
```

Only bash is currently supported.

### Store layout

Everything lives under one directory (`--dir`, or `$BORINGCA_HOME`, default
`~/.boringca`):

```
ca.key                  root CA private key   (mode 600)
ca.crt                  root CA certificate
ca.cn                   CA's Common Name (informational, read from ca.crt)
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

To run the unit tests (no network, no root, nothing outside a temporary
directory is touched):

```console
$ cargo test
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
$ rpmbuild -ta boringca-<version>.tar.gz
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
