Name:           boringca
Version:        5.0.0
Release:        1%{?dist}
Summary:        Quickly create a CA and issue child certificates

License:        MIT OR Apache-2.0
URL:            https://github.com/fabroce/boringca
Source0:        %{name}-%{version}.tar.gz

BuildRequires:  cargo
BuildRequires:  rust

Recommends:     nss-tools

%description
boringca is a small, self-contained command-line tool to create a root
Certificate Authority and issue server/client certificates signed by it,
in a couple of commands, for local development, home lab and internal PKI
use. Not intended to replace a production CA/PKI system (step-ca,
easy-rsa, HashiCorp Vault PKI) for real-world deployments.

"boringca init" creates the root CA, "boringca issue <name>" generates a
key pair and certificate signed by that CA, with SAN and
extendedKeyUsage (server/client) support, and "boringca install-trust"
trusts the CA system-wide and, best-effort, in Firefox/Chromium
(requires nss-tools for the browser part).

Written in Rust using rcgen (ring backend, ECDSA P-256 keys): all
certificate generation and signing happens in-process, with no runtime
dependency on openssl or any other external tool.

%prep
%autosetup

%build
cargo build --release --locked || cargo build --release

%install
install -Dm755 target/release/boringca %{buildroot}%{_bindir}/boringca
install -Dm644 man/boringca.1 %{buildroot}%{_mandir}/man1/boringca.1

%files
%license LICENSE-MIT LICENSE-APACHE
%doc README.md
%{_bindir}/boringca
%{_mandir}/man1/boringca.1*

%changelog
* Mon Oct 05 2026 Fabrice Dagorn <fabrice@dagorn.fr> - 5.0.0-1
- Private keys are never on disk with loose permissions; key and
  certificate are written atomically.
- issue: refuses to overwrite an existing certificate without --force;
  default SAN is ip:<cn> for an IP address, none for a client cert whose
  CN isn't a host name; validity capped to the CA's expiry; leaf certs no
  longer carry keyEncipherment; the CA is read back from ca.crt.
- New CAs are created with pathlen:0.
- install-trust: detection by trust anchors directory (fixes Arch,
  adds openSUSE), unique per-store names, sudo/doas fallback, Firefox
  Snap/Flatpak and Chromium Snap support.
- Stricter option parsing; "help" subcommand; --days validated.

* Wed Sep 16 2026 Fabrice Dagorn <fabrice@dagorn.fr> - 4.0.2-1
- Sync version with upstream; add boringca install-trust (system trust
  store, plus best-effort Firefox/Chromium via nss-tools).

* Sat Aug 22 2026 Fabrice Dagorn <fabrice@dagorn.fr> - 0.1.0-1
- Initial release: boringca init / boringca issue.
