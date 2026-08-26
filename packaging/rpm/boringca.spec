Name:           boringca
Version:        0.1.0
Release:        1%{?dist}
Summary:        Quickly create a CA and issue child certificates

License:        MIT OR Apache-2.0
URL:            https://github.com/fdagorn/boringca
Source0:        %{name}-%{version}.tar.gz

BuildRequires:  cargo
BuildRequires:  rust

%description
boringca is a small, self-contained command-line tool to create a root
Certificate Authority and issue server/client certificates signed by it,
in a couple of commands, for local development, home lab and internal PKI
use. Not intended to replace a production CA/PKI system (step-ca,
easy-rsa, HashiCorp Vault PKI) for real-world deployments.

Two subcommands: "boringca init" creates the root CA, and "boringca issue
<name>" generates a key pair and certificate signed by that CA, with SAN
and extendedKeyUsage (server/client) support.

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
* Sat Aug 22 2026 Fabrice Dagorn <fabrice@dagorn.fr> - 0.1.0-1
- Initial release: boringca init / boringca issue.
