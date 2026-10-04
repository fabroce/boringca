// boringca -- quickly create a CA and issue child certificates.
//
// Self-contained: certificate generation and signing is done in-process
// with rcgen (backed by ring), no external openssl binary required at
// runtime. Keys are ECDSA P-256 (ring does not support RSA key
// generation, and P-256 is a perfectly good modern default for a "quick
// CA" tool).
//
// Copyright (c) 2026 Fabrice Dagorn
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::env;
use std::fs;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose,
    Ia5String, IsCa, KeyPair, KeyUsagePurpose, SanType,
};
use time::{Duration, OffsetDateTime};

const DEFAULT_CA_DAYS: u32 = 3650; // 10 years
const DEFAULT_CA_CN: &str = "BoringCA Root";

const DEFAULT_LEAF_DAYS: u32 = 825; // ~ historical browser cap for server certs

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();

    // -h/--help anywhere before a "--" (e.g. "boringca issue --help")
    // shows the help rather than being rejected as an unknown option.
    if args.iter().take_while(|a| a.as_str() != "--").any(|a| a == "-h" || a == "--help") {
        print_help();
        return ExitCode::SUCCESS;
    }

    // The common case needs no subcommand at all:
    //   boringca            -> set up the CA on first run
    //   boringca <name>     -> issue a certificate for DNS name <name>,
    //                          creating the CA first if needed
    // "init"/"issue" remain available, with their full set of options, for
    // anyone who wants more control (see --help).
    let result = match args.first().map(String::as_str) {
        None => quick_start(),
        Some("help") => {
            print_help();
            return ExitCode::SUCCESS;
        }
        Some("init") => cmd_init(&args[1..]),
        Some("issue") => cmd_issue(&args[1..]),
        Some("install-trust") => cmd_install_trust(&args[1..]),
        Some(_) => quick_issue(&args),
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("boringca: error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn print_help() {
    println!(
        r#"boringca {version} - quickly create a CA and issue child certificates

QUICK START:
    boringca              Set up the CA on first run (prints where it's stored)
    boringca <name>       Issue a certificate for <name> (a DNS name or an IP
                          address), signed by the CA (creates the CA
                          automatically on first use)

    e.g.
        boringca
        boringca nas.lan

ADVANCED USAGE:
    boringca init          [OPTIONS]   (Re)create the root CA explicitly
    boringca issue  <name> [OPTIONS]   Issue a certificate with full control
    boringca install-trust [OPTIONS]   Trust the CA system-wide (uses sudo)
    boringca help                      Show this help (also -h/--help)

    "boringca <name>" above is shorthand for "boringca issue <name>"; it
    accepts the same options. Options also accept the --opt=value form.

INIT OPTIONS:
    --cn <name>       Common Name of the root CA          [default: "{ca_cn}"]
    --days <n>        Validity in days                    [default: {ca_days}]
    --dir <path>      CA store directory                  [default: $BORINGCA_HOME or ~/.boringca]
    --force           Overwrite an existing CA in --dir

INSTALL-TRUST OPTIONS:
    --dir <path>      CA store directory                  [default: $BORINGCA_HOME or ~/.boringca]

ISSUE OPTIONS:
    <name>            Short name for the certificate (used for file names)
    --cn <name>       Common Name                         [default: <name>]
    --san <list>      Comma-separated Subject Alt. Names (dns:, ip:, email:, uri:),
                      e.g. "dns:example.com,dns:www.example.com,ip:10.0.0.1"
                      [default: ip:<cn> if <cn> is an IP address, else dns:<cn>;
                       none for a --client cert whose CN is not a DNS name]
    --server          Issue a server certificate (extendedKeyUsage=serverAuth) [default]
    --client          Issue a client certificate (extendedKeyUsage=clientAuth)
    --both            Issue a cert valid for both server and client auth
    --days <n>        Validity in days, capped to the CA's [default: {leaf_days}]
    --dir <path>      CA store directory                  [default: $BORINGCA_HOME or ~/.boringca]
    --force           Replace an existing certificate with the same <name>

EXAMPLES:
    boringca init --cn "Home Lab CA"
    boringca issue nas --san dns:nas.lan,ip:192.168.1.10
    boringca issue laptop --client --cn "user@laptop"
    boringca install-trust

STORE LAYOUT (under --dir):
    ca.key, ca.crt          root CA private key and certificate
    ca.cn                   root CA's Common Name (informational)
    private/<name>.key      issued certificate's private key
    certs/<name>.crt        issued certificate

Keys are ECDSA P-256. Certificate generation is entirely in-process (no
external openssl binary is invoked).

WARNING: this tool is meant for local development, home lab and internal
PKI use, NOT as a replacement for a production CA/PKI system (step-ca,
easy-rsa, HashiCorp Vault PKI, ...).
"#,
        version = env!("CARGO_PKG_VERSION"),
        ca_cn = DEFAULT_CA_CN,
        ca_days = DEFAULT_CA_DAYS,
        leaf_days = DEFAULT_LEAF_DAYS,
    );
}

// ---------------------------------------------------------------------
// Shared option parsing helpers
// ---------------------------------------------------------------------

/// A tiny hand-rolled flag parser: no external crate, just enough for the
/// handful of flags boringca needs. Positional (non-flag) arguments are
/// collected into `positionals`.
#[derive(Debug)]
struct Args {
    positionals: Vec<String>,
    flags: std::collections::HashMap<String, String>,
    switches: std::collections::HashSet<String>,
}

/// Parse `raw` against the given value flags (`--name value` or
/// `--name=value`) and switches (`--name`), accepting at most
/// `max_positionals` positional arguments. A lone `--` ends the options.
fn parse_args(
    raw: &[String],
    value_flags: &[&str],
    switch_flags: &[&str],
    max_positionals: usize,
) -> Result<Args, String> {
    let mut positionals = Vec::new();
    let mut flags = std::collections::HashMap::new();
    let mut switches = std::collections::HashSet::new();
    let mut options_ended = false;

    let mut i = 0;
    while i < raw.len() {
        let arg = &raw[i];
        i += 1;
        if !options_ended {
            if arg == "--" {
                options_ended = true;
                continue;
            }
            if let Some(opt) = arg.strip_prefix("--") {
                let (name, inline_value) = match opt.split_once('=') {
                    Some((name, value)) => (name, Some(value.to_string())),
                    None => (opt, None),
                };
                if value_flags.contains(&name) {
                    let value = match inline_value {
                        Some(value) => value,
                        // "--cn --server" is a forgotten value, not a CN.
                        None => match raw.get(i) {
                            Some(value) if !value.starts_with("--") => {
                                i += 1;
                                value.clone()
                            }
                            _ => return Err(format!("--{name} expects a value")),
                        },
                    };
                    flags.insert(name.to_string(), value);
                } else if switch_flags.contains(&name) {
                    if inline_value.is_some() {
                        return Err(format!("--{name} doesn't take a value"));
                    }
                    switches.insert(name.to_string());
                } else {
                    return Err(format!("unknown option '--{name}'"));
                }
                continue;
            }
        }
        if positionals.len() == max_positionals {
            return Err(format!("unexpected argument '{arg}'"));
        }
        positionals.push(arg.clone());
    }

    Ok(Args { positionals, flags, switches })
}

fn ca_dir(explicit: Option<&String>) -> Result<PathBuf, String> {
    if let Some(dir) = explicit {
        return Ok(PathBuf::from(dir));
    }
    if let Ok(dir) = env::var("BORINGCA_HOME") {
        return Ok(PathBuf::from(dir));
    }
    let home = env::var("HOME").map_err(|_| "cannot determine home directory (set $HOME or pass --dir)".to_string())?;
    Ok(Path::new(&home).join(".boringca"))
}

/// Parse --days: a positive number of days whose validity period can
/// actually be represented (see `validity_period`).
fn parse_days(flags: &std::collections::HashMap<String, String>, default: u32) -> Result<u32, String> {
    let days = match flags.get("days") {
        Some(v) => v
            .parse::<u32>()
            .ok()
            .filter(|&d| d > 0)
            .ok_or_else(|| format!("--days must be a positive integer, got '{v}'"))?,
        None => default,
    };
    validity_period(days)?;
    Ok(days)
}

/// Compute (not_before, not_after) for a certificate valid `days` days.
///
/// not_before is backdated one day to tolerate a bit of clock skew, and
/// not_after counts from it so the total validity is exactly `days` (Apple
/// platforms reject TLS server certs whose notAfter - notBefore exceeds
/// 825 days, DEFAULT_LEAF_DAYS). Fails instead of overflowing when the
/// end date would be past what can be represented (year 9999).
fn validity_period(days: u32) -> Result<(OffsetDateTime, OffsetDateTime), String> {
    let not_before = OffsetDateTime::now_utc() - Duration::days(1);
    let not_after = not_before
        .checked_add(Duration::days(i64::from(days)))
        .filter(|t| t.year() <= 9999)
        .ok_or_else(|| format!("--days {days} is too large (the certificate would expire after year 9999)"))?;
    Ok((not_before, not_after))
}

// ---------------------------------------------------------------------
// Writing files
// ---------------------------------------------------------------------

/// A file to write with `write_files`.
struct OutFile<'a> {
    path: &'a Path,
    contents: &'a str,
    /// Private key material: readable by its owner only (mode 600).
    private: bool,
}

/// Temporary name `write_files` writes `path` under before renaming it.
fn staging_path(path: &Path) -> PathBuf {
    let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    path.with_file_name(format!(".{name}.tmp"))
}

/// Write one file from scratch. A private file is created with mode 600
/// from the start (and a leftover file is chmod'ed through its handle
/// before anything is written), so a key is never on disk with looser
/// permissions, even briefly.
#[cfg(unix)]
fn write_new_file(path: &Path, contents: &str, private: bool) -> Result<(), String> {
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    let err = |e: std::io::Error| format!("failed to write {}: {e}", path.display());
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    if private {
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(err)?;
    if private {
        // mode() only applies when the file is created: tighten a leftover
        // one too (it has just been truncated, so nothing leaks meanwhile).
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("failed to chmod 600 {}: {e}", path.display()))?;
    }
    file.write_all(contents.as_bytes()).map_err(err)?;
    file.sync_all().map_err(err)
}

#[cfg(not(unix))]
fn write_new_file(path: &Path, contents: &str, _private: bool) -> Result<(), String> {
    fs::write(path, contents).map_err(|e| format!("failed to write {}: {e}", path.display()))
}

/// Write a set of related files (a key and its certificate) so that a
/// failure halfway never leaves a mismatched pair behind: every file is
/// first written in full under a temporary name next to its destination,
/// and only once all of them are written are they renamed into place.
fn write_files(files: &[OutFile]) -> Result<(), String> {
    let staged: Vec<PathBuf> = files.iter().map(|f| staging_path(f.path)).collect();
    let written = files
        .iter()
        .zip(&staged)
        .try_for_each(|(f, tmp)| write_new_file(tmp, f.contents, f.private));
    if let Err(e) = written {
        for tmp in &staged {
            let _ = fs::remove_file(tmp);
        }
        return Err(e);
    }
    for (f, tmp) in files.iter().zip(&staged) {
        fs::rename(tmp, f.path).map_err(|e| format!("failed to write {}: {e}", f.path.display()))?;
    }
    Ok(())
}

fn common_name_dn(cn: &str) -> DistinguishedName {
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, cn);
    dn
}

// ---------------------------------------------------------------------
// Reading certificates back
//
// rcgen can only parse existing certificates with its optional x509-parser
// feature, which would pull in a large dependency tree (and isn't what the
// Debian package builds against). boringca only needs a few fields of its
// own CA certificate, so it reads them with this minimal DER walker.
// ---------------------------------------------------------------------

/// Base64 bodies of every PEM block in `pem`, whitespace removed, so two
/// encodings of the same certificate compare equal whatever the line
/// wrapping.
fn pem_bodies(pem: &str) -> Vec<String> {
    let mut bodies = Vec::new();
    let mut current: Option<String> = None;
    for line in pem.lines().map(str::trim) {
        if line.starts_with("-----BEGIN ") {
            current = Some(String::new());
        } else if line.starts_with("-----END ") {
            bodies.extend(current.take());
        } else if let Some(body) = current.as_mut() {
            body.push_str(line);
        }
    }
    bodies
}

/// Decode standard (padded or not) base64; None on any invalid character.
fn base64_decode(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let (mut acc, mut bits) = (0u32, 0u32);
    for c in s.bytes() {
        let v = u32::from(match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b'=' => break,
            _ => return None,
        });
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    Some(out)
}

/// Split the DER element at the start of `der` into (tag, content, rest).
fn der_next(der: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, der) = der.split_first()?;
    let (&first, mut der) = der.split_first()?;
    let len = if first < 0x80 {
        usize::from(first)
    } else {
        let n = usize::from(first & 0x7f);
        if n == 0 || n > 4 || der.len() < n {
            return None;
        }
        let (len_bytes, rest) = der.split_at(n);
        der = rest;
        len_bytes.iter().fold(0, |len, &b| (len << 8) | usize::from(b))
    };
    if der.len() < len {
        return None;
    }
    let (content, rest) = der.split_at(len);
    Some((tag, content, rest))
}

/// Parse a DER UTCTime (tag 0x17) or GeneralizedTime (tag 0x18) of the
/// "...HHMMSSZ" form X.509 requires.
fn parse_der_time(tag: u8, bytes: &[u8]) -> Option<OffsetDateTime> {
    let s = std::str::from_utf8(bytes).ok()?.strip_suffix('Z')?;
    let (year, rest) = match tag {
        0x17 => {
            let yy: i32 = s.get(..2)?.parse().ok()?;
            (if yy < 50 { 2000 + yy } else { 1900 + yy }, s.get(2..)?)
        }
        0x18 => (s.get(..4)?.parse().ok()?, s.get(4..)?),
        _ => return None,
    };
    if rest.len() != 10 || !rest.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let field = |i: usize| rest[i..i + 2].parse::<u8>().ok();
    let date = time::Date::from_calendar_date(year, time::Month::try_from(field(0)?).ok()?, field(2)?).ok()?;
    let time = time::Time::from_hms(field(4)?, field(6)?, field(8)?).ok()?;
    Some(time::PrimitiveDateTime::new(date, time).assume_utc())
}

/// The few fields of an X.509 certificate boringca needs (as raw DER
/// contents for the names and the public key).
struct CertInfo<'a> {
    issuer: &'a [u8],
    subject: &'a [u8],
    spki: &'a [u8],
    not_after: OffsetDateTime,
}

fn parse_certificate(der: &[u8]) -> Option<CertInfo<'_>> {
    let (0x30, cert, _) = der_next(der)? else { return None };
    let (0x30, tbs, _) = der_next(cert)? else { return None };
    let (mut tag, _, mut rest) = der_next(tbs)?;
    if tag == 0xa0 {
        // Explicit [0] version: the serial number follows.
        (tag, _, rest) = der_next(rest)?;
    }
    if tag != 0x02 {
        return None;
    }
    let (0x30, _signature, rest) = der_next(rest)? else { return None };
    let (0x30, issuer, rest) = der_next(rest)? else { return None };
    let (0x30, validity, rest) = der_next(rest)? else { return None };
    let (0x30, subject, rest) = der_next(rest)? else { return None };
    let (0x30, spki, _) = der_next(rest)? else { return None };
    let (_, _, validity) = der_next(validity)?; // notBefore
    let (tag, not_after, _) = der_next(validity)?;
    Some(CertInfo { issuer, subject, spki, not_after: parse_der_time(tag, not_after)? })
}

/// The Common Name in a DER-encoded Name, if any.
fn name_common_name(name: &[u8]) -> Option<String> {
    let mut rdns = name;
    while !rdns.is_empty() {
        let (_, mut attributes, rest) = der_next(rdns)?;
        rdns = rest;
        while !attributes.is_empty() {
            let (_, attribute, rest) = der_next(attributes)?;
            attributes = rest;
            let (0x06, oid, value) = der_next(attribute)? else { return None };
            if oid == [0x55, 0x04, 0x03] {
                let (_, value, _) = der_next(value)?;
                return String::from_utf8(value.to_vec()).ok();
            }
        }
    }
    None
}

/// Read the (first) certificate of a PEM file as DER.
fn read_cert_der(path: &Path) -> Result<Vec<u8>, String> {
    let pem = fs::read_to_string(path).map_err(|e| format!("failed to read {}: {e}", path.display()))?;
    pem_bodies(&pem)
        .first()
        .and_then(|body| base64_decode(body))
        .ok_or_else(|| format!("{} is not a PEM certificate", path.display()))
}

/// The CA's Common Name, read from its certificate.
fn ca_common_name(ca_crt_path: &Path) -> Option<String> {
    let der = read_cert_der(ca_crt_path).ok()?;
    name_common_name(parse_certificate(&der)?.subject)
}

// ---------------------------------------------------------------------
// CA creation, shared by "boringca" (no args), "boringca init" and the
// auto-create-on-first-use path of "boringca <name>".
// ---------------------------------------------------------------------

/// Parameters of a boringca root CA with the given CN, minus validity.
fn ca_params(cn: &str) -> Result<CertificateParams, String> {
    let mut params = CertificateParams::new(Vec::new())
        .map_err(|e| format!("failed to build CA parameters: {e}"))?;
    params.distinguished_name = common_name_dn(cn);
    // pathlen:0 -- this CA signs leaf certificates only, never another CA.
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    Ok(params)
}

fn create_ca(dir: &Path, cn: &str, days: u32) -> Result<(), String> {
    let ca_key_path = dir.join("ca.key");
    let ca_crt_path = dir.join("ca.crt");
    let ca_cn_path = dir.join("ca.cn");

    fs::create_dir_all(dir.join("private")).map_err(|e| format!("failed to create {}: {e}", dir.display()))?;
    fs::create_dir_all(dir.join("certs")).map_err(|e| format!("failed to create {}: {e}", dir.display()))?;

    println!("Generating CA key pair (ECDSA P-256) ...");
    let ca_key = KeyPair::generate().map_err(|e| format!("failed to generate CA key pair: {e}"))?;

    println!("Generating self-signed CA certificate (CN=\"{cn}\", {days} days) ...");
    let mut params = ca_params(cn)?;
    (params.not_before, params.not_after) = validity_period(days)?;

    let ca_cert = params
        .self_signed(&ca_key)
        .map_err(|e| format!("failed to self-sign CA certificate: {e}"))?;

    // ca.cn is informational only (the CN is read back from ca.crt), but
    // still written for older boringca versions sharing this store.
    write_files(&[
        OutFile { path: &ca_key_path, contents: &ca_key.serialize_pem(), private: true },
        OutFile { path: &ca_crt_path, contents: &ca_cert.pem(), private: false },
        OutFile { path: &ca_cn_path, contents: &format!("{cn}\n"), private: false },
    ])?;

    println!();
    println!("CA ready in {}", dir.display());
    println!("  key:  {}", ca_key_path.display());
    println!("  cert: {}", ca_crt_path.display());
    println!();
    println!("To trust this CA system-wide, run:");
    println!("    boringca install-trust");
    println!("(it will ask for your password via sudo; see the README for manual steps");
    println!(" or unsupported distros)");
    Ok(())
}

/// The CA as needed to sign: its key, an rcgen certificate object to sign
/// with, and its expiry.
struct LoadedCa {
    key: KeyPair,
    cert: Certificate,
    not_after: OffsetDateTime,
}

/// Load the CA from `dir` for signing.
///
/// rcgen needs an issuer certificate object to sign with, which it can't
/// parse back from ca.crt (see "Reading certificates back"), so it is
/// rebuilt from ca.key and the CN read from ca.crt -- then checked against
/// ca.crt, so that a key and certificate that don't belong together (or a
/// CA boringca didn't create) are refused rather than silently producing
/// certificates that don't chain to ca.crt.
fn load_ca(dir: &Path) -> Result<LoadedCa, String> {
    let ca_key_path = dir.join("ca.key");
    let ca_crt_path = dir.join("ca.crt");
    if !ca_key_path.exists() {
        return Err(format!(
            "no CA found in {} -- run 'boringca init' first (or pass --dir)",
            dir.display()
        ));
    }

    let key_pem = fs::read_to_string(&ca_key_path)
        .map_err(|e| format!("failed to read {}: {e}", ca_key_path.display()))?;
    let key = KeyPair::from_pem(&key_pem).map_err(|e| format!("failed to load CA private key: {e}"))?;

    let der = read_cert_der(&ca_crt_path)?;
    let info = parse_certificate(&der)
        .ok_or_else(|| format!("{} is not a valid certificate", ca_crt_path.display()))?;
    let cn = name_common_name(info.subject)
        .ok_or_else(|| format!("{} has no Common Name", ca_crt_path.display()))?;

    let cert = ca_params(&cn)?
        .self_signed(&key)
        .map_err(|e| format!("failed to reconstruct CA certificate: {e}"))?;
    let rebuilt = parse_certificate(cert.der()).ok_or("failed to reconstruct CA certificate")?;
    if rebuilt.spki != info.spki {
        return Err(format!(
            "{} and {} don't belong together (different key pairs)",
            ca_key_path.display(),
            ca_crt_path.display()
        ));
    }
    if rebuilt.subject != info.subject || info.issuer != info.subject {
        return Err(format!(
            "the subject of {} can't be reproduced (boringca only signs with self-signed root \
             CAs whose subject is a single Common Name, as created by 'boringca init')",
            ca_crt_path.display()
        ));
    }

    Ok(LoadedCa { key, cert, not_after: info.not_after })
}

/// Name identifying a store in the trust stores, before boringca made it
/// unique: just the directory's name. Two stores with the same directory
/// name (/srv/a/ca and /srv/b/ca, or two users' ~/.boringca) collided on
/// it; it is only still computed to clean up after older versions.
fn legacy_store_stem(dir: &Path) -> String {
    let name = dir
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("boringca")
        .trim_start_matches('.');
    let name = if name.is_empty() { "boringca" } else { name };
    name.to_string()
}

/// 64-bit FNV-1a followed by the murmur3 finalizer (so that paths differing
/// only in their last characters don't get near-identical hashes): tiny,
/// and unlike std's DefaultHasher guaranteed to give the same result across
/// Rust versions, which matters for names that must stay the same from one
/// boringca run to the next.
fn path_hash(bytes: &[u8]) -> u64 {
    let mut h = bytes.iter().fold(0xcbf2_9ce4_8422_2325_u64, |hash, &b| {
        (hash ^ u64::from(b)).wrapping_mul(0x0000_0100_0000_01b3)
    });
    h ^= h >> 33;
    h = h.wrapping_mul(0xff51_afd7_ed55_8ccd);
    h ^= h >> 33;
    h = h.wrapping_mul(0xc4ce_b9fe_1a85_ec53);
    h ^ (h >> 33)
}

/// Name identifying a store in the system and browser trust stores: the
/// directory's name for readability, plus a short hash of its absolute path
/// so that different stores never share it.
fn store_stem(dir: &Path) -> String {
    let abs = fs::canonicalize(dir).unwrap_or_else(|_| dir.to_path_buf());
    let hash = path_hash(abs.as_os_str().as_encoded_bytes());
    format!("{}-{:08x}", legacy_store_stem(&abs), (hash ^ (hash >> 32)) as u32)
}

/// File name to use in the system trust anchors directory
/// (e.g. /usr/local/share/ca-certificates/).
fn ca_trust_filename(stem: &str) -> String {
    format!("{stem}.crt")
}

/// True if both files hold the same (first) PEM certificate.
fn same_certificate(a: &Path, b: &Path) -> bool {
    let first = |p: &Path| fs::read_to_string(p).ok().and_then(|s| pem_bodies(&s).into_iter().next());
    matches!((first(a), first(b)), (Some(x), Some(y)) if x == y)
}

/// Create the CA in `dir` if it isn't there yet; does nothing otherwise.
/// Used by the "boringca <name>" quick path so a first run just works.
fn ensure_ca(dir: &Path) -> Result<(), String> {
    if dir.join("ca.key").exists() {
        return Ok(());
    }
    println!("No CA found in {} -- creating one now.", dir.display());
    create_ca(dir, DEFAULT_CA_CN, DEFAULT_CA_DAYS)?;
    println!();
    Ok(())
}

// ---------------------------------------------------------------------
// boringca            (no arguments: quick start)
// ---------------------------------------------------------------------

fn quick_start() -> Result<(), String> {
    let dir = ca_dir(None)?;
    if dir.join("ca.key").exists() {
        println!("CA already set up in {}", dir.display());
    } else {
        create_ca(&dir, DEFAULT_CA_CN, DEFAULT_CA_DAYS)?;
    }
    println!();
    println!("Run 'boringca <name>' to issue a certificate, e.g.:");
    println!("    boringca nas.lan");
    Ok(())
}

// ---------------------------------------------------------------------
// boringca <name> [OPTIONS]   (no "issue" keyword: quick path)
// ---------------------------------------------------------------------

fn quick_issue(raw: &[String]) -> Result<(), String> {
    // Validate the whole command line first, so a typo (bad name, bad
    // --days, bad --san, ...) never leaves a freshly created CA behind;
    // only then create the CA (if missing) in the store "issue" will use.
    let req = parse_issue_args(raw)?;
    ensure_ca(&req.dir)?;
    issue(req)
}

// ---------------------------------------------------------------------
// boringca init [OPTIONS]   (explicit, full control)
// ---------------------------------------------------------------------

fn cmd_init(raw: &[String]) -> Result<(), String> {
    let args = parse_args(raw, &["cn", "days", "dir"], &["force"], 0)?;
    let dir = ca_dir(args.flags.get("dir"))?;
    let cn = args.flags.get("cn").cloned().unwrap_or_else(|| DEFAULT_CA_CN.to_string());
    if cn.trim().is_empty() {
        return Err("--cn must not be empty".to_string());
    }
    let days = parse_days(&args.flags, DEFAULT_CA_DAYS)?;
    let force = args.switches.contains("force");

    if (dir.join("ca.key").exists() || dir.join("ca.crt").exists()) && !force {
        return Err(format!(
            "a CA already exists in {} (use --force to overwrite, this destroys the ability to \
             validate any certificate previously issued from it /!\\ Use at your own risk ! /!\\)",
            dir.display()
        ));
    }

    create_ca(&dir, &cn, days)?;
    println!();
    println!("Next: boringca <name>   (issues a certificate for DNS name <name>)");
    Ok(())
}

// ---------------------------------------------------------------------
// boringca install-trust [OPTIONS]
//
// Explicit, opt-in system trust installation: this is never triggered
// implicitly by detecting an elevated UID (running "boringca <name>" under
// sudo for an unrelated reason must never have the side effect of touching
// the system trust store). It goes through `sudo` itself instead (or
// `doas`), so the user doesn't need to already be root to ask for this --
// mirroring how `mkcert -install` behaves.
// ---------------------------------------------------------------------

/// One of the OS-specific ways to add a locally-trusted CA, matched against
/// what's actually installed on this machine (see `detect_trust_method`).
enum TrustMethod {
    /// Drop the cert into a distribution's anchors directory, then run the
    /// command that refreshes the system bundle from it.
    CopyAndUpdate { target: PathBuf, update: &'static [&'static str] },
    /// Arch (p11-kit's `trust`): a single command does both steps.
    P11KitTrust,
}

/// Anchors directory and refresh command for each "copy then update"
/// distribution family. Detection keys on the directory, which is specific
/// to each family, rather than on the command name alone: the same command
/// can exist on several distributions with a different directory
/// (update-ca-certificates on Debian vs openSUSE, update-ca-trust on
/// Fedora vs Arch).
const COPY_AND_UPDATE_METHODS: &[(&str, &[&str])] = &[
    // Debian/Ubuntu (and Alpine)
    ("/usr/local/share/ca-certificates", &["update-ca-certificates"]),
    // Fedora/RHEL
    ("/etc/pki/ca-trust/source/anchors", &["update-ca-trust", "extract"]),
    // openSUSE/SLES
    ("/etc/pki/trust/anchors", &["update-ca-certificates"]),
];

/// Arch's local trust source, managed through p11-kit's `trust anchor`.
const ARCH_TRUST_SOURCE: &str = "/etc/ca-certificates/trust-source";

/// Directories searched for programs on top of $PATH: the trust tools live
/// in sbin, which sudo's secure_path includes but a regular user's $PATH
/// may not (e.g. on Debian before trixie).
const SBIN_DIRS: &[&str] = &["/usr/local/sbin", "/usr/sbin", "/sbin"];

#[cfg(unix)]
fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    fs::metadata(path).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
}

#[cfg(not(unix))]
fn is_executable(path: &Path) -> bool {
    path.is_file()
}

/// Look up an executable `bin` the way a shell would (plus SBIN_DIRS),
/// without spawning a subprocess -- used to pick which tools are present.
fn find_program(bin: &str) -> Option<PathBuf> {
    let path = env::var_os("PATH").unwrap_or_default();
    env::split_paths(&path)
        .chain(SBIN_DIRS.iter().map(PathBuf::from))
        .map(|dir| dir.join(bin))
        .find(|full| is_executable(full))
}

fn detect_trust_method(filename: &str) -> Option<TrustMethod> {
    for &(anchors, update) in COPY_AND_UPDATE_METHODS {
        if Path::new(anchors).is_dir() && find_program(update[0]).is_some() {
            return Some(TrustMethod::CopyAndUpdate {
                target: Path::new(anchors).join(filename),
                update,
            });
        }
    }
    if Path::new(ARCH_TRUST_SOURCE).is_dir() && find_program("trust").is_some() {
        return Some(TrustMethod::P11KitTrust);
    }
    None
}

fn running_as_root() -> bool {
    Command::new("id")
        .arg("-u")
        .output()
        .is_ok_and(|out| out.status.success() && out.stdout.trim_ascii() == b"0")
}

/// How to run a command as root: through `sudo` (even if we're already
/// root -- `sudo` lets that through without a password prompt on every
/// setup we care about), else `doas`, else directly when already root
/// (e.g. a minimal container with neither installed).
fn privilege_tool() -> Result<Option<&'static str>, String> {
    if let Some(tool) = ["sudo", "doas"].into_iter().find(|tool| find_program(tool).is_some()) {
        return Ok(Some(tool));
    }
    if running_as_root() {
        return Ok(None);
    }
    Err("neither sudo nor doas found -- install one of them, or run 'boringca install-trust' as root".to_string())
}

/// Run a command as root, through `tool` (see `privilege_tool`).
fn run_privileged(tool: Option<&str>, program: &str, args: &[&str]) -> Result<(), String> {
    let command: Vec<&str> = tool.into_iter().chain([program]).collect();
    let shown = command.join(" ");
    println!("    {}", command.iter().chain(args).copied().collect::<Vec<_>>().join(" "));
    let status = Command::new(command[0])
        .args(&command[1..])
        .args(args)
        .status()
        .map_err(|e| format!("failed to run '{shown}': {e}"))?;
    if !status.success() {
        return Err(format!("'{shown}' exited with {status}"));
    }
    Ok(())
}

fn cmd_install_trust(raw: &[String]) -> Result<(), String> {
    let args = parse_args(raw, &["dir"], &[], 0)?;
    let dir = ca_dir(args.flags.get("dir"))?;
    let ca_crt_path = dir.join("ca.crt");
    if !ca_crt_path.exists() {
        return Err(format!(
            "no CA found in {} -- run 'boringca init' first (or pass --dir)",
            dir.display()
        ));
    }

    let stem = store_stem(&dir);
    let legacy_stem = legacy_store_stem(&dir);
    let method = detect_trust_method(&ca_trust_filename(&stem)).ok_or_else(|| {
        format!(
            "couldn't find a known trust mechanism (Debian/Ubuntu, Fedora/RHEL, openSUSE or \
             Arch layout) on this system -- see the README to install {} into your OS/browser \
             trust store manually",
            ca_crt_path.display()
        )
    })?;
    let tool = privilege_tool()?;

    println!("Installing {} into the system trust store ...", ca_crt_path.display());
    let src_str = ca_crt_path.to_str().ok_or("--dir contains invalid UTF-8")?;
    match method {
        TrustMethod::CopyAndUpdate { target, update } => {
            let target_str = target.to_str().ok_or("--dir contains invalid UTF-8")?;
            // "--": a relative --dir starting with '-' is a path, not an option.
            run_privileged(tool, "cp", &["--", src_str, target_str])?;
            // Older versions installed this same CA under a name derived
            // from the directory name alone: remove that copy, but only if
            // it really is this CA (another store may own that name).
            let legacy = target.with_file_name(ca_trust_filename(&legacy_stem));
            if legacy != target && same_certificate(&legacy, &ca_crt_path) {
                let legacy_str = legacy.to_str().ok_or("--dir contains invalid UTF-8")?;
                run_privileged(tool, "rm", &["-f", "--", legacy_str])?;
            }
            run_privileged(tool, update[0], &update[1..])?;
        }
        TrustMethod::P11KitTrust => {
            run_privileged(tool, "trust", &["anchor", "--store", src_str])?;
        }
    }

    println!();
    println!("CA trusted system-wide.");

    // Firefox and Chromium-based browsers on Linux ignore the system trust
    // store and keep their own NSS certificate databases instead, so the
    // steps above never reach them. This part is best-effort: it needs
    // `certutil` (nss's own tool) and a guess at where each browser keeps
    // its database, neither of which is guaranteed to be there -- unlike
    // the system trust store above, a failure here is reported, not fatal.
    println!();
    println!("Browser trust stores (best effort, no sudo needed):");
    let cn = ca_common_name(&ca_crt_path).unwrap_or_else(|| DEFAULT_CA_CN.to_string());
    let nicknames = NssNicknames {
        current: nss_nickname(&cn, &stem),
        legacy: nss_nickname(&cn, &legacy_stem),
    };
    for line in install_browser_trust(&ca_crt_path, &nicknames) {
        println!("  {line}");
    }
    Ok(())
}

/// Nickname used for the CA in NSS certificate databases: the CA's Common
/// Name for readability, plus the same store-derived stem `install-trust`
/// uses for the system copy, so two different `--dir` stores (even with
/// the same default CN) never get treated as the same already-trusted
/// entry.
fn nss_nickname(cn: &str, stem: &str) -> String {
    format!("{cn} ({stem})")
}

/// The nickname to install the CA under, and the one older versions used
/// (derived from the directory name alone, see `legacy_store_stem`).
struct NssNicknames {
    current: String,
    legacy: String,
}

/// The certificate (as a PEM body) stored under `nickname` in an NSS
/// database, if any.
///
/// `certutil -L -n <nickname>` prints every certificate sharing that
/// certificate's *subject*, not just the one under `nickname` -- and all
/// CAs created with the same CN share it, whatever their store. The one
/// actually under `nickname` comes first, so only that one is kept.
fn nss_cert_named(db_arg: &str, nickname: &str) -> Option<String> {
    let out = Command::new("certutil")
        .args(["-d", db_arg, "-L", "-n", nickname, "-a"])
        .output()
        .ok()
        .filter(|out| out.status.success())?;
    pem_bodies(&String::from_utf8_lossy(&out.stdout)).into_iter().next()
}

/// Delete the certificate stored under `nickname` -- only that one: unlike
/// `-L`, `certutil -D` leaves other certificates of the same subject alone.
fn nss_delete(db_arg: &str, nickname: &str) -> Result<(), String> {
    let status = Command::new("certutil")
        .args(["-d", db_arg, "-D", "-n", nickname])
        .status()
        .map_err(|e| format!("failed to run certutil: {e}"))?;
    if !status.success() {
        return Err(format!("failed to remove the previous CA, certutil exited with {status}"));
    }
    Ok(())
}

/// Add `ca_crt_path` to one NSS certificate database (`sql:<nss_dir>`),
/// trusted for issuing server certs ("C,,"). Returns what happened so the
/// caller can report it; a missing database or a `certutil` failure is
/// communicated through `Err`, not a hard error for the whole command.
fn nss_install(nss_dir: &Path, ca_crt_path: &Path, nicknames: &NssNicknames) -> Result<&'static str, String> {
    if !nss_dir.is_dir() {
        return Err("no database found".to_string());
    }
    let db_arg = format!("sql:{}", nss_dir.display());
    let nickname = nicknames.current.as_str();

    let ours = fs::read_to_string(ca_crt_path)
        .map_err(|e| format!("failed to read {}: {e}", ca_crt_path.display()))?;
    let ours = pem_bodies(&ours)
        .into_iter()
        .next()
        .ok_or_else(|| format!("{} is not a PEM certificate", ca_crt_path.display()))?;

    // Older versions installed this CA under a nickname derived from the
    // directory name alone. NSS keeps a certificate under a single
    // nickname (adding it again under another one is a no-op), so remove
    // that entry first -- only if it is exactly this CA, since another
    // store with the same directory name may own that nickname.
    if nicknames.legacy != nickname && nss_cert_named(&db_arg, &nicknames.legacy).as_ref() == Some(&ours) {
        nss_delete(&db_arg, &nicknames.legacy)?;
    }

    // The nickname only identifies the store (CN + directory), not the CA
    // itself: after "init --force" in the same store it still points at
    // the previous CA. Compare the actual certificates, and drop a previous
    // CA rather than leaving it trusted next to the new one.
    let mut replaced = false;
    match nss_cert_named(&db_arg, nickname) {
        Some(cert) if cert == ours => return Ok("already trusted"),
        Some(_) => {
            nss_delete(&db_arg, nickname)?;
            replaced = true;
        }
        None => {}
    }

    let status = Command::new("certutil")
        .args(["-d", &db_arg, "-A", "-t", "C,,", "-n", nickname, "-i"])
        .arg(ca_crt_path)
        .status()
        .map_err(|e| format!("failed to run certutil: {e}"))?;
    if !status.success() {
        return Err(format!("certutil exited with {status}"));
    }
    // If this exact CA was already there under some other nickname (e.g.
    // imported by hand), NSS keeps it under that one and ignores ours.
    if nss_cert_named(&db_arg, nickname).as_ref() != Some(&ours) {
        return Ok("already trusted (under another nickname)");
    }
    Ok(if replaced { "installed (replaced a previous CA from this store)" } else { "installed" })
}

/// Where Firefox keeps its profiles (profiles.ini), relative to $HOME:
/// the classic package, the Snap and the Flatpak.
const FIREFOX_DIRS: &[&str] = &[
    ".mozilla/firefox",
    "snap/firefox/common/.mozilla/firefox",
    ".var/app/org.mozilla.firefox/.mozilla/firefox",
];

/// Shared NSS databases of Chromium-based browsers, relative to $HOME, with
/// the label to report them under. The first one (Chrome, Chromium and
/// most others) is always reported; the others only when present.
const CHROMIUM_NSSDBS: &[(&str, &str)] = &[
    (".pki/nssdb", "Chromium/Chrome (~/.pki/nssdb)"),
    ("snap/chromium/current/.pki/nssdb", "Chromium Snap (~/snap/chromium/current/.pki/nssdb)"),
];

/// Parse `<firefox_dir>/profiles.ini` (the same format Firefox itself
/// reads) just enough to list each profile's directory -- no ini crate,
/// this is the one section shape ([Profile0], [Profile1], ...) we need.
fn find_firefox_profiles(firefox_dir: &Path) -> Vec<PathBuf> {
    let Ok(content) = fs::read_to_string(firefox_dir.join("profiles.ini")) else {
        return Vec::new();
    };

    let mut profiles = Vec::new();
    let mut in_profile = false;
    let mut is_relative = true;
    let mut path: Option<String> = None;

    let flush = |in_profile: bool, is_relative: bool, path: &mut Option<String>, out: &mut Vec<PathBuf>| {
        if in_profile {
            if let Some(p) = path.take() {
                out.push(if is_relative { firefox_dir.join(&p) } else { PathBuf::from(&p) });
            }
        }
    };

    for line in content.lines() {
        let line = line.trim();
        if let Some(section) = line.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            flush(in_profile, is_relative, &mut path, &mut profiles);
            in_profile = section.starts_with("Profile");
            is_relative = true;
            continue;
        }
        if !in_profile {
            continue;
        }
        if let Some(v) = line.strip_prefix("Path=") {
            path = Some(v.to_string());
        } else if let Some(v) = line.strip_prefix("IsRelative=") {
            is_relative = v.trim() != "0";
        }
    }
    flush(in_profile, is_relative, &mut path, &mut profiles);
    profiles
}

fn install_browser_trust(ca_crt_path: &Path, nicknames: &NssNicknames) -> Vec<String> {
    if find_program("certutil").is_none() {
        return vec![
            "certutil not found -- install 'libnss3-tools' (Debian/Ubuntu) to also trust \
             Firefox/Chromium, skipped"
                .to_string(),
        ];
    }
    let Ok(home) = env::var("HOME") else {
        return vec!["cannot determine home directory, skipped".to_string()];
    };
    let home = Path::new(&home);

    let report = |label: &str, nss_dir: &Path| match nss_install(nss_dir, ca_crt_path, nicknames) {
        Ok(status) => format!("{label}: {status}"),
        Err(e) => format!("{label}: skipped -- {e}"),
    };
    let mut lines = Vec::new();

    let profiles: Vec<PathBuf> = FIREFOX_DIRS.iter().flat_map(|dir| find_firefox_profiles(&home.join(dir))).collect();
    if profiles.is_empty() {
        lines.push("Firefox: no profile found, skipped".to_string());
    }
    for profile in &profiles {
        lines.push(report(&format!("Firefox ({})", profile.display()), profile));
    }

    for (i, (dir, label)) in CHROMIUM_NSSDBS.iter().enumerate() {
        let nssdb = home.join(dir);
        if i == 0 || nssdb.is_dir() {
            lines.push(report(label, &nssdb));
        }
    }

    lines
}

// ---------------------------------------------------------------------
// boringca issue <name>
// ---------------------------------------------------------------------

/// Everything "issue" needs from the command line, parsed and validated
/// up front -- before any file is read or written.
struct IssueRequest {
    name: String,
    dir: PathBuf,
    cn: String,
    days: u32,
    eku: Vec<ExtendedKeyUsagePurpose>,
    eku_label: &'static str,
    /// The SAN list as given or defaulted, for display; None for none.
    san: Option<String>,
    sans: Vec<SanType>,
    force: bool,
}

fn parse_issue_args(raw: &[String]) -> Result<IssueRequest, String> {
    let args = parse_args(
        raw,
        &["cn", "san", "days", "dir"],
        &["server", "client", "both", "force"],
        1,
    )?;

    let name = args
        .positionals
        .first()
        .ok_or("missing <name>\n\nUsage: boringca issue <name> [OPTIONS]")?
        .clone();
    validate_name(&name)?;

    let dir = ca_dir(args.flags.get("dir"))?;
    let cn = args.flags.get("cn").cloned().unwrap_or_else(|| name.clone());
    if cn.trim().is_empty() {
        return Err("--cn must not be empty".to_string());
    }
    let days = parse_days(&args.flags, DEFAULT_LEAF_DAYS)?;

    let kinds: Vec<&str> = ["server", "client", "both"].into_iter().filter(|s| args.switches.contains(*s)).collect();
    let (eku, eku_label) = match kinds.as_slice() {
        [] | ["server"] => (vec![ExtendedKeyUsagePurpose::ServerAuth], "serverAuth"),
        ["client"] => (vec![ExtendedKeyUsagePurpose::ClientAuth], "clientAuth"),
        ["both"] => (
            vec![ExtendedKeyUsagePurpose::ServerAuth, ExtendedKeyUsagePurpose::ClientAuth],
            "serverAuth,clientAuth",
        ),
        _ => return Err("--server, --client and --both are mutually exclusive".to_string()),
    };

    let san = match args.flags.get("san") {
        Some(san) => Some(san.clone()),
        None => default_san(&cn, kinds == ["client"])?,
    };
    let sans = match &san {
        Some(san) => parse_sans(san)?,
        None => Vec::new(),
    };

    Ok(IssueRequest { name, dir, cn, days, eku, eku_label, san, sans, force: args.switches.contains("force") })
}

fn cmd_issue(raw: &[String]) -> Result<(), String> {
    issue(parse_issue_args(raw)?)
}

fn issue(req: IssueRequest) -> Result<(), String> {
    let IssueRequest { name, dir, cn, days, eku, eku_label, san, sans, force } = req;

    let ca = load_ca(&dir)?;

    let key_path = dir.join("private").join(format!("{name}.key"));
    let crt_path = dir.join("certs").join(format!("{name}.crt"));
    if !force && (key_path.exists() || crt_path.exists()) {
        return Err(format!(
            "a certificate named '{name}' already exists in {} (use --force to replace it)",
            dir.display()
        ));
    }

    // A certificate can't outlive the CA that signed it: past the CA's
    // expiry nothing validates it anyway, so cap it rather than issue
    // something that looks valid longer than it is.
    let (not_before, mut not_after) = validity_period(days)?;
    if ca.not_after <= OffsetDateTime::now_utc() {
        return Err(format!(
            "the CA in {} expired on {} -- create a new one with 'boringca init --force'",
            dir.display(),
            ca.not_after.date()
        ));
    }
    if not_after > ca.not_after {
        not_after = ca.not_after;
        println!(
            "note: the CA expires on {}, so this certificate is capped to {} days instead of {days}",
            ca.not_after.date(),
            (not_after - not_before).whole_days()
        );
    }

    fs::create_dir_all(dir.join("private")).map_err(|e| format!("failed to create private dir: {e}"))?;
    fs::create_dir_all(dir.join("certs")).map_err(|e| format!("failed to create certs dir: {e}"))?;

    println!("Generating key pair for '{name}' (ECDSA P-256) ...");
    let leaf_key = KeyPair::generate().map_err(|e| format!("failed to generate key pair: {e}"))?;

    println!(
        "Signing certificate with CA (CN=\"{cn}\", {} days, EKU={eku_label}) ...",
        (not_after - not_before).whole_days()
    );
    let mut leaf_params = CertificateParams::new(Vec::new())
        .map_err(|e| format!("failed to build certificate parameters: {e}"))?;
    leaf_params.distinguished_name = common_name_dn(&cn);
    leaf_params.subject_alt_names = sans;
    leaf_params.is_ca = IsCa::NoCa;
    // ECDSA keys sign; KeyEncipherment only makes sense for RSA.
    leaf_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    leaf_params.extended_key_usages = eku;
    leaf_params.use_authority_key_identifier_extension = true;
    leaf_params.not_before = not_before;
    leaf_params.not_after = not_after;

    let leaf_cert = leaf_params
        .signed_by(&leaf_key, &ca.cert, &ca.key)
        .map_err(|e| format!("failed to sign certificate: {e}"))?;

    write_files(&[
        OutFile { path: &key_path, contents: &leaf_key.serialize_pem(), private: true },
        OutFile { path: &crt_path, contents: &leaf_cert.pem(), private: false },
    ])?;

    println!();
    println!("Certificate ready:");
    println!("  key:  {}", key_path.display());
    println!("  cert: {}", crt_path.display());
    println!("  SAN:  {}", san.as_deref().unwrap_or("(none)"));
    Ok(())
}

/// Restrict certificate short names to something safe to use as a file name
/// (no path separators, no leading dot/dash).
fn validate_name(name: &str) -> Result<(), String> {
    let ok = !name.is_empty()
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
        && !name.starts_with('.')
        && !name.starts_with('-');
    if ok {
        Ok(())
    } else {
        Err(format!(
            "invalid name '{name}': use only letters, digits, '-', '_' or '.', and don't start with '-' or '.'"
        ))
    }
}

/// A host name usable in a DNS SAN: dot-separated labels of letters,
/// digits and inner hyphens (1-63 characters each, 253 in total), with an
/// optional leading "*." wildcard label.
fn is_valid_dns_name(name: &str) -> bool {
    let host = name.strip_prefix("*.").unwrap_or(name);
    !host.is_empty()
        && name.len() <= 253
        && host.split('.').all(|label| {
            (1..=63).contains(&label.len())
                && label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
                && !label.starts_with('-')
                && !label.ends_with('-')
        })
}

/// The SAN list used when --san isn't given, derived from the CN: an IP
/// address SAN for an IP, a DNS SAN for a host name. A CN that is neither
/// (e.g. "user@laptop") makes no valid SAN: fine for a client-only
/// certificate, which then gets none, but an error for a server one, which
/// browsers match against its SANs only.
fn default_san(cn: &str, client_only: bool) -> Result<Option<String>, String> {
    if cn.parse::<IpAddr>().is_ok() {
        Ok(Some(format!("ip:{cn}")))
    } else if is_valid_dns_name(cn) {
        Ok(Some(format!("dns:{cn}")))
    } else if client_only {
        Ok(None)
    } else {
        Err(format!(
            "'{cn}' is neither a valid DNS name nor an IP address, so it can't be used as the \
             certificate's Subject Alternative Name -- pass the names it is for with --san \
             (e.g. --san dns:host.example,ip:10.0.0.1)"
        ))
    }
}

/// Turn a friendly "dns:foo.example,ip:10.0.0.1" list into rcgen SAN entries.
fn parse_sans(san: &str) -> Result<Vec<SanType>, String> {
    let mut out = Vec::new();
    for entry in san.split(',') {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }
        let (kind, value) = entry
            .split_once(':')
            .ok_or_else(|| format!("invalid --san entry '{entry}', expected 'dns:<name>' or 'ip:<addr>'"))?;
        let parsed = match kind.to_ascii_lowercase().as_str() {
            "dns" => {
                if !is_valid_dns_name(value) {
                    return Err(format!("invalid DNS SAN '{value}' (not a valid host name)"));
                }
                SanType::DnsName(
                    Ia5String::try_from(value.to_string())
                        .map_err(|e| format!("invalid DNS SAN '{value}': {e}"))?,
                )
            }
            "ip" => SanType::IpAddress(
                value
                    .parse::<IpAddr>()
                    .map_err(|_| format!("invalid IP SAN '{value}'"))?,
            ),
            "email" => SanType::Rfc822Name(
                Ia5String::try_from(value.to_string())
                    .map_err(|e| format!("invalid email SAN '{value}': {e}"))?,
            ),
            "uri" => SanType::URI(
                Ia5String::try_from(value.to_string())
                    .map_err(|e| format!("invalid URI SAN '{value}': {e}"))?,
            ),
            other => return Err(format!("unsupported SAN type '{other}' (use dns, ip, email or uri)")),
        };
        out.push(parsed);
    }
    if out.is_empty() {
        return Err("--san must contain at least one entry".to_string());
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strings(args: &[&str]) -> Vec<String> {
        args.iter().map(|s| s.to_string()).collect()
    }

    /// A scratch directory under the system temp dir, removed on drop.
    struct TempDir(PathBuf);

    impl TempDir {
        fn new(label: &str) -> TempDir {
            let dir = env::temp_dir().join(format!("boringca-test-{}-{label}", std::process::id()));
            let _ = fs::remove_dir_all(&dir);
            fs::create_dir_all(&dir).unwrap();
            TempDir(dir)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn issue_args(dir: &Path, extra: &[&str]) -> Vec<String> {
        let mut args = strings(extra);
        args.extend(strings(&["--dir", dir.to_str().unwrap()]));
        args
    }

    fn cert_der(path: &Path) -> Vec<u8> {
        read_cert_der(path).unwrap()
    }

    // --- option parsing --------------------------------------------------

    #[test]
    fn parse_args_values_switches_and_positionals() {
        let args = parse_args(&strings(&["nas", "--cn", "x", "--san=dns:a", "--both"]), &["cn", "san"], &["both"], 1).unwrap();
        assert_eq!(args.positionals, ["nas"]);
        assert_eq!(args.flags["cn"], "x");
        assert_eq!(args.flags["san"], "dns:a");
        assert!(args.switches.contains("both"));
    }

    #[test]
    fn parse_args_rejects_bad_input() {
        let parse = |raw: &[&str]| parse_args(&strings(raw), &["cn"], &["force"], 1);
        assert!(parse(&["--cn"]).is_err(), "missing value");
        assert!(parse(&["--cn", "--force"]).is_err(), "option taken as a value");
        assert!(parse(&["--force=yes"]).is_err(), "value given to a switch");
        assert!(parse(&["--bogus"]).is_err(), "unknown option");
        assert!(parse(&["a", "b"]).is_err(), "extra positional");
    }

    #[test]
    fn parse_args_double_dash_ends_options() {
        let args = parse_args(&strings(&["--", "--cn"]), &["cn"], &[], 1).unwrap();
        assert_eq!(args.positionals, ["--cn"]);
        assert!(args.flags.is_empty());
    }

    #[test]
    fn days_validation() {
        let flags = |v: &str| std::collections::HashMap::from([("days".to_string(), v.to_string())]);
        assert_eq!(parse_days(&std::collections::HashMap::new(), 42).unwrap(), 42);
        assert_eq!(parse_days(&flags("10"), 42).unwrap(), 10);
        for bad in ["0", "-5", "abc", "4294967295", "4000000"] {
            assert!(parse_days(&flags(bad), 42).is_err(), "--days {bad} accepted");
        }
    }

    #[test]
    fn validity_is_exactly_the_requested_days() {
        let (not_before, not_after) = validity_period(DEFAULT_LEAF_DAYS).unwrap();
        assert_eq!(not_after - not_before, Duration::days(i64::from(DEFAULT_LEAF_DAYS)));
        assert!(not_before < OffsetDateTime::now_utc());
    }

    // --- names and SANs --------------------------------------------------

    #[test]
    fn certificate_names() {
        for ok in ["nas", "nas.lan", "my_host-1", "10.0.0.1"] {
            assert!(validate_name(ok).is_ok(), "{ok} rejected");
        }
        for bad in ["", ".hidden", "-v", "a/b", "foo bar", "::1"] {
            assert!(validate_name(bad).is_err(), "{bad} accepted");
        }
    }

    #[test]
    fn dns_names() {
        for ok in ["nas", "nas.lan", "*.example.com", "a-b.c0", "NAS.Lan"] {
            assert!(is_valid_dns_name(ok), "{ok} rejected");
        }
        for bad in ["", "*.", "user@laptop", "my_host", "a..b", "-a.b", "a-.b", "a b", "a.*.b", &"a".repeat(64)] {
            assert!(!is_valid_dns_name(bad), "{bad} accepted");
        }
    }

    #[test]
    fn default_sans() {
        assert_eq!(default_san("nas.lan", false).unwrap().as_deref(), Some("dns:nas.lan"));
        assert_eq!(default_san("10.0.0.1", false).unwrap().as_deref(), Some("ip:10.0.0.1"));
        assert_eq!(default_san("::1", false).unwrap().as_deref(), Some("ip:::1"));
        assert_eq!(default_san("user@laptop", true).unwrap(), None);
        assert!(default_san("user@laptop", false).is_err());
    }

    #[test]
    fn san_lists() {
        assert_eq!(parse_sans("dns:a.lan, ip:10.0.0.1,email:me@x.y,uri:https://x.y/").unwrap().len(), 4);
        for bad in ["", ",", "a.lan", "dns:user@laptop", "ip:300.0.0.1", "foo:bar"] {
            assert!(parse_sans(bad).is_err(), "{bad} accepted");
        }
    }

    #[test]
    fn issue_switches_are_exclusive() {
        let dir = Path::new("/nonexistent");
        assert!(parse_issue_args(&issue_args(dir, &["nas", "--client", "--both"])).is_err());
        assert!(parse_issue_args(&issue_args(dir, &["nas", "--server", "--client"])).is_err());
        let req = parse_issue_args(&issue_args(dir, &["laptop", "--client", "--cn", "user@laptop"])).unwrap();
        assert_eq!(req.eku_label, "clientAuth");
        assert!(req.san.is_none() && req.sans.is_empty());
    }

    // --- PEM / DER -------------------------------------------------------

    #[test]
    fn base64() {
        assert_eq!(base64_decode("aGVsbG8=").unwrap(), b"hello");
        assert_eq!(base64_decode("aGVsbG8").unwrap(), b"hello");
        assert_eq!(base64_decode("").unwrap(), b"");
        assert!(base64_decode("a b").is_none());
    }

    #[test]
    fn pem_bodies_ignore_wrapping() {
        let one = "-----BEGIN CERTIFICATE-----\nQUJD\nREVG\n-----END CERTIFICATE-----\n";
        let two = "junk\n-----BEGIN CERTIFICATE-----\r\nQUJDREVG\r\n-----END CERTIFICATE-----\r\n";
        assert_eq!(pem_bodies(one), ["QUJDREVG"]);
        assert_eq!(pem_bodies(one), pem_bodies(two));
    }

    #[test]
    fn der_times() {
        let t = parse_der_time(0x17, b"360925050233Z").unwrap();
        assert_eq!((t.year(), u8::from(t.month()), t.day(), t.second()), (2036, 9, 25, 33));
        assert_eq!(parse_der_time(0x17, b"990101000000Z").unwrap().year(), 1999);
        assert_eq!(parse_der_time(0x18, b"99991231235959Z").unwrap().year(), 9999);
        assert!(parse_der_time(0x17, b"361325050233Z").is_none(), "month 13");
        assert!(parse_der_time(0x17, b"3609250502Z").is_none(), "too short");
    }

    #[test]
    fn parses_rcgen_certificates() {
        let key = KeyPair::generate().unwrap();
        let mut params = ca_params("Test CA \u{e9}").unwrap();
        let (_, not_after) = validity_period(10).unwrap();
        params.not_after = not_after;
        let cert = params.self_signed(&key).unwrap();

        let info = parse_certificate(cert.der()).unwrap();
        assert_eq!(name_common_name(info.subject).as_deref(), Some("Test CA \u{e9}"));
        assert_eq!(info.issuer, info.subject);
        assert_eq!(info.not_after.unix_timestamp(), not_after.unix_timestamp());
        // Same key, same SPKI: what load_ca relies on.
        let again = ca_params("other").unwrap().self_signed(&key).unwrap();
        assert_eq!(parse_certificate(again.der()).unwrap().spki, info.spki);
        assert!(parse_certificate(&cert.der()[..50]).is_none(), "truncated");
    }

    // --- store naming ----------------------------------------------------

    #[test]
    fn store_names() {
        assert_eq!(legacy_store_stem(Path::new("/home/u/.boringca")), "boringca");
        assert_eq!(legacy_store_stem(Path::new("/srv/ca")), "ca");
        assert_eq!(legacy_store_stem(Path::new("/")), "boringca");
        // Pinned: changing the hash would rename every installed CA (and
        // leave the copies under the old names behind).
        assert_eq!(path_hash(b"/home/u/.boringca"), 0x1704_5e70_8642_ea2c);
        assert_eq!(path_hash(b"/srv/a/ca"), 0xd3d1_2d76_d482_4f53);
        assert_ne!(path_hash(b"/srv/a/ca"), path_hash(b"/srv/b/ca"));

        let tmp = TempDir::new("stems");
        let (a, b) = (tmp.0.join("a/ca"), tmp.0.join("b/ca"));
        fs::create_dir_all(&a).unwrap();
        fs::create_dir_all(&b).unwrap();
        assert_ne!(store_stem(&a), store_stem(&b));
        assert!(store_stem(&a).starts_with("ca-"));
        assert_eq!(store_stem(&a), store_stem(&a.join("../ca")));
    }

    #[test]
    fn firefox_profiles_ini() {
        let tmp = TempDir::new("firefox");
        fs::write(
            tmp.0.join("profiles.ini"),
            "[General]\nStartWithLastProfile=1\n\n[Profile0]\nName=default\nIsRelative=1\nPath=abc.default\n\n\
             [Profile1]\nIsRelative=0\nPath=/elsewhere/xyz\n\n[Install4F96D1932A9F858E]\nDefault=abc.default\n",
        )
        .unwrap();
        assert_eq!(find_firefox_profiles(&tmp.0), [tmp.0.join("abc.default"), PathBuf::from("/elsewhere/xyz")]);
        assert!(find_firefox_profiles(&tmp.0.join("missing")).is_empty());
    }

    // --- end to end: create a CA, issue certificates ---------------------

    #[test]
    fn create_ca_and_issue() {
        let tmp = TempDir::new("e2e");
        let dir = tmp.0.join("store");
        create_ca(&dir, "Test Root", 30).unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(dir.join("ca.key")).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        assert_eq!(ca_common_name(&dir.join("ca.crt")).as_deref(), Some("Test Root"));

        // Capped to the CA's 30 days, and chained to it.
        cmd_issue(&issue_args(&dir, &["nas.lan"])).unwrap();
        let ca_der = cert_der(&dir.join("ca.crt"));
        let leaf_der = cert_der(&dir.join("certs/nas.lan.crt"));
        let (ca_info, leaf_info) = (parse_certificate(&ca_der).unwrap(), parse_certificate(&leaf_der).unwrap());
        assert_eq!(leaf_info.issuer, ca_info.subject);
        assert_eq!(leaf_info.not_after, ca_info.not_after);
        assert_eq!(name_common_name(leaf_info.subject).as_deref(), Some("nas.lan"));

        // No silent overwrite; --force replaces.
        let err = cmd_issue(&issue_args(&dir, &["nas.lan"])).unwrap_err();
        assert!(err.contains("--force"), "{err}");
        cmd_issue(&issue_args(&dir, &["nas.lan", "--force"])).unwrap();
        assert_ne!(cert_der(&dir.join("certs/nas.lan.crt")), leaf_der);

        // No staging file left behind.
        let leftovers: Vec<_> = fs::read_dir(dir.join("certs"))
            .unwrap()
            .chain(fs::read_dir(&dir).unwrap())
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().ends_with(".tmp"))
            .collect();
        assert!(leftovers.is_empty(), "{leftovers:?}");
    }

    #[test]
    fn issue_refuses_mismatched_ca_files() {
        let tmp = TempDir::new("mismatch");
        let (one, two) = (tmp.0.join("one"), tmp.0.join("two"));
        create_ca(&one, "Root", 30).unwrap();
        create_ca(&two, "Root", 30).unwrap();
        fs::copy(two.join("ca.crt"), one.join("ca.crt")).unwrap();
        let err = cmd_issue(&issue_args(&one, &["x"])).unwrap_err();
        assert!(err.contains("don't belong together"), "{err}");
    }

    #[test]
    fn issue_ignores_a_stale_ca_cn() {
        // The CN is read from ca.crt: an edited or missing ca.cn doesn't
        // break the chain anymore.
        let tmp = TempDir::new("cn");
        let dir = tmp.0.join("store");
        create_ca(&dir, "  Spaced Root  ", 30).unwrap();
        fs::remove_file(dir.join("ca.cn")).unwrap();
        cmd_issue(&issue_args(&dir, &["x"])).unwrap();
        let ca_der = cert_der(&dir.join("ca.crt"));
        let leaf_der = cert_der(&dir.join("certs/x.crt"));
        assert_eq!(parse_certificate(&leaf_der).unwrap().issuer, parse_certificate(&ca_der).unwrap().subject);
    }

    #[test]
    fn write_files_tightens_leftover_staging_file() {
        let tmp = TempDir::new("write");
        let key = tmp.0.join("k.key");
        fs::write(staging_path(&key), "old").unwrap();
        write_files(&[OutFile { path: &key, contents: "secret", private: true }]).unwrap();
        assert_eq!(fs::read_to_string(&key).unwrap(), "secret");
        assert!(!staging_path(&key).exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(fs::metadata(&key).unwrap().permissions().mode() & 0o777, 0o600);
        }
    }
}
