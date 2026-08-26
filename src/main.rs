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
use std::process::ExitCode;

use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose,
    Ia5String, IsCa, KeyPair, KeyUsagePurpose, SanType,
};
use time::{Duration, OffsetDateTime};

const DEFAULT_CA_DAYS: u32 = 3650; // 10 years
const DEFAULT_CA_CN: &str = "BoringCA Root";

const DEFAULT_LEAF_DAYS: u32 = 825; // ~ historical browser cap for server certs

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();

    // The common case needs no subcommand at all:
    //   boringca            -> set up the CA on first run
    //   boringca <name>     -> issue a certificate for DNS name <name>,
    //                          creating the CA first if needed
    // "init"/"issue" remain available, with their full set of options, for
    // anyone who wants more control (see --help).
    let result = match args.first().map(String::as_str) {
        None => quick_start(),
        Some("-h") | Some("--help") => {
            print_help();
            return ExitCode::SUCCESS;
        }
        Some("init") => cmd_init(&args[1..]),
        Some("issue") => cmd_issue(&args[1..]),
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
    boringca <name>       Issue a certificate for DNS name <name>, signed by
                           the CA (creates the CA automatically on first use)

    e.g.
        boringca
        boringca nas.lan

ADVANCED USAGE:
    boringca init   [OPTIONS]          (Re)create the root CA explicitly
    boringca issue  <name> [OPTIONS]   Issue a certificate with full control
    boringca help

    "boringca <name>" above is shorthand for "boringca issue <name>" with
    every option left at its default.

INIT OPTIONS:
    --cn <name>       Common Name of the root CA          [default: "{ca_cn}"]
    --days <n>        Validity in days                    [default: {ca_days}]
    --dir <path>      CA store directory                  [default: $BORINGCA_HOME or ~/.boringca]
    --force           Overwrite an existing CA in --dir

ISSUE OPTIONS:
    <name>            Short name for the certificate (used for file names)
    --cn <name>       Common Name                         [default: <name>]
    --san <list>      Comma-separated Subject Alt. Names, e.g. "dns:example.com,dns:www.example.com,ip:10.0.0.1"
                                                            [default: dns:<cn>]
    --server          Issue a server certificate (extendedKeyUsage=serverAuth) [default]
    --client          Issue a client certificate (extendedKeyUsage=clientAuth)
    --both            Issue a cert valid for both server and client auth
    --days <n>        Validity in days                    [default: {leaf_days}]
    --dir <path>      CA store directory                  [default: $BORINGCA_HOME or ~/.boringca]

EXAMPLES:
    boringca init --cn "Home Lab CA"
    boringca issue nas --san dns:nas.lan,ip:192.168.1.10
    boringca issue laptop --client --cn "user@laptop"

STORE LAYOUT (under --dir):
    ca.key, ca.crt, ca.cn   root CA key, certificate and Common Name
    private/<name>.key      issued certificate's private key
    certs/<name>.crt         issued certificate

Keys are ECDSA P-256. Certificate generation is entirely in-process (no
external openssl binary is invoked) -- 
WARNING : this tool is meant for local
development, home lab and internal PKI use, NOT as a replacement for a
production CA/PKI system (step-ca, easy-rsa, HashiCorp Vault PKI, ...).
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
struct Args {
    positionals: Vec<String>,
    flags: std::collections::HashMap<String, String>,
    switches: std::collections::HashSet<String>,
}

fn parse_args(raw: &[String], value_flags: &[&str], switch_flags: &[&str]) -> Result<Args, String> {
    let mut positionals = Vec::new();
    let mut flags = std::collections::HashMap::new();
    let mut switches = std::collections::HashSet::new();

    let mut i = 0;
    while i < raw.len() {
        let arg = &raw[i];
        if let Some(name) = arg.strip_prefix("--") {
            if value_flags.contains(&name) {
                let value = raw
                    .get(i + 1)
                    .ok_or_else(|| format!("--{name} expects a value"))?;
                flags.insert(name.to_string(), value.clone());
                i += 2;
                continue;
            } else if switch_flags.contains(&name) {
                switches.insert(name.to_string());
                i += 1;
                continue;
            } else {
                return Err(format!("unknown option '--{name}'"));
            }
        }
        positionals.push(arg.clone());
        i += 1;
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

fn parse_u32(flags: &std::collections::HashMap<String, String>, name: &str, default: u32) -> Result<u32, String> {
    match flags.get(name) {
        Some(v) => v.parse::<u32>().map_err(|_| format!("--{name} must be a positive integer, got '{v}'")),
        None => Ok(default),
    }
}

#[cfg(unix)]
fn restrict_permissions(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .map_err(|e| format!("failed to chmod 600 {}: {e}", path.display()))
}

#[cfg(not(unix))]
fn restrict_permissions(_path: &Path) -> Result<(), String> {
    Ok(())
}

/// Write a PEM-encoded private key to `path` and restrict its permissions.
fn write_private_pem(path: &Path, pem: &str) -> Result<(), String> {
    fs::write(path, pem).map_err(|e| format!("failed to write {}: {e}", path.display()))?;
    restrict_permissions(path)
}

fn common_name_dn(cn: &str) -> DistinguishedName {
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, cn);
    dn
}

// ---------------------------------------------------------------------
// CA creation, shared by "boringca" (no args), "boringca init" and the
// auto-create-on-first-use path of "boringca <name>".
// ---------------------------------------------------------------------

fn create_ca(dir: &Path, cn: &str, days: u32) -> Result<(), String> {
    let ca_key_path = dir.join("ca.key");
    let ca_crt_path = dir.join("ca.crt");
    let ca_cn_path = dir.join("ca.cn");

    fs::create_dir_all(dir.join("private")).map_err(|e| format!("failed to create {}: {e}", dir.display()))?;
    fs::create_dir_all(dir.join("certs")).map_err(|e| format!("failed to create {}: {e}", dir.display()))?;

    println!("Generating CA key pair (ECDSA P-256) ...");
    let ca_key = KeyPair::generate().map_err(|e| format!("failed to generate CA key pair: {e}"))?;

    println!("Generating self-signed CA certificate (CN=\"{cn}\", {days} days) ...");
    let mut params = CertificateParams::new(Vec::new())
        .map_err(|e| format!("failed to build CA parameters: {e}"))?;
    params.distinguished_name = common_name_dn(cn);
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let now = OffsetDateTime::now_utc();
    params.not_before = now - Duration::days(1); // tolerate a bit of clock skew
    params.not_after = now + Duration::days(i64::from(days));

    let ca_cert = params
        .self_signed(&ca_key)
        .map_err(|e| format!("failed to self-sign CA certificate: {e}"))?;

    write_private_pem(&ca_key_path, &ca_key.serialize_pem())?;
    fs::write(&ca_crt_path, ca_cert.pem()).map_err(|e| format!("failed to write {}: {e}", ca_crt_path.display()))?;
    fs::write(&ca_cn_path, format!("{cn}\n")).map_err(|e| format!("failed to write {}: {e}", ca_cn_path.display()))?;

    println!();
    println!("CA ready in {}", dir.display());
    println!("  key:  {}", ca_key_path.display());
    println!("  cert: {}", ca_crt_path.display());
    println!();
    println!("To trust this CA on Debian/Ubuntu, run:");
    println!(
        "    sudo cp {} /usr/local/share/ca-certificates/{}",
        ca_crt_path.display(),
        ca_trust_filename(dir)
    );
    println!("    sudo update-ca-certificates");
    Ok(())
}

/// File name to use under /usr/local/share/ca-certificates/ so multiple
/// boringca stores (different --dir) don't collide on the same name.
fn ca_trust_filename(dir: &Path) -> String {
    let name = dir
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("boringca")
        .trim_start_matches('.');
    let name = if name.is_empty() { "boringca" } else { name };
    format!("{name}.crt")
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
    // Peek at --dir so the CA (if missing) is created in the same store
    // "issue" below will use, then delegate to it for everything else.
    let peek = parse_args(raw, &["cn", "san", "days", "dir"], &["server", "client", "both"])?;
    let dir = ca_dir(peek.flags.get("dir"))?;
    ensure_ca(&dir)?;
    cmd_issue(raw)
}

// ---------------------------------------------------------------------
// boringca init [OPTIONS]   (explicit, full control)
// ---------------------------------------------------------------------

fn cmd_init(raw: &[String]) -> Result<(), String> {
    let args = parse_args(raw, &["cn", "days", "dir"], &["force"])?;
    let dir = ca_dir(args.flags.get("dir"))?;
    let cn = args.flags.get("cn").cloned().unwrap_or_else(|| DEFAULT_CA_CN.to_string());
    let days = parse_u32(&args.flags, "days", DEFAULT_CA_DAYS)?;
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
// boringca issue <name>
// ---------------------------------------------------------------------

fn cmd_issue(raw: &[String]) -> Result<(), String> {
    let args = parse_args(
        raw,
        &["cn", "san", "days", "dir"],
        &["server", "client", "both"],
    )?;

    let name = args
        .positionals
        .first()
        .ok_or("missing <name>\n\nUsage: boringca issue <name> [OPTIONS]")?
        .clone();
    validate_name(&name)?;

    let dir = ca_dir(args.flags.get("dir"))?;
    let ca_key_path = dir.join("ca.key");
    let ca_cn_path = dir.join("ca.cn");
    if !ca_key_path.exists() {
        return Err(format!(
            "no CA found in {} -- run 'boringca init' first (or pass --dir)",
            dir.display()
        ));
    }

    let ca_key_pem = fs::read_to_string(&ca_key_path)
        .map_err(|e| format!("failed to read {}: {e}", ca_key_path.display()))?;
    let ca_key = KeyPair::from_pem(&ca_key_pem).map_err(|e| format!("failed to load CA private key: {e}"))?;
    let ca_cn = fs::read_to_string(&ca_cn_path)
        .map(|s| s.trim().to_string())
        .map_err(|_| {
            format!(
                "missing {} (CA metadata not found) -- re-run 'boringca init' or recreate this \
                 file with the CA's Common Name",
                ca_cn_path.display()
            )
        })?;

    // Rebuild an in-memory CA certificate object from the persisted key and
    // CN: rcgen only needs it to read back distinguished_name/key_usages
    // when signing a child certificate, so this doesn't touch ca.crt on disk.
    let mut ca_params = CertificateParams::new(Vec::new())
        .map_err(|e| format!("failed to rebuild CA parameters: {e}"))?;
    ca_params.distinguished_name = common_name_dn(&ca_cn);
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let ca_cert = ca_params
        .self_signed(&ca_key)
        .map_err(|e| format!("failed to reconstruct CA certificate: {e}"))?;

    let cn = args.flags.get("cn").cloned().unwrap_or_else(|| name.clone());
    let days = parse_u32(&args.flags, "days", DEFAULT_LEAF_DAYS)?;

    let (eku, eku_label) = match (args.switches.contains("client"), args.switches.contains("both")) {
        (_, true) => (
            vec![ExtendedKeyUsagePurpose::ServerAuth, ExtendedKeyUsagePurpose::ClientAuth],
            "serverAuth,clientAuth",
        ),
        (true, false) => (vec![ExtendedKeyUsagePurpose::ClientAuth], "clientAuth"),
        (false, false) => (vec![ExtendedKeyUsagePurpose::ServerAuth], "serverAuth"),
    };

    let san = args.flags.get("san").cloned().unwrap_or_else(|| format!("dns:{cn}"));
    let sans = parse_sans(&san)?;

    let key_path = dir.join("private").join(format!("{name}.key"));
    let crt_path = dir.join("certs").join(format!("{name}.crt"));
    fs::create_dir_all(dir.join("private")).map_err(|e| format!("failed to create private dir: {e}"))?;
    fs::create_dir_all(dir.join("certs")).map_err(|e| format!("failed to create certs dir: {e}"))?;

    println!("Generating key pair for '{name}' (ECDSA P-256) ...");
    let leaf_key = KeyPair::generate().map_err(|e| format!("failed to generate key pair: {e}"))?;

    println!("Signing certificate with CA (CN=\"{cn}\", {days} days, EKU={eku_label}) ...");
    let mut leaf_params = CertificateParams::new(Vec::new())
        .map_err(|e| format!("failed to build certificate parameters: {e}"))?;
    leaf_params.distinguished_name = common_name_dn(&cn);
    leaf_params.subject_alt_names = sans;
    leaf_params.is_ca = IsCa::NoCa;
    leaf_params.key_usages = vec![KeyUsagePurpose::DigitalSignature, KeyUsagePurpose::KeyEncipherment];
    leaf_params.extended_key_usages = eku;
    leaf_params.use_authority_key_identifier_extension = true;
    let now = OffsetDateTime::now_utc();
    leaf_params.not_before = now - Duration::days(1);
    leaf_params.not_after = now + Duration::days(i64::from(days));

    let leaf_cert = leaf_params
        .signed_by(&leaf_key, &ca_cert, &ca_key)
        .map_err(|e| format!("failed to sign certificate: {e}"))?;

    write_private_pem(&key_path, &leaf_key.serialize_pem())?;
    fs::write(&crt_path, leaf_cert.pem()).map_err(|e| format!("failed to write {}: {e}", crt_path.display()))?;

    println!();
    println!("Certificate ready:");
    println!("  key:  {}", key_path.display());
    println!("  cert: {}", crt_path.display());
    println!("  SAN:  {san}");
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
            "dns" => SanType::DnsName(
                Ia5String::try_from(value.to_string())
                    .map_err(|e| format!("invalid DNS SAN '{value}': {e}"))?,
            ),
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
