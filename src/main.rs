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
        Some("-h") | Some("--help") | Some("help") => {
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
    boringca <name>       Issue a certificate for DNS name <name>, signed by
                           the CA (creates the CA automatically on first use)

    e.g.
        boringca
        boringca nas.lan

ADVANCED USAGE:
    boringca init          [OPTIONS]   (Re)create the root CA explicitly
    boringca issue  <name> [OPTIONS]   Issue a certificate with full control
    boringca install-trust [OPTIONS]   Trust the CA system-wide (uses sudo)
    boringca help

    "boringca <name>" above is shorthand for "boringca issue <name>" with
    every option left at its default.

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
    boringca install-trust

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
        .ok_or_else(|| format!("--days {days} is too large (the certificate would expire after year 9999)"))?;
    Ok((not_before, not_after))
}

/// Write a PEM-encoded private key to `path`, readable by its owner only.
///
/// The file is created with mode 600 from the start (and an existing file
/// is chmod'ed through its handle before anything is written), so the key
/// is never on disk with looser permissions, even briefly.
#[cfg(unix)]
fn write_private_pem(path: &Path, pem: &str) -> Result<(), String> {
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| format!("failed to write {}: {e}", path.display()))?;
    // mode() only applies when the file is created: tighten a pre-existing
    // one too (it has just been truncated, so nothing leaks meanwhile).
    file.set_permissions(fs::Permissions::from_mode(0o600))
        .map_err(|e| format!("failed to chmod 600 {}: {e}", path.display()))?;
    file.write_all(pem.as_bytes())
        .map_err(|e| format!("failed to write {}: {e}", path.display()))
}

#[cfg(not(unix))]
fn write_private_pem(path: &Path, pem: &str) -> Result<(), String> {
    fs::write(path, pem).map_err(|e| format!("failed to write {}: {e}", path.display()))
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
    (params.not_before, params.not_after) = validity_period(days)?;

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
    println!("To trust this CA system-wide, run:");
    println!("    boringca install-trust");
    println!("(it will ask for your password via sudo; see the README for manual steps");
    println!(" or unsupported distros)");
    Ok(())
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
    let args = parse_args(raw, &["cn", "days", "dir"], &["force"])?;
    let dir = ca_dir(args.flags.get("dir"))?;
    let cn = args.flags.get("cn").cloned().unwrap_or_else(|| DEFAULT_CA_CN.to_string());
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
// the system trust store). It always goes through `sudo` itself instead,
// so the user doesn't need to already be root to ask for this -- mirroring
// how `mkcert -install` behaves.
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

/// Look up `bin` in $PATH without spawning a subprocess, the same way a
/// shell would -- used to pick which trust mechanism is actually present.
fn find_in_path(bin: &str) -> Option<PathBuf> {
    let path = env::var_os("PATH")?;
    env::split_paths(&path).map(|dir| dir.join(bin)).find(|full| full.is_file())
}

fn detect_trust_method(filename: &str) -> Option<TrustMethod> {
    for &(anchors, update) in COPY_AND_UPDATE_METHODS {
        if Path::new(anchors).is_dir() && find_in_path(update[0]).is_some() {
            return Some(TrustMethod::CopyAndUpdate {
                target: Path::new(anchors).join(filename),
                update,
            });
        }
    }
    if Path::new(ARCH_TRUST_SOURCE).is_dir() && find_in_path("trust").is_some() {
        return Some(TrustMethod::P11KitTrust);
    }
    None
}

/// Run a command as root, always going through `sudo` (even if we're
/// already root -- `sudo` lets that through without a password prompt on
/// every setup we care about) so the user is never required to have
/// already elevated just to ask boringca to install trust.
fn run_privileged(program: &str, args: &[&str]) -> Result<(), String> {
    println!("    sudo {program} {}", args.join(" "));
    let status = Command::new("sudo")
        .arg(program)
        .args(args)
        .status()
        .map_err(|e| format!("failed to run 'sudo {program}': {e}"))?;
    if !status.success() {
        return Err(format!("'sudo {program}' exited with {status}"));
    }
    Ok(())
}

fn cmd_install_trust(raw: &[String]) -> Result<(), String> {
    let args = parse_args(raw, &["dir"], &[])?;
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

    println!("Installing {} into the system trust store ...", ca_crt_path.display());
    match method {
        TrustMethod::CopyAndUpdate { target, update } => {
            let target_str = target.to_str().ok_or("--dir contains invalid UTF-8")?;
            let src_str = ca_crt_path.to_str().ok_or("--dir contains invalid UTF-8")?;
            run_privileged("cp", &[src_str, target_str])?;
            // Older versions installed this same CA under a name derived
            // from the directory name alone: remove that copy, but only if
            // it really is this CA (another store may own that name).
            let legacy = target.with_file_name(ca_trust_filename(&legacy_stem));
            if legacy != target && same_certificate(&legacy, &ca_crt_path) {
                let legacy_str = legacy.to_str().ok_or("--dir contains invalid UTF-8")?;
                run_privileged("rm", &["-f", legacy_str])?;
            }
            run_privileged(update[0], &update[1..])?;
        }
        TrustMethod::P11KitTrust => {
            let src_str = ca_crt_path.to_str().ok_or("--dir contains invalid UTF-8")?;
            run_privileged("trust", &["anchor", "--store", src_str])?;
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
    let nicknames = NssNicknames {
        current: nss_nickname(&dir, &stem),
        legacy: nss_nickname(&dir, &legacy_stem),
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
fn nss_nickname(dir: &Path, stem: &str) -> String {
    let cn = fs::read_to_string(dir.join("ca.cn"))
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| DEFAULT_CA_CN.to_string());
    format!("{cn} ({stem})")
}

/// The nickname to install the CA under, and the one older versions used
/// (derived from the directory name alone, see `legacy_store_stem`).
struct NssNicknames {
    current: String,
    legacy: String,
}

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

/// Parse ~/.mozilla/firefox/profiles.ini (the same format Firefox itself
/// reads) just enough to list each profile's directory -- no ini crate,
/// this is the one section shape ([Profile0], [Profile1], ...) we need.
fn find_firefox_profiles(home: &str) -> Vec<PathBuf> {
    let firefox_dir = Path::new(home).join(".mozilla/firefox");
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
    if find_in_path("certutil").is_none() {
        return vec![
            "certutil not found -- install 'libnss3-tools' (Debian/Ubuntu) to also trust \
             Firefox/Chromium, skipped"
                .to_string(),
        ];
    }
    let Ok(home) = env::var("HOME") else {
        return vec!["cannot determine home directory, skipped".to_string()];
    };

    let mut lines = Vec::new();

    let profiles = find_firefox_profiles(&home);
    if profiles.is_empty() {
        lines.push("Firefox: no profile found, skipped".to_string());
    } else {
        for profile in profiles {
            let label = format!("Firefox ({})", profile.display());
            match nss_install(&profile, ca_crt_path, nicknames) {
                Ok(status) => lines.push(format!("{label}: {status}")),
                Err(e) => lines.push(format!("{label}: skipped -- {e}")),
            }
        }
    }

    // Chromium, Chrome and most other Chromium-based browsers share this
    // one NSS database on Linux.
    let nssdb = Path::new(&home).join(".pki/nssdb");
    let label = "Chromium/Chrome (~/.pki/nssdb)";
    match nss_install(&nssdb, ca_crt_path, nicknames) {
        Ok(status) => lines.push(format!("{label}: {status}")),
        Err(e) => lines.push(format!("{label}: skipped -- {e}")),
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
    san: String,
    sans: Vec<SanType>,
}

fn parse_issue_args(raw: &[String]) -> Result<IssueRequest, String> {
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
    let cn = args.flags.get("cn").cloned().unwrap_or_else(|| name.clone());
    let days = parse_days(&args.flags, DEFAULT_LEAF_DAYS)?;

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

    Ok(IssueRequest { name, dir, cn, days, eku, eku_label, san, sans })
}

fn cmd_issue(raw: &[String]) -> Result<(), String> {
    issue(parse_issue_args(raw)?)
}

fn issue(req: IssueRequest) -> Result<(), String> {
    let IssueRequest { name, dir, cn, days, eku, eku_label, san, sans } = req;

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
    (leaf_params.not_before, leaf_params.not_after) = validity_period(days)?;

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
