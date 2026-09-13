//! TODO B.2.5: large-group scalability — an information-gathering
//! benchmark, not a correctness test. `umbra-group`'s public API
//! (`create_group`/`add_member`/`send_group_message`) has been
//! validated only at the small (3-party) scale exercised by
//! `hermetic_multi_party.rs`. TreeKEM is O(log N) by construction, so
//! the creator's own per-operation cost (the group-crypto path update)
//! is expected to scale well; the a priori suspect is Umbra's own
//! per-member pairwise fan-out loop in `delivery.rs`, which is O(current
//! roster size) by construction and NOT expected to be a problem at the
//! cell sizes this project targets — this benchmark exists to check
//! that expectation against real numbers rather than assume it.
//!
//! No protocol or engineering changes are made from this benchmark
//! alone (per the TODO item's own ruling: "no optimization without
//! numbers") — its output is a measurement for a human to read and
//! judge, recorded in `docs/TODO.md`'s B.2.5 entry once run.
//!
//! # Why `#[ignore]`d
//!
//! `create_group`/`export_keypackage`/`add_member` have no
//! test-cost seam for Argon2id — a deliberate design choice (see
//! `create.rs`'s and `add.rs`'s own test module docs: "no cost knob, by
//! design: it is a CLI-facing entry point, not a persistence
//! primitive"). A single `create_group` call alone costs ~15-30s of
//! real Argon2id time on this project's reference hardware, and this
//! benchmark drives one `create_group`, `member_count - 1` calls each
//! of `export_keypackage` and `add_member`, plus one
//! `send_group_message` — at `member_count = 50` this is on the order
//! of 30-45 minutes, unsuitable for the default `cargo test` run. Run
//! explicitly:
//!
//! ```sh
//! cargo test -p umbra-group --test scalability_benchmark -- \
//!     --ignored --nocapture --test-threads=1
//! ```
//!
//! `--test-threads=1` matters: these are CPU/memory-bound Argon2id
//! benchmarks, and running the two size points concurrently would
//! contend for the same cores and skew the wall-clock comparison
//! between them.

use std::path::PathBuf;
use std::pin::Pin;
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite};

use umbra_group::delivery::PeerTransportAddress;
use umbra_group::{GroupError, add, create, keypackage, send};

/// Shorthand for a boxed, `Send`, `Send`-error result — matches this
/// crate's other test modules (`unwrap()`/`expect()` are denied even in
/// test code by this workspace's clippy lints).
type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

/// The future type returned by [`sink_connect`]'s closure — factored
/// into its own alias to satisfy `clippy::type_complexity`, mirroring
/// `hermetic_multi_party.rs`'s identical `ConnectFuture` alias.
type ConnectFuture = Pin<
    Box<
        dyn std::future::Future<Output = Result<Box<dyn AsyncWrite + Unpin + Send>, GroupError>>
            + Send,
    >,
>;

/// Fresh temp dir, unique per test/label pair (mirrors this crate's
/// other test modules' `temp_dir` helpers).
fn temp_dir(label: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "umbra-group-scalability-benchmark-{}-{label}",
        std::process::id()
    ))
}

/// A `connect` closure for a benchmark that measures only the CREATOR's
/// (Alice's) own cost of driving `create`/`add`/`send` at scale — not
/// every other member's cost of independently processing every frame
/// addressed to them. Every call returns a FRESH `tokio::io::duplex`
/// pair, immediately spawns a background task draining and discarding
/// the observer side, and hands back the member side — so
/// `delivery.rs`'s fan-out loop never blocks on a full buffer,
/// regardless of how many members exist, without this benchmark having
/// to pre-register one stream per expected connection (impractical at
/// `member_count = 50`, where a single `add_member` call alone can fan
/// out to up to `member_count - 1` recipients).
///
/// This is a deliberately narrower harness than
/// `hermetic_multi_party.rs`'s `addressed_streams`: it proves nothing
/// about what a real member decrypts, by design — this benchmark's
/// subject is the creator's own scaling, not full multi-party
/// correctness (already covered by the 3-party hermetic test).
fn sink_connect() -> impl Fn(&PeerTransportAddress) -> ConnectFuture {
    move |_address: &PeerTransportAddress| {
        Box::pin(async move {
            let (member_side, observer_side) = tokio::io::duplex(8192);
            tokio::spawn(drain(observer_side));
            Ok(Box::new(member_side) as Box<dyn AsyncWrite + Unpin + Send>)
        })
    }
}

/// Reads `stream` to EOF and discards the bytes — the background half
/// of [`sink_connect`]'s draining sink.
async fn drain<S: AsyncRead + Unpin>(mut stream: S) {
    let mut discard = Vec::new();
    let _ = stream.read_to_end(&mut discard).await;
}

/// Every member name in this benchmark resolves to the same placeholder
/// address: `sink_connect`'s connect closure ignores the address
/// entirely (it hands out a fresh sink regardless), so distinct
/// addresses buy nothing here — unlike `hermetic_multi_party.rs`, which
/// needs distinct, stable addresses to route pre-registered streams to
/// the right place.
fn any_member_has_an_address(_name: &str) -> Option<PeerTransportAddress> {
    Some(PeerTransportAddress::Mesh("benchmark-sink".to_string()))
}

/// This process's peak resident-set size since it started, in KiB —
/// Linux's `/proc/self/status` `VmHWM` ("high water mark"), the same
/// source this project's own hardware/sandbox code already reads
/// procfs from elsewhere. Monotonically non-decreasing for the whole
/// process lifetime, so a single read at the end of a benchmark run
/// (one size point per process, since these are `--test-threads=1`
/// `#[ignore]`d integration-test binaries run one at a time) reports
/// this run's peak.
///
/// # Errors
///
/// Returns an error if `/proc/self/status` cannot be read or has no
/// `VmHWM` line (both would indicate a non-Linux host — out of scope
/// for this Linux-only project).
fn peak_rss_kib() -> Result<u64, Box<dyn std::error::Error + Send + Sync>> {
    let status = std::fs::read_to_string("/proc/self/status")?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("VmHWM:") {
            let digits = rest.trim().trim_end_matches(" kB").trim();
            return Ok(digits.parse()?);
        }
    }
    Err("no VmHWM line in /proc/self/status".into())
}

/// One benchmark run's timing/memory report, printed (not asserted
/// against a threshold — see the module docs: this is an information
/// gap, not a code gap, and no baseline exists yet to assert against).
struct Report {
    /// Number of members in the finished group (creator included).
    member_count: usize,
    /// Wall-clock for the single `create_group` call.
    create: Duration,
    /// Wall-clock for all `member_count - 1` `export_keypackage` calls,
    /// summed.
    keypackages_total: Duration,
    /// Wall-clock for all `member_count - 1` `add_member` calls, summed.
    adds_total: Duration,
    /// Wall-clock for the FIRST `add_member` call alone (roster size 0
    /// fanned out to) versus the LAST (roster size `member_count - 2`
    /// fanned out to) — the pair that would show a fan-out-driven
    /// slowdown most clearly, if one exists.
    first_add: Duration,
    /// See [`Self::first_add`].
    last_add: Duration,
    /// Wall-clock for the one `send_group_message` call fanning out to
    /// every other member.
    send: Duration,
    /// This process's peak RSS (KiB) at the end of the run.
    peak_rss_kib: u64,
}

impl std::fmt::Display for Report {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "scalability_benchmark N={}: create={:?} keypackages_total={:?} \
             adds_total={:?} first_add={:?} last_add={:?} send={:?} peak_rss={}KiB",
            self.member_count,
            self.create,
            self.keypackages_total,
            self.adds_total,
            self.first_add,
            self.last_add,
            self.send,
            self.peak_rss_kib
        )
    }
}

/// Builds a `member_count`-member group one `add_member` call at a
/// time (Alice creates, then adds `member_count - 1` members in
/// sequence — the only way OpenMLS's own `add_members` API works: no
/// bulk-add primitive exists), sends one group message, and returns the
/// timing/memory [`Report`]. Every directory created under
/// [`temp_dir`] is removed before returning, success or failure, so a
/// benchmark run never leaks temp state across runs.
async fn run_benchmark(
    member_count: usize,
) -> Result<Report, Box<dyn std::error::Error + Send + Sync>> {
    assert!(member_count >= 2, "need at least a creator and one member");
    let alice_dir = temp_dir(&format!("alice-{member_count}"));
    std::fs::create_dir_all(&alice_dir)?;
    let alice_pw = b"scalability-benchmark-alice-pw";

    let cleanup = |dir: &std::path::Path| {
        let _ = std::fs::remove_dir_all(dir);
    };

    let result: Result<Report, Box<dyn std::error::Error + Send + Sync>> = async {
        let create_started = Instant::now();
        create::create_group(&alice_dir, alice_pw, "cell", "alice")?;
        let create = create_started.elapsed();

        let mut keypackages_total = Duration::ZERO;
        let mut adds_total = Duration::ZERO;
        let mut first_add = Duration::ZERO;
        let mut last_add = Duration::ZERO;
        let mut member_dirs = Vec::with_capacity(member_count.saturating_sub(1));

        for index in 1..member_count {
            let member_name = format!("member{index}");
            let member_dir = temp_dir(&format!("{member_name}-{member_count}"));
            std::fs::create_dir_all(&member_dir)?;
            member_dirs.push(member_dir.clone());
            let member_pw = b"scalability-benchmark-member-pw";

            let kp_started = Instant::now();
            let key_package = keypackage::export_keypackage(&member_dir, member_pw)?;
            keypackages_total = keypackages_total.saturating_add(kp_started.elapsed());

            let add_started = Instant::now();
            add::add_member(
                &alice_dir,
                alice_pw,
                "cell",
                &member_name,
                &key_package,
                any_member_has_an_address,
                sink_connect(),
            )
            .await?;
            let add_elapsed = add_started.elapsed();
            adds_total = adds_total.saturating_add(add_elapsed);
            if index == 1 {
                first_add = add_elapsed;
            }
            last_add = add_elapsed;
        }

        let send_started = Instant::now();
        send::send_group_message(
            &alice_dir,
            alice_pw,
            "cell",
            b"scalability benchmark message",
            any_member_has_an_address,
            sink_connect(),
        )
        .await?;
        let send = send_started.elapsed();

        for dir in &member_dirs {
            cleanup(dir);
        }

        Ok(Report {
            member_count,
            create,
            keypackages_total,
            adds_total,
            first_add,
            last_add,
            send,
            peak_rss_kib: peak_rss_kib()?,
        })
    }
    .await;

    cleanup(&alice_dir);
    result
}

/// N=10: the smaller of the two size points the TODO item names.
#[ignore = "real production Argon2id x ~20 calls, several minutes — see module docs to run explicitly"]
#[tokio::test]
async fn scalability_n10() -> TestResult {
    let report = run_benchmark(10).await?;
    println!("{report}");
    Ok(())
}

/// N=50: the larger of the two size points the TODO item names.
#[ignore = "real production Argon2id x ~100 calls, tens of minutes — see module docs to run explicitly"]
#[tokio::test]
async fn scalability_n50() -> TestResult {
    let report = run_benchmark(50).await?;
    println!("{report}");
    Ok(())
}
