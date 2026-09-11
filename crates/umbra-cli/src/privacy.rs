//! Per-transport privacy/trust profiles, shown to the operator at
//! runtime (docs/THREAT_MODEL.md, "Per-transport privacy/trust
//! profiles" — the canonical, human-readable source this module's
//! text points to).
//!
//! Every transport Umbra can send or serve over carries a static
//! [`Profile`]: three dimensions (anonymity/metadata protection,
//! content confidentiality, network maturity), each rated on a closed
//! four-step [`Level`] scale, plus operator guidance and a doc
//! reference. There is deliberately NO single numeric score — a
//! collapsed number would hide exactly the per-dimension nuances the
//! threat model exists to document, and a user who "just sees 8/10"
//! cannot make the informed transport decision this module exists to
//! enable.
//!
//! The notice is ALWAYS ON and has no opt-out flag: it is a safety
//! notice printed on stderr (the diagnostics channel — stdout stays
//! the requested-data/NDJSON channel per the Rule of Silence, so
//! scripting contracts are untouched), and suppressibility would
//! defeat the "the user is always informed" requirement.
//!
//! Adding a profile for a future transport (checklist — I2P
//! (TODO B.1.1) and Veilid (TODO B.1.2) will each need one):
//! 1. add a [`TransportKind`] variant and its [`Profile`] in
//!    [`profile`], with levels reviewed against
//!    docs/THREAT_MODEL.md's honest-scope notes;
//! 2. add the matching row to THREAT_MODEL.md's profiles table
//!    (the runtime text and the document must never drift apart);
//! 3. wire a [`print_notice`] call into the transport's send AND
//!    serve entry points, BEFORE `harden_process`/sandbox install.

/// One dimension of a transport's privacy posture, rated on a closed
/// four-step scale.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    /// Best-in-class for this dimension (e.g. Tor's relay network).
    Strong,
    /// Real protection with documented reservations.
    Moderate,
    /// Weak or experimental; the operator must understand the caveat.
    Limited,
    /// No protection in this dimension at all (e.g. mesh anonymity).
    None,
}

impl Level {
    /// The uppercase label used in notices and documents.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Strong => "STRONG",
            Self::Moderate => "MODERATE",
            Self::Limited => "LIMITED",
            Self::None => "NONE",
        }
    }
}

/// The transports Umbra can send or serve over today.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportKind {
    /// Tor onion services via embedded Arti (`send --onion`, `serve`,
    /// `tui`).
    Tor,
    /// Wi-Fi Direct off-grid mesh (`send --mesh`, `serve-mesh`).
    Mesh,
    /// Nym mixnet, Sandbox testnet (`umbra-nym` default).
    NymSandbox,
    /// Nym mixnet, production mainnet (`umbra-nym --mainnet`).
    NymMainnet,
    /// PQ-MLS group ("cell") traffic (`umbra group …`) — delivery is
    /// Tor-only today, so anonymity/maturity inherit the Tor profile
    /// while content carries the partial-PQ caveat (ADR-033).
    Group,
}

/// A transport's static privacy/trust profile. All text is static —
/// profiles change only with a code change, by design (a rating that
/// could be edited at runtime would not be a rating the operator can
/// trust).
#[derive(Debug, Clone, Copy)]
pub struct Profile {
    /// Which transport this profile describes.
    pub kind: TransportKind,
    /// Display name of the transport/mode (e.g. "Nym mixnet (Sandbox
    /// TESTNET)").
    pub name: &'static str,
    /// Anonymity/metadata protection: who can learn THAT you
    /// communicate, and with whom.
    pub anonymity: Level,
    /// One honest clause backing the anonymity rating.
    pub anonymity_note: &'static str,
    /// Content confidentiality: cryptographic strength of the payload
    /// layer.
    pub content: Level,
    /// One honest clause backing the content rating.
    pub content_note: &'static str,
    /// Maturity: battle-testing and review history of the underlying
    /// network.
    pub maturity: Level,
    /// One honest clause backing the maturity rating.
    pub maturity_note: &'static str,
    /// One line of operator guidance (when to use, when NOT to use).
    pub guidance: &'static str,
    /// Where the full, canonical write-up lives.
    pub doc_ref: &'static str,
}

/// The canonical doc reference every profile's notice points at.
const PROFILES_DOC: &str = "docs/THREAT_MODEL.md \"Per-transport privacy/trust profiles\"";

/// Returns the static [`Profile`] for `kind`.
pub fn profile(kind: TransportKind) -> Profile {
    match kind {
        TransportKind::Tor => Profile {
            kind,
            name: "Tor onion service",
            anonymity: Level::Strong,
            anonymity_note: "both endpoints hidden behind v3 onion services \
                             on a decade-plus relay network",
            content: Level::Strong,
            content_note: "PQXDH hybrid (X25519 + ML-KEM-768) with ML-DSA identity",
            maturity: Level::Strong,
            maturity_note: "the most deployed and reviewed anonymity network in existence",
            guidance: "Tor's own circuits are classical cryptography — metadata \
                       protection rests on Tor; Umbra's post-quantum layer covers \
                       message CONTENT, not Tor's transport",
            doc_ref: PROFILES_DOC,
        },
        TransportKind::Mesh => Profile {
            kind,
            name: "Wi-Fi Direct mesh (off-grid)",
            anonymity: Level::None,
            anonymity_note: "NO onion routing — anyone in radio range can observe \
                             the P2P device address and that two Umbra devices \
                             are communicating",
            content: Level::Strong,
            content_note: "PQXDH hybrid (X25519 + ML-KEM-768) with ML-DSA identity",
            maturity: Level::Limited,
            maturity_note: "single-hop only; live-hardware interop not yet verified",
            guidance: "an off-grid AVAILABILITY trade for a total infrastructure \
                       blackout, not a privacy transport — use only when the \
                       absence of infrastructure outweighs total metadata exposure",
            doc_ref: PROFILES_DOC,
        },
        TransportKind::NymSandbox => Profile {
            kind,
            name: "Nym mixnet (Sandbox TESTNET)",
            anonymity: Level::Limited,
            anonymity_note: "the mixnet model is strong on paper (cover traffic, \
                             Poisson delay) but the Sandbox testnet's anonymity \
                             set is small, young, and third-party-operated",
            content: Level::Strong,
            content_note: "PQXDH hybrid (X25519 + ML-KEM-768) with ML-DSA identity",
            maturity: Level::Limited,
            maturity_note: "experimental purpose-built test network — the only \
                            environment this project has verified against",
            guidance: "this is NOT the production network — pass --mainnet for \
                       Nym mainnet (itself unverified by this project)",
            doc_ref: PROFILES_DOC,
        },
        TransportKind::NymMainnet => Profile {
            kind,
            name: "Nym mixnet (mainnet)",
            anonymity: Level::Moderate,
            anonymity_note: "a real mixnet, but with a smaller and younger \
                             anonymity set than Tor's decade-plus relay set",
            content: Level::Strong,
            content_note: "PQXDH hybrid (X25519 + ML-KEM-768) with ML-DSA identity",
            maturity: Level::Moderate,
            maturity_note: "production network, but its behavior is unverified \
                            by this project",
            guidance: "mainnet operation (real anonymity set, real \
                       bandwidth-credential acquisition) is unverified by this \
                       project — verify it meets your threat model yourself",
            doc_ref: PROFILES_DOC,
        },
        TransportKind::Group => Profile {
            kind,
            name: "PQ-MLS group cell (over Tor)",
            anonymity: Level::Strong,
            anonymity_note: "inherited from the Tor transport — each fan-out \
                             delivery is an ordinary two-party onion-service stream",
            content: Level::Moderate,
            content_note: "hybrid X-Wing KEM (X25519 + ML-KEM-768) protects \
                           content, but leaf/message signatures remain CLASSICAL \
                           Ed25519 — no PQ signature ciphersuite exists in \
                           OpenMLS yet (ADR-033)",
            maturity: Level::Limited,
            maturity_note: "single-cell increment validated at 3-party scale \
                            only; member removal and manual key rotation landed \
                            (TODO B.2.2/B.2.3) but there is NO ACL — every \
                            member is co-equal",
            guidance: "roster bootstrapping for Welcome-joined members landed \
                       (TODO B.2.1 RosterSync) — group frames are Tor-only",
            doc_ref: PROFILES_DOC,
        },
    }
}

/// Renders the full multi-line operator notice for `profile`, each
/// line prefixed with `{binary}:` (matching the `umbra: {err}` /
/// `umbra-nym: {err}` diagnostics convention). The caller prints it on
/// stderr.
pub fn render_notice(profile: &Profile, binary: &str) -> String {
    format!(
        "{binary}: privacy profile — {name}\n\
         {binary}:   anonymity: {anon} ({anon_note})\n\
         {binary}:   content:   {content} ({content_note})\n\
         {binary}:   maturity:  {maturity} ({maturity_note})\n\
         {binary}:   guidance: {guidance} · details: {doc_ref}",
        name = profile.name,
        anon = profile.anonymity.label(),
        anon_note = profile.anonymity_note,
        content = profile.content.label(),
        content_note = profile.content_note,
        maturity = profile.maturity.label(),
        maturity_note = profile.maturity_note,
        guidance = profile.guidance,
        doc_ref = profile.doc_ref,
    )
}

/// Prints [`render_notice`] on stderr — the diagnostics channel, so
/// the stdout data/NDJSON contract is untouched (Rule of Silence).
/// Call BEFORE `harden_process`/sandbox install at every send/serve
/// entry point.
pub fn print_notice(profile: &Profile, binary: &str) {
    eprintln!("{}", render_notice(profile, binary));
}

/// Renders the one-line summary for persistent display (the TUI
/// footer), where the full notice is too tall.
pub fn render_brief(profile: &Profile) -> String {
    format!(
        "privacy — {name}: anonymity {anon} · content {content} · maturity {maturity} \
         (docs/THREAT_MODEL.md)",
        name = profile.name,
        anon = profile.anonymity.label(),
        content = profile.content.label(),
        maturity = profile.maturity.label(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL_KINDS: [TransportKind; 5] = [
        TransportKind::Tor,
        TransportKind::Mesh,
        TransportKind::NymSandbox,
        TransportKind::NymMainnet,
        TransportKind::Group,
    ];

    #[test]
    fn every_transport_has_a_complete_profile() {
        for kind in ALL_KINDS {
            let profile = profile(kind);
            assert_eq!(profile.kind, kind);
            assert!(!profile.name.is_empty());
            assert!(!profile.anonymity_note.is_empty());
            assert!(!profile.content_note.is_empty());
            assert!(!profile.maturity_note.is_empty());
            assert!(!profile.guidance.is_empty());
            assert!(profile.doc_ref.contains("THREAT_MODEL"));
        }
    }

    #[test]
    fn mesh_anonymity_is_honestly_none() {
        // The load-bearing honesty property of this module: the mesh
        // profile must never claim metadata protection it does not
        // have (THREAT_MODEL "Mesh-mode honest scope").
        assert_eq!(profile(TransportKind::Mesh).anonymity, Level::None);
    }

    #[test]
    fn nym_sandbox_is_rated_below_mainnet() {
        // The testnet must never look as safe as the production
        // network (THREAT_MODEL "Nym-mode honest scope").
        assert_eq!(profile(TransportKind::NymSandbox).anonymity, Level::Limited);
        assert_eq!(
            profile(TransportKind::NymMainnet).anonymity,
            Level::Moderate
        );
    }

    #[test]
    fn levels_render_uppercase() {
        assert_eq!(Level::Strong.label(), "STRONG");
        assert_eq!(Level::Moderate.label(), "MODERATE");
        assert_eq!(Level::Limited.label(), "LIMITED");
        assert_eq!(Level::None.label(), "NONE");
    }

    #[test]
    fn notice_contains_all_dimensions_guidance_and_doc_ref() {
        let notice = render_notice(&profile(TransportKind::NymSandbox), "umbra-nym");
        assert!(notice.contains("umbra-nym: privacy profile — Nym mixnet (Sandbox TESTNET)"));
        assert!(notice.contains("anonymity: LIMITED"));
        assert!(notice.contains("content:   STRONG"));
        assert!(notice.contains("maturity:  LIMITED"));
        assert!(notice.contains("guidance:"));
        assert!(notice.contains("--mainnet"));
        assert!(notice.contains("docs/THREAT_MODEL.md"));
    }

    #[test]
    fn brief_is_a_single_line_with_all_levels() {
        let brief = render_brief(&profile(TransportKind::Tor));
        assert!(!brief.contains('\n'));
        assert!(brief.contains("Tor onion service"));
        assert!(brief.contains("anonymity STRONG"));
        assert!(brief.contains("content STRONG"));
        assert!(brief.contains("maturity STRONG"));
    }

    #[test]
    fn group_content_rating_carries_the_partial_pq_caveat() {
        // The group profile must never claim full post-quantum content
        // protection: signatures remain classical Ed25519 (ADR-033,
        // THREAT_MODEL "Group-mode honest scope"). The no-ACL co-equal
        // trust model must stay visible too.
        let group = profile(TransportKind::Group);
        assert_eq!(group.content, Level::Moderate);
        assert!(group.content_note.contains("Ed25519"));
        assert!(group.maturity_note.contains("NO ACL"));
    }
}
