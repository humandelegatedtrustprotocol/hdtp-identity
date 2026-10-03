//! `hdtp`: the HDTP 1.0 command line. One native binary, two halves — the implementer's tools
//! (cards, chains, certificates, requests, vectors, an intrusion run) and the wallet a person or a
//! script drives (a root in a vault, leaves issued under SPEC §9's rules, the ledger, the contact
//! book). Every rule is the core's; this binary is the terminal.
mod implementer;
mod io;
mod piv;
mod vectors;
mod wallet;

use clap::{Args, Parser, Subcommand};
use io::Res;

#[derive(Parser)]
#[command(name = "hdtp", version, about = "HDTP 1.0: certificates, cards, envelopes and the wallet, from the terminal", long_about = None)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// A contact card: read it as a receiver would
    Card {
        #[command(subcommand)]
        cmd: CardCmd,
    },
    /// A chain of leaf and root: validate it (SPEC §14.2)
    Chain {
        #[command(subcommand)]
        cmd: ChainCmd,
    },
    /// One certificate: what it says and whether it is in the profile (§14.1)
    Cert {
        #[command(subcommand)]
        cmd: CertCmd,
    },
    /// Certificate signing requests: a host makes one, a wallet checks one (§9)
    Csr {
        #[command(subcommand)]
        cmd: CsrCmd,
    },
    /// Leaf keys for a host
    Key {
        #[command(subcommand)]
        cmd: KeyCmd,
    },
    /// Appendix B: regenerate, prove, and aim the intrusion scenarios at a live endpoint
    Vectors {
        #[command(subcommand)]
        cmd: VectorsCmd,
    },
    /// The wallet: an identity is a root in a vault, and this is where leaves come from
    Id {
        #[command(subcommand)]
        cmd: IdCmd,
    },
    /// The wallet's contact book, which outlives any host
    Contacts {
        #[command(subcommand)]
        cmd: ContactsCmd,
    },
    /// A smartcard holding a root: the reader, the card, the slot, the key, and whose identity it is
    CardStatus {
        /// Check the key against the roots in this vault
        #[arg(long)]
        vault: Option<String>,
        /// Which PIV key slot (9a, 9c, 9d, 9e, or a retired 82-95)
        #[arg(long, default_value = piv::DEFAULT_SLOT)]
        slot: String,
        /// Which reader, when this machine has more than one
        #[arg(long)]
        reader: Option<String>,
    },
    /// Hand an identity already in a vault over to the card that now holds a copy of its key
    CardAttach {
        /// The vault holding the identity whose key the card now has a copy of
        #[arg(long)]
        vault: String,
        /// Which PIV key slot the copy went into
        #[arg(long, default_value = piv::DEFAULT_SLOT)]
        slot: String,
        /// Which reader, when this machine has more than one
        #[arg(long)]
        reader: Option<String>,
        /// Which root, when the vault holds several
        #[arg(long)]
        root: Option<String>,
    },
}

#[derive(Subcommand)]
enum CardCmd {
    /// Decode a card: name, root, endpoint, validity, seal, what was ignored
    Show {
        /// A vCard file, or - for stdin
        file: String,
        #[arg(long)]
        now: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// The intake verdict (§3): accepted, or refused with the reason; exit 1 on refusal
    Check {
        file: String,
        #[arg(long)]
        now: Option<String>,
    },
}

#[derive(Subcommand)]
enum ChainCmd {
    /// Validate a chain; exit 1 with the rule and the reason on refusal
    Check {
        /// The leaf certificate (DER or PEM)
        #[arg(long)]
        leaf: Option<String>,
        /// The root certificate (DER or PEM)
        #[arg(long)]
        root: Option<String>,
        /// A PEM bundle, leaf first, instead of --leaf and --root
        #[arg(long, conflicts_with_all = ["leaf", "root"])]
        chain: Option<String>,
        /// The root fingerprint the verifier already holds
        #[arg(long)]
        expect_root: Option<String>,
        /// The address in question: dialed, pinned, or on the card
        #[arg(long)]
        expect_endpoint: Option<String>,
        /// The verifier's clock, RFC 3339; the system clock otherwise
        #[arg(long)]
        now: Option<String>,
    },
}

#[derive(Subcommand)]
enum CertCmd {
    /// Parse a certificate and report the profile verdict
    Show {
        file: String,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
enum CsrCmd {
    /// A host's request for a leaf: its key, its endpoint, proof of possession
    New {
        /// The host's leaf key (PKCS #8 DER or PEM)
        #[arg(long)]
        key: String,
        /// The endpoint the leaf will name, an https URL in normal form
        #[arg(long)]
        endpoint: String,
        /// The subject name; the endpoint's host when absent
        #[arg(long)]
        cn: Option<String>,
        /// Add the endpoint's host as a dNSName beside the URI
        #[arg(long)]
        dns: bool,
        /// Write the PEM here instead of stdout
        #[arg(long)]
        out: Option<String>,
    },
    /// What a wallet checks before signing: the profile, the proof of possession, the root-key refusal
    Check {
        file: String,
        /// A root's public key or certificate; a request carrying that key is refused
        #[arg(long = "root-spki")]
        root_spki: Vec<String>,
    },
}

#[derive(Subcommand)]
enum KeyCmd {
    /// A fresh leaf key, written owner-only; prints its fingerprint
    New {
        #[arg(long, default_value = "ed25519", value_parser = ["ed25519", "p256"])]
        alg: String,
        #[arg(long)]
        out: String,
        /// Replace the key already at that path. The leaf issued to it stops working.
        #[arg(long)]
        force: bool,
    },
}

#[derive(Subcommand)]
enum VectorsCmd {
    /// Regenerate the vectors from their labelled seeds
    Gen {
        #[arg(long)]
        out: Option<String>,
    },
    /// Prove the vectors: from the Appendix B of a specification (a version directory of hdtp-spec's
    /// docs/specification, or one document), or from a vector file
    Check {
        #[arg(long, conflicts_with = "file")]
        spec: Option<String>,
        #[arg(long)]
        file: Option<String>,
    },
    /// Write the export corpus (go/exportcorpus) for another owner root: every file keeps its one
    /// defect and cases.json its refusal, so a host that holds that root can reach every check
    Corpus {
        /// The owner's root fingerprint, sha256:<43 base64url>: an identity the host under test holds
        #[arg(long)]
        owner: String,
        /// The directory to write cases.json and the zips into (created if missing; nothing in it is
        /// written over)
        #[arg(long)]
        out: String,
    },
    /// Aim the black-box intrusion scenarios at a live endpoint and judge by the answers
    Intrude {
        /// The endpoint, https://host/slug
        #[arg(long)]
        against: String,
        /// The target's card, from a file. Needed for a host that serves no card at a URL of its
        /// own: SPEC §9 puts the card on the invite landing page, so `<endpoint>/card.vcf` is one
        /// deployment's convenience and not something a target must offer.
        #[arg(long)]
        card: Option<String>,
        /// A node on your own machine, and nothing else: the address guard stands aside, and so does
        /// WebPKI, because a node in direct mode serves TLS under its own chain
        #[arg(long)]
        allow_insecure: bool,
        #[arg(long)]
        now: Option<String>,
    },
}

#[derive(Args)]
struct IssueCommon {
    /// The vault holding the root
    #[arg(long)]
    vault: String,
    /// The host's request (PEM or DER)
    #[arg(long)]
    csr: String,
    /// How long the leaf lives: 1y, 90d, 6w (at most 398 days)
    #[arg(long, default_value = "1y")]
    valid: String,
    /// The origin of the page or host that asked, shown beside the endpoint
    #[arg(long)]
    origin: Option<String>,
    /// Which root, when the vault holds several
    #[arg(long)]
    root: Option<String>,
    /// Sign without asking (scripts and the harness)
    #[arg(long)]
    yes: bool,
    /// Which reader, when the root is held on a card and this machine has more than one
    #[arg(long)]
    reader: Option<String>,
    /// Write the leaf PEM here instead of stdout
    #[arg(long)]
    out: Option<String>,
    /// Also write leaf and root as one PEM bundle here
    #[arg(long)]
    chain_out: Option<String>,
    /// The wallet's clock, RFC 3339; the system clock otherwise
    #[arg(long)]
    now: Option<String>,
}

#[derive(Subcommand)]
enum IdCmd {
    /// A new identity: a root in a new vault, and its record beside it, under a passphrase asked twice
    Create {
        /// The name contacts see; it carries no authority (SPEC §3)
        #[arg(long)]
        name: String,
        /// The root's algorithm, when the root is made here
        #[arg(long, default_value = "ed25519", value_parser = ["ed25519", "p256"])]
        alg: String,
        /// Where the vault goes; it must not exist, and neither may its record (<name>.hdtp-record.json)
        #[arg(long)]
        vault: String,
        /// Hold the root on a smartcard in this PIV slot (9c by default) instead of in the vault.
        /// The slot must already hold a P-256 key and a certificate; the key never leaves the card,
        /// the vault keeps only the certificate, and there is no export — lose the
        /// card and the identity is gone.
        #[arg(long, num_args = 0..=1, default_missing_value = piv::DEFAULT_SLOT)]
        piv: Option<String>,
        /// Which reader, when this machine has more than one
        #[arg(long)]
        reader: Option<String>,
        /// Make the root here and write its key to this file, to be imported into a card with
        /// `ykman piv keys import`. Weaker than --piv, because the key existed in software for as
        /// long as that file does — and the vault keeps it, so a lost card is not a lost identity.
        #[arg(long, conflicts_with = "piv")]
        key_out: Option<String>,
    },
    /// Issue a leaf for a request, after showing what it names and asking
    Issue {
        #[command(flatten)]
        common: IssueCommon,
        /// A second endpoint while a leaf is live is a move, not a second home; say so
        #[arg(long = "move")]
        moving: bool,
    },
    /// Renew: a leaf for an endpoint already in the ledger, with a fresh key
    Renew {
        #[command(flatten)]
        common: IssueCommon,
    },
    /// Every leaf this identity issued, read from the record beside its vault
    Ledger {
        #[arg(long)]
        vault: String,
        #[arg(long)]
        root: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// The root certificate (public), as PEM
    Show {
        #[arg(long)]
        vault: String,
        #[arg(long)]
        root: Option<String>,
        #[arg(long)]
        out: Option<String>,
    },
    /// A copy of the vault and of its record, each proven to open
    Backup {
        #[arg(long)]
        vault: String,
        #[arg(long)]
        to: String,
        /// Write over an existing file at --to
        #[arg(long)]
        force: bool,
    },
    /// Bring a copy back — the vault, and its record when the copy has one — to a path that is empty
    Restore {
        #[arg(long)]
        from: String,
        #[arg(long)]
        vault: String,
    },
}

#[derive(Subcommand)]
enum ContactsCmd {
    /// The contact book as a book (SPEC §9.2): an unencrypted zip of manifest.json and contacts.csv
    Export {
        #[arg(long)]
        vault: String,
        /// The book to write: a new file, never written over
        #[arg(long)]
        out: String,
    },
    /// Replace the wallet's book with an export's or a book's contacts, showing every difference
    /// first; the whole file is checked, messages and files included
    Import {
        #[arg(long)]
        vault: String,
        file: String,
        #[arg(long)]
        yes: bool,
    },
}

fn run(cli: Cli) -> Res<i32> {
    match cli.cmd {
        Cmd::Card { cmd } => match cmd {
            CardCmd::Show { file, now, json } => implementer::card_show(&file, now.as_deref(), json),
            CardCmd::Check { file, now } => implementer::card_check(&file, now.as_deref()),
        },
        Cmd::Chain { cmd } => match cmd {
            ChainCmd::Check { leaf, root, chain, expect_root, expect_endpoint, now } => implementer::chain_check(
                leaf.as_deref(),
                root.as_deref(),
                chain.as_deref(),
                expect_root.as_deref(),
                expect_endpoint.as_deref(),
                now.as_deref(),
            ),
        },
        Cmd::Cert { cmd } => match cmd {
            CertCmd::Show { file, json } => implementer::cert_show(&file, json),
        },
        Cmd::Csr { cmd } => match cmd {
            CsrCmd::New { key, endpoint, cn, dns, out } => implementer::csr_new(&key, &endpoint, cn.as_deref(), dns, out.as_deref()),
            CsrCmd::Check { file, root_spki } => implementer::csr_check(&file, &root_spki),
        },
        Cmd::Key { cmd } => match cmd {
            KeyCmd::New { alg, out, force } => implementer::key_new(&alg, &out, force),
        },
        Cmd::Vectors { cmd } => match cmd {
            VectorsCmd::Gen { out } => vectors::gen(out.as_deref()),
            VectorsCmd::Check { spec, file } => vectors::check(spec.as_deref(), file.as_deref()),
            VectorsCmd::Corpus { owner, out } => vectors::corpus(&owner, &out),
            VectorsCmd::Intrude { against, card, allow_insecure, now } => {
                vectors::intrude(&against, card.as_deref(), allow_insecure, now.as_deref())
            }
        },
        Cmd::Id { cmd } => match cmd {
            IdCmd::Create { name, alg, vault, piv, reader, key_out } => match piv {
                Some(slot) => wallet::id_create_piv(&name, &slot, reader.as_deref(), &vault),
                None => wallet::id_create(&name, &alg, &vault, key_out.as_deref()),
            },
            IdCmd::Issue { common: c, moving } => wallet::id_issue(wallet::IssueArgs {
                vault: &c.vault,
                csr: &c.csr,
                valid_days: io::parse_valid(&c.valid)?,
                moving,
                renew_only: false,
                origin: c.origin.as_deref(),
                root: c.root.as_deref(),
                yes: c.yes,
                out: c.out.as_deref(),
                chain_out: c.chain_out.as_deref(),
                now: c.now.as_deref(),
                reader: c.reader.as_deref(),
            }),
            IdCmd::Renew { common: c } => wallet::id_issue(wallet::IssueArgs {
                vault: &c.vault,
                csr: &c.csr,
                valid_days: io::parse_valid(&c.valid)?,
                moving: false,
                renew_only: true,
                origin: c.origin.as_deref(),
                root: c.root.as_deref(),
                yes: c.yes,
                out: c.out.as_deref(),
                chain_out: c.chain_out.as_deref(),
                now: c.now.as_deref(),
                reader: c.reader.as_deref(),
            }),
            IdCmd::Ledger { vault, root, json } => wallet::id_ledger(&vault, root.as_deref(), json),
            IdCmd::Show { vault, root, out } => wallet::id_show(&vault, root.as_deref(), out.as_deref()),
            IdCmd::Backup { vault, to, force } => wallet::id_backup(&vault, &to, force),
            IdCmd::Restore { from, vault } => wallet::id_restore(&from, &vault),
        },
        Cmd::Contacts { cmd } => match cmd {
            ContactsCmd::Export { vault, out } => wallet::contacts_export(&vault, &out),
            ContactsCmd::Import { vault, file, yes } => wallet::contacts_import(&vault, &file, yes),
        },
        Cmd::CardStatus { vault, slot, reader } => wallet::card_status(vault.as_deref(), &slot, reader.as_deref()),
        Cmd::CardAttach { vault, slot, reader, root } => wallet::card_attach(&vault, &slot, reader.as_deref(), root.as_deref()),
    }
}

fn main() {
    let cli = Cli::parse();
    match run(cli) {
        Ok(code) => std::process::exit(code),
        Err(e) => {
            eprintln!("hdtp: {}", e.0);
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn the_command_tree_is_well_formed() {
        Cli::command().debug_assert();
    }

    #[test]
    fn arguments_parse_as_documented() {
        let cli = Cli::try_parse_from(["hdtp", "id", "issue", "--vault", "v.json", "--csr", "r.pem", "--valid", "90d", "--move", "--yes"])
            .unwrap();
        match cli.cmd {
            Cmd::Id { cmd: IdCmd::Issue { common, moving } } => {
                assert!(moving && common.yes);
                assert_eq!(common.valid, "90d");
            }
            _ => panic!("issue"),
        }
        // There is no way to hand a passphrase on the command line, and renew has no --move.
        assert!(Cli::try_parse_from(["hdtp", "id", "create", "--name", "x", "--vault", "v", "--passphrase", "p"]).is_err());
        assert!(Cli::try_parse_from(["hdtp", "id", "renew", "--vault", "v", "--csr", "r", "--move"]).is_err());
        assert!(Cli::try_parse_from(["hdtp", "id", "export"]).is_err());
        assert!(Cli::try_parse_from(["hdtp", "chain", "check", "--chain", "b.pem", "--leaf", "l"]).is_err());
    }

    /// Every `hdtp …` this binary prints or documents is a command this binary has.
    ///
    /// A command named in a message is advice a person types next, and advice that does not run is
    /// worse than none: it teaches a wrong name at the moment someone is stuck. Two had drifted —
    /// the card commands were written as subcommands of `card`, which has only show and check,
    /// where clap spells them `card-attach` and `card-status` — because nothing connected the
    /// strings to the tree. This does.
    #[test]
    fn every_command_this_binary_names_is_one_it_has() {
        let root = Cli::command();
        let top: Vec<String> = root.get_subcommands().map(|c| c.get_name().to_string()).collect();
        let sources = [
            ("main.rs", include_str!("main.rs")),
            ("wallet.rs", include_str!("wallet.rs")),
            ("wallet/files.rs", include_str!("wallet/files.rs")),
            ("wallet/card.rs", include_str!("wallet/card.rs")),
            ("wallet/id.rs", include_str!("wallet/id.rs")),
            ("wallet/contacts.rs", include_str!("wallet/contacts.rs")),
            ("wallet/exportzip.rs", include_str!("wallet/exportzip.rs")),
            ("piv.rs", include_str!("piv.rs")),
            ("io.rs", include_str!("io.rs")),
            ("vectors.rs", include_str!("vectors.rs")),
            ("vectors/check.rs", include_str!("vectors/check.rs")),
            ("vectors/corpus.rs", include_str!("vectors/corpus.rs")),
            ("vectors/intrude.rs", include_str!("vectors/intrude.rs")),
            ("implementer.rs", include_str!("implementer.rs")),
            ("README.md", include_str!("../README.md")),
        ];
        let mut checked = 0;
        for (where_, text) in sources {
            for (line_no, line) in text.lines().enumerate() {
                for (first, second) in mentions(line) {
                    // Only a line that names a real top-level command is read as advice; prose that
                    // happens to say "hdtp binary" is prose.
                    if !top.contains(&first) {
                        continue;
                    }
                    checked += 1;
                    let cmd = root.get_subcommands().find(|c| c.get_name() == first).expect("the command");
                    let subs: Vec<&str> = cmd.get_subcommands().map(|c| c.get_name()).collect();
                    let Some(second) = second else { continue };
                    if subs.is_empty() || second.starts_with('-') {
                        continue;
                    }
                    assert!(
                        subs.contains(&second.as_str()),
                        "{where_}:{}: `hdtp {first} {second}` is not a command; `hdtp {first}` has {subs:?}\n  {}",
                        line_no + 1,
                        line.trim()
                    );
                }
            }
        }
        assert!(checked > 5, "the scan found only {checked} command mentions, so it has stopped reading them");

        // The list above is written by hand, so a new source file would go unscanned without this:
        // every .rs file under src/ must be on it.
        fn walk(dir: &std::path::Path, base: &std::path::Path, out: &mut Vec<String>) {
            for entry in std::fs::read_dir(dir).expect("read src") {
                let path = entry.expect("entry").path();
                if path.is_dir() {
                    walk(&path, base, out);
                } else if path.extension().is_some_and(|e| e == "rs") {
                    out.push(path.strip_prefix(base).expect("under src").to_string_lossy().replace('\\', "/"));
                }
            }
        }
        let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut on_disk = Vec::new();
        walk(&src, &src, &mut on_disk);
        let listed: Vec<&str> = sources.iter().map(|(name, _)| *name).collect();
        let unlisted: Vec<&String> = on_disk.iter().filter(|f| !listed.contains(&f.as_str())).collect();
        assert!(unlisted.is_empty(), "source files the command scan does not read: {unlisted:?}");
    }

    /// `hdtp <word> [<word>]` where the mention is advice: inside backticks, or the indented line of
    /// a printed hint, or a shell block. Anything looser reads prose as commands.
    fn mentions(line: &str) -> Vec<(String, Option<String>)> {
        let mut out = Vec::new();
        for (i, _) in line.match_indices("hdtp ") {
            let before = line[..i].chars().next_back();
            let advice =
                matches!(before, Some('`') | Some(' ') | Some('(') | None) && !line[..i].ends_with("the ") && !line[..i].ends_with("this ");
            if !advice {
                continue;
            }
            let mut words = line[i + "hdtp ".len()..].split_whitespace();
            let word =
                |w: Option<&str>| w.map(|w| w.trim_end_matches(['`', ',', '.', ';', ')', '"', '\'']).to_string()).filter(|w| !w.is_empty());
            if let Some(first) = word(words.next()) {
                out.push((first, word(words.next())));
            }
        }
        out
    }
}
