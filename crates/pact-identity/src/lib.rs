//! PACT 2.0 identity core: the certificate profile and chain validation of SPEC §14, the sealed
//! envelopes of §13 in both forms, the card codec of §3, PKCS #10 requests and issuance per §9,
//! the receiving rules as one pure decision, and the vault. Stateless; the host applies what it
//! returns. `pact-protocol/vectors/lib` is the specification of every byte here.

pub mod util;
pub mod time;
pub mod der;
pub mod keys;
pub mod canonical;
pub mod hpke;
pub mod x509;
pub mod address;
pub mod csr;
pub mod card;
pub mod envelope;
pub mod vault;
pub mod api;

pub use api::call;
pub use util::{Error, Result};
