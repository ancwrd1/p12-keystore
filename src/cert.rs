use std::fmt;

use crate::Result;

/// X.509 certificate wrapper
#[derive(Clone, PartialEq, Eq)]
pub struct Certificate {
    pub(crate) data: Vec<u8>,
    pub(crate) subject: String,
    pub(crate) issuer: String,
}

impl Certificate {
    /// Create certificate from DER encoding
    pub fn from_der(der: &[u8]) -> Result<Self> {
        let (_, cert) = x509_parser::parse_x509_certificate(der)?;
        Ok(Self {
            data: der.to_vec(),
            subject: cert.subject.to_string(),
            issuer: cert.issuer.to_string(),
        })
    }

    /// Get certificate subject
    pub fn subject(&self) -> &str {
        &self.subject
    }

    /// Get certificate issuer
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// Get certificate data in DER encoding
    pub fn as_der(&self) -> &[u8] {
        &self.data
    }
}

impl fmt::Debug for Certificate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Certificate")
            .field("data", &"<X.509>")
            .field("subject", &self.subject)
            .field("issuer", &self.issuer)
            .finish()
    }
}
