//! Decoy credentials: the right formats, fresh random values, worth nothing.
//!
//! Nothing marks a decoy as fake: a marker would let malware skip it. cirven
//! recognises its own decoys by the hash recorded when they were planted.

use std::fs::File;
use std::io::Read;

use base64::Engine as _;

pub struct Decoy {
    /// Relative to the home directory.
    pub path: &'static str,
    pub what: &'static str,
    pub make: fn(&mut Random) -> Vec<u8>,
}

pub const DECOYS: &[Decoy] = &[
    Decoy {
        path: ".aws/credentials.bak",
        what: "aws access key pair",
        make: aws,
    },
    Decoy {
        path: ".ssh/id_ed25519_old",
        what: "ssh private key",
        make: ssh_key,
    },
    Decoy {
        path: "backup/.env.production",
        what: "production database url and api keys",
        make: env_file,
    },
    Decoy {
        path: ".config/solana/id-backup.json",
        what: "crypto wallet keypair",
        make: wallet,
    },
    Decoy {
        path: ".config/chromium-backup/Default/Login Data",
        what: "browser password store",
        make: login_data,
    },
];

/// Bytes from the kernel's CSPRNG.
pub struct Random(File);

impl Random {
    pub fn new() -> std::io::Result<Random> {
        File::open("/dev/urandom").map(Random)
    }

    pub fn bytes(&mut self, n: usize) -> Vec<u8> {
        let mut buf = vec![0; n];
        self.0
            .read_exact(&mut buf)
            .expect("/dev/urandom is readable");
        buf
    }

    /// `n` characters drawn uniformly from `alphabet` (rejection sampling).
    pub fn text(&mut self, n: usize, alphabet: &[u8]) -> String {
        let limit = 256 - 256 % alphabet.len();
        let mut out = String::with_capacity(n);
        while out.len() < n {
            for b in self.bytes(n) {
                if (b as usize) < limit && out.len() < n {
                    out.push(alphabet[b as usize % alphabet.len()] as char);
                }
            }
        }
        out
    }
}

const UPPER_DIGITS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const ALNUM: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
const B64ISH: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789/+";

fn aws(r: &mut Random) -> Vec<u8> {
    format!(
        "[default]\naws_access_key_id = AKIA{}\naws_secret_access_key = {}\nregion = eu-central-1\n",
        r.text(16, UPPER_DIGITS),
        r.text(40, B64ISH)
    )
    .into_bytes()
}

fn ssh_string(out: &mut Vec<u8>, data: &[u8]) {
    out.extend((data.len() as u32).to_be_bytes());
    out.extend(data);
}

/// A passphrase-protected OpenSSH ed25519 key: correct structure, random body.
/// Protected so that cirven audit does not report it as a weak real key.
fn ssh_key(r: &mut Random) -> Vec<u8> {
    let mut kdf = Vec::new();
    ssh_string(&mut kdf, &r.bytes(16));
    kdf.extend(24u32.to_be_bytes());
    let mut public = Vec::new();
    ssh_string(&mut public, b"ssh-ed25519");
    ssh_string(&mut public, &r.bytes(32));

    let mut raw = b"openssh-key-v1\0".to_vec();
    ssh_string(&mut raw, b"aes256-ctr");
    ssh_string(&mut raw, b"bcrypt");
    ssh_string(&mut raw, &kdf);
    raw.extend(1u32.to_be_bytes());
    ssh_string(&mut raw, &public);
    ssh_string(&mut raw, &r.bytes(144));

    let b64 = base64::engine::general_purpose::STANDARD.encode(raw);
    let mut pem = String::from("-----BEGIN OPENSSH PRIVATE KEY-----\n");
    for chunk in b64.as_bytes().chunks(70) {
        pem.push_str(std::str::from_utf8(chunk).expect("base64 is ascii"));
        pem.push('\n');
    }
    pem.push_str("-----END OPENSSH PRIVATE KEY-----\n");
    pem.into_bytes()
}

fn env_file(r: &mut Random) -> Vec<u8> {
    // Built from parts so this source file never contains a live-looking key.
    let stripe = format!("sk_{}_{}", "live", r.text(24, ALNUM));
    format!(
        "NODE_ENV=production\nDATABASE_URL=postgres://deploy:{}@db.internal:5432/app\nSTRIPE_SECRET_KEY={stripe}\nJWT_SECRET={}\nSENTRY_DSN=https://{}@o4504.ingest.sentry.io/4505\n",
        r.text(20, ALNUM),
        r.text(48, ALNUM),
        r.text(32, b"0123456789abcdef"),
    )
    .into_bytes()
}

/// Solana CLI keypair format: a JSON array of 64 byte values.
fn wallet(r: &mut Random) -> Vec<u8> {
    let nums: Vec<String> = r.bytes(64).iter().map(u8::to_string).collect();
    format!("[{}]", nums.join(",")).into_bytes()
}

/// Starts with the SQLite magic so file(1) and stealers recognise it.
fn login_data(r: &mut Random) -> Vec<u8> {
    let mut data = b"SQLite format 3\0".to_vec();
    data.extend(r.bytes(16 * 1024 - 16));
    data
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decoys_have_the_right_shape_and_differ_each_time() {
        let mut r = Random::new().unwrap();
        let a = String::from_utf8(aws(&mut r)).unwrap();
        assert!(a.contains("aws_access_key_id = AKIA"));
        assert_ne!(aws(&mut r), aws(&mut r));
        let key = String::from_utf8(ssh_key(&mut r)).unwrap();
        assert!(key.starts_with("-----BEGIN OPENSSH PRIVATE KEY-----\n"));
        assert!(key.lines().all(|l| l.len() <= 70 || l.starts_with("-----")));
        let w: Vec<u8> = serde_json::from_slice(&wallet(&mut r)).unwrap();
        assert_eq!(w.len(), 64);
        assert!(login_data(&mut r).starts_with(b"SQLite format 3\0"));
    }

    #[test]
    fn random_text_uses_only_the_alphabet() {
        let mut r = Random::new().unwrap();
        let t = r.text(500, b"ab");
        assert_eq!(t.len(), 500);
        assert!(t.chars().all(|c| c == 'a' || c == 'b'));
    }
}
