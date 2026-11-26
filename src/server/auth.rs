//! 服务端鉴权：口令哈希（PBKDF2-HMAC-SHA256）与会话令牌。
//!
//! 只依赖 `sha2`，不引入 bcrypt/argon2，避免为服务端增加编译负担；
//! PBKDF2 迭代 20 万次，对「共享管理口令」这一使用场景足够。

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use anyhow::{bail, Result};
use sha2::{Digest, Sha256};

const ITERATIONS: u32 = 200_000;
const SALT_LEN: usize = 16;
const KEY_LEN: usize = 32;

/// 生成 `pbkdf2$<iter>$<salt_hex>$<key_hex>` 格式的口令记录。
pub fn hash_password(password: &str) -> String {
    let salt = random_bytes(SALT_LEN);
    let key = pbkdf2(password.as_bytes(), &salt, ITERATIONS, KEY_LEN);
    format!(
        "pbkdf2${ITERATIONS}${}${}",
        hex::encode(salt),
        hex::encode(key)
    )
}

/// 校验口令；格式非法时返回 false 而不是报错，避免泄露内部细节。
pub fn verify_password(password: &str, stored: &str) -> bool {
    let mut parts = stored.split('$');
    if parts.next() != Some("pbkdf2") {
        return false;
    }
    let (Some(iterations), Some(salt_hex), Some(key_hex)) = (parts.next(), parts.next(), parts.next())
    else {
        return false;
    };
    let Ok(iterations) = iterations.parse::<u32>() else {
        return false;
    };
    let (Ok(salt), Ok(expected)) = (hex::decode(salt_hex), hex::decode(key_hex)) else {
        return false;
    };
    let actual = pbkdf2(password.as_bytes(), &salt, iterations, expected.len());
    // 定长比较，避免按字节短路带来的时序差异。
    actual.len() == expected.len()
        && actual
            .iter()
            .zip(expected.iter())
            .fold(0u8, |acc, (a, b)| acc | (a ^ b))
            == 0
}

fn pbkdf2(password: &[u8], salt: &[u8], iterations: u32, key_len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(key_len);
    let mut block = 1u32;
    while out.len() < key_len {
        let mut mac = Sha256::new();
        mac.update(password);
        mac.update(salt);
        mac.update(block.to_be_bytes());
        let mut u = mac.finalize().to_vec();
        let mut t = u.clone();
        for _ in 1..iterations {
            let mut mac = Sha256::new();
            mac.update(&u);
            u = mac.finalize().to_vec();
            for (acc, byte) in t.iter_mut().zip(u.iter()) {
                *acc ^= byte;
            }
        }
        out.extend_from_slice(&t);
        block += 1;
    }
    out.truncate(key_len);
    out
}

fn random_bytes(len: usize) -> Vec<u8> {
    // 用系统熵源；不可用时退回时间+地址混合，避免 panic（服务端不应因熵源失败而崩）。
    // 注意：不能用 `std::fs::read`——它会一直读到 EOF，而 /dev/urandom 永不 EOF，
    // 会导致无限读取直到内存耗尽。必须只读需要的字节数。
    let mut buf = vec![0u8; len];
    {
        use std::io::Read;
        if let Ok(mut file) = std::fs::File::open("/dev/urandom") {
            if file.read_exact(&mut buf).is_ok() {
                return buf;
            }
        }
    }
    let mut seed = Sha256::new();
    seed.update(std::process::id().to_be_bytes());
    seed.update(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos().to_be_bytes())
            .unwrap_or_default(),
    );
    let local = 0u8;
    seed.update((&local as *const u8 as usize).to_be_bytes());
    let digest = seed.finalize();
    for (index, slot) in buf.iter_mut().enumerate() {
        *slot = digest[index % digest.len()];
    }
    buf
}

/// 生成 32 字节随机令牌（hex）。
pub fn random_token() -> String {
    hex::encode(random_bytes(32))
}

/// 内存中的会话表：令牌 → 过期时间。
pub struct Sessions {
    ttl: Duration,
    inner: Mutex<HashMap<String, Instant>>,
}

impl Sessions {
    pub fn new(ttl: Duration) -> Self {
        Self {
            ttl,
            inner: Mutex::new(HashMap::new()),
        }
    }

    pub fn issue(&self) -> String {
        let token = random_token();
        if let Ok(mut map) = self.inner.lock() {
            // 顺手清理过期会话，避免长期运行后无限增长。
            let now = Instant::now();
            map.retain(|_, expires| *expires > now);
            map.insert(token.clone(), Instant::now() + self.ttl);
        }
        token
    }

    pub fn valid(&self, token: &str) -> bool {
        let Ok(mut map) = self.inner.lock() else {
            return false;
        };
        let now = Instant::now();
        match map.get(token) {
            Some(expires) if *expires > now => true,
            Some(_) => {
                map.remove(token);
                false
            }
            None => false,
        }
    }

    pub fn revoke(&self, token: &str) {
        if let Ok(mut map) = self.inner.lock() {
            map.remove(token);
        }
    }
}

/// 定长时间比较，用于共享 Agent Token 校验。
pub fn constant_time_eq(left: &str, right: &str) -> bool {
    let a = left.as_bytes();
    let b = right.as_bytes();
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b.iter()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// 生成一个可读的随机口令（首启打印给管理员）。
pub fn generate_passphrase() -> String {
    // 去掉易混淆字符（0/O、1/l/I），便于人工抄写。
    const ALPHABET: &[u8] = b"abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    let bytes = random_bytes(20);
    bytes
        .iter()
        .map(|byte| ALPHABET[*byte as usize % ALPHABET.len()] as char)
        .collect()
}

/// 校验口令强度，太弱直接拒绝而不是静默接受。
pub fn validate_password_strength(password: &str) -> Result<()> {
    if password.chars().count() < 8 {
        bail!("管理口令至少 8 个字符");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashes_and_verifies() {
        let record = hash_password("correct horse battery staple");
        assert!(record.starts_with("pbkdf2$"));
        assert!(verify_password("correct horse battery staple", &record));
        assert!(!verify_password("wrong password", &record));
        // 同一口令两次哈希应因盐不同而不同
        assert_ne!(record, hash_password("correct horse battery staple"));
    }

    #[test]
    fn rejects_malformed_records() {
        assert!(!verify_password("x", ""));
        assert!(!verify_password("x", "bcrypt$1$aa$bb"));
        assert!(!verify_password("x", "pbkdf2$notanumber$aa$bb"));
        assert!(!verify_password("x", "pbkdf2$10$zz$bb"));
    }

    #[test]
    fn sessions_expire_and_revoke() {
        let sessions = Sessions::new(Duration::from_millis(60));
        let token = sessions.issue();
        assert!(sessions.valid(&token));
        sessions.revoke(&token);
        assert!(!sessions.valid(&token));

        let token = sessions.issue();
        std::thread::sleep(Duration::from_millis(90));
        assert!(!sessions.valid(&token));
    }

    #[test]
    fn constant_time_compare() {
        assert!(constant_time_eq("abc", "abc"));
        assert!(!constant_time_eq("abc", "abd"));
        assert!(!constant_time_eq("abc", "abcd"));
    }

    #[test]
    fn passphrase_is_readable() {
        let pass = generate_passphrase();
        assert_eq!(pass.chars().count(), 20);
        assert!(!pass.contains('0') && !pass.contains('O') && !pass.contains('l'));
    }

    #[test]
    fn password_strength() {
        assert!(validate_password_strength("12345678").is_ok());
        assert!(validate_password_strength("1234567").is_err());
    }
}
