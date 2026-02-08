use sha2::{Digest, Sha256};

/// Hash an API key using SHA-256
pub fn hash_api_key(key: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(key.as_bytes());
    format!("{:x}", hasher.finalize())
}

/// Verify an API key against a stored hash
pub fn verify_api_key(provided_key: &str, stored_hash: &str) -> bool {
    let provided_hash = hash_api_key(provided_key);
    provided_hash == stored_hash
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_api_key_hashing() {
        let key = "test_key_12345";
        let hash = hash_api_key(key);

        // Verify hash is deterministic
        assert_eq!(hash, hash_api_key(key));

        // Verify validation works
        assert!(verify_api_key(key, &hash));
        assert!(!verify_api_key("wrong_key", &hash));
    }
}
