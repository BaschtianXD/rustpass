use std::{
    collections::HashMap,
    fmt::{self, Display},
};

use aes_gcm::aead::Aead;
use aes_gcm::{
    aead::generic_array::{
        typenum::{U12, U32},
        GenericArray,
    },
    KeyInit,
};
use aes_gcm::{Aes256Gcm, Nonce};
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHasher, SaltString},
    Argon2,
};
use chrono::{NaiveDateTime, Utc};
use rand_core::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::Cursor;

const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Main structure to safely store credentials.
///
/// This is the unencrypted structure containing credentials and cryptographical data.
#[derive(Clone)]
pub struct Vault {
    pub name: String,
    version: String,
    password_hash_hash: GenericArray<u8, U32>,
    salt: SaltString,
    encrypted_key: Vec<u8>,

    nonce: GenericArray<u8, U12>,
    key_nonce: GenericArray<u8, U12>,
    entries: Vec<VaultEntry>,

    changed: bool,
}

impl Vault {
    /// Create a new Vault with a password as authentication method.
    ///
    /// # Example
    ///
    /// ```
    /// use rustpass::Vault;
    ///
    /// let name = "My new vault";
    /// let password = "supersecretpassword";
    /// let vault = Vault::new_with_password(name.into(), password).expect("Unable to create vault");
    /// # assert_eq!(vault.name, name);
    ///
    /// ```
    pub fn new_with_password<N: AsRef<str>>(
        name: String,
        password: N,
    ) -> Result<Vault, VaultCreationError> {
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        let password_hash = match argon2.hash_password(password.as_ref().as_bytes(), &salt) {
            Ok(pw_hash) => pw_hash,
            // This could only happen when password is longer than usize::MAX
            Err(_) => return Err(VaultCreationError::HashError),
        };

        let safe_pw = match password_hash.hash {
            Some(hash) => hash,
            None => return Err(VaultCreationError::HashError),
        };

        let mut gen_key = [0u8; 32];
        OsRng.fill_bytes(&mut gen_key);

        let cipher = match Aes256Gcm::new_from_slice(safe_pw.as_bytes()) {
            Ok(cipher) => cipher,
            Err(_) => return Err(VaultCreationError::EncryptionError),
        };

        let nonce = Nonce::from([0u8; 12]);
        let key_nonce = Nonce::from([0u8; 12]);

        let encrypted_key = match cipher.encrypt(&key_nonce, gen_key.as_ref()) {
            Ok(enc_key) => enc_key,
            Err(_) => return Err(VaultCreationError::EncryptionError),
        };

        let mut hasher = Sha256::new();
        hasher.update(safe_pw);
        let password_hash_hash = hasher.finalize();

        let vault = Vault {
            name,
            version: VERSION.to_owned(),
            password_hash_hash,
            salt,
            encrypted_key,

            key_nonce,
            nonce,

            entries: Vec::new(),

            changed: true,
        };

        Ok(vault)
    }

    /// Adds a new vault entry to self.
    ///
    /// Appends a new entry at the back. If you want to insert a new entry at a specific index use [`insert_entry`](Self::insert_entry) instead.
    pub fn add_entry(&mut self, entry: VaultEntry) {
        self.entries.push(entry);
        self.changed = true;
    }

    /// Retrieve all vault entries from self.
    pub fn get_entries(&self) -> &Vec<VaultEntry> {
        &self.entries
    }

    /// Inserts a new vault entry to self at the given index.
    pub fn insert_entry(&mut self, entry: VaultEntry, index: usize) {
        self.entries.insert(index, entry);
        self.changed = true;
    }

    /// Updates the vault entry at the give index with the new vault entry.
    ///
    /// This replaces the old entry with the new one.
    pub fn update_entry(&mut self, index: usize, new_entry: VaultEntry) {
        let entry = self.entries.get_mut(index).unwrap();
        *entry = new_entry;
    }

    /// Removes an enrty from self.
    ///
    /// For further information check [`Vec::remove`](https://doc.rust-lang.org/alloc/vec/struct.Vec.html#method.remove)
    pub fn remove_entry(&mut self, index: usize) {
        self.entries.remove(index);
        self.changed = true;
    }

    /// Removes an enrty from self.
    ///
    /// For further information check [`Vec::swap_remove`](https://doc.rust-lang.org/alloc/vec/struct.Vec.html#method.swap_remove)
    pub fn swap_remove_entry(&mut self, index: usize) {
        self.entries.swap_remove(index);
        self.changed = true;
    }

    /// Sets `last_used` to now on the [VaultEntry] at the given `index`.
    pub fn set_last_used(&mut self, index: usize) {
        let entry = &mut self.entries[index];
        entry.last_used = Some(Utc::now().naive_local());
    }

    /// Encrypts `self`.
    ///
    /// Checks if the given password is correct. If so, the vault gets encrypted and a `Result<VaultEncrypted, Error>` gets returned
    pub fn encrypt(mut self, password: &str) -> Result<VaultEncrypted, VaultTransformError> {
        let argon2 = Argon2::default();
        let password_hash = argon2
            .hash_password(password.as_bytes(), &self.salt)
            .expect("Could not hash password");

        // Check if password is correct
        let mut hasher = Sha256::new();
        hasher.update(password_hash.hash.expect("Could not extract hash"));
        let password_hash_hash = hasher.finalize();

        if password_hash_hash != self.password_hash_hash {
            return Err(VaultTransformError::WrongPassword);
        }

        // Decrypt key
        let pw_hash = password_hash.hash.expect("Could not extract hash");
        let cipher =
            Aes256Gcm::new_from_slice(pw_hash.as_bytes()).expect("Argon2hash has wrong size");

        if self.changed && !increase_nonce(&mut self.nonce) {
            // we need to change the key as we otherwise use the same nonce for encryption of the vault entries twice which is not safe
            let mut gen_key = [0u8; 32];

            if !increase_nonce(&mut self.key_nonce) {
                return Err(VaultTransformError::PasswordIntegrityCompromised);
            }
            OsRng.fill_bytes(&mut gen_key);

            self.encrypted_key = cipher
                .encrypt(&self.key_nonce, gen_key.as_ref())
                .expect("Could not encrypt key");
        }

        let key = cipher
            .decrypt(&self.key_nonce, self.encrypted_key.as_ref())
            .expect("Could not decrypt key");

        let mut buf: Vec<u8> = Vec::new();
        ciborium::ser::into_writer(&self.entries, &mut buf).expect("Could not write to buffer");
        let cipher = Aes256Gcm::new_from_slice(&key).expect("Key has wrong size");

        let encrypted_data = cipher
            .encrypt(&self.nonce, &*buf)
            .expect("Could not encrypt json data");

        let enc_vault = VaultEncrypted {
            name: self.name,
            version: self.version,
            password_hash_hash: self.password_hash_hash.into(),
            salt: self.salt.as_str().to_owned(),
            encrypted_key: self.encrypted_key,
            nonce: self.nonce.into(),
            key_nonce: self.key_nonce.into(),

            encrypted_data,
        };

        Ok(enc_vault)
    }

    /// Changes the password of `self`
    ///
    /// Checks if the given `old_password` is correct. If so the password for `self` gets changed to `new_password`. Returns a `Result<(), Error>` wether the change was successfull or not.
    pub fn change_password<N: AsRef<str>>(
        &mut self,
        old_password: N,
        new_password: N,
    ) -> Result<(), VaultPasswordChangeError> {
        let argon2 = Argon2::default();
        let password_hash = argon2
            .hash_password(old_password.as_ref().as_bytes(), &self.salt)
            .expect("Could not hash old password");

        // Check if password is correct
        let mut hasher = Sha256::new();
        hasher.update(password_hash.hash.expect("Could not extract hash"));
        let password_hash_hash = hasher.finalize();

        let pwhh = GenericArray::from_slice(&self.password_hash_hash);

        if password_hash_hash != *pwhh {
            return Err(VaultPasswordChangeError::WrongPassword);
        }

        // decrypt key with old password
        let old_safe_pw = password_hash.hash.expect("Could not extract hash");
        let cipher =
            Aes256Gcm::new_from_slice(old_safe_pw.as_bytes()).expect("Argon2hash has wrong size");

        let key = cipher
            .decrypt(&self.key_nonce, self.encrypted_key.as_ref())
            .expect("Could not decrypt key");

        // generate new cipher
        self.salt = SaltString::generate(&mut OsRng);
        let password_hash = argon2
            .hash_password(new_password.as_ref().as_bytes(), &self.salt)
            .expect("Could not hash new password");

        let mut hasher = Sha256::new();
        hasher.update(password_hash.hash.expect("Could not extract hash"));
        self.password_hash_hash = hasher.finalize();

        // encrypt new key with new password
        let cipher = Aes256Gcm::new_from_slice(
            password_hash
                .hash
                .expect("Could not extract hash")
                .as_bytes(),
        )
        .expect("Key has wrong size");
        self.encrypted_key = cipher
            .encrypt(&self.key_nonce, key.as_ref())
            .expect("Could not encrypt key");

        Ok(())
    }

    /// Returns an iterator over all [VaultEntry] of self.
    pub fn iter(&self) -> VaultIterator {
        VaultIterator {
            index: 0,
            vault: self,
        }
    }

    /// Checks for duplicated passwords
    ///
    /// Entries with matching passwords are returned in a [Vec].
    pub fn check_for_duplicated_passwords(&self) -> Vec<&VaultEntry> {
        let mut duplicated = vec![false; self.entries.len()];
        let mut hash_map = HashMap::new();

        for (index, bar) in self.get_entries().iter().enumerate() {
            match &bar.data {
                VaultEntryData::Password {
                    website: _,
                    username: _,
                    password,
                } => match hash_map.insert(password.clone(), index) {
                    Some(old_index) => {
                        duplicated[index] = true;
                        duplicated[old_index] = true;
                    }
                    None => continue, // Haven't seen that password yet
                },
                VaultEntryData::Anything { data: _ } => continue, // Not a password
            }
        }
        self.get_entries()
            .iter()
            .zip(duplicated)
            .filter_map(|(entry, dup)| if dup { Some(entry) } else { None })
            .collect()
    }
}

/// Iterator over [VaultEntry]
pub struct VaultIterator<'a> {
    index: usize,
    vault: &'a Vault,
}

impl<'a> Iterator for VaultIterator<'a> {
    type Item = &'a VaultEntry;

    fn next(&mut self) -> Option<Self::Item> {
        let res = self.vault.entries.get(self.index);
        self.index += 1;
        res
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.vault.entries.len(), Some(self.vault.entries.len()))
    }
}

/// Variants of [VaultEntry] data that can be saved in a [Vault]
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum VaultEntryData {
    Password {
        website: String,
        username: String,
        password: String,
    },
    Anything {
        data: String,
    },
}

/// Item for [Vault]
///
/// Contains [VaultEntryData] and metadata for the item.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct VaultEntry {
    pub title: String,
    pub created: NaiveDateTime,
    pub last_changed: NaiveDateTime,
    pub last_used: Option<NaiveDateTime>,
    pub data: VaultEntryData,
    pub comment: String,
}

impl VaultEntry {
    /// Creates a new [VaultEntry] with password credentials
    pub fn new_password(
        website: String,
        title: Option<String>,
        username: String,
        password: String,
        comment: String,
    ) -> VaultEntry {
        VaultEntry {
            title: title.unwrap_or(format!("{}@{}", &username, &website)),
            created: Utc::now().naive_local(),
            last_changed: Utc::now().naive_local(),
            last_used: None,
            data: VaultEntryData::Password {
                website,
                username,
                password,
            },
            comment,
        }
    }

    /// Creates a new [VaultEntry] with string data
    pub fn new_anything(title: String, data: String, comment: String) -> VaultEntry {
        VaultEntry {
            title,
            created: Utc::now().naive_local(),
            last_changed: Utc::now().naive_local(),
            last_used: None,
            data: VaultEntryData::Anything { data },
            comment,
        }
    }

    /// If [self] has password data, check the password for its quality.
    pub fn get_password_quality(&self) -> Option<PasswordQuality> {
        // TODO maybe check if we can check for exposed passwords in leaks.
        // example: https://haveibeenpwned.com/API/v3
        match &self.data {
            VaultEntryData::Password {
                website: _,
                username: _,
                password,
            } => {
                let mut score = 0u8;
                // lowercase character
                if password.chars().any(|c| c.is_ascii_lowercase()) {
                    score += 1;
                }
                // uppercase character
                if password.chars().any(|c| c.is_ascii_uppercase()) {
                    score += 1;
                }
                // numerical character
                if password.chars().any(|c| c.is_ascii_digit()) {
                    score += 1;
                }
                // special character
                if password.chars().any(|c| {
                    matches!(c, '!'..='/')
                        || matches!(c, ':'..='@')
                        || matches!(c, '['..='`')
                        || matches!(c, '{'..='~')
                }) {
                    score += 1;
                }

                // password length
                let num_chars = password.chars().count();
                match num_chars {
                    0..=9 => return Some(PasswordQuality::Bad),
                    10..=12 => score += 1,
                    13..=15 => score += 2,
                    _other => score += 3,
                }

                match score {
                    0..=4 => Some(PasswordQuality::Bad),
                    5..=6 => Some(PasswordQuality::Good),
                    _other => Some(PasswordQuality::Excellent),
                }
            }
            VaultEntryData::Anything { data: _ } => None,
        }
    }
}

impl Display for VaultEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: TODO", self.title) // TODO
    }
}

#[derive(PartialEq, Eq, Debug)]
pub enum PasswordQuality {
    Exposed,
    Bad,
    Good,
    Excellent,
}

/// Represents a [Vault] in an encrypted state
///
/// Use [`Self::decrypt`] to transform it to [Vault]
#[derive(Serialize, Deserialize, Clone)]
pub struct VaultEncrypted {
    pub name: String,
    version: String,
    #[serde(rename = "hash")]
    password_hash_hash: [u8; 32],
    salt: String,
    #[serde(rename = "key")]
    encrypted_key: Vec<u8>,
    nonce: [u8; 12],
    key_nonce: [u8; 12],

    encrypted_data: Vec<u8>,
}

impl VaultEncrypted {
    /// Tries to decrypt [self] with the given `password`
    pub fn decrypt(self, password: &str) -> Result<Vault, VaultTransformError> {
        let argon2 = Argon2::default();
        let Ok(salt) = SaltString::from_b64(&self.salt) else { return Err(VaultTransformError::VaultIntegrityCompromised)};
        let password_hash = argon2
            .hash_password(password.as_bytes(), salt.as_salt())
            .expect("Could not hash password");

        // Check if password is correct
        let mut hasher = Sha256::new();
        hasher.update(password_hash.hash.expect("Could not extract hash"));
        let password_hash_hash = hasher.finalize();

        let pwhh = GenericArray::from_slice(&self.password_hash_hash);

        if password_hash_hash != *pwhh {
            return Err(VaultTransformError::WrongPassword);
        }

        // Decrypt key
        let hash = password_hash.hash.expect("Could not extract hash");
        let cipher = Aes256Gcm::new_from_slice(hash.as_bytes()).expect("Key has wrong size");

        let nonce = GenericArray::from_slice(&self.nonce);

        let key = cipher
            .decrypt(
                GenericArray::from_slice(&self.key_nonce),
                self.encrypted_key.as_ref(),
            )
            .expect("Could not decrypt key");

        // Decrypt data
        let cipher = Aes256Gcm::new_from_slice(&key).expect("Key has wrong size");
        let plain_data = cipher
            .decrypt(nonce, self.encrypted_data.as_ref())
            .expect("Could not decrypt data"); // TODO better error handling
        let cursor = Cursor::new(plain_data);
        //let data: Vec<VaultEntry> =
        let data = ciborium::de::from_reader(cursor).expect("Could not parse data");

        let vault = Vault {
            name: self.name,
            version: self.version,
            password_hash_hash: GenericArray::from_slice(&self.password_hash_hash).to_owned(),
            salt,
            encrypted_key: self.encrypted_key,
            nonce: GenericArray::from_slice(&self.nonce).to_owned(),
            key_nonce: GenericArray::from_slice(&self.key_nonce).to_owned(),

            entries: data,

            changed: false,
        };

        Ok(vault)
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum VaultTransformError {
    WrongPassword,
    PasswordIntegrityCompromised,
    VaultIntegrityCompromised,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum VaultPasswordChangeError {
    WrongPassword,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum VaultCreationError {
    HashError,
    EncryptionError,
}

/// Increases the given `nonce` by one
///
/// Returns a `bool` wether the nonce has overflowed and reset back to 0000...0000.
///
/// # Beware
/// An overflow usually indicates that the nonce will be reused and we have to take further precautions as to not reuse a nonce.
fn increase_nonce(nonce: &mut GenericArray<u8, U12>) -> bool {
    //let slice = nonce.as_mut_slice();
    // for i in 0..11 {
    //     let curr = slice[i];
    //     if curr == u8::MAX {
    //         slice[i] = 0;
    //     } else {
    //         slice[i] += 1;
    //         break;
    //     }
    // }
    for item in nonce.iter_mut() {
        if item == &u8::MAX {
            *item = 0;
        } else {
            *item += 1;
            break;
        }
    }
    // this checks if we are back to 00...00
    !nonce.iter().all(|num| num == &0u8)
}

#[cfg(test)]
mod test {
    use aes_gcm::{
        aead::{generic_array::GenericArray, Aead},
        Aes256Gcm, KeyInit,
    };
    use argon2::{Argon2, PasswordHasher};

    use crate::{PasswordQuality::*, Vault, VaultEntry, VaultTransformError};

    const NAME: &str = "TestVault";
    const PW: &str = "Super-Secret_P4ssw0rd!";

    fn get_small_vault() -> Vault {
        let mut vault = Vault::new_with_password(NAME.into(), PW).expect("Could not create vault");
        vault.add_entry(VaultEntry::new_password(
            "www.google.com".to_string(),
            Some("Googlerus Maximus".to_string()),
            "Tim Burton".to_string(),
            "GooglePW".to_string(),
            "".to_string(),
        ));

        vault
    }

    #[test]
    fn encrypt_decrypt() -> Result<(), String> {
        let vault = get_small_vault();

        let enc = vault.encrypt(PW).expect("Could not encrypt vault");
        let decrypted = enc.decrypt(PW).expect("Could not decrypt vault");

        let entries = decrypted.get_entries();

        assert_eq!(entries.len(), 1, "Vault has wrong amount of entries");

        let entry = entries.get(0).expect("Could not get entry");

        assert_eq!(entry.title, "Googlerus Maximus");

        match &entry.data {
            crate::VaultEntryData::Password {
                website,
                username,
                password,
            } => {
                assert_eq!(website, "www.google.com");
                assert_eq!(username, "Tim Burton");
                assert_eq!(password, "GooglePW");
            }
            crate::VaultEntryData::Anything { data: _ } => {
                return Err("Entry is of wrong type".into())
            }
        }
        Ok(())
    }

    #[test]
    fn encrypt_wrong_password() -> Result<(), String> {
        let vault = get_small_vault();
        let wrong_password = "NotYourPassword";

        let res = vault.encrypt(wrong_password);

        match res {
            Ok(_) => Err("Encrypt with wrong password is supposed to fail".into()),
            Err(_) => Ok(()),
        }
    }

    #[test]
    fn decrypt_wrong_password() -> Result<(), String> {
        let vault = get_small_vault();
        let wrong_password = "NotYourPassword";

        let enc_vault = vault.encrypt(PW).expect("Could not encrypt vault");

        let res = enc_vault.decrypt(wrong_password);

        match res {
            Ok(_) => Err("Decrypt with wrong password is supposed to fail.".into()),
            Err(_) => Ok(()),
        }
    }

    #[test]
    fn add_entry() -> Result<(), String> {
        let expected_result = 2;
        let mut vault = get_small_vault();
        vault.add_entry(VaultEntry::new_anything(
            "Bullut".into(),
            "Wallah Krise".into(),
            "".into(),
        ));

        assert_eq!(
            vault.entries.len(),
            expected_result,
            "Vault entries has {} number of entries, expected: {}",
            vault.entries.len(),
            expected_result
        );

        let entry = vault.entries.get(1).expect("Could not get entry");
        assert_eq!(entry.title, "Bullut");
        match &entry.data {
            crate::VaultEntryData::Anything { data } => {
                assert_eq!(data, "Wallah Krise");
            }
            _default => return Err("Entry is of wrong type".into()),
        }

        Ok(())
    }

    #[test]
    fn change_password_fail() -> Result<(), String> {
        let mut vault = get_small_vault();
        let new_pw = "AnotehrSuperSecurePassword";
        let fail_pw = "WrongPassword";

        match vault.change_password(fail_pw, new_pw) {
            Ok(_) => Err("Call to change_password with wrong password is supposed to fail".into()),
            Err(_) => Ok(()),
        }
    }

    #[test]
    fn change_password_success() -> Result<(), String> {
        let mut vault = get_small_vault();
        let new_pw = "AnotherSuperSecurePassword";

        let enc_key = vault.encrypted_key.to_owned();

        match vault.change_password(PW, new_pw) {
            Ok(_) => {}
            Err(_) => {
                return Err(
                    "Call to change_password with correct password is supposed to succeed".into(),
                )
            }
        }

        if enc_key == vault.encrypted_key {
            return Err("Encrypted key is the same".into());
        }

        let enc_vault = vault
            .encrypt(new_pw)
            .expect("Could not encrypt vault with new password");
        let _vault = enc_vault
            .decrypt(new_pw)
            .expect("Coudl not decrypt vault with new password");

        Ok(())
    }

    #[test]
    fn test_password_quality() -> Result<(), String> {
        let website = "www.nitter.com".to_string();
        let title = None;
        let username = "FooBar".to_string();

        let test_cases = [
            ("Sh0rty!", Bad),
            ("NotABadPassw0rd", Good),
            ("W0nderful-adr6!9-Password!", Excellent),
        ];

        for case in test_cases {
            assert_eq!(
                VaultEntry::new_password(
                    website.clone(),
                    title.clone(),
                    username.clone(),
                    case.0.into(),
                    "".into()
                )
                .get_password_quality()
                .expect("Should return Some quality"),
                case.1,
                "{} is supposed to be {:?}",
                case.0,
                case.1
            );
        }

        Ok(())
    }

    #[test]
    fn test_duplicated_passwords() -> Result<(), String> {
        let mut vault = get_small_vault();
        let entry = VaultEntry::new_password(
            // add the same entry again
            "www.google.com".to_string(),
            Some("Googlerus Maximus".to_string()),
            "Tim Burton".to_string(),
            "GooglePW".to_string(),
            "".to_string(),
        );
        vault.add_entry(entry.clone());
        vault.add_entry(entry);

        let result = vault.check_for_duplicated_passwords();

        for (result, expected) in result
            .iter()
            .zip(vec![&vault.entries[0], &vault.entries[1]])
        {
            assert_eq!(**result, *expected, "Returned wrong entry");
        }

        Ok(())
    }

    #[test]
    fn test_integrity_compromised() -> Result<(), String> {
        let expected = VaultTransformError::PasswordIntegrityCompromised;
        let mut vault = get_small_vault();

        let max_nonce = GenericArray::from([u8::MAX; 12]);

        let argon2 = Argon2::default();
        let password_hash = argon2
            .hash_password(PW.as_bytes(), &vault.salt)
            .expect("Could not hash password");

        let pw_hash = password_hash.hash.expect("Could not extract hash");
        let cipher =
            Aes256Gcm::new_from_slice(pw_hash.as_bytes()).expect("Argon2hash has wrong size");

        let key = cipher
            .decrypt(&vault.key_nonce, vault.encrypted_key.as_ref())
            .expect("Could not decrypt key");

        vault.key_nonce = max_nonce;
        vault.encrypted_key = cipher
            .encrypt(&vault.key_nonce, key.as_ref())
            .expect("Could not encrypt key");

        vault.nonce = max_nonce;

        match vault.encrypt(PW) {
            Ok(_) => Err("Encryption should fail as nonce overflows".into()),
            Err(err) => {
                if err != VaultTransformError::PasswordIntegrityCompromised {
                    Err(format!(
                        "Wrong error was thrown, expected: {:?}, actual: {:?}",
                        expected, err
                    ))
                } else {
                    Ok(())
                }
            }
        }
    }
}
