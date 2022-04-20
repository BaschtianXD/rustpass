use std::fmt::{self, Display};

use aes_gcm::aead::generic_array::{
    typenum::{U12, U32},
    GenericArray,
};
use aes_gcm::aead::{Aead, NewAead};
use aes_gcm::{Aes256Gcm, Key, Nonce};
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

pub struct RpVault {
    pub name: String,
    version: String,
    password_hash_hash: GenericArray<u8, U32>,
    salt: SaltString,
    encrypted_key: Vec<u8>,
    nonce: GenericArray<u8, U12>,

    entries: Vec<VaultEntry>,
}

impl RpVault {
    pub fn new_with_password(name: String, password: &str) -> Result<RpVault, ()> {
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        let password_hash = argon2
            .hash_password(password.as_bytes(), &salt)
            .expect("Could not hash password");

        let safe_pw = password_hash.hash.expect("Could not extract hash");

        let mut gen_key = [0u8; 32];
        OsRng.fill_bytes(&mut gen_key);

        let key = Key::from_slice(safe_pw.as_bytes());
        let cipher = Aes256Gcm::new(key);

        let nonce = Nonce::from([0u8; 12]);

        let encrypted_key = cipher
            .encrypt(&nonce, gen_key.as_ref())
            .expect("Could not encrypt key");

        let mut hasher = Sha256::new();
        hasher.update(safe_pw);
        let password_hash_hash = hasher.finalize();

        let vault = RpVault {
            name,
            version: VERSION.to_owned(),
            password_hash_hash,
            salt,
            encrypted_key,
            nonce,

            entries: Vec::new(),
        };

        return Ok(vault);
    }

    pub fn add_entry(&mut self, entry: VaultEntry) {
        self.entries.push(entry);
    }

    pub fn get_entries(&self) -> &Vec<VaultEntry> {
        &self.entries
    }

    pub fn insert_entry(&mut self, entry: VaultEntry, index: usize) {
        self.entries.insert(index, entry);
    }

    pub fn remove_entry(&mut self, index: usize) {
        self.entries.swap_remove(index);
    }

    pub fn encrypt(self, password: &str) -> Result<RpVaultEncrypted, Error> {
        let argon2 = Argon2::default();
        let password_hash = argon2
            .hash_password(password.as_bytes(), &self.salt)
            .expect("Could not hash password");

        // Check if password is correct
        let mut hasher = Sha256::new();
        hasher.update(password_hash.hash.expect("Could not extract hash"));
        let password_hash_hash = hasher.finalize();

        if password_hash_hash != self.password_hash_hash {
            return Err(Error::WrongPassword);
        }

        // Decrypt key
        let foo = password_hash.hash.expect("Could not extract hash");
        let pw_key = Key::from_slice(foo.as_bytes());
        let cipher = Aes256Gcm::new(pw_key);

        let key = cipher
            .decrypt(&Nonce::from([0u8; 12]), self.encrypted_key.as_ref())
            .expect("Could not decrypt key");

        // Encode data as json and encrypt
        //let json = serde_json::to_string(&self.entries).expect("Could not serialize data");
        let mut buf: Vec<u8> = Vec::new();
        ciborium::ser::into_writer(&self.entries, &mut buf).expect("Could not write to buffer");
        let key = Key::from_slice(&key);
        let cipher = Aes256Gcm::new(key);

        let encrypted_data = cipher
            .encrypt(&self.nonce, &*buf)
            .expect("Could not encrypt json data");

        let enc_vault = RpVaultEncrypted {
            name: self.name,
            version: self.version,
            password_hash_hash: self.password_hash_hash.into(),
            salt: self.salt.as_str().to_owned(),
            encrypted_key: self.encrypted_key,
            nonce: self.nonce.into(),

            encrypted_data,
        };

        Ok(enc_vault)
    }

    pub fn iter(&self) -> VaultIterator {
        VaultIterator {
            index: 0,
            vault: (&self),
        }
    }
}

pub struct VaultIterator<'a> {
    index: usize,
    vault: &'a RpVault,
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

#[derive(Serialize, Deserialize)]
pub enum VaultEntryData {
    Password {
        #[serde(rename = "w")]
        website: String,
        #[serde(rename = "u")]
        username: String,
        #[serde(rename = "p")]
        password: String,
    },
    Anything {
        #[serde(rename = "d")]
        data: String,
    },
}

#[derive(Serialize, Deserialize)]
pub struct VaultEntry {
    #[serde(rename = "t")]
    pub title: String,
    #[serde(rename = "c")]
    pub created: NaiveDateTime,
    #[serde(rename = "lc")]
    pub last_changed: NaiveDateTime,
    #[serde(rename = "lu")]
    pub last_used: Option<NaiveDateTime>,
    #[serde(rename = "d")]
    pub data: VaultEntryData,
}

impl VaultEntry {
    pub fn new_password(
        website: String,
        title: Option<String>,
        username: String,
        password: String,
    ) -> VaultEntry {
        VaultEntry {
            title: title.unwrap_or((&website).into()),
            created: Utc::now().naive_local(),
            last_changed: Utc::now().naive_local(),
            last_used: None,
            data: VaultEntryData::Password {
                website,
                username,
                password,
            },
        }
    }

    pub fn new_anything(title: String, data: String) -> VaultEntry {
        VaultEntry {
            title,
            created: Utc::now().naive_local(),
            last_changed: Utc::now().naive_local(),
            last_used: None,
            data: VaultEntryData::Anything { data },
        }
    }
}

impl Display for VaultEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: TODO", self.title) // TODO
    }
}

#[derive(Serialize, Deserialize)]
pub struct RpVaultEncrypted {
    pub name: String,
    version: String,
    #[serde(rename = "hash")]
    password_hash_hash: [u8; 32],
    salt: String,
    #[serde(rename = "key")]
    encrypted_key: Vec<u8>,
    nonce: [u8; 12],

    encrypted_data: Vec<u8>,
}

impl RpVaultEncrypted {
    pub fn decrypt(self, password: &str) -> Result<RpVault, Error> {
        let argon2 = Argon2::default();
        let password_hash = argon2
            .hash_password(password.as_bytes(), &self.salt)
            .expect("Could not hash password");

        // Check if password is correct
        let mut hasher = Sha256::new();
        hasher.update(password_hash.hash.expect("Could not extract hash"));
        let password_hash_hash = hasher.finalize();

        let pwhh = GenericArray::from_slice(&self.password_hash_hash);

        if password_hash_hash != *pwhh {
            return Err(Error::WrongPassword);
        }

        // Decrypt key
        let foo = password_hash.hash.expect("Could not extract hash");
        let pw_key = Key::from_slice(foo.as_bytes());
        let cipher = Aes256Gcm::new(pw_key);

        let nonce = GenericArray::from_slice(&self.nonce);

        let key = cipher
            .decrypt(&Nonce::from([0u8; 12]), self.encrypted_key.as_ref())
            .expect("Could not decrypt key");

        // Decrypt data
        let key = Key::from_slice(&key);
        let cipher = Aes256Gcm::new(key);
        let plain_data = cipher
            .decrypt(nonce, self.encrypted_data.as_ref())
            .expect("Could not decrypt data"); // TODO better error handling
        let cursor = Cursor::new(plain_data);
        //let data: Vec<VaultEntry> =
        let data = ciborium::de::from_reader(cursor).expect("Could not parse data");

        let mut nonce = GenericArray::from_slice(&self.nonce).to_owned();
        increase_nonce(&mut nonce);

        let vault = RpVault {
            name: self.name,
            version: self.version,
            password_hash_hash: GenericArray::from_slice(&self.password_hash_hash).to_owned(),
            salt: SaltString::new(&self.salt).expect("Could not parse salt"),
            encrypted_key: self.encrypted_key,
            nonce: nonce,

            entries: data,
        };

        Ok(vault)
    }
}

#[derive(Debug)]
pub enum Error {
    WrongPassword,
    Unknown,
}

fn increase_nonce(nonce: &mut GenericArray<u8, U12>) {
    // TODO when nonce is back at 0000....0000 again we should change the key as it is no longer considered safe, as we use the same nonce twice
    let slice = nonce.as_mut_slice();
    for i in 0..11 {
        let curr = slice[i];
        if curr == u8::MAX {
            slice[i] = 0;
        } else {
            slice[i] += 1;
            return;
        }
    }
}

#[cfg(test)]
mod test {
    use crate::{RpVault, VaultEntry};

    const NAME: &str = "TestVault";
    const PW: &str = "Super-Secret_P4ssw0rd!";

    fn get_small_vault() -> RpVault {
        let mut vault =
            RpVault::new_with_password(NAME.into(), &PW).expect("Could not create vault");
        vault.add_entry(VaultEntry::new_password(
            "www.google.com".to_string(),
            Some("Googlerus Maximus".to_string()),
            "Tim Burton".to_string(),
            "GooglePW".to_string(),
        ));

        vault
    }

    #[test]
    fn encrypt_decrypt() -> Result<(), String> {
        let vault = get_small_vault();

        let enc = vault.encrypt(&PW).expect("Could not encrypt vault");
        let decrypted = enc.decrypt(&PW).expect("Could not decrypt vault");

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
    fn add_entry() -> Result<(), String> {
        let mut vault = get_small_vault();
        vault.add_entry(VaultEntry::new_anything(
            "Bullut".into(),
            "Wallah Krise".into(),
        ));

        assert_eq!(
            vault.entries.len(),
            2,
            "Vault entries has wrong number of entries"
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
}
