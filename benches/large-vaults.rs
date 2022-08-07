#![feature(test)]

extern crate test;

#[cfg(test)]
mod tests {
    use rustpass::{Vault, VaultEntry};
    use test::{black_box, Bencher};

    const NAME: &str = "TestVault";
    const PW: &str = "Super-Secret_P4ssw0rd!";

    #[bench]
    fn benchmark_10k_vault(b: &mut Bencher) {
        let mut vault = Vault::new_with_password(NAME.into(), &PW).expect("Could not create vault");
        let expected = 100_000;
        (0..expected).for_each(|_| {
            vault.add_entry(VaultEntry::new_password(
                "www.google.com".to_string(),
                Some("Googlerus Maximus".to_string()),
                "Tim Burton".to_string(),
                "GooglePW".to_string(),
                "".to_string(),
            ));
        });

        assert_eq!(
            vault.get_entries().len(),
            expected,
            "Before encryption: Vault has {} number of entries, expected: {}",
            vault.get_entries().len(),
            expected
        );

        b.iter(|| {
            let vault = vault.clone();
            black_box(|| {
                vault
                    .encrypt(&PW)
                    .expect("Could not encrypt vault")
                    .decrypt(&PW)
                    .expect("Could not decrypt vault");
            });
        });
    }

    #[bench]
    fn benchmark_100_vault(b: &mut Bencher) {
        let mut vault = Vault::new_with_password(NAME.into(), &PW).expect("Could not create vault");
        let expected = 100;
        (0..expected).for_each(|_| {
            vault.add_entry(VaultEntry::new_password(
                "www.google.com".to_string(),
                Some("Googlerus Maximus".to_string()),
                "Tim Burton".to_string(),
                "GooglePW".to_string(),
                "".to_string(),
            ));
        });

        assert_eq!(
            vault.get_entries().len(),
            expected,
            "Before encryption: Vault has {} number of entries, expected: {}",
            vault.get_entries().len(),
            expected
        );

        b.iter(|| {
            let vault = vault.clone();
            black_box(|| {
                vault
                    .encrypt(&PW)
                    .expect("Could not encrypt vault")
                    .decrypt(&PW)
                    .expect("Could not decrypt vault");
            });
        });
    }
}
