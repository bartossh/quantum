use criterion::{criterion_group, criterion_main, Criterion};
use crypto::asymmetric_pre_quant_cipher::CipherWallet;
use crypto::asymmetric_quant_cipher::*;
use crypto::asymmetric_quant_signer::*;
use crypto::globals::EncryptorDecryptor;
use crypto::globals::{AddressReader as _, EncapsulatorDecapsulator};
use crypto::transaction::*;

fn benchmark_transaction_issue(c: &mut Criterion) {
    c.bench_function("benchmark_transaction_issue", |b| {
        let issuer = SignerWallet::new();
        let receiver = SignerWallet::new();
        let cap = 100000;
        let mut data: Vec<u8> = Vec::with_capacity(cap);
        for _ in 0..cap {
            data.push(128);
        }

        b.iter(|| {
            let _ =
                Transaction::issue(issuer, "transaction".to_string(), &data, receiver.address());
        })
    });
}

fn benchmark_transaction_approve(c: &mut Criterion) {
    c.bench_function("benchmark_transaction_approve", |b| {
        let issuer = SignerWallet::new();
        let receiver = SignerWallet::new();
        let cap = 100000;
        let mut data: Vec<u8> = Vec::with_capacity(cap);
        for _ in 0..cap {
            data.push(128);
        }
        let mut trx =
            Transaction::issue(issuer, "transaction".to_string(), &data, receiver.address());

        b.iter(|| trx.approve(&receiver).to_owned())
    });
}

fn benchmark_transaction_validate_issuer(c: &mut Criterion) {
    c.bench_function("benchmark_transaction_validate_issuer", |b| {
        let issuer = SignerWallet::new();
        let receiver = SignerWallet::new();
        let cap = 100000;
        let mut data: Vec<u8> = Vec::with_capacity(cap);
        for _ in 0..cap {
            data.push(128);
        }
        let trx = Transaction::issue(issuer, "transaction".to_string(), &data, receiver.address());

        b.iter(|| trx.validate_for_issuer(&issuer).to_owned())
    });
}

fn benchmark_transaction_validate_receiver(c: &mut Criterion) {
    c.bench_function("benchmark_transaction_validate_receiver", |b| {
        let issuer = SignerWallet::new();
        let receiver = SignerWallet::new();
        let cap = 100000;
        let mut data: Vec<u8> = Vec::with_capacity(cap);
        for _ in 0..cap {
            data.push(128);
        }
        let mut trx =
            Transaction::issue(issuer, "transaction".to_string(), &data, receiver.address());

        trx.approve(&receiver);

        b.iter(|| trx.validate_for_receiver(&issuer).to_owned())
    });
}

fn benchmark_asymmetric_key_encapsulation(c: &mut Criterion) {
    c.bench_function("benchmark_asymmetric_key_encapsulation", |b| {
        let encrypter = SharedKeyGeneratorWallet::new();
        let decrypter: SharedKeyGeneratorWallet = SharedKeyGeneratorWallet::new();

        b.iter(|| encrypter.encapsulate_shared_key(decrypter.address()));
    });
}

fn benchmark_asymmetric_key_decapsulation(c: &mut Criterion) {
    c.bench_function("benchmark_asymmetric_key_decapsulation", |b| {
        let encrypter = SharedKeyGeneratorWallet::new();
        let decrypter: SharedKeyGeneratorWallet = SharedKeyGeneratorWallet::new();
        let (_, ciphertext) = encrypter
            .encapsulate_shared_key(decrypter.address())
            .unwrap();
        b.iter(|| decrypter.decapsulate_shared_key(&ciphertext));
    });
}

fn benchmark_asymmetric_key_encryption(c: &mut Criterion) {
    c.bench_function("benchmark_asymmetric_key_encryption", |b| {
        let encrypter = CipherWallet::new().unwrap();
        let decrypter = CipherWallet::new().unwrap();
        let msg: &[u8] = "this is example message to encrypt".as_bytes();

        b.iter(|| encrypter.encrypt(decrypter.address(), msg));
    });
}

fn benchmark_asymmetric_key_decryption(c: &mut Criterion) {
    c.bench_function("benchmark_asymmetric_key_decryption", |b| {
        let encrypter = CipherWallet::new().unwrap();
        let decrypter = CipherWallet::new().unwrap();
        let msg: &[u8] = "this is example message to encrypt".as_bytes();
        let result = encrypter.encrypt(decrypter.address(), msg);
        if let Ok(ciphertext) = result {
            b.iter(|| decrypter.decrypt(&ciphertext));
        } else {
            assert!(false);
        }
    });
}

criterion_group!(
    benches,
    benchmark_transaction_issue,
    benchmark_transaction_approve,
    benchmark_transaction_validate_issuer,
    benchmark_transaction_validate_receiver,
    benchmark_asymmetric_key_encapsulation,
    benchmark_asymmetric_key_decapsulation,
    benchmark_asymmetric_key_encryption,
    benchmark_asymmetric_key_decryption
);
criterion_main!(benches);
