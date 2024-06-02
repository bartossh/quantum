use criterion::{criterion_group, criterion_main, Criterion};
use secure::asymmetric_pre_quant_cipher::CipherWallet;
use secure::asymmetric_pre_quant_signer::SignerWallet as PreQuantSignerWallet;
use secure::asymmetric_quant_cipher::*;
use secure::asymmetric_quant_signer::*;
use secure::globals::AsymmetricEncryptorDecryptor;
use secure::globals::{AddressReader as _, AsymmetricEncapsulatorDecapsulator};
use secure::handshake::*;
use secure::randomizer;
use secure::transaction::*;

fn benchmark_transaction_issue(c: &mut Criterion) {
    c.bench_function("benchmark_transaction_issue", |b| {
        let q_issuer: SignerWallet = SignerWallet::new();
        let issuer: PreQuantSignerWallet = PreQuantSignerWallet::new();
        let q_receiver: SignerWallet = SignerWallet::new();
        let receiver: PreQuantSignerWallet = PreQuantSignerWallet::new();
        let cap = 100000;
        let mut data: Vec<u8> = Vec::with_capacity(cap);
        for _ in 0..cap {
            data.push(128);
        }

        b.iter(|| {
            let _ = Transaction::issue(
                &issuer,
                &q_issuer,
                "next transaction".to_string(),
                data.clone(),
                Address::from_address_reader(&receiver, &q_receiver),
            );
        })
    });
}

fn benchmark_transaction_approve(c: &mut Criterion) {
    c.bench_function("benchmark_transaction_approve", |b| {
        let q_issuer: SignerWallet = SignerWallet::new();
        let issuer: PreQuantSignerWallet = PreQuantSignerWallet::new();
        let q_receiver: SignerWallet = SignerWallet::new();
        let receiver: PreQuantSignerWallet = PreQuantSignerWallet::new();
        let cap = 100000;
        let mut data: Vec<u8> = Vec::with_capacity(cap);
        for _ in 0..cap {
            data.push(128);
        }
        let mut trx = Transaction::issue(
            &issuer,
            &q_issuer,
            "next transaction".to_string(),
            data,
            Address::from_address_reader(&receiver, &q_receiver),
        );

        b.iter(|| trx.approve(&receiver, &q_receiver).to_owned())
    });
}

fn benchmark_transaction_validate_issuer(c: &mut Criterion) {
    c.bench_function("benchmark_transaction_validate_issuer", |b| {
        let q_issuer: SignerWallet = SignerWallet::new();
        let issuer: PreQuantSignerWallet = PreQuantSignerWallet::new();
        let q_receiver: SignerWallet = SignerWallet::new();
        let receiver: PreQuantSignerWallet = PreQuantSignerWallet::new();
        let cap = 100000;
        let mut data: Vec<u8> = Vec::with_capacity(cap);
        for _ in 0..cap {
            data.push(128);
        }
        let mut trx = Transaction::issue(
            &issuer,
            &q_issuer,
            "next transaction".to_string(),
            data,
            Address::from_address_reader(&receiver, &q_receiver),
        );
        trx.approve(&receiver, &q_receiver);
        b.iter(|| trx.validate_for_issuer(&issuer, &q_issuer).to_owned())
    });
}

fn benchmark_transaction_validate_receiver(c: &mut Criterion) {
    c.bench_function("benchmark_transaction_validate_receiver", |b| {
        let q_issuer: SignerWallet = SignerWallet::new();
        let issuer: PreQuantSignerWallet = PreQuantSignerWallet::new();
        let q_receiver: SignerWallet = SignerWallet::new();
        let receiver: PreQuantSignerWallet = PreQuantSignerWallet::new();
        let cap = 100000;
        let mut data: Vec<u8> = Vec::with_capacity(cap);
        for _ in 0..cap {
            data.push(128);
        }
        let mut trx = Transaction::issue(
            &issuer,
            &q_issuer,
            "next transaction".to_string(),
            data,
            Address::from_address_reader(&receiver, &q_receiver),
        );
        trx.approve(&receiver, &q_receiver);

        b.iter(|| trx.validate_for_receiver(&receiver, &q_receiver).to_owned())
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

fn benchmark_random_hash(c: &mut Criterion) {
    c.bench_function("benchmark_random_hash", |b| {
        b.iter(|| randomizer::generate_random_hash());
    });
}

fn benchmark_handshake(c: &mut Criterion) {
    c.bench_function("benchmark_handshake", |b| {
        let mut alice = State::new();
        let mut bob = State::new();
        b.iter(|| {
            let h = alice.hello_propose();
            if h.is_err() {
                assert!(false);
            }

            let h = bob.hello_select(&h.unwrap());
            if h.is_err() {
                dbg!(&h);
                assert!(false);
            }

            let c = alice.cipher_generate(&h.unwrap());
            if c.is_err() {
                dbg!(&c);
                assert!(false);
            }

            let r = bob.cipher_decode_sharedkey(&c.unwrap());
            if r.is_err() {
                dbg!(&r);
                assert!(false);
            }

            alice.reset();
            bob.reset();
        });
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
    benchmark_asymmetric_key_decryption,
    benchmark_random_hash,
    benchmark_handshake
);
criterion_main!(benches);
