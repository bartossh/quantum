use criterion::{criterion_group, criterion_main, Criterion};
use crypto::traits::Signer;
use crypto::transaction::*;
use crypto::wallet::*;

fn benchmark_transaction_issue(c: &mut Criterion) {
    c.bench_function("benchmark_transaction_issue", |b| {
        let issuer = Wallet::new();
        let receiver = Wallet::new();
        let cap = 100000;
        let mut data: Vec<u8> = Vec::with_capacity(cap);
        for _ in 0..cap {
            data.push(128);
        }

        b.iter(|| {
            let _ = Transaction::issue(
                &issuer,
                "transaction".to_string(),
                &data,
                receiver.address(),
            );
        })
    });
}

fn benchmark_transaction_approve(c: &mut Criterion) {
    c.bench_function("benchmark_transaction_approve", |b| {
        let issuer = Wallet::new();
        let receiver = Wallet::new();
        let cap = 100000;
        let mut data: Vec<u8> = Vec::with_capacity(cap);
        for _ in 0..cap {
            data.push(128);
        }
        let mut trx = Transaction::issue(
            &issuer,
            "transaction".to_string(),
            &data,
            receiver.address(),
        );

        b.iter(|| trx.approve(&receiver).to_owned())
    });
}

fn benchmark_transaction_validate_issuer(c: &mut Criterion) {
    c.bench_function("benchmark_transaction_validate_issuer", |b| {
        let issuer = Wallet::new();
        let receiver = Wallet::new();
        let cap = 100000;
        let mut data: Vec<u8> = Vec::with_capacity(cap);
        for _ in 0..cap {
            data.push(128);
        }
        let trx = Transaction::issue(
            &issuer,
            "transaction".to_string(),
            &data,
            receiver.address(),
        );

        b.iter(|| trx.validate_for_issuer(&issuer).to_owned())
    });
}

fn benchmark_transaction_validate_receiver(c: &mut Criterion) {
    c.bench_function("benchmark_transaction_validate_receiver", |b| {
        let issuer = Wallet::new();
        let receiver = Wallet::new();
        let cap = 100000;
        let mut data: Vec<u8> = Vec::with_capacity(cap);
        for _ in 0..cap {
            data.push(128);
        }
        let mut trx = Transaction::issue(
            &issuer,
            "transaction".to_string(),
            &data,
            receiver.address(),
        );

        trx.approve(&receiver);

        b.iter(|| trx.validate_for_receiver(&issuer).to_owned())
    });
}

criterion_group!(
    benches,
    benchmark_transaction_issue,
    benchmark_transaction_approve,
    benchmark_transaction_validate_issuer,
    benchmark_transaction_validate_receiver
);
criterion_main!(benches);
