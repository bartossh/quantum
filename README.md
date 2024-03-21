# Quantum

Post quantum cryptography message broker.

## IT IS STILL A PROTOTYPE

WORK IN PROGRESS. KEEP YOUR EXPECTATIONS LOW.

## Why

### TLDR;

PQC is an essential investment in a more secure digital future. Rust, with its focus on memory safety, performance, and a growing PQC ecosystem, is a powerful language for building the secure message brokers we'll need in the quantum age.

### Actually read

The internet thrives on secure communication. We rely on cryptography to scramble messages, ensuring only authorized parties can read them. But a looming threat – the rise of quantum computers – could shatter this security.

Traditional cryptography relies on complex mathematical problems that are difficult for classical computers to solve. However, quantum computers leverage the bizarre principles of quantum mechanics to tackle these problems with frightening ease. This is where Post-Quantum Cryptography (PQC) comes in.

Why is PQC Important?

Imagine a world where emails, online banking, and even medical records are vulnerable to eavesdropping by powerful quantum computers. This isn't science fiction; it's a potential future without PQC. Here's why it's crucial:

Protecting Sensitive Information: PQC safeguards sensitive data like financial transactions, personal details, and national secrets from unauthorized access even in the quantum age.
Securing Communication Channels: PQC ensures secure communication across the internet, protecting everything from emails and instant messages to voice calls and video conferences.
Maintaining Trust in Online Systems: By bolstering cryptography, PQC helps maintain trust in online systems, fostering a more secure digital environment.
Why Use Rust for PQC Message Brokers?

Now, let's talk about building secure PQC systems. Message brokers, which handle encrypted messages, play a critical role in secure communication. Here's why Rust is an excellent choice for building PQC message brokers:

Memory Safety: Rust's ownership system prevents memory leaks and dangling pointers, common security vulnerabilities in other languages. This is crucial for PQC implementations, where even minor errors can compromise security.
Performance: Rust is known for its speed and efficiency, making it ideal for building high-performance message brokers that can handle large volumes of encrypted messages.
Modern Language Features: Rust offers features like powerful pattern matching and built-in concurrency support, simplifying complex PQC algorithms and improving development efficiency.
Growing PQC Ecosystem: The Rust community is actively developing PQC libraries and tools, providing a rich ecosystem for building secure and efficient PQC systems.
Building a Secure Future

PQC is vital for safeguarding our digital future in the age of quantum computing. By leveraging the strengths of languages like Rust, developers can build robust and secure PQC message brokers, ensuring the continued confidentiality and integrity of our online communications.

## Dependencies

1. Post quantum cryptography library used in project: [pqcrypto](https://docs.rs/pqcrypto/latest/pqcrypto/index.html).
2. Server and client are built on top of: [actix-web](https://github.com/actix/actix-web).

## Deployment

To build project use `make` command:

- server: `make server`
- client: `make client`

## Components

1. Server.
2. Client.
3. Crypto

## Testing


### Unit test

To unit test single component for example `crypto`:

```sh
cd crypto
cargo test --profile test -v -- --nocapture --test-threads=1
```

### Benchmarking

To benchmark single component for example `crypto`:

```sh
cd crypto
cargo bench 
```