# Authentication with Trusted Third Party (TTP)

A Python implementation of a three-party authentication scheme using a **Trusted Third Party (TTP)**, built around RSA key pairs, X.509 certificates, and hybrid (RSA + AES) encryption.

This project was built as an academic exercise to practice applied cryptography: asymmetric key management, certificate issuance/verification, and secure session key exchange between parties that don't trust each other directly.

> **Note on authorship:** this was a two-person university project. I designed and implemented the cryptographic logic and all three backend components (TTP, server, client communication/protocol logic). My teammate built the GUI and the project documentation.

---

## Project Overview

The system models a classic **trusted third party authentication** scenario with three components:

- **TTP (Trusted Third Party)** — the central authority. Issues and signs X.509 certificates for the other two parties and helps establish a shared session key between them.
- **Server** — a service that clients want to authenticate with. Trusts the TTP to vouch for client identities.
- **Client** — the GUI application end users interact with to authenticate against the server via the TTP.

Instead of the client and server trusting each other directly, both trust the TTP, which issues certificates and mediates the initial handshake — a simplified model of how real-world PKI (Public Key Infrastructure) systems work.

---

## How It Works

1. **Key & certificate generation** — each party generates an RSA-2048 key pair. The TTP issues an X.509 certificate binding each party's identity (Common Name) to its public key, self-signed with SHA-256.
2. **Asymmetric handshake** — parties exchange and verify certificates, then use **RSA-OAEP** (with SHA-256) to securely encrypt and exchange data needed to establish a shared session key.
3. **Symmetric session encryption** — once a session key is established, all further communication between client and server is encrypted with **AES-256 in CBC mode**, using a fresh random IV for every message.
4. **Persistence** — generated keys and certificates are stored locally as PEM files so a party doesn't need to regenerate them on every run.

This hybrid approach (asymmetric for the handshake, symmetric for the actual data) mirrors how protocols like TLS work in practice.

---

## Technologies Used

- **Python**
- **`cryptography`** library — RSA key generation, X.509 certificate building/signing, AES-CBC and RSA-OAEP encryption
- **Docker / Docker Compose** — containerized TTP and server components
- Raw **socket-based networking** for communication between TTP, server, and client

---

## Project Structure

```
authentication-with-ttp/
├── ttp/              # Trusted Third Party service (certificate issuing, handshake mediation)
├── server/           # Service the client authenticates against
├── client/           # GUI client application
├── documentation/    # Project write-up
├── generator.py      # Core crypto utilities: RSA keys, X.509 certs, AES/RSA encryption helpers
├── docker-compose.yml
└── requirements.txt
```

---

## Running the Project

### Prerequisites

- Docker and Docker Compose
- Python 3 (for running the client locally, if not containerized)

### Steps

1. Clone the repository.
2. Start the TTP and server containers:
   ```
   docker-compose up --build
   ```
   This starts:
   - `ttp` on port `9000`
   - `server` on port `9001` (waits for `ttp` to be available)
3. Run the client application separately to connect and authenticate against the server through the TTP.

On first run, each component generates its own RSA key pair and certificate (saved locally as `key.pem` / `cert.pem`); subsequent runs reuse them instead of regenerating.

---

## What I'd Improve

This was a learning-focused academic project, so a few things are simplified compared to a production-grade implementation:

- Private keys are stored unencrypted on disk (no passphrase protection).
- Certificate validation doesn't yet support revocation or full chain verification beyond the single-CA (TTP) model.
- AES padding uses a simple space-padding scheme rather than a standard like PKCS#7.

---

*This project was developed for academic purposes.*
