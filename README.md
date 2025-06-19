# Trusted Hardware for Secure Data Lakes

This repository contains the final project for the **Trusted Hardware and Secure Applications** course (University of Porto, 2024/2025), focused on secure collaborative data processing using Intel SGX.
It also includes **theoretical and practical lab assignments** involving Smartcards, cryptographic protocols, and trusted hardware fundamentals.



## Project Summary

This project implements a secure data lake architecture using **Intel SGX enclaves**, allowing multiple entities (e.g., hospitals and laboratories) to collaboratively store and process **sensitive medical data**. The goal is to ensure **confidentiality, integrity, and trust** across all operations through hardware-based trusted execution.

The system supports:

- Secure storage and encrypted transmission of data
- Remote attestation of enclaves (via Azure Attestation)
- Multi-entity participation with digital signature validation
- Privacy-preserving statistics computation (e.g., averages, modes)
- Key wrapping for encrypted recovery and secure key management


## Key Concepts

- **Intel SGX**: Trusted Execution Environment (TEE) for running secure code in isolated enclaves
- **Remote Attestation**: Verifies enclave legitimacy before data sharing
- **Key Wrapping**: Enables distributed key recovery across entities
- **Privacy-Preserving Analytics**: No raw data ever leaves the enclave


## Technologies & Tools

- **C++ with Intel SGX SDK**
- **Azure Confidential Computing (Attestation)**
- **OpenSSL** for cryptographic primitives (ECDSA, ECC, Base64)
- **Google Cloud Storage** for secure persistence of encrypted data
- **Linux Pipes + SSH** for secure inter-process communication


## Supported Operations

- `encrypt`: Securely encrypt and upload datasets
- `stat`: Perform statistical operations (e.g., average, mode) on encrypted datasets
- `addkey`: Submit an entity's private key to unlock the master key (via recursive wrapping)


## Datasets Used

Two synthetic datasets simulate real medical use cases:

- **hospital.csv** — Patient admission and diagnostic data  
- **laboratory.csv** — Exam results mapped via patient healthcare ID  

These were used to test authorization, encryption, statistical aggregation, and access control mechanisms.


## Security Guarantees

- **Data confidentiality** — Enforced by SGX memory encryption (MEE)
- **Code integrity** — Verified through remote attestation and hardcoded public keys
- **Access control** — Enforced via multi-party digital signatures
- **Replay resistance** — Timestamp validation prevents message re-use
- **Scalability** — Modular design supports integration of new entities


## Repository Structure

```
/
├── labs/ # Lab assignments (JavaCard, Trusted Hardware)
├── projeto/ # Project Trusted Hardware (code, datasets, report)
└── README.md 
```

## Included Labs

This repository also contains theoretical and practical lab assignments from the Trusted Hardware and Secure Applications course on **labs/**:

- **Smartcards (JavaCard)**: Labs involving applet development, secure PIN handling, and symmetric cryptography (DES/AES)  
- Theoretical labs about trusted hardware.

## Project Report

The project design, implementation, and analysis are documented in [`projeto/report.pdf`](projeto/report.pdf).

