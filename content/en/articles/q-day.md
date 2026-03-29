---
title: "Q-Day: Why Current Cryptography Is Not Ready for a Quantum Adversary"
date: 2026-01-27
draft: false
tags: ["CyberSecurity, QuantumComputing, Cryptography, Infosec, TechnologyStrategy, Engineeringlinux"]
---

# Q-Day: Why Current Cryptography Is Not Ready for a Quantum Adversary

**Author:** Michele Piccinni  
**Category:** Explainers  
**Reading Time:** 8 min read

---

![Copertina articolo DNS Cache Poisoning](/images/dns/cover.png)

## Introduction

In day-to-day security operations, a significant portion of the work is dedicated to mitigating known vulnerabilities; another part focuses on risks that have not yet materialized but must be considered during the planning phase. The so-called quantum threat falls into this second category, with a distinctive characteristic: the conditions that make it relevant already exist, even though the concrete effects will only manifest in the future.

This is not a hypothetical or speculative scenario, but rather a long-term risk management problem. The critical factor is not when quantum computers will become operational at scale, but the fact that data encrypted today can be collected and stored to be decrypted later, according to the model known as *Harvest Now, Decrypt Later*. In this context, the exposure window is already open.

The evolution of quantum computing poses a direct threat to the cryptographic algorithms most widely used today. Schemes such as RSA, ECDSA, and Diffie-Hellman, which form the backbone of modern communications security, were not designed to withstand adversaries equipped with sufficiently advanced quantum capabilities. To address this scenario, two distinct approaches are emerging: Post-Quantum Cryptography (PQC) and Quantum Key Distribution (QKD). Both aim to ensure the confidentiality of communications in a post-quantum context, but they rely on different technical assumptions and entail different operational implications.

Within this framework, cryptography can no longer be considered a mechanism limited to protecting credentials or commercial transactions. It is a structural component of national security, critical infrastructure, and geopolitical relations. The longevity of the informational value of data therefore becomes a central factor.

If information must remain confidential for periods of ten, twenty, or more years (as is the case for healthcare, industrial, or governmental data), the exclusive adoption of cryptographic schemes that are not resistant to a quantum adversary already represents a risk today, one that must be assessed and managed.

---

## Technical Deep Dive: PQC vs QKD and At-Risk Algorithms

Before evaluating countermeasures, it is necessary to clarify the threat model. On a sufficiently powerful quantum computer, Shor's algorithm enables integer factorization and the solution of the discrete logarithm problem in polynomial time. This renders today's most widely used public-key cryptographic schemes insecure, as their security is based precisely on the computational hardness of these problems.

Symmetric cryptography is also affected by quantum computing, albeit in a different way. Grover's algorithm enables accelerated brute-force key search, effectively reducing the security level provided by a symmetric key. To compensate for this effect, key sizes must be increased to maintain an equivalent level of protection.

Below is a quick reference table to understand the impact on the algorithms we use every day:

| **Algorithm** | **Type** | **Quantum Vulnerability** | **Security** |
| --- | --- | --- | --- |
| RSA | Asymmetric | Total (Shor) | Compromised; must be completely replaced. |
| ECC / ECDH | Asymmetric | Total (Shor) | Compromised; must be completely replaced. |
| AES | Symmetric | Partial (Grover) | Vulnerable; security is effectively halved. AES-128 becomes insecure; migration to AES-256 is required. |
| SHA-2 / SHA-3 | Hashing | Partial | Secure; increasing output size (e.g., SHA-384) is sufficient. |

NIST has published its main PQC standards (defined as Federal Information Processing Standards, or FIPS), specifying key establishment and digital signature schemes based on candidates evaluated and selected through a multi-year process: FIPS-203, FIPS-204, and FIPS-205.

With the release of the first three finalized PQC standards, organizations should begin migrating their systems toward quantum-resistant cryptography.

NIST expects that the two digital signature standards (ML-DSA and SLH-DSA) and the key encapsulation mechanism standard (ML-KEM) will form the foundation for most post-quantum cryptography implementations. They can and should be used starting today. (Reference: https://csrc.nist.gov/projects/post-quantum-cryptography#pqc-standards)

---

## Post-Quantum Cryptography (PQC) - The Software Solution

PQC is based on algorithms designed to run on current computers, but structured around mathematical problems that are sufficiently complex to resist even the computational power of future quantum computers.

### Standardized Algorithm Families (NIST)

* **Lattice-based**: The most promising family. It includes ML-KEM (formerly Kyber) for key exchange and ML-DSA (formerly Dilithium) for signatures. These schemes rely on problems such as the Shortest Vector Problem.
* **Code-based**: Derived from the McEliece system. Extremely secure and well-studied, but characterized by very large public keys.
* **Hash-based**: Used for digital signatures (e.g., SLH-DSA / SPHINCS+). Security depends exclusively on the robustness of hash functions, making this family highly reliable.
* **Isogeny-based**: Leverages properties of elliptic curves. Despite its efficiency, the recent break of the SIKE algorithm has prompted extreme caution.

### Pros and Cons of PQC:

| **Advantages** | **Limitations** |
| --- | --- |
| Compatibility: Works on existing hardware and the current Internet. | Size: Keys and signatures are larger (increased data traffic). |
| Lower Costs: Requires only software updates. | Performance: Some computations are slower than traditional RSA/ECC. |
| Scalability: Can be deployed globally in relatively short timeframes. | Theoretical Security: Based on mathematical assumptions, not physical laws. |

---

## Quantum Key Distribution (QKD) - The Physical Solution

Unlike PQC, QKD does not rely on mathematics, but on the laws of quantum mechanics to distribute cryptographic keys. The reference protocol is BB84.

### Fundamental Quantum Principles:

* **Heisenberg Uncertainty Principle**: Measuring a quantum system inevitably alters it.
* **No-Cloning Theorem**: It is impossible to copy an unknown quantum state without destroying it.

**Result:** If an attacker attempts to intercept the key during transmission, the particles (photons) change state, immediately revealing the intrusion.

### Limitations of QKD:

Despite its "theoretically perfect" security, QKD requires dedicated infrastructure (special optical fiber or satellites) and has limited range (approximately 200 km) due to signal loss. Moreover, it does not handle authentication, still requiring classical or PQC algorithms to identify the communicating parties.

---

## Comparison and Hybrid Strategy

### Comparative Analysis:

* **Security Model**: PQC is *computational* (hard to break), while QKD is *information-theoretic* (impossible to break under physical laws).
* **Implementation**: PQC is software-defined (patches and updates); QKD is hardware-defined (new physical networks).
* **Use Cases**: PQC is the solution for the mass market (web, banking, IoT). QKD is reserved for ultra-high-security scenarios (military, critical infrastructure, government communications).

### The Solution with the Hybrid Approach:

The winning strategy, known as *Defense in Depth*, involves the combined use of:

* **Classical Algorithms + PQC**: To ensure security today and during the transition phase.
* **PQC + QKD**: For ultra-sensitive data, where PQC mathematics protects authentication and QKD physics protects key confidentiality.

At this point, we leave theory behind and get hands-on directly at the shell. Below, we will see how to build a lab to negotiate the first post-quantum connection of your life.

But first, we must ask ourselves a question: how exposed are we today? Let's look at a snippet that makes this clear; as an example, the website google.com was used:

![curl](/images/qday/curl.png)

By observing this output, an analyst can see the "expiration date" of their infrastructure. Despite the use of modern protocols such as TLS 1.2, the presence of rsaEncryption and ECDHE (Elliptic Curve Diffie-Hellman Ephemeral) exposes two immediate quantum threats:

* **Shor's Algorithm**: Capable of solving discrete logarithms and factorization, nullifying current public keys.
* **PKI Instability**: If the CA signature is RSA-based, the entire chain of trust collapses.

---

## Lab in a Box

At this point, the challenge shifts to operational resilience: which cryptographic architectures must we adopt immediately to ensure that data exfiltrated today remains indecipherable even in the quantum computing era?

As indicated by NIST, the immediately adoptable solution is the use of a hybrid approach combining classical algorithms and PQC.

In this lab session, we will explore the implementation of an NGINX server configured with Post-Quantum (PQ) algorithms. For the exercise, we will use the OpenQuantumSafe (OQS) framework within a Docker Desktop containerized environment on Windows.

We will use the liboqs ecosystem, an open-source C library for quantum-resistant cryptographic algorithms, integrated into NGINX through a modified version of OpenSSL.

### Prerequisites:

Ensure that Docker Desktop (WSL2 backend) is installed and running on your system.

### Technology Stack:

* **Server**: Docker image openquantumsafe/nginx
* **Client**: Docker image openquantumsafe/curl
* **Protocol**: TLS 1.3 with Post-Quantum key exchange

---

## Step 1: Environment Preparation

Ensure that Docker Desktop is running on your Windows system. Open a terminal (PowerShell).

Download the required images from the official OpenQuantumSafe repository:

![pull](/images/qday/pull_nginx.png)
![pull](/images/qday/pull_curl.png)

Verify the downloaded images:

![pull](/images/qday/ls.png)

Create a Docker network to allow container communication:

![pull](/images/qday/ntw.png)

---

## Step 2: NGINX Server Configuration and Startup

The openquantumsafe/nginx image is preconfigured with PQC-enabled OpenSSL. By default, the server is ready to accept connections on a specific port using hybrid or purely quantum algorithms.

To observe which type of negotiation is being established, the following lines were added to the nginx.conf file to enable logging of the relevant information:

```
# --- INSIDE HTTP ---
log_format pqc_logs '$remote_addr - $remote_user [$time_local] '
                     '"$request" $status $body_bytes_sent '
                     '"$ssl_protocol" "$ssl_cipher" "$ssl_curve"';
# --- INSIDE SERVER ---
access_log  /opt/nginx/logs/access.log pqc_logs pqc_logs;
```

Start the server container exposing port 4433:

```bash
docker run -d --network nginx-test --name oq-nginx -p 4433:4433 openquantumsafe/nginx
```

Tail the NGINX container log file:

```bash
docker logs tail -100 oq-nginx
```

---

## Step 3: Functional Testing

Perform two connection tests targeting the local IP address (or the container name if on the same Docker network), using the curl container, while simultaneously tailing the NGINX log. This allows us to observe which algorithm is being negotiated:

* The first test is performed without forcing post-quantum mode; the server negotiates a modern, highly secure connection still based on classical (pre-quantum) cryptography.
* The second test forces a quantum algorithm in hybrid mode.

---

## First Test

![test1](/images/qday/test1.png)

This string represents the technical details of a secure TLS 1.3 connection. It describes the "rules of the game" agreed upon by the client (e.g., curl) and the server (e.g., NGINX) to protect data.

It consists of two main components: the Cipher Suite and the Key Exchange Group.

### 1. TLS_AES_256_GCM_SHA384 (Cipher Suite)

This defines the algorithms used for data encryption and integrity once the connection is established.

* **TLS**: Indicates the protocol used (TLS 1.3).
* **AES_256_GCM**: The symmetric encryption algorithm.
  * **AES-256**: Uses 256-bit keys (extremely secure).
  * **GCM (Galois/Counter Mode)**: Provides both confidentiality and data authentication (AEAD).
* **SHA384**: Hash function used for message digests and key derivation.

### 2. X25519 (Key Exchange)

The most critical component in modern (but not yet post-quantum) cryptography.

* **X25519**: An elliptic curve (based on Curve25519) used for Diffie-Hellman key exchange (ECDHE).
* **Purpose**: Enables two parties to derive a shared secret over a public channel.
* **Quantum Limitation**: While secure today, it is vulnerable to future quantum computers via Shor's algorithm.

---

## Second Test

![test2](/images/qday/test2.png)

Here we switch to a hybrid connection. Details:

### 1. TLS_AES_256_GCM_SHA384

Unchanged from the previous test. This is the "vault" protecting data once the connection is established.

### 2. X25519MLKEM768 (Quantum Innovation)

This is the true novelty of the OpenQuantumSafe test: a hybrid key exchange algorithm.

* **X25519**: Classical elliptic-curve-based algorithm.
* **ML-KEM-768**: NIST post-quantum standard (formerly Kyber-768), based on lattice problems that quantum computers cannot efficiently solve.
* **Why hybrid?** During the transition phase, both are used. The final key is derived by combining both results.
  * If Kyber has a bug, X25519 still protects you.
  * If a quantum computer breaks X25519, Kyber protects you.

### Comparative Table:

| **Algorithm** | **X25519 (Classical)** | **X25519MLKEM768 (Hybrid)** |
| --- | --- | --- |
| Quantum Resistance | No | Yes |
| Key Size | Small (~32 bytes) | Large (~1200 bytes) |
| Standardization | Mature | New NIST standard (FIPS 203) |
| Browser Support | Universal | Chrome 131+, Firefox 132+, Safari 2026+ |

---

## Conclusions

In a hybrid architecture (such as X25519MLKEM768), the classical component (X25519) is not a forgotten legacy artifact, but fulfills two critical "combined security" roles:

### 1. Security Fallback

Post-quantum algorithms such as ML-KEM (Kyber) are relatively new. If a mathematical vulnerability were discovered allowing a classical computer to break ML-KEM, the connection would still be protected by X25519.

* **Logic**: An attacker must break both algorithms simultaneously.

### 2. Compatibility with Non-PQC Systems

If the client (e.g., an older browser or IoT device) does not support OpenQuantumSafe libraries, NGINX can fall back and negotiate a connection using only X25519.

* Without this mechanism, non-quantum-capable systems would be excluded from the network.

An increasingly common modern attack scenario is *Store Now, Decrypt Later*: today, an attacker records traffic protected only by X25519; in ten years, a quantum computer is used to break X25519 and decrypt historical data.

By using the quantum component now, you render that data unreadable even to future quantum computers.

### Summary of the Lab Hierarchy:

* **X25519MLKEM768**: Highest level (Hybrid). Protects against classical and quantum computers.
* **X25519**: "Luxury fallback." Excellent today, vulnerable in the future.
* **RSA/DH**: True legacy. Must be eliminated.

---

## Appendix: Creating Test CA and Server Certificates

**Note:** For demonstration purposes, the OQS-nginx image is provided with preloaded server and CA certificates. In real deployments, dedicated server certificates must be installed. This can be facilitated by mounting your own key and server certificate into the image at /opt/nginx/pki.

Assuming the server certificate and key are located in a local folder named server-pki, the startup command would be:

```bash
docker run -d --network nginx-test --name oq-nginx \
  -v $(pwd)/server-pki:/opt/nginx/pki \
  -p 4433:4433 openquantumsafe/nginx
```

### Creating (Test) CA and Server Certificates

To create the required keys and certificates, the openquantumsafe/curl image can be used with standard OpenSSL commands.

An example sequence is shown below using:

* **qteslapi** for CA certificate signing;
* **dilithium2** for server certificate signing;
* **nginx-server.my.org** as the server address.

Any currently supported quantum-safe authentication algorithm can be used instead of qteslapi or dilithium2.

```bash
# Create a new directory for keys and certificates
mkdir -p server-pki && cd server-pki

# Create the key and the CA certificate with qteslapi
docker run -v $(pwd):/opt/tmp -it openquantumsafe/curl openssl req -x509 \
  -new -newkey qteslapi -keyout /opt/tmp/CA.key -out /opt/tmp/CA.crt \
  -nodes -subj "/CN=oqstest CA" -days 365

# Create the server's key with dilithium2
docker run -v $(pwd):/opt/tmp -it openquantumsafe/curl openssl req -new \
  -newkey dilithium2 -keyout /opt/tmp/server.key -out /opt/tmp/server.csr \
  -nodes -subj "/CN=nginx-server.my.org"

# Create the certificate for the server
docker run -v $(pwd):/opt/tmp -it openquantumsafe/curl openssl x509 -req \
  -in /opt/tmp/server.csr -out /opt/tmp/server.crt \
  -CA /opt/tmp/CA.crt -CAkey /opt/tmp/CA.key -CAcreateserial -days 365
```

It is recommended to omit the -nodes option in the CA key generation command to ensure the key is encrypted, allowing it to be stored securely for future use.

---

## Related Articles

![How to Execute a DNS Cache Poisoning Attack: Between Entropy and Post-Quantum](https://8bitsecurity.com/images/eDy1t1mY0u-300.jpeg)

### [How to Execute a DNS Cache Poisoning Attack: Between Entropy and Post-Quantum](https://8bitsecurity.com/posts/how-to-execute-a-dns-cache-poisoning-attack-between-entropy-and-post-quantum/)

![How to attack Large Language Models using Poetry](https://8bitsecurity.com/images/oL91tK4sHg-300.jpeg)

### [How to attack Large Language Models using Poetry](https://8bitsecurity.com/posts/how-to-attack-large-language-models-using-poetry/)

![Chain-Of-Thoughts Hijacking against Reasoning Models](https://8bitsecurity.com/images/7xqRhUMYR3-300.jpeg)

### [Chain-Of-Thoughts Hijacking against Reasoning Models](https://8bitsecurity.com/posts/chain-of-thoughts-hijacking-against-reasoning-models/)

![Threat Hunting Cobalt Strike The Final Guide: From the Depths of Beaconing to C2 Infrastructure](https://8bitsecurity.com/images/pAxgM2TrTy-300.jpeg)

### [Threat Hunting Cobalt Strike The Final Guide: From the Depths of Beaconing to C2 Infrastructure](https://8bitsecurity.com/posts/threat-hunting-cobalt-strike-the-final-guide-from-the-depths-of-beaconing-to-c2-infrastructure/)

![Malware Analysis: Reverse Engineering of an ELF File (Linux)](https://8bitsecurity.com/images/zq-NE5g3jY-300.jpeg)

### [Malware Analysis: Reverse Engineering of an ELF File (Linux)](https://8bitsecurity.com/posts/malware-analysis-reverse-engineering-of-an-elf-file-linux/)

---

**Source:** [8BitSecurity](https://8bitsecurity.com/)  
**Article URL:** https://8bitsecurity.com/posts/q-day-why-current-cryptography-is-not-ready-for-a-quantum-adversary/


