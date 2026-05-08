# Confidential AI Agent

An AI agent that runs LLM calls inside an Intel SGX enclave. The Anthropic API key never touches the host. Every response is cryptographically signed and independently verifiable.

Built with Python, LangGraph, Gramine, and the Anthropic Claude API. Deployed on Azure DCsv3 (SGX-capable hardware).

---

## What this project does

When you send a message to this agent, the following happens:

1. The LangGraph host agent receives your message and forwards it to the enclave over a TCP socket.
2. Inside the SGX enclave, the Anthropic API key is decrypted from hardware-sealed storage, and the Claude API is called.
3. The enclave signs the response using an ECDSA private key that also lives in sealed storage.
4. The host receives the response, the signature, and a DCAP attestation quote.
5. The host verifies the signature and the quote before showing you anything.

The host process never sees the API key. The signing private key never leaves the enclave. A third party can verify that a specific response came from a specific enclave running on real Intel SGX hardware.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  HOST (outside SGX)                                         │
│                                                             │
│  LangGraph agent                                            │
│   - manages conversation state                              │
│   - routes prompts to enclave via TCP                       │
│   - verifies every response signature                       │
│   - verifies DCAP attestation quote at startup              │
│   - writes to audit log                                     │
└────────────────────────┬────────────────────────────────────┘
                         │ TCP socket (localhost:7777)
                         │ JSON messages, length-prefixed
┌────────────────────────▼────────────────────────────────────┐
│  SGX ENCLAVE (inside Gramine LibOS)                         │
│                                                             │
│  enclave_llm.py                                             │
│   - loads API key from /sealed/anthropic_api_key            │
│   - loads signing key from /sealed/signing_key              │
│   - calls api.anthropic.com over HTTPS                      │
│   - signs: SHA256(prompt ‖ result ‖ timestamp ‖ MRENCLAVE)  │
│   - generates DCAP quote with SHA256(pubkey) in report_data │
└─────────────────────────────────────────────────────────────┘
                         │
                         │ /sealed mount (encrypted, key = _sgx_mrenclave)
┌────────────────────────▼────────────────────────────────────┐
│  SEALED STORAGE (disk, encrypted)                           │
│                                                             │
│  /sealed/anthropic_api_key   — Anthropic API key            │
│  /sealed/signing_key         — ECDSA P-256 private key      │
│                                                             │
│  Decryption key = KDF(MRENCLAVE, CPU hardware secret)       │
│  Unreadable outside this exact enclave on this exact CPU    │
└─────────────────────────────────────────────────────────────┘
```

---

## What SGX protects

**Memory encryption.** The enclave runs in a region of memory called EPC (Enclave Page Cache). The CPU encrypts this memory using a key only the CPU knows. The host OS, hypervisor, and even Azure infrastructure cannot read enclave memory.

**Sealed storage.** Files written to the `/sealed` mount are encrypted with a key derived from two things: the enclave's MRENCLAVE measurement and a hardware secret fused into the CPU at manufacture. This means only this exact enclave (same code, same configuration) on this exact physical CPU can decrypt them. If you change a single line of enclave code, the MRENCLAVE changes and the sealed files become permanently unreadable.

**Remote attestation.** The DCAP quote is a cryptographic certificate signed by Intel's PKI. It contains the enclave's MRENCLAVE, its configuration, and the `report_data` field which we populate with `SHA256(signing_public_key)`. A verifier anywhere in the world can check this quote against Intel's certificate authority and confirm: this response was signed by a key that was present inside a real SGX enclave with measurement X.

**Output integrity.** Every LLM response is signed with `ECDSA-P256` over `SHA256(prompt ‖ result ‖ timestamp ‖ MRENCLAVE)`. The signature covers the input, the output, and the enclave identity. A tampered response cannot produce a valid signature.

---

## Threat model

### What this system defends against

**Stolen API key.** A malicious host operator with root access cannot read the API key from memory or disk. The key exists only inside the enclave and in encrypted form on disk.

**Response tampering.** A man-in-the-middle between the enclave and the host cannot modify a response without invalidating the ECDSA signature.

**Code substitution.** If someone replaces the enclave binary with a different one, the MRENCLAVE changes. The DCAP quote will carry the new MRENCLAVE, which will not match the expected value published by the developer. Verification will fail.

**Impersonation.** An attacker cannot produce a valid DCAP quote for a fake enclave without access to Intel's signing infrastructure. The quote signature chain goes up to Intel's root CA.

### What this system does not defend against

**Compromised CPU or Intel.** SGX's root of trust is Intel. If Intel's PKI is compromised, or if the CPU itself is backdoored, the guarantees do not hold.

**Malicious prompts exfiltrated through the LLM response.** The enclave signs the response but does not enforce what the response says. A prompt injection attack could cause the LLM to include sensitive content in its response, which the enclave would faithfully sign and return. Policy enforcement on response content is not implemented (see future work).

**DNS hijacking.** DNS resolution happens on the host OS, not inside the enclave. A compromised host could redirect `api.anthropic.com` to a different server. The TLS certificate is verified inside the enclave using the `certifi` CA bundle, which is measured in MRENCLAVE, so a redirected server would need a valid certificate for `api.anthropic.com` to pass verification.

**Side-channel attacks.** SGX has a history of microarchitectural side-channel vulnerabilities (Spectre, Foreshadow, SGAxe). The DCsv3 hardware used here has microcode mitigations for known attacks, but this is not a strong guarantee against a sophisticated attacker with physical access.

**Enclave code is visible.** The enclave binary is not secret. Anyone can inspect it. This is by design — the value of the system comes from the verifiable guarantee that the code running matches the inspected binary, not from secrecy of the code itself.

**Gramine increases TCB.** Using Gramine as a LibOS layer adds complexity to the Trusted Computing Base compared to a native SGX enclave. Gramine is a large, well-maintained project, but more code in the TCB means more potential attack surface.

**Bootstrap requires one trusted run.** On first startup, the `ANTHROPIC_API_KEY` is passed as an environment variable, visible to the host OS. This happens only once: the enclave immediately seals it to hardware-encrypted storage and it is never passed in plaintext again. In a production deployment, this bootstrap step would use remote attestation — the enclave would prove its identity before receiving the key from a trusted provisioning server.

**Ephemeral session, persistent identity.** The signing key persists across restarts (it is sealed to storage). The DCAP quote is regenerated each session. A verifier cannot link two sessions without the published MRENCLAVE as an anchor, but can verify that both sessions used keys from enclaves with the same measurement.

---

## How to verify a response

The project includes a standalone verification CLI. It does not require SGX hardware to run — you can verify a response on any machine with the Intel DCAP libraries and the Azure QPL installed.

```bash
python3 verify/verify_output.py \
  --quote enclave_quote.bin \
  --response response.json \
  --expected-mrenclave <mrenclave-hex>
```

The response JSON must contain:

```json
{
  "prompt": "...",
  "result": "...",
  "timestamp": 1234567890.0,
  "mrenclave": "...",
  "signature_hex": "...",
  "public_key_pem": "-----BEGIN PUBLIC KEY-----\n...",
  "payload_hash": "..."
}
```

The verifier checks three things independently:

**Structural.** Parses the DCAP quote binary, extracts MRENCLAVE and `report_data`, confirms MRENCLAVE matches the expected value, and confirms `report_data[:32] == SHA256(public_key_der)`. This proves the quote was built for this specific signing key.

**Cryptographic.** Calls `tee_verify_quote` from Intel's `libsgx_dcap_quoteverify` library using the Azure THIM endpoint to fetch collateral. Confirms the quote signature chain is valid up to Intel's root CA. This proves the quote came from real SGX hardware.

**Response signature.** Rebuilds the signed payload `SHA256(prompt ‖ result ‖ timestamp ‖ mrenclave)` and verifies the ECDSA signature using the public key from the quote. This proves the response content has not been modified since it left the enclave.

A response passes verification only if all three checks succeed.

---

## Setup and first run

### Prerequisites

- Azure DCsv3 VM (or any Intel SGX-capable machine with FLC support)
- Ubuntu 22.04 or 24.04
- Gramine 1.9 installed
- Intel SGX PSW and AESMD running
- Azure DCAP QPL (`az-dcap-client` or built from source)
- Python 3.12
- `uv` for enclave dependency management

### Installation

```bash
git clone <repo>
cd confidential-ai

# Install host dependencies
pip3 install langgraph langchain-core cryptography

# Set up the enclave Python environment
cd enclave
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python \
  anthropic httpx certifi cryptography

# Build the enclave
make
```

### First run — bootstrap sealed storage

On first run, provide the Anthropic API key. The enclave will seal it immediately and never require it again.

```bash
# Terminal 1 — start the enclave
cd enclave
ANTHROPIC_API_KEY=sk-ant-... gramine-sgx enclave_llm
```

Wait for:
```
API key sealed to /sealed/anthropic_api_key (future runs need no env var)
Signing key sealed to /sealed/signing_key
DCAP quote generated (4734 bytes)
Ready — waiting for connections on port 7777
```

```bash
# Terminal 2 — run the agent
python3 host/langgraph_agent.py
```

### All subsequent runs — no secrets needed

```bash
# Terminal 1
gramine-sgx enclave_llm

# Terminal 2
python3 host/langgraph_agent.py
```

### What to do after changing enclave code

When you modify `enclave_llm.py` or the manifest, MRENCLAVE changes and the sealed files become unreadable. This is correct behavior.

```bash
# Delete stale sealed files
rm ~/confidential-ai/sealed/*

# Rebuild
cd enclave && make clean && make

# Re-bootstrap with API key
ANTHROPIC_API_KEY=sk-ant-... gramine-sgx enclave_llm

# Update the expected MRENCLAVE
# (printed as "Measurement:" during make)
echo "<new-mrenclave>" > expected_mrenclave.txt
```

---

## Project structure

```
confidential-ai/
├── enclave/
│   ├── enclave_llm.py                 # enclave process — runs inside SGX
│   ├── enclave_llm.manifest.template  # Gramine manifest — defines trust boundary
│   ├── Makefile
│   └── .venv/                         # Python packages for the enclave
├── host/
│   ├── langgraph_agent.py             # LangGraph conversational agent
│   └── host_agent.py                  # simple test harness
├── verify/
│   ├── quote_verifier.py              # verification logic (importable)
│   └── verify_output.py               # standalone verification CLI
├── sealed/                            # hardware-encrypted secrets (gitignored)
├── expected_mrenclave.txt             # canonical enclave measurement
├── audit_log.jsonl                    # append-only verified response log
└── README.md
```

---

## Known limitations and future work

**Post-quantum signing.** Output signing uses ECDSA P-256, which is vulnerable to Shor's algorithm on a sufficiently powerful quantum computer. A production deployment should use a hybrid scheme combining ECDSA P-256 with ML-DSA (NIST FIPS 204). The signing primitive in `enclave_llm.py` and the verification primitive in the CLI are the only components that would need to change.

**Bootstrap security.** The first run exposes `ANTHROPIC_API_KEY` as an environment variable, visible to the host. In production, this should use a remote attestation provisioning flow: the enclave generates a DCAP quote, a trusted provisioning server verifies the quote, and only then sends the key over a TLS channel attested to the enclave's MRENCLAVE.

**Policy enforcement.** The enclave signs whatever the LLM returns. A future version could add a policy engine inside the enclave that validates outputs before signing — for example, refusing to sign responses that contain patterns matching known sensitive data formats.

**Conversation history in the clear.** The full conversation history is sent to the enclave with each prompt. A host operator can see all conversation history. Encrypting conversation history between the host and the enclave would require a separate key exchange protocol.

**AMD SEV-SNP.** This project uses Intel SGX because it offers process-level isolation and mature DCAP attestation tooling via Gramine. AMD SEV-SNP provides VM-level confidential computing with a different trust boundary. The architectural principles here — sealed secrets, signed outputs, remote attestation — apply equally to SEV-SNP. A production system might use both: SEV-SNP for infrastructure-level isolation and SGX for application-level key protection.

**Persistent audit log.** The current audit log is append-only but not tamper-evident. A production version should chain entries with cryptographic hashes, producing a verifiable log where any modification to a past entry invalidates all subsequent entries.

---

## Hardware and infrastructure

- **VM:** Azure Standard_DC2s_v3 (2 vCPU, 16 GB RAM, 8 GB EPC)
- **CPU:** Intel Xeon 8370C (Ice Lake), SGX1 + SGX2, FLC
- **Attestation:** DCAP via Azure THIM (`global.acccache.azure.net`)
- **Gramine:** 1.9
- **Python:** 3.12.3
- **Anthropic SDK:** 0.97.0

---

## Background

This project was built to explore what it looks like to run a modern AI agent inside a hardware-enforced trust boundary. The core question it answers is: can a user verify not just what an AI said, but that it said it from inside a specific, auditable, hardware-protected environment?

The answer, after working through the SGX toolchain, Gramine, DCAP attestation, and the Anthropic SDK, is yes — with the limitations documented above.

The combination of LangGraph for agent orchestration, Gramine for SGX compatibility, and DCAP for remote attestation is not something that existed as a published, working implementation before this project. Each component is well-documented in isolation. The integration is the contribution.
