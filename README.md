# Confidential AI Agent

A LangGraph-based AI agent where the Claude API key and signing key live inside an Intel SGX enclave. The LLM call executes from inside the enclave. The host process never holds secrets. Every response is cryptographically signed and independently verifiable.

**Repository:** https://github.com/mkaihara/confidential-ai-agent

---

## What this project demonstrates

- A running LLM agent whose API credentials are sealed inside SGX hardware
- Cryptographic output signing: every response carries an ECDSA-P256 signature over `SHA256(prompt || result || timestamp || MRENCLAVE)`
- DCAP remote attestation: a DCAP quote binds the signing key to the enclave measurement, verified against Intel's certificate authority
- An independent verification CLI that validates the complete trust chain without requiring access to the running system

The combination is new. Gramine running the Anthropic Python SDK with sealed storage, output signing, and DCAP attestation wired together in a LangGraph agent has no prior published implementation.

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│  Host process (host/langgraph_agent.py)                 │
│                                                         │
│  LangGraph agent — manages conversation state           │
│  Verifies every response signature before display       │
│  Writes append-only audit log                           │
│  Never holds API key or signing private key             │
└────────────────┬────────────────────────────────────────┘
                 │  TCP socket (localhost:7777)
                 │  JSON + length-prefix framing
┌────────────────▼────────────────────────────────────────┐
│  SGX Enclave (enclave/enclave_llm.py via Gramine)       │
│                                                         │
│  Secrets in memory:                                     │
│    Claude API key  — decrypted from /secrets at startup │
│    ECDSA-P256 signing key — generated fresh each run    │
│                                                         │
│  On each prompt:                                        │
│    1. Call api.anthropic.com via HTTPS (TLS inside SGX) │
│    2. Sign SHA256(prompt || result || timestamp ||       │
│                   MRENCLAVE)                            │
│    3. Return result + signature + DCAP quote            │
│                                                         │
│  Sealed storage:                                        │
│    /secrets/anthropic_api_key.txt  (external wrap key)  │
│    /sealed/wrap_key  (_sgx_mrenclave key — hardware)    │
└─────────────────────────────────────────────────────────┘
```

### Trust boundary

The host manages agent orchestration, user I/O, and non-sensitive logging. The enclave manages secrets and LLM calls. The host receives only response text, signatures, and the public key — nothing that requires confidentiality.

---

## What SGX protects

**Confidentiality of secrets at runtime.** The Claude API key is decrypted inside the enclave using a Gramine-managed encrypted filesystem. The host OS sees only ciphertext on disk. The key exists in plaintext only inside EPC (Enclave Page Cache) memory, which is encrypted by the CPU's Memory Encryption Engine. A root-level attacker on the host cannot read EPC memory contents.

**Integrity of the enclave code.** The MRENCLAVE value `5013fc039c76d3bc0d75f9a1f44e1efa249461257bd38d58d1294420ceac902f` is a SHA256 measurement over every page loaded into the enclave — the Python source, all trusted libraries, and the manifest configuration. If any file in `sgx.trusted_files` is modified, Gramine refuses to load it.

**Authenticity of outputs.** Every response is signed inside the enclave with a key that never exits EPC memory. The DCAP quote binds the signing public key to the MRENCLAVE via Intel's PKI, so a verifier can establish: this signature was produced by this exact code running on genuine Intel SGX hardware.

**Sealed wrap key.** After the first run, the wrap key for `/secrets` is sealed using the `_sgx_mrenclave` Gramine key — derived from MRENCLAVE and the CPU hardware secret. Subsequent enclave starts require no external secrets.

---

## Threat model

### Attacker capabilities considered

A root-level attacker with full access to the host OS: can read all host memory, modify files on disk, intercept network traffic, and inspect process state. This is the primary threat SGX is designed to address.

### What the system defends against

| Attack | Defense |
|--------|---------|
| Read API key from host memory | Key exists only in EPC, encrypted by CPU MEE |
| Read API key from disk | Encrypted file, key derived from MRENCLAVE + CPU hardware secret |
| Modify enclave code to exfiltrate key | MRENCLAVE changes, sealed files become unreadable, quote verification fails |
| Substitute a different enclave | MRENCLAVE mismatch detected by verifier |
| Forge a response signature | Private key never exits enclave memory |
| Replay an old response | Timestamp is bound into the signature |
| Claim a different enclave produced the response | DCAP quote binds signing key to MRENCLAVE via Intel CA |

### What the system does NOT defend against

| Limitation | Notes |
|-----------|-------|
| DNS resolution | Host OS controls DNS. Mitigated by TLS certificate verification inside the enclave using the measured `certifi` CA bundle. A host cannot redirect connections without breaking TLS. |
| Network-level interception | Enclave makes outbound TLS connections through the host network stack. Host sees ciphertext only. |
| Wrap key bootstrapping | On first run, `WRAP_KEY_HEX` is passed as an environment variable visible to the host. Production fix: deliver the wrap key via remote attestation — the verifier confirms the DCAP quote, then sends the wrap key encrypted to the enclave's public key. |
| Ephemeral signing key | The ECDSA signing key is generated fresh on each enclave start. No identity continuity across sessions. Fix: seal the signing key with `_sgx_mrenclave`, identical to the wrap key sealing already implemented. |
| Gramine TCB | Gramine increases the trusted computing base relative to a native SGX enclave. The LibOS, syscall shim, and Python runtime are all inside the trust boundary. |
| SGX debug mode | This build uses `sgx.debug = true`. Debug enclaves can be attached with a debugger. Production deployments must set `sgx.debug = false` and re-measure. |
| Microarchitectural side channels | SGX does not protect against all side-channel attacks (Spectre, Foreshadow, etc.). Intel microcode mitigations reduce but do not eliminate this surface. |
| Post-quantum cryptography | ECDSA-P256 is vulnerable to Shor's algorithm. A production deployment should use a hybrid classical/post-quantum scheme combining ECDSA-P256 with ML-DSA (NIST FIPS 204). |

---

## Project structure

```
confidential-ai-agent/
├── enclave/
│   ├── enclave_llm.py                  # Enclave process — runs inside SGX
│   ├── enclave_llm.manifest.template   # Gramine manifest — defines trust boundary
│   └── Makefile
├── host/
│   ├── langgraph_agent.py              # LangGraph agent — runs on host
│   └── host_agent.py                   # Low-level test harness
├── verify/
│   ├── quote_verifier.py               # Verification engine (importable)
│   └── verify_output.py                # Standalone verification CLI
├── secrets/
│   ├── anthropic_api_key.txt           # Encrypted — readable only inside enclave
│   ├── wrap_key.bin                    # 16-byte AES wrap key (binary)
│   └── wrap_key.hex                    # Hex-encoded wrap key for bootstrapping
├── sealed/
│   └── wrap_key                        # Wrap key sealed with _sgx_mrenclave key
├── expected_mrenclave.txt              # Published expected enclave measurement
└── audit_log.jsonl                     # Append-only session audit log
```

---

## Prerequisites

- Azure DCsv3 VM (Standard_DC2s_v3 or larger) — SGX2 + FLC required
- Ubuntu 24.04 (Noble)
- Gramine 1.9
- Intel SGX PSW + AESMD
- Azure DCAP client (built from source — `az-dcap-client` not yet packaged for Ubuntu 24.04)
- Python 3.12
- uv (Python package manager)

---

## Setup

### 1. Install Gramine and SGX PSW

```bash
# Add Gramine repo
sudo curl -fsSLo /etc/apt/keyrings/gramine-keyring-$(lsb_release -sc).gpg \
  https://packages.gramineproject.io/gramine-keyring-$(lsb_release -sc).gpg
echo "deb [arch=amd64 signed-by=/etc/apt/keyrings/gramine-keyring-$(lsb_release -sc).gpg] \
  https://packages.gramineproject.io/ $(lsb_release -sc) main" \
  | sudo tee /etc/apt/sources.list.d/gramine.list

# Add Intel SGX repo
sudo curl -fsSLo /etc/apt/keyrings/intel-sgx-deb.asc \
  https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key
echo "deb [arch=amd64 signed-by=/etc/apt/keyrings/intel-sgx-deb.asc] \
  https://download.01.org/intel-sgx/sgx_repo/ubuntu $(lsb_release -sc) main" \
  | sudo tee /etc/apt/sources.list.d/intel-sgx.list

sudo apt-get update
sudo apt-get install -y gramine libsgx-enclave-common libsgx-urts \
  libsgx-aesm-launch-plugin libsgx-aesm-pce-plugin libsgx-aesm-ecdsa-plugin \
  libsgx-aesm-quote-ex-plugin libsgx-pce-logic libsgx-qe3-logic \
  libsgx-dcap-ql libsgx-dcap-default-qpl libsgx-quote-ex sgx-aesm-service

sudo systemctl enable aesmd && sudo systemctl start aesmd
```

### 2. Configure Azure THIM endpoint

```bash
sudo tee /etc/sgx_default_qcnl.conf << 'EOF'
{
  "pccs_url": "https://global.acccache.azure.net/sgx/certification/v4/",
  "use_secure_cert": true,
  "collateral_service": "https://global.acccache.azure.net/sgx/certification/v4/",
  "pccs_api_version": "3.1",
  "retry_times": 6,
  "retry_delay": 5,
  "local_pck_url": "http://169.254.169.254/metadata/THIM/sgx/certification/v4/",
  "pck_cache_expire_hours": 168,
  "verify_collateral_cache_expire_hours": 168,
  "local_cache_only": false
}
EOF
sudo systemctl restart aesmd
```

### 3. Build and install Azure DCAP client

The `az-dcap-client` package is not available for Ubuntu 24.04. Build from source:

```bash
sudo apt-get install -y cmake build-essential libssl-dev libcurl4-openssl-dev \
  pkg-config libgtest-dev nlohmann-json3-dev

git clone https://github.com/microsoft/Azure-DCAP-Client.git
cd Azure-DCAP-Client/src/Linux
./configure && make

sudo mv /usr/lib/x86_64-linux-gnu/libdcap_quoteprov.so.1.*.0 \
  /tmp/libdcap_quoteprov.so.intel.bak
sudo cp libdcap_quoteprov.so \
  /usr/lib/x86_64-linux-gnu/libdcap_quoteprov.so.1.microsoft
sudo rm -f /usr/lib/x86_64-linux-gnu/libdcap_quoteprov.so.1
sudo ln -s libdcap_quoteprov.so.1.microsoft \
  /usr/lib/x86_64-linux-gnu/libdcap_quoteprov.so.1
sudo ldconfig
```

### 4. Generate the enclave signing key

```bash
gramine-sgx-gen-private-key
```

### 5. Install Python dependencies

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
source $HOME/.local/bin/env

cd enclave
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python \
  anthropic httpx certifi cryptography

pip3 install langgraph langchain-core cryptography --break-system-packages
```

### 6. Seal the API key

```bash
# Generate wrap key
dd if=/dev/urandom of=secrets/wrap_key.bin bs=16 count=1
python3 -c "
data = open('secrets/wrap_key.bin','rb').read()
print(data.hex(), end='')
" > secrets/wrap_key.hex

# Encrypt the API key
echo -n "your-anthropic-api-key" > secrets/anthropic_api_key.txt.plain
gramine-sgx-pf-crypt encrypt \
  -w secrets/wrap_key.bin \
  -i secrets/anthropic_api_key.txt.plain \
  -o /path/to/confidential-ai/secrets/anthropic_api_key.txt
rm secrets/anthropic_api_key.txt.plain
```

### 7. Build the enclave

```bash
cd enclave
make clean && make
```

The build output includes the MRENCLAVE measurement:

```
Measurement:
    5013fc039c76d3bc0d75f9a1f44e1efa249461257bd38d58d1294420ceac902f
```

### 8. First run — bootstrap sealed wrap key

```bash
WRAP_KEY_HEX=$(cat secrets/wrap_key.hex) gramine-sgx enclave_llm
```

On first run the enclave seals the wrap key to `/sealed/wrap_key` using the hardware-derived `_sgx_mrenclave` key. Subsequent runs require no environment variable:

```bash
# All subsequent runs
gramine-sgx enclave_llm
```

### 9. Update expected MRENCLAVE

```bash
echo "5013fc039c76d3bc0d75f9a1f44e1efa249461257bd38d58d1294420ceac902f" \
  > expected_mrenclave.txt
```

---

## Running the agent

**Terminal 1 — start the enclave:**

```bash
cd enclave
gramine-sgx enclave_llm
```

Expected output:

```
[ENCLAVE] Wrap key loaded from sealed storage (/sealed/wrap_key)
[ENCLAVE] Wrap key provisioned to /dev/attestation/keys/api_key
[ENCLAVE] Signing key generated (fingerprint: ...)
[ENCLAVE] DCAP quote generated (4734 bytes)
[ENCLAVE] TCP connectivity to api.anthropic.com:443 OK
[ENCLAVE] Ready — waiting for connections on port 7777
```

**Terminal 2 — start the LangGraph agent:**

```bash
python3 host/langgraph_agent.py
```

Expected output:

```
============================================================
  Confidential AI Agent
  LLM calls execute inside Intel SGX enclave
  Every response is cryptographically signed
============================================================

[Agent] Connecting to enclave...
[Agent] ✓ Enclave attested successfully
[Agent]   MRENCLAVE: 5013fc039c76d3bc...

You:
```

Every response is verified before display:

```
You: What is the capital of France?

A: The capital of France is Paris.

[Agent] ✓ Response signature: VALID
```

---

## Verifying a response independently

The verification CLI requires only the quote binary, the response JSON, and the expected MRENCLAVE. It does not require access to the running enclave.

```bash
python3 verify/verify_output.py \
  --quote host/enclave_quote.bin \
  --response sample_response.json \
  --expected-mrenclave $(cat expected_mrenclave.txt)
```

Expected output:

```
============================================================
  STRUCTURAL VERIFICATION
============================================================
  passed: True
  mrenclave_match: True
  report_data_match: True
  cpu_svn: 10101110ffff0100...
  errors: none

============================================================
  CRYPTOGRAPHIC VERIFICATION
============================================================
  passed: True
  result: OK — quote is valid
  collateral_status: 0
  errors: none

============================================================
  RESPONSE SIGNATURE #1
============================================================
  passed: True
  errors: none

============================================================
  SUMMARY
============================================================
Structural:     PASS
Cryptographic:  PASS
Signatures:     PASS (1 checked)
Overall:        ✓ VERIFIED
```

### What each check proves

**Structural verification** (pure Python, works offline):

- The DCAP quote parses correctly as a valid SGX v3 quote
- `MRENCLAVE` in the quote matches the published expected value — the correct code ran
- `report_data[:32]` in the quote equals `SHA256(public_key_der)` — the signing key was generated inside that specific enclave, not substituted externally

**Cryptographic verification** (requires Azure THIM access):

- The quote signature chain verifies up to Intel's root CA — genuine SGX hardware produced this quote
- PCK certificate, TCB info, QE identity, and CRL all fetched from Azure THIM and validated

**Response signature verification**:

- ECDSA-P256 signature over `SHA256(prompt || result || timestamp || MRENCLAVE)` verifies with the enclave's public key
- Payload hash computed locally matches what the enclave reported — no tampering in transit

---

## Reproducing the MRENCLAVE measurement

MRENCLAVE is deterministic given identical inputs. To reproduce:

```bash
cd enclave
make clean && make
# gramine-sgx-sign prints:
# Measurement: 5013fc039c76d3bc0d75f9a1f44e1efa249461257bd38d58d1294420ceac902f
```

The measurement changes if any of the following change:

- `enclave_llm.py` source code
- Any file listed in `sgx.trusted_files` in the manifest
- `sgx.enclave_size`, `sgx.max_threads`, or `sgx.debug`
- The manifest configuration itself

When the enclave is updated, the sealed wrap key must be re-provisioned:

```bash
rm sealed/wrap_key
make clean && make
WRAP_KEY_HEX=$(cat secrets/wrap_key.hex) gramine-sgx enclave_llm  # re-seals
echo "<new-mrenclave>" > expected_mrenclave.txt
```

---

## Known limitations and future work

**Ephemeral signing key.** The ECDSA signing key is generated fresh on each enclave start. There is no cross-session identity continuity. Fix: seal the signing key with `_sgx_mrenclave` on first generation and load it on subsequent starts — architecturally identical to the wrap key sealing already implemented.

**Wrap key bootstrapping gap.** On first run, `WRAP_KEY_HEX` is visible to the host OS as an environment variable. This is the provisioning gap. Production fix: the verifier confirms the DCAP quote, then sends the wrap key encrypted to the enclave's ephemeral public key over a TLS channel attested to MRENCLAVE. The host never sees the plaintext wrap key.

**Debug enclave.** `sgx.debug = true` allows debugger attachment and disables full confidentiality protection. Set `sgx.debug = false` for production. The MRENCLAVE will change and all sealed files must be re-provisioned.

**Gramine TCB.** Running Python inside Gramine includes the LibOS, syscall shim, and Python runtime in the trusted computing base. This is larger than a native C SGX enclave. The tradeoff is development velocity and compatibility with existing Python libraries.

**DNS resolution.** The host OS resolves `api.anthropic.com`. A compromised host could redirect DNS. TLS certificate verification inside the enclave — using the measured `certifi` CA bundle in `trusted_files` — prevents successful impersonation of Anthropic's API endpoint without detection.

**Post-quantum cryptography.** ECDSA-P256 is vulnerable to Shor's algorithm on a sufficiently capable quantum computer. A production deployment should use a hybrid scheme combining ECDSA-P256 with ML-DSA (NIST FIPS 204) to maintain security against quantum adversaries. The verification CLI is designed to support multiple signature algorithms — adding ML-DSA requires replacing the signing primitive in `enclave_llm.py` and the verification primitive in `verify/quote_verifier.py` with no architectural changes.

**SGX vs AMD SEV-SNP.** SGX provides process-level isolation. AMD SEV-SNP provides VM-level isolation with a different trust boundary — the entire guest OS is protected rather than individual processes. SGX was chosen for its mature DCAP attestation tooling and Gramine compatibility. The architectural principles demonstrated here — sealed secrets, signed outputs, remote attestation — apply to both TEE models.

**az-dcap-client packaging.** Microsoft's `az-dcap-client` package is not available for Ubuntu 24.04 as of the time of writing. The setup instructions include building from source. This will simplify once Microsoft publishes a Noble package.

---

## Security notes

- Never commit `secrets/wrap_key.bin`, `secrets/wrap_key.hex`, or `secrets/anthropic_api_key.txt` to version control. Add them to `.gitignore`.
- The `sealed/wrap_key` file is safe to commit — it is encrypted and readable only by this enclave on this CPU.
- The `audit_log.jsonl` contains prompt text. Treat as sensitive if prompts contain confidential data.
- Rotate the API key by re-running the sealing step with the new key and restarting the enclave.
- The enclave signing key (`~/.config/gramine/enclave-key.pem`) signs the MRENCLAVE measurement. Protect it. In production, use an HSM or Azure Key Vault.

---

## References

- [Gramine documentation](https://gramine.readthedocs.io)
- [Intel SGX DCAP Quote Library API](https://download.01.org/intel-sgx/sgx-dcap/1.3/linux/docs/Intel_SGX_ECDSA_QuoteLibReference_DCAP_API.pdf)
- [Azure Trusted Hardware Identity Management](https://learn.microsoft.com/en-us/azure/security/fundamentals/trusted-hardware-identity-management)
- [Microsoft Azure DCAP Client](https://github.com/microsoft/Azure-DCAP-Client)
- [NIST ML-DSA (FIPS 204)](https://csrc.nist.gov/pubs/fips/204/final)
- [Anthropic API documentation](https://docs.anthropic.com)
- [LangGraph documentation](https://langchain-ai.github.io/langgraph/)
