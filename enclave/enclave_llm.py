"""
enclave_llm.py — runs inside SGX via Gramine.
Phase 5: Added DCAP quote generation to bind signing key to enclave identity.
"""

import socket
import json
import struct
import sys
import os
import logging
import hashlib
import time

logging.basicConfig(
    stream=sys.stdout,
    level=logging.INFO,
    format="[ENCLAVE] %(asctime)s %(levelname)s %(message)s"
)
log = logging.getLogger(__name__)

HOST = "127.0.0.1"
PORT = int(os.environ.get("ENCLAVE_PORT", "7777"))
API_KEY_PATH = "/secrets/anthropic_api_key.txt"
CERT_PATH = "/enclave/.venv/lib/python3.12/site-packages/certifi/cacert.pem"
WRAP_KEY_PATH = "/dev/attestation/keys/api_key"
MRENCLAVE_PATH = "/dev/attestation/report_data"

_anthropic_client = None
_signing_key = None
_signing_key_public_pem = None
_mrenclave_hex = None
_dcap_quote_hex = ""


SEALED_WRAP_KEY_PATH = "/sealed/wrap_key"


def provision_key() -> None:
    """
    Provision the wrap key for the encrypted /secrets mount.

    Bootstrap logic:
    1. If /sealed/wrap_key exists (sealed with _sgx_mrenclave key),
       load it from there — no external secret needed on subsequent runs.
    2. If not, read WRAP_KEY_HEX from environment, provision it,
       then seal it to /sealed/wrap_key for future runs.
    3. If neither exists, fail with a clear error.

    /sealed uses Gramine's _sgx_mrenclave key — derived from the enclave
    measurement and the CPU hardware secret. Only this exact enclave on
    this exact CPU can decrypt it.
    """
    wrap_key_bytes = None

    # Try loading from sealed storage first
    try:
        with open(SEALED_WRAP_KEY_PATH, "rb") as f:
            wrap_key_bytes = f.read()
        if len(wrap_key_bytes) == 16:
            log.info("Wrap key loaded from sealed storage (/sealed/wrap_key)")
        else:
            log.warning(f"Sealed wrap key has wrong size ({len(wrap_key_bytes)}), ignoring")
            wrap_key_bytes = None
    except FileNotFoundError:
        log.info("No sealed wrap key found — checking environment")
    except Exception as e:
        log.warning(f"Failed to read sealed wrap key: {e} — checking environment")

    # Fall back to environment variable
    if wrap_key_bytes is None:
        wrap_key_hex = os.environ.get("WRAP_KEY_HEX", "")
        if not wrap_key_hex:
            raise RuntimeError(
                "Wrap key not found. "
                "Provide WRAP_KEY_HEX on first run, or ensure /sealed/wrap_key exists."
            )        
        wrap_key_bytes = bytes.fromhex(wrap_key_hex)
        if len(wrap_key_bytes) != 16:
            raise RuntimeError(f"WRAP_KEY_HEX must be 16 bytes, got {len(wrap_key_bytes)}")

        # Seal the wrap key for future runs
        try:
            with open(SEALED_WRAP_KEY_PATH, "wb") as f:
                f.write(wrap_key_bytes)
            log.info("Wrap key sealed to /sealed/wrap_key (future runs need no env var)")
        except Exception as e:
            log.warning(f"Could not seal wrap key: {e} — will require WRAP_KEY_HEX on next run")

    # Provision to Gramine's key slot
    with open(WRAP_KEY_PATH, "wb") as f:
        f.write(wrap_key_bytes)
    log.info("Wrap key provisioned to /dev/attestation/keys/api_key")


def generate_signing_key():
    """
    Generate ECDSA P-256 key pair inside the enclave.
    The private key is held in memory only — never written to disk,
    never sent outside the enclave boundary.
    """
    global _signing_key, _signing_key_public_pem

    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import serialization

    _signing_key = ec.generate_private_key(ec.SECP256R1())
    _signing_key_public_pem = _signing_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")

    # Log the public key fingerprint (SHA256 of DER) for identification
    pub_der = _signing_key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    fingerprint = hashlib.sha256(pub_der).hexdigest()[:16]
    log.info(f"Signing key generated (fingerprint: {fingerprint}...)")
    log.info(f"Public key:\n{_signing_key_public_pem}")


def sign_output(prompt: str, result: str, timestamp: float) -> dict:
    """
    Sign the tuple (input, output, timestamp, mrenclave).
    Returns the hex signature and the public key PEM.

    The signed payload is:
        SHA256( prompt_bytes || b"||" || result_bytes || b"||"
                || timestamp_bytes || b"||" || mrenclave_bytes )

    The separator b"||" prevents ambiguity between field boundaries.
    """
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import hashes

    mrenclave = get_mrenclave()

    # Build the canonical payload
    sep = b"||"
    payload = (
        prompt.encode("utf-8") + sep
        + result.encode("utf-8") + sep
        + str(timestamp).encode("utf-8") + sep
        + mrenclave.encode("utf-8")
    )
    payload_hash = hashlib.sha256(payload).hexdigest()

    signature = _signing_key.sign(
        payload,
        ec.ECDSA(hashes.SHA256())
    )

    return {
        "signature_hex": signature.hex(),
        "public_key_pem": _signing_key_public_pem,
        "mrenclave": mrenclave,
        "timestamp": timestamp,
        "payload_hash": payload_hash,
    }


def get_mrenclave() -> str:
    """
    Read MRENCLAVE from the SGX report via /dev/attestation/report.

    The SGX report (sgx_report_t) layout relevant offsets:
      - report_data (64 bytes) must be written to user_report_data first
      - After writing user_report_data, reading report returns sgx_report_t
      - MRENCLAVE is at bytes 176..208 of sgx_report_t (32 bytes)

    sgx_report_t structure (512 bytes total):
      offset   0: cpu_svn (16 bytes)
      offset  16: misc_select (4 bytes)
      offset  20: reserved1 (12 bytes)
      offset  32: isv_ext_prod_id (16 bytes)
      offset  48: attributes (16 bytes)
      offset  64: mr_enclave (32 bytes)  <-- what we want
      offset  96: reserved2 (32 bytes)
      offset 128: mr_signer (32 bytes)
      ...
    """
    global _mrenclave_hex
    if _mrenclave_hex is not None:
        return _mrenclave_hex
    try:
        # Must write 64 bytes to user_report_data before reading report
        with open("/dev/attestation/user_report_data", "wb") as f:
            f.write(b"\\x00" * 64)

        with open("/dev/attestation/report", "rb") as f:
            report = f.read()

        # MRENCLAVE is at offset 64, length 32
        mrenclave_bytes = report[64:96]
        _mrenclave_hex = mrenclave_bytes.hex()
        log.info(f"MRENCLAVE: {_mrenclave_hex}")
    except Exception as e:
        log.warning(f"MRENCLAVE read failed: {type(e).__name__}: {e}")
        _mrenclave_hex = "0" * 64
    return _mrenclave_hex


def generate_dcap_quote() -> str:
    """
    Generate a DCAP quote that cryptographically binds the signing key
    to the enclave identity.

    The quote's report_data field contains SHA256(public_key_der),
    which ties the signing key to the MRENCLAVE measurement.
    A verifier can confirm:
      1. The quote signature chain → Intel CA (real SGX hardware)
      2. MRENCLAVE in quote == expected value (correct code)
      3. SHA256(public_key) == report_data in quote (key generated in this enclave)
    """
    from cryptography.hazmat.primitives import serialization

    # Compute SHA256 of the signing public key in DER format
    pub_der = _signing_key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    pub_hash = hashlib.sha256(pub_der).digest()  # 32 bytes

    # report_data is 64 bytes — put key hash in first 32, zeros in last 32
    report_data = pub_hash + b"\x00" * 32

    try:
        # Write report_data to trigger quote generation
        with open("/dev/attestation/user_report_data", "wb") as f:
            f.write(report_data)

        # Read the DCAP quote
        with open("/dev/attestation/quote", "rb") as f:
            quote_bytes = f.read()

        quote_hex = quote_bytes.hex()
        log.info(f"DCAP quote generated ({len(quote_bytes)} bytes)")
        log.info(f"Quote report_data (pub key hash): {pub_hash.hex()}")
        return quote_hex

    except FileNotFoundError as e:
        log.warning(f"DCAP quote not available: {e}")
        return ""
    except Exception as e:
        log.error(f"DCAP quote generation failed: {type(e).__name__}: {e}")
        return ""


def load_api_key() -> str:
    with open(API_KEY_PATH, "r") as f:
        key = f.read().strip()
    if not key:
        raise RuntimeError(f"API key file is empty: {API_KEY_PATH}")
    log.info("API key loaded from encrypted storage")
    return key


def get_client():
    global _anthropic_client
    if _anthropic_client is None:
        import httpx
        import anthropic
        api_key = load_api_key()
        http_client = httpx.Client(verify=CERT_PATH)
        _anthropic_client = anthropic.Anthropic(
            api_key=api_key,
            http_client=http_client,
        )
        log.info("Anthropic client initialized")
    return _anthropic_client


def call_llm(prompt: str) -> str:
    client = get_client()
    message = client.messages.create(
        model="claude-sonnet-4-5",
        max_tokens=1024,
        messages=[{"role": "user", "content": prompt}],
    )
    return message.content[0].text


def send_message(sock: socket.socket, payload: dict) -> None:
    data = json.dumps(payload).encode("utf-8")
    header = struct.pack(">I", len(data))
    sock.sendall(header + data)


def recv_message(sock: socket.socket) -> dict:
    header = _recv_exact(sock, 4)
    if not header:
        raise ConnectionResetError("Client disconnected")
    length = struct.unpack(">I", header)[0]
    if length > 10 * 1024 * 1024:
        raise ValueError(f"Message too large: {length} bytes")
    data = _recv_exact(sock, length)
    return json.loads(data.decode("utf-8"))


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return b""
        buf.extend(chunk)
    return bytes(buf)


def handle_client(conn: socket.socket) -> None:
    log.info("Client connected")
    try:
        while True:
            try:
                request = recv_message(conn)
            except ConnectionResetError:
                log.info("Client disconnected")
                break

            log.info(f"Received request type: {request.get('type')}")
            request_type = request.get("type")

            if request_type == "ping":
                response = {
                    "type": "pong",
                    "status": "ok",
                    "public_key_pem": _signing_key_public_pem,
                    "dcap_quote_hex": _dcap_quote_hex,
                }

            elif request_type == "prompt":
                prompt = request.get("prompt", "")
                if not prompt:
                    response = {
                        "type": "error",
                        "status": "error",
                        "message": "Empty prompt",
                    }
                else:
                    try:
                        timestamp = time.time()
                        result = call_llm(prompt)
                        signing_data = sign_output(prompt, result, timestamp)
                        response = {
                            "type": "response",
                            "status": "ok",
                            "result": result,
                            "timestamp": signing_data["timestamp"],
                            "signature_hex": signing_data["signature_hex"],
                            "public_key_pem": signing_data["public_key_pem"],
                            "mrenclave": signing_data["mrenclave"],
                            "payload_hash": signing_data["payload_hash"],
                        }
                    except Exception as e:
                        log.error(f"LLM call failed: {e}")
                        response = {
                            "type": "error",
                            "status": "error",
                            "message": str(e),
                        }

            else:
                response = {
                    "type": "error",
                    "status": "error",
                    "message": f"Unknown request type: {request_type}",
                }

            send_message(conn, response)
            log.info(f"Sent response type: {response.get('type')}")

    except Exception as e:
        log.error(f"Error handling client: {e}")
    finally:
        conn.close()


def main() -> None:
    log.info(f"Enclave process starting (PID={os.getpid()})")
    log.info(f"Python {sys.version}")

    provision_key()
    generate_signing_key()

    # Diagnostic — list /dev/attestation contents
    try:
        entries = os.listdir("/dev/attestation")
        log.info(f"/dev/attestation contents: {entries}")
    except Exception as e:
        log.warning(f"Cannot list /dev/attestation: {e}")

    # Generate DCAP quote at startup — binds signing key to enclave identity
    global _dcap_quote_hex
    _dcap_quote_hex = generate_dcap_quote()

    log.info("Testing outbound TCP to api.anthropic.com:443 ...")
    try:
        test_sock = socket.create_connection(("api.anthropic.com", 443), timeout=10)
        test_sock.close()
        log.info("TCP connectivity to api.anthropic.com:443 OK")
    except Exception as e:
        log.error(f"TCP connectivity test FAILED: {type(e).__name__}: {e}")

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen(1)
    log.info(f"Ready — waiting for connections on port {PORT}")

    try:
        while True:
            conn, addr = server.accept()
            handle_client(conn)
    except KeyboardInterrupt:
        log.info("Shutting down")
    finally:
        server.close()


if __name__ == "__main__":
    main()
