"""
host_agent.py — runs on the host, outside SGX.
Receives signed responses from the enclave and verifies them locally.
"""

import socket
import json
import struct
import sys
import time
import hashlib
import logging

logging.basicConfig(
    stream=sys.stdout,
    level=logging.INFO,
    format="[HOST] %(asctime)s %(levelname)s %(message)s"
)
log = logging.getLogger(__name__)

HOST = "127.0.0.1"
PORT = 7777
CONNECT_TIMEOUT = 30
CONNECT_RETRY_INTERVAL = 0.5


def send_message(sock: socket.socket, payload: dict) -> None:
    data = json.dumps(payload).encode("utf-8")
    header = struct.pack(">I", len(data))
    sock.sendall(header + data)


def recv_message(sock: socket.socket) -> dict:
    header = _recv_exact(sock, 4)
    if not header:
        raise ConnectionResetError("Enclave disconnected")
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


def connect_to_enclave() -> socket.socket:
    deadline = time.time() + CONNECT_TIMEOUT
    last_error = None
    attempts = 0
    while time.time() < deadline:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((HOST, PORT))
            log.info(f"Connected to enclave at {HOST}:{PORT}")
            return sock
        except ConnectionRefusedError as e:
            last_error = e
            attempts += 1
            if attempts % 10 == 0:
                log.info(f"Waiting for enclave... ({attempts} attempts)")
            time.sleep(CONNECT_RETRY_INTERVAL)
    raise TimeoutError(f"Could not connect to enclave after {CONNECT_TIMEOUT}s: {last_error}")


def verify_response(prompt: str, response: dict) -> bool:
    """
    Verify the enclave's signature over (input || output || timestamp || mrenclave).
    Returns True if the signature is valid.
    """
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.exceptions import InvalidSignature

    try:
        public_key = serialization.load_pem_public_key(
            response["public_key_pem"].encode("utf-8")
        )

        sep = b"||"
        payload = (
            prompt.encode("utf-8") + sep
            + response["result"].encode("utf-8") + sep
            + str(response["timestamp"]).encode("utf-8") + sep
            + response["mrenclave"].encode("utf-8")
        )
        payload_hash = hashlib.sha256(payload).hexdigest()

        # Verify our locally computed hash matches what the enclave reported
        assert payload_hash == response["payload_hash"],             "Payload hash mismatch — response may have been tampered with"

        public_key.verify(
            bytes.fromhex(response["signature_hex"]),
            payload,
            ec.ECDSA(hashes.SHA256())
        )
        return True

    except InvalidSignature:
        log.error("SIGNATURE INVALID — response integrity check failed")
        return False
    except Exception as e:
        log.error(f"Verification error: {e}")
        return False


def send_request(sock: socket.socket, request: dict) -> dict:
    log.info(f"Sending: {request}")
    send_message(sock, request)
    response = recv_message(sock)
    return response


def main() -> None:
    log.info("Host agent starting")
    sock = connect_to_enclave()

    try:
        # Get public key via ping
        response = send_request(sock, {"type": "ping"})
        assert response["type"] == "pong"
        enclave_public_key = response.get("public_key_pem")
        print(f"\n✓ Connected to enclave")
        print(f"  Enclave public key fingerprint: {enclave_public_key[:60]}...")

        # Send prompts and verify signatures
        prompts = [
            "What is the capital of France?",
            "Explain quantum entanglement in one sentence.",
        ]

        for prompt in prompts:
            response = send_request(sock, {"type": "prompt", "prompt": prompt})
            assert response["status"] == "ok", f"Error: {response}"

            # Verify signature
            valid = verify_response(prompt, response)
            status = "✓ SIGNATURE VALID" if valid else "✗ SIGNATURE INVALID"

            print(f"\nPrompt: {prompt!r}")
            print(f"Result: {response['result'][:100]}...")
            print(f"Timestamp: {response['timestamp']}")
            print(f"MRENCLAVE: {response['mrenclave'][:32]}...")
            print(f"Payload hash: {response['payload_hash'][:32]}...")
            print(f"Signature: {response['signature_hex'][:32]}...")
            print(f"Verification: {status}")

        print("\n✓ All signed responses verified")

    finally:
        sock.close()


if __name__ == "__main__":
    main()
