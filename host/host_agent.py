"""
host_agent.py — runs on the host, outside SGX.
Communicates with the enclave over localhost TCP.
"""

import socket
import json
import struct
import sys
import time
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

    raise TimeoutError(
        f"Could not connect to enclave after {CONNECT_TIMEOUT}s: {last_error}"
    )


def send_request(sock: socket.socket, request: dict) -> dict:
    log.info(f"Sending: {request}")
    send_message(sock, request)
    response = recv_message(sock)
    log.info(f"Received: {response}")
    return response


def main() -> None:
    log.info("Host agent starting")
    sock = connect_to_enclave()

    try:
        # Test 1: ping
        response = send_request(sock, {"type": "ping"})
        assert response["type"] == "pong", f"Expected pong, got: {response}"
        print(f"\n✓ Ping/pong successful: {response}")

        # Test 2: prompt echo
        prompts = [
            "Summarize this document and classify risk",
            "What is the capital of France?",
            "Explain quantum entanglement in simple terms",
        ]

        for prompt in prompts:
            response = send_request(sock, {"type": "prompt", "prompt": prompt})
            assert response["status"] == "ok", f"Unexpected status: {response}"
            print(f"\n✓ Prompt: '{prompt}'")
            print(f"  Result: '{response['result']}'")

        # Test 3: unknown request type
        response = send_request(sock, {"type": "unknown_type"})
        assert response["type"] == "error", f"Expected error, got: {response}"
        print(f"\n✓ Error handling works: {response}")

        print("\n✓ All IPC tests passed")

    finally:
        sock.close()


if __name__ == "__main__":
    main()
