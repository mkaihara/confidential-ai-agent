"""
enclave_llm.py — runs inside SGX via Gramine.
Phase 1: TCP echo server. No LLM yet.
Uses TCP (not Unix socket) because Gramine encrypts UDS and
requires both ends to be inside Gramine for UDS communication.
"""

import socket
import json
import struct
import sys
import os
import logging

logging.basicConfig(
    stream=sys.stdout,
    level=logging.INFO,
    format="[ENCLAVE] %(asctime)s %(levelname)s %(message)s"
)
log = logging.getLogger(__name__)

HOST = "127.0.0.1"
PORT = int(os.environ.get("ENCLAVE_PORT", "7777"))


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

            log.info(f"Received request: {request}")
            request_type = request.get("type")

            if request_type == "ping":
                response = {"type": "pong", "status": "ok"}

            elif request_type == "prompt":
                prompt = request.get("prompt", "")
                response = {
                    "type": "response",
                    "status": "ok",
                    "result": f"ECHO from enclave (PID {os.getpid()}): {prompt}",
                }

            else:
                response = {
                    "type": "error",
                    "status": "error",
                    "message": f"Unknown request type: {request_type}",
                }

            send_message(conn, response)
            log.info(f"Sent response: {response}")

    except Exception as e:
        log.error(f"Error handling client: {e}")
    finally:
        conn.close()


def main() -> None:
    log.info(f"Enclave process starting (PID={os.getpid()})")
    log.info(f"Python {sys.version}")
    log.info(f"Listening on {HOST}:{PORT}")

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
