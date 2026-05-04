"""
enclave_llm.py — diagnostic version.
Prints the full exception chain for connection errors.
"""

import socket
import json
import struct
import sys
import os
import logging
import traceback

logging.basicConfig(
    stream=sys.stdout,
    level=logging.INFO,
    format="[ENCLAVE] %(asctime)s %(levelname)s %(message)s"
)
log = logging.getLogger(__name__)

HOST = "127.0.0.1"
PORT = int(os.environ.get("ENCLAVE_PORT", "7777"))
CERT_PATH = "/enclave/.venv/lib/python3.12/site-packages/certifi/cacert.pem"

_anthropic_client = None


def get_client():
    global _anthropic_client
    if _anthropic_client is None:
        import httpx
        import anthropic
        api_key = os.environ.get("ANTHROPIC_API_KEY", "")
        if not api_key:
            raise RuntimeError("ANTHROPIC_API_KEY not set")
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

            request_type = request.get("type")
            log.info(f"Received request type: {request_type}")

            if request_type == "ping":
                response = {"type": "pong", "status": "ok"}

            elif request_type == "prompt":
                prompt = request.get("prompt", "")
                try:
                    result = call_llm(prompt)
                    response = {"type": "response", "status": "ok", "result": result}
                except Exception as e:
                    # Print full traceback to enclave stdout for diagnosis
                    log.error(f"LLM call failed: {type(e).__name__}: {e}")
                    log.error(f"Full traceback:\n{traceback.format_exc()}")
                    response = {
                        "type": "error",
                        "status": "error",
                        "message": f"{type(e).__name__}: {e}",
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

    # Test basic TCP connectivity before accepting any client
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
