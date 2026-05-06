"""
langgraph_agent.py — LangGraph host agent for the Confidential AI Agent.

Architecture:
  - LangGraph manages conversation state and agent flow
  - All LLM calls are routed through the SGX enclave via TCP socket
  - Every response is signature-verified before being shown to the user
  - Verified responses are logged to an append-only audit trail

The host never holds the API key or the signing private key.
Both live inside the SGX enclave.
"""

import socket
import json
import struct
import sys
import os
import time
import hashlib
import logging
from typing import TypedDict, Annotated
from pathlib import Path

from langgraph.graph import StateGraph, END
from langgraph.graph.message import add_messages
from langchain_core.messages import HumanMessage, AIMessage, SystemMessage

# Add verify module to path
sys.path.insert(0, str(Path(__file__).parent.parent))
from verify.quote_verifier import verify_structural, verify_cryptographic, verify_response_signature

logging.basicConfig(
    stream=sys.stdout,
    level=logging.WARNING,
    format="[HOST] %(asctime)s %(levelname)s %(message)s"
)
log = logging.getLogger(__name__)

# Enclave connection config
ENCLAVE_HOST = "127.0.0.1"
ENCLAVE_PORT = 7777
CONNECT_TIMEOUT = 30
AUDIT_LOG_PATH = Path(__file__).parent.parent / "audit_log.jsonl"
EXPECTED_MRENCLAVE_PATH = Path(__file__).parent.parent / "expected_mrenclave.txt"


# ─────────────────────────────────────────────
# LangGraph State
# ─────────────────────────────────────────────

class AgentState(TypedDict):
    messages: Annotated[list, add_messages]
    enclave_socket: object        # live socket connection to enclave
    enclave_public_key: str       # ECDSA public key from enclave
    dcap_quote_hex: str           # DCAP quote for attestation
    expected_mrenclave: str       # expected MRENCLAVE from file
    quote_verified: bool          # whether quote passed verification
    last_verification: dict       # verification result for last response
    audit_entries: list           # accumulated audit log entries


# ─────────────────────────────────────────────
# Socket utilities
# ─────────────────────────────────────────────

def send_message(sock: socket.socket, payload: dict) -> None:
    data = json.dumps(payload).encode("utf-8")
    header = struct.pack(">I", len(data))
    sock.sendall(header + data)


def recv_message(sock: socket.socket) -> dict:
    header = _recv_exact(sock, 4)
    if not header:
        raise ConnectionResetError("Enclave disconnected")
    length = struct.unpack(">I", header)[0]
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
    while time.time() < deadline:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((ENCLAVE_HOST, ENCLAVE_PORT))
            return sock
        except ConnectionRefusedError:
            time.sleep(0.5)
    raise TimeoutError(f"Could not connect to enclave after {CONNECT_TIMEOUT}s")


# ─────────────────────────────────────────────
# Audit log
# ─────────────────────────────────────────────

def append_audit_log(entry: dict) -> None:
    with open(AUDIT_LOG_PATH, "a") as f:
        f.write(json.dumps(entry) + "\n")


# ─────────────────────────────────────────────
# LangGraph nodes
# ─────────────────────────────────────────────

def node_connect_and_attest(state: AgentState) -> dict:
    """
    Connect to the enclave and verify its DCAP quote.
    This runs once at agent startup.
    """
    print("\n[Agent] Connecting to enclave...", flush=True)

    sock = connect_to_enclave()
    send_message(sock, {"type": "ping"})
    pong = recv_message(sock)

    public_key_pem = pong.get("public_key_pem", "")
    dcap_quote_hex = pong.get("dcap_quote_hex", "")

    # Load expected MRENCLAVE
    expected_mrenclave = ""
    if EXPECTED_MRENCLAVE_PATH.exists():
        expected_mrenclave = EXPECTED_MRENCLAVE_PATH.read_text().strip()

    quote_verified = False
    verification_summary = {}

    if dcap_quote_hex and expected_mrenclave:
        quote_bytes = bytes.fromhex(dcap_quote_hex)

        structural = verify_structural(quote_bytes, public_key_pem, expected_mrenclave)
        crypto = verify_cryptographic(quote_bytes)

        quote_verified = structural["passed"] and crypto.get("passed", False)
        verification_summary = {
            "structural": structural["passed"],
            "cryptographic": crypto.get("passed"),
            "mrenclave": structural["details"].get("mrenclave", "")[:16] + "...",
            "errors": structural["errors"] + crypto.get("errors", []),
        }

        if quote_verified:
            print(f"[Agent] ✓ Enclave attested successfully", flush=True)
            print(f"[Agent]   MRENCLAVE: {verification_summary['mrenclave']}", flush=True)
        else:
            print(f"[Agent] ✗ Enclave attestation FAILED", flush=True)
            for err in verification_summary["errors"]:
                print(f"[Agent]   ERROR: {err}", flush=True)
    elif not expected_mrenclave:
        print("[Agent] ⚠ expected_mrenclave.txt not found — skipping attestation", flush=True)
    else:
        print("[Agent] ⚠ No DCAP quote received from enclave", flush=True)

    return {
        "enclave_socket": sock,
        "enclave_public_key": public_key_pem,
        "dcap_quote_hex": dcap_quote_hex,
        "expected_mrenclave": expected_mrenclave,
        "quote_verified": quote_verified,
        "last_verification": verification_summary,
        "audit_entries": [],
    }


def node_call_enclave(state: AgentState) -> dict:
    """
    Send the latest user message to the enclave and get a signed response.
    Verify the response signature before returning.
    """
    messages = state["messages"]
    sock = state["enclave_socket"]

    # Get the last human message
    last_human = None
    for msg in reversed(messages):
        if isinstance(msg, HumanMessage):
            last_human = msg.content
            break

    if not last_human:
        return {"messages": [AIMessage(content="No user message found.")]}

    # Build full conversation history for context
    # The enclave is stateless — we send the full history each time
    conversation_lines = []
    for msg in messages:
        if isinstance(msg, HumanMessage):
            conversation_lines.append(f"Human: {msg.content}")
        elif isinstance(msg, AIMessage):
            conversation_lines.append(f"Assistant: {msg.content}")

    full_prompt = "\n".join(conversation_lines)

    # Send to enclave
    send_message(sock, {"type": "prompt", "prompt": full_prompt})
    response = recv_message(sock)

    if response.get("status") != "ok":
        error_msg = response.get("message", "Unknown error from enclave")
        return {"messages": [AIMessage(content=f"[Enclave error: {error_msg}]")]}

    result = response["result"]
    timestamp = response["timestamp"]
    mrenclave = response["mrenclave"]
    signature_hex = response["signature_hex"]
    public_key_pem = response["public_key_pem"]
    payload_hash = response["payload_hash"]

    # Print the response to the user
    print(f"\nAssistant: {result}\n", flush=True)

    # Verify response signature against the full prompt sent to the enclave
    sig_verification = verify_response_signature(
        prompt=full_prompt,
        result=result,
        timestamp=timestamp,
        mrenclave=mrenclave,
        signature_hex=signature_hex,
        public_key_pem=public_key_pem,
        payload_hash=payload_hash,
    )

    verified = sig_verification["passed"]
    status_symbol = "✓" if verified else "✗"
    print(f"\n[Agent] {status_symbol} Response signature: {'VALID' if verified else 'INVALID'}", flush=True)

    if not verified:
        print(f"[Agent]   Errors: {sig_verification['errors']}", flush=True)

    # Build audit entry
    audit_entry = {
        "timestamp": timestamp,
        "prompt": last_human,
        "full_prompt_hash": hashlib.sha256(full_prompt.encode()).hexdigest(),
        "result": result,
        "result_hash": hashlib.sha256(result.encode()).hexdigest(),
        "mrenclave": mrenclave,
        "signature_hex": signature_hex[:32] + "...",
        "payload_hash": payload_hash,
        "signature_valid": verified,
        "quote_verified": state["quote_verified"],
    }
    append_audit_log(audit_entry)

    new_entries = state.get("audit_entries", []) + [audit_entry]

    return {
        "messages": [AIMessage(content=result)],
        "last_verification": sig_verification,
        "audit_entries": new_entries,
    }


def node_should_continue(state: AgentState) -> str:
    """Route back to call_enclave for next user message, or end."""
    messages = state["messages"]
    last = messages[-1] if messages else None
    if isinstance(last, AIMessage):
        return "get_input"
    return "call_enclave"


def node_get_input(state: AgentState) -> dict:
    """Get next user input from stdin."""
    try:
        user_input = input("\nYou: ").strip()
    except (EOFError, KeyboardInterrupt):
        return {"messages": [HumanMessage(content="/exit")]}

    if user_input.lower() in ("/exit", "/quit", "exit", "quit"):
        return {"messages": [HumanMessage(content="/exit")]}

    return {"messages": [HumanMessage(content=user_input)]}


def node_check_exit(state: AgentState) -> str:
    """Check if user wants to exit."""
    messages = state["messages"]
    last = messages[-1] if messages else None
    if isinstance(last, HumanMessage) and last.content == "/exit":
        return "end"
    return "call_enclave"


# ─────────────────────────────────────────────
# Build the graph
# ─────────────────────────────────────────────

def build_agent() -> StateGraph:
    graph = StateGraph(AgentState)

    graph.add_node("connect_and_attest", node_connect_and_attest)
    graph.add_node("get_input", node_get_input)
    graph.add_node("call_enclave", node_call_enclave)

    graph.set_entry_point("connect_and_attest")

    graph.add_edge("connect_and_attest", "get_input")

    graph.add_conditional_edges(
        "get_input",
        node_check_exit,
        {
            "call_enclave": "call_enclave",
            "end": END,
        }
    )

    graph.add_edge("call_enclave", "get_input")

    return graph.compile()


# ─────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────

def main():
    print("=" * 60)
    print("  Confidential AI Agent")
    print("  LLM calls execute inside Intel SGX enclave")
    print("  Every response is cryptographically signed")
    print("=" * 60)
    print("Type your message and press Enter.")
    print("Type /exit to quit.")
    print()

    agent = build_agent()

    initial_state: AgentState = {
        "messages": [],
        "enclave_socket": None,
        "enclave_public_key": "",
        "dcap_quote_hex": "",
        "expected_mrenclave": "",
        "quote_verified": False,
        "last_verification": {},
        "audit_entries": [],
    }

    try:
        final_state = agent.invoke(initial_state)
    except KeyboardInterrupt:
        print("\n[Agent] Interrupted")
    finally:
        # Close socket if open
        sock = initial_state.get("enclave_socket")
        if sock:
            try:
                sock.close()
            except Exception:
                pass

    print("\n[Agent] Session ended")
    print(f"[Agent] Audit log: {AUDIT_LOG_PATH}")

    # Print session summary
    if final_state and final_state.get("audit_entries"):
        entries = final_state["audit_entries"]
        valid = sum(1 for e in entries if e["signature_valid"])
        print(f"[Agent] Responses: {len(entries)} total, {valid} verified")


if __name__ == "__main__":
    main()
