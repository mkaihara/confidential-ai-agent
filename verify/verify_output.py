#!/usr/bin/env python3
"""
verify_output.py — standalone verification CLI for the Confidential AI Agent.

Usage:
  python3 verify_output.py \
    --quote enclave_quote.bin \
    --response response.json \
    --expected-mrenclave <hex> \
    [--skip-crypto]

The response JSON must contain:
  public_key_pem, prompt, result, timestamp,
  mrenclave, signature_hex, payload_hash

Exit codes:
  0 = verification passed
  1 = verification failed
  2 = usage error
"""

import sys
import json
import argparse
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from quote_verifier import full_verification


def print_section(title: str, data: dict) -> None:
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}")
    for key, value in data.items():
        if isinstance(value, str) and len(value) > 80:
            print(f"  {key}: {value[:64]}...")
        elif isinstance(value, list):
            print(f"  {key}: {value}")
        else:
            print(f"  {key}: {value}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify a Confidential AI Agent response"
    )
    parser.add_argument(
        "--quote", required=True,
        help="Path to DCAP quote binary file"
    )
    parser.add_argument(
        "--response", required=True,
        help="Path to response JSON file"
    )
    parser.add_argument(
        "--expected-mrenclave", required=True,
        help="Expected MRENCLAVE hex value"
    )
    parser.add_argument(
        "--skip-crypto", action="store_true",
        help="Skip cryptographic quote verification (structural only)"
    )

    args = parser.parse_args()

    # Load quote
    try:
        with open(args.quote, "rb") as f:
            quote_bytes = f.read()
        print(f"Quote loaded: {len(quote_bytes)} bytes from {args.quote}")
    except FileNotFoundError:
        print(f"ERROR: Quote file not found: {args.quote}")
        return 2

    # Load response
    try:
        with open(args.response, "r") as f:
            response = json.load(f)
        print(f"Response loaded from {args.response}")
    except FileNotFoundError:
        print(f"ERROR: Response file not found: {args.response}")
        return 2
    except json.JSONDecodeError as e:
        print(f"ERROR: Invalid JSON in response file: {e}")
        return 2

    required_fields = [
        "public_key_pem", "prompt", "result",
        "timestamp", "mrenclave", "signature_hex", "payload_hash"
    ]
    missing = [f for f in required_fields if f not in response]
    if missing:
        print(f"ERROR: Response JSON missing fields: {missing}")
        return 2

    print(f"\nVerifying response for prompt: {response['prompt'][:60]!r}")
    print(f"Expected MRENCLAVE: {args.expected_mrenclave[:32]}...")

    # Run full verification
    report = full_verification(
        quote_bytes=quote_bytes,
        public_key_pem=response["public_key_pem"],
        expected_mrenclave=args.expected_mrenclave,
        signed_responses=[response],
        run_crypto_verify=not args.skip_crypto,
    )

    # Print detailed results
    print_section("STRUCTURAL VERIFICATION", {
        "passed": report["structural"]["passed"],
        "quote_version": report["structural"]["details"].get("quote_version"),
        "mrenclave": report["structural"]["details"].get("mrenclave", "")[:32] + "...",
        "mrenclave_match": report["structural"]["mrenclave_match"],
        "report_data_match": report["structural"]["report_data_match"],
        "cpu_svn": report["structural"]["details"].get("cpu_svn"),
        "errors": report["structural"]["errors"] or "none",
    })

    if not report["cryptographic"].get("skipped"):
        print_section("CRYPTOGRAPHIC VERIFICATION", {
            "passed": report["cryptographic"].get("passed"),
            "library_loaded": report["cryptographic"].get("library_loaded"),
            "return_code": report["cryptographic"].get("return_code"),
            "result": report["cryptographic"].get("verification_result_description"),
            "collateral_status": report["cryptographic"].get("collateral_status"),
            "errors": report["cryptographic"].get("errors") or "none",
        })
    else:
        print("\n[Cryptographic verification skipped]")

    for i, sig in enumerate(report["response_signatures"]):
        print_section(f"RESPONSE SIGNATURE #{i+1}", {
            "passed": sig["passed"],
            "errors": sig["errors"] or "none",
        })

    print(f"\n{'='*60}")
    print("  SUMMARY")
    print(f"{'='*60}")
    print(report["summary"])
    print(f"{'='*60}\n")

    return 0 if report["overall_passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
