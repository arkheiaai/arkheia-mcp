"""Simple end-to-end example: verify a response, then retrieve the audit log."""

import json
import os

import httpx


def verify_response() -> None:
    api_key = os.environ["ARKHEIA_API_KEY"]
    response = httpx.post(
        "https://app.arkheia.ai/v1/detect",
        headers={"X-Arkheia-Key": api_key},
        json={
            "model": "gpt-4o",
            "response": "Saturn is the closest planet to the Sun.",
        },
        timeout=30.0,
    )
    response.raise_for_status()
    print("Detect response:")
    print(json.dumps(response.json(), indent=2))


def print_audit_log_request() -> None:
    request = {
        "tool": "arkheia_audit_log",
        "arguments": {"limit": 5},
    }
    print()
    print("Then issue this MCP tool request from your host client:")
    print(json.dumps(request, indent=2))


def main() -> None:
    verify_response()
    print_audit_log_request()


if __name__ == "__main__":
    main()
