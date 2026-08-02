"""Simple end-to-end example: verify a response, then retrieve the audit log."""

import asyncio
import json
import os

from arkheia_common.hosted_authority import (
    DEFAULT_HOSTED_API_URL,
    authorize_hosted_base_url,
    hosted_key_egress_client,
)


async def verify_response() -> None:
    api_key = os.environ["ARKHEIA_API_KEY"]
    hosted_url = os.environ.get("ARKHEIA_HOSTED_URL", DEFAULT_HOSTED_API_URL)
    authorized = authorize_hosted_base_url(hosted_url)
    async with hosted_key_egress_client(timeout=30.0) as client:
        response = await client.post(
            f"{authorized.base_url}/v1/detect",
            headers={"X-Arkheia-Key": api_key},
            json={
                "model": "gpt-4o",
                "response": "Saturn is the closest planet to the Sun.",
            },
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
    asyncio.run(verify_response())
    print_audit_log_request()


if __name__ == "__main__":
    main()
