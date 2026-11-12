"""Minimal MCP example for retrieving Arkheia audit history.

Run this from an MCP-capable client after the Arkheia server is configured.
The exact call shape may vary by host, but the tool name remains `arkheia_audit_log`.
"""

import json


REQUEST = {
    "tool": "arkheia_audit_log",
    "arguments": {
        "limit": 10,
    },
}


def main() -> None:
    print("Send this MCP tool request from your host client:")
    print(json.dumps(REQUEST, indent=2))
    print()
    print("Expected result: the most recent Arkheia verification events for the current API key.")


if __name__ == "__main__":
    main()
