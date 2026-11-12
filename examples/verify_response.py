import os

import httpx


def main() -> None:
    api_key = os.environ["ARKHEIA_API_KEY"]
    response = httpx.post(
        "https://arkheia-proxy-production.up.railway.app/v1/detect",
        headers={"X-Arkheia-Key": api_key},
        json={
            "model": "gpt-4o",
            "response": "The Eiffel Tower is in Berlin.",
        },
        timeout=30.0,
    )
    response.raise_for_status()
    print(response.json())


if __name__ == "__main__":
    main()
