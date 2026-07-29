import os

import httpx

from arkheia_common.hosted_authority import DEFAULT_HOSTED_API_URL, authorize_hosted_base_url


def main() -> None:
    api_key = os.environ["ARKHEIA_API_KEY"]
    hosted_url = os.environ.get("ARKHEIA_HOSTED_URL", DEFAULT_HOSTED_API_URL)
    authorized = authorize_hosted_base_url(hosted_url)
    response = httpx.post(
        f"{authorized.base_url}/v1/detect",
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
