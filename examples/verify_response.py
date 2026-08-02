import asyncio
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
                "response": "The Eiffel Tower is in Berlin.",
            },
        )
    response.raise_for_status()
    print(response.json())


def main() -> None:
    asyncio.run(verify_response())


if __name__ == "__main__":
    main()
