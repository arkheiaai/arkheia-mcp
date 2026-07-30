import os

from arkheia_common.egress import egress_client


def main() -> None:
    api_key = os.environ["ARKHEIA_API_KEY"]
    with egress_client(timeout=30.0) as client:
        response = client.post(
            "https://arkheia-proxy-production.up.railway.app/v1/detect",
            headers={"X-Arkheia-Key": api_key},
            json={
                "model": "gpt-4o",
                "response": "The Eiffel Tower is in Berlin.",
            },
        )
    response.raise_for_status()
    print(response.json())


if __name__ == "__main__":
    main()
