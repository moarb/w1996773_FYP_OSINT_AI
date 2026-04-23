import socket
import requests
from typing import Any, Dict
from osint_tool.config import settings


class ShodanClient:
    BASE_URL = "https://api.shodan.io"

    def __init__(self, api_key: str | None = None):
        # Use provided API key or fall back to config settings
        self.api_key = api_key or settings.shodan_api_key

        # Fail early if key is missing (prevents silent runtime errors)
        if not self.api_key:
            raise ValueError(
                "Shodan API key is missing. "
                "Set SHODAN_API_KEY in .env (local) "
                "or Streamlit Secrets (cloud)."
            )

    def resolve_domain_local(self, domain: str) -> str:
        # Resolve a domain to an IP using local DNS (no API call needed)
        # Example: bbc.co.uk -> 151.x.x.x
        return socket.gethostbyname(domain)

    def get_host(self, ip: str) -> Dict[str, Any]:
        # Query Shodan for host data using an IP address
        url = f"{self.BASE_URL}/shodan/host/{ip}"
        params = {"key": self.api_key}

        response = requests.get(url, params=params, timeout=30)
        response.raise_for_status()  # ensures HTTP errors are not ignored

        return response.json()

    def get_domain_bundle(self, domain: str) -> Dict[str, Any]:
        # Resolve domain to IP first (Shodan free tier limitation workaround)
        ip = self.resolve_domain_local(domain)

        # Attempt to fetch host data from Shodan
        host_data = {}
        try:
            host_data = self.get_host(ip)
        except requests.HTTPError:
            # If Shodan fails (e.g. no data), continue with empty result
            host_data = {}

        # Return a combined structure for easier downstream processing
        return {
            "query": domain,
            "resolved_ip": ip,
            "host": host_data,
        }