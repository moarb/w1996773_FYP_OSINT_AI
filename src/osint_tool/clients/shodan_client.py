# import requests
# from typing import Any, Dict
# from osint_tool.config import settings


# class ShodanClient:
#     BASE_URL = "https://api.shodan.io"

#     def __init__(self, api_key: str | None = None):
#         self.api_key = api_key or settings.shodan_api_key

#         if not self.api_key:
#             raise ValueError(
#                 "Shodan API key is missing. "
#                 "Set SHODAN_API_KEY in .env (local) "
#                 "or Streamlit Secrets (cloud)."
#             )

#     def resolve_domain(self, domain: str) -> Dict[str, Any]:
#         """
#         Resolve a domain to IP using Shodan DNS resolve endpoint.
#         """
#         url = f"{self.BASE_URL}/dns/resolve"
#         params = {
#             "hostnames": domain,
#             "key": self.api_key,
#         }
#         response = requests.get(url, params=params, timeout=30)
#         response.raise_for_status()
#         return response.json()

#     def get_host(self, ip: str) -> Dict[str, Any]:
#         """
#         Retrieve Shodan host information for an IP.
#         """
#         url = f"{self.BASE_URL}/shodan/host/{ip}"
#         params = {"key": self.api_key}
#         response = requests.get(url, params=params, timeout=30)
#         response.raise_for_status()
#         return response.json()

#     def get_domain_bundle(self, domain: str) -> Dict[str, Any]:
#         """
#         Resolve domain, then fetch host details for its IP.
#         Returns a combined payload for easier raw storage.
#         """
#         resolved = self.resolve_domain(domain)
#         ip = resolved.get(domain)

#         host_data = {}
#         if ip:
#             try:
#                 host_data = self.get_host(ip)
#             except requests.HTTPError:
#                 host_data = {}

#         return {
#             "query": domain,
#             "resolved_ip": ip,
#             "host": host_data,
#         }


import socket
import requests
from typing import Any, Dict
from osint_tool.config import settings


class ShodanClient:
    BASE_URL = "https://api.shodan.io"

    def __init__(self, api_key: str | None = None):
        self.api_key = api_key or settings.shodan_api_key

        if not self.api_key:
            raise ValueError(
                "Shodan API key is missing. "
                "Set SHODAN_API_KEY in .env (local) "
                "or Streamlit Secrets (cloud)."
            )

    def resolve_domain_local(self, domain: str) -> str:
        """
        Resolve a domain to an IP address using Python's built-in DNS lookup.
        Example:
            bbc.co.uk -> 151.xxx.xxx.xxx
        """
        return socket.gethostbyname(domain)

    def get_host(self, ip: str) -> Dict[str, Any]:
        """
        Retrieve Shodan host information for an IP.
        """
        url = f"{self.BASE_URL}/shodan/host/{ip}"
        params = {"key": self.api_key}
        response = requests.get(url, params=params, timeout=30)
        response.raise_for_status()
        return response.json()

    def get_domain_bundle(self, domain: str) -> Dict[str, Any]:
        """
        Resolve domain locally to IP, then fetch Shodan host data for that IP.
        Returns one combined payload for easier raw storage.
        """
        ip = self.resolve_domain_local(domain)

        host_data = {}
        try:
            host_data = self.get_host(ip)
        except requests.HTTPError:
            host_data = {}

        return {
            "query": domain,
            "resolved_ip": ip,
            "host": host_data,
        }