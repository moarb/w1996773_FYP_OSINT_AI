import requests
from typing import Any, Dict

class VirusTotalClient:
    BASE_URL = "https://www.virustotal.com/api/v3"

    def __init__(self, api_key: str):
        if not api_key:
            raise ValueError("VirusTotal API key is missing. Set VIRUSTOTAL_API_KEY in .env")
        self.api_key = api_key

    def _headers(self) -> Dict[str, str]:
        return {"x-apikey": self.api_key}

    def get_domain_report(self, domain: str) -> Dict[str, Any]:
        url = f"{self.BASE_URL}/domains/{domain}"
        r = requests.get(url, headers=self._headers(), timeout=30)
        r.raise_for_status()
        return r.json()

    def get_ip_report(self, ip: str) -> Dict[str, Any]:
        url = f"{self.BASE_URL}/ip_addresses/{ip}"
        r = requests.get(url, headers=self._headers(), timeout=30)
        r.raise_for_status()
        return r.json()

    def get_file_hash_report(self, file_hash: str) -> Dict[str, Any]:
        url = f"{self.BASE_URL}/files/{file_hash}"
        r = requests.get(url, headers=self._headers(), timeout=30)
        r.raise_for_status()
        return r.json()
