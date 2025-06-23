from __future__ import annotations

import logging
from typing import Any, Dict, Literal, Optional

import requests

# No type hints for EdgeGridAuth =(
from akamai.edgegrid import EdgeGridAuth  # type: ignore
from pydantic import Field, PrivateAttr
from requests.exceptions import RequestException

from certwrangler.exceptions import SolverError
from certwrangler.models import Solver
from certwrangler.types import Domain

log = logging.getLogger(__name__)


# Docs for this endpoint:
#   https://techdocs.akamai.com/edge-dns/reference/delete-zone-name-type
#   https://techdocs.akamai.com/edge-dns/reference/get-zone-name-type
#   https://techdocs.akamai.com/edge-dns/reference/post-zones-zone-names-name-types-type
#   https://techdocs.akamai.com/edge-dns/reference/put-zones-zone-names-name-types-type
ENDPOINT_PATTERN = (
    "https://{host}/config-dns/v2/zones/{domain}/names/{name}.{domain}/types/TXT"
)


class EdgeDNSSolver(Solver):
    """
    Solver powered by Akamai Edge DNS.
    """

    driver: Literal["edgedns"]
    host: Domain = Field(..., description="The Akamai API host.")
    client_token: str = Field(..., description="The Akamai API client token.")
    client_secret: str = Field(..., description="The Akamai API client secret.")
    access_token: str = Field(..., description="The Akamai API access token.")

    _session: requests.Session = PrivateAttr(default_factory=requests.Session)

    def initialize(self) -> None:
        """
        Set up the auth session to EdgeDNS.
        """
        self._session.auth = EdgeGridAuth(
            client_token=self.client_token,
            client_secret=self.client_secret,
            access_token=self.access_token,
        )

    def create(self, name: str, domain: str, content: str) -> None:
        """
        Create a TXT record in EdgeDNS.

        :raises SolverError: Raised on failures creating the DNS record or
            unexpected results from the API.
        """
        log.info(
            f"Solver '{self.name}' creating TXT '{name}' zone '{domain}' - '{content}'..."
        )
        endpoint = ENDPOINT_PATTERN.format(host=self.host, domain=domain, name=name)
        log.debug(f"Sending GET to '{endpoint}' to get current TXT record.")
        record = self._get(endpoint)
        log.debug(f"Got '{record}' from '{endpoint}'.")
        if record is None:
            record = {
                "name": f"{name}.{domain}",
                "type": "TXT",
                "ttl": 300,
                "rdata": [content],
            }
            log.debug(f"Sending POST to '{endpoint}' to create TXT record.")
            self._post(endpoint, record)
        elif isinstance(record.get("rdata"), list):
            if content in record["rdata"]:
                log.debug("Record is already in place, no action needed.")
                return
            else:
                record["rdata"].append(content)
                log.debug(f"Sending PUT to '{endpoint}' to update existing TXT record.")
                self._put(endpoint, record)
        else:
            raise SolverError(
                f"Expected 'rdata' in response to be a list, got {type(record.get('rdata')).__name__}."
            )

    def delete(self, name: str, domain: str, content: str) -> None:
        """
        Delete a TXT record in EdgeDNS.

        :raises SolverError: Raised on failures deleting the DNS record or
            unexpected results from the API.
        """
        log.info(
            f"Solver '{self.name}' deleting TXT '{name}' zone '{domain}' - '{content}'..."
        )
        endpoint = ENDPOINT_PATTERN.format(host=self.host, domain=domain, name=name)
        log.debug(f"Sending GET to '{endpoint}' to get current TXT record.")
        record = self._get(endpoint)
        log.debug(f"Got '{record}' from '{endpoint}'.")
        if record is None:
            log.debug("Record is already removed, no action needed.")
            return
        elif isinstance(record.get("rdata"), list):
            if content not in record["rdata"]:
                log.debug(f"'{content}' not found in record, no action needed.")
                return
            record["rdata"].remove(content)
            if not record["rdata"]:
                log.debug("Removed last entry, deleting TXT record.")
                self._delete(endpoint)
            else:
                log.debug(f"Updating TXT record to remove '{content}'.")
                self._put(endpoint, record)
        else:
            raise SolverError(
                f"Expected 'rdata' in response to be a list, got {type(record.get('rdata')).__name__}."
            )

    def _cleanup_response(self, response: Dict[str, Any]) -> Dict[str, Any]:
        """
        The EdgeDNS API seems to leave literal double quotes on the strings for
        TXT records. This just goes through each of the entries to strip them away.
        """
        if "rdata" in response and isinstance(response["rdata"], list):
            for idx, record_data in enumerate(response["rdata"]):
                if (
                    isinstance(record_data, str)
                    and record_data.startswith('"')
                    and record_data.endswith('"')
                ):
                    # This seems like a round-about way of stripping double
                    # quotes when str.strip('"') would also work. The reason I
                    # do it this way is to ensure we're only stripping the
                    # outer-most characters, whereas str.strip('"') would
                    # get rid of all leading or trailing double quotes.
                    response["rdata"][idx] = record_data[1:-1]
        return response

    def _delete(self, endpoint: str) -> bytes:
        """
        Send a DELETE request to the specified endpoint and return the
        contents of the response.

        :raises SolverError: Raised on unexpected results form the API.
        """
        try:
            response = self._session.delete(endpoint)
            response.raise_for_status()
        except RequestException as error:
            raise SolverError(error) from error
        return response.content

    def _get(self, endpoint: str) -> Optional[Dict[str, Any]]:
        """
        Send a GET request to the specified endpoint and return the parsed
        json response.

        :raises SolverError: Raised on unexpected results form the API.
        """
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        try:
            response = self._session.get(endpoint, headers=headers)
            if response.status_code == 404:
                return None
            response.raise_for_status()
        except RequestException as error:
            raise SolverError(error) from error
        return self._cleanup_response(response.json())

    def _post(self, endpoint: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Send a POST request to the specified endpoint with the specified payload
        and return the parsed json response.

        :raises SolverError: Raised on unexpected results form the API.
        """
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        try:
            response = self._session.post(endpoint, json=payload, headers=headers)
            response.raise_for_status()
        except RequestException as error:
            raise SolverError(error) from error
        return self._cleanup_response(response.json())

    def _put(self, endpoint: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Send a PUT request to the specified endpoint with the specified payload
        and return the parsed json response.

        :raises SolverError: Raised on unexpected results form the API.
        """
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        try:
            response = self._session.put(endpoint, json=payload, headers=headers)
            response.raise_for_status()
        except RequestException as error:
            raise SolverError(error) from error
        return self._cleanup_response(response.json())
