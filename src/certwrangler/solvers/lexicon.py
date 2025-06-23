from __future__ import annotations

import logging
from typing import Any, Dict, Literal

from lexicon.client import Client
from lexicon.config import ConfigResolver
from lexicon.exceptions import LexiconError
from pydantic import Field
from requests.exceptions import RequestException

from certwrangler.exceptions import SolverError
from certwrangler.models import Solver

log = logging.getLogger(__name__)


class LexiconSolver(Solver):
    """
    Solver powered by lexicon.

    A full list of available providers and options is available at:
    https://dns-lexicon.readthedocs.io/en/latest/configuration_reference.html
    """

    driver: Literal["lexicon"]
    provider_name: str = Field(
        ..., description="The name of the lexicon provider to use."
    )
    provider_options: Dict[str, Any] = Field(
        default_factory=dict, description="Provider-specific options."
    )

    def create(self, name: str, domain: str, content: str) -> None:
        """
        Create a TXT record based on the lexicon config.

        :raises SolverError: Raised on failures creating the DNS record.
        """
        log.info(
            f"Solver '{self.name}' creating TXT '{name}' zone '{domain}' - '{content}'..."
        )
        config_dict = self._build_config("create", name, domain, content)
        lexicon_config = ConfigResolver().with_dict(config_dict)
        try:
            Client(lexicon_config).execute()
        except (RequestException, LexiconError) as error:
            raise SolverError(error) from error

    def delete(self, name: str, domain: str, content: str) -> None:
        """
        Delete a TXT record based on the lexicon config.

        :raises SolverError: Raised on failures deleting the DNS record.
        """
        log.info(
            f"Solver '{self.name}' deleting TXT '{name}' zone '{domain}' - '{content}'..."
        )
        config_dict = self._build_config("delete", name, domain, content)
        lexicon_config = ConfigResolver().with_dict(config_dict)
        try:
            Client(lexicon_config).execute()
        except (RequestException, LexiconError) as error:
            raise SolverError(error) from error

    def _build_config(
        self, action: str, name: str, domain: str, content: str
    ) -> Dict[str, Any]:
        """
        Generate the needed lexicon config for the request based on the action
        and the provider_options.
        """
        return {
            "action": action,
            "name": name,
            "domain": domain,
            "delegated": domain,
            "type": "TXT",
            "content": content,
            "provider_name": self.provider_name,
            self.provider_name: self.provider_options,
        }
