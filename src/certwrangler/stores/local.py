from __future__ import annotations

import hashlib
import logging
from pathlib import Path
from typing import Literal, Union

from pydantic import Field

from certwrangler.exceptions import StoreError
from certwrangler.models import Cert, Store

log = logging.getLogger(__name__)


class LocalStore(Store):
    """
    Local storage driver.
    """

    driver: Literal["local"]
    path: Path = Field(
        ..., description="Path to where this driver should publish certs."
    )

    def initialize(self) -> None:
        """
        Create the target directory if it does not already exist.

        :raises StoreError: Raised on errors when creating the directory
            defined by :attr:`path`.
        """
        if not self.path.exists():
            log.info(f"Creating directory '{self.path}' for store '{self.name}'")
            try:
                self.path.mkdir(parents=True)
            except (OSError, IOError) as error:
                raise StoreError(error) from error

    def publish(self, cert: Cert) -> None:
        """
        Publish the cert, key, chain and fullchain to the target directory.
        This will update the files if the contents changed, no-op otherwise.

        :raises StoreError: Raised on errors creating, reading, or writing files
            under the directory defined by :attr:`path`.
        """
        if not (cert.state.key and cert.state.cert):
            return
        cert_path = self.path.joinpath(cert.name)
        if not cert_path.exists():
            log.info(
                f"Creating directory '{self.path}' for cert '{cert.name}' in store '{self.name}'"
            )
            try:
                cert_path.mkdir(parents=True)
            except (OSError, IOError) as error:
                raise StoreError(error) from error
        state_contents = cert.state.model_dump()
        entities = [
            # entity_type, contents
            [
                "key",
                state_contents["key"],
            ],
            [
                "cert",
                state_contents["cert"],
            ],
            [
                "chain",
                self._join_certs(*state_contents["chain"]),
            ],
            [
                "fullchain",
                self._join_certs(*state_contents["fullchain"]),
            ],
        ]
        for entity_type, contents in entities:
            # Update the entity if needed
            entity_path = cert_path.joinpath(f"{entity_type}.pem")
            try:
                if self._get_digest(contents) != self._get_digest(entity_path):
                    with open(entity_path, "w") as file_handler:
                        file_handler.write(contents)
                    log.info(
                        f"Cert '{cert.name}' {entity_type} saved to '{entity_path}'"
                    )
            except (OSError, IOError) as error:
                raise StoreError(error) from error

    def _get_digest(self, obj: Union[str, Path]) -> str:
        """
        Get the sha256sum of either a str or Path object.
        """
        if isinstance(obj, str):
            return hashlib.sha256(obj.encode()).hexdigest()
        if not obj.exists():
            return ""
        with open(obj, "r") as file_handler:
            return hashlib.sha256(
                "".join(file_handler.readlines()).encode()
            ).hexdigest()
