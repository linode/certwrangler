from __future__ import annotations

import hashlib
import logging
import os
from pathlib import Path
from typing import Literal

from pydantic import Field

from certwrangler.exceptions import StoreError
from certwrangler.models import Cert, Store
from certwrangler.types import FileMode

log = logging.getLogger(__name__)


class LocalStore(Store):
    """
    Local storage driver.
    """

    driver: Literal["local"]
    path: Path = Field(
        ..., description="Path to where this driver should publish certs."
    )
    cert_mode: FileMode = Field(
        0o644, description="File mode to use when creating certificate files."
    )
    key_mode: FileMode = Field(
        0o600, description="File mode to use when creating key files."
    )
    dir_mode: FileMode = Field(
        0o755, description="File mode to use when creating directories."
    )

    def initialize(self) -> None:
        """
        Create the target directory if it does not already exist.

        :raises StoreError: Raised on errors when creating the directory
            defined by :attr:`path`.
        """
        try:
            if not self.path.exists():
                log.info(f"Creating directory '{self.path}' for store '{self.name}'")
                self.path.mkdir(parents=True, mode=self.dir_mode)
            if self.path.stat().st_mode & 0o777 != self.dir_mode:
                log.info(
                    f"Setting mode for directory '{self.path}' in store '{self.name}' "
                    f"to '{oct(self.dir_mode)}'"
                )
                self.path.chmod(self.dir_mode)
        except OSError as error:
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
        try:
            if not cert_path.exists():
                log.info(
                    f"Creating directory '{cert_path}' for cert '{cert.name}' in store '{self.name}'"
                )
                cert_path.mkdir(parents=True, mode=self.dir_mode)
            if cert_path.stat().st_mode & 0o777 != self.dir_mode:
                log.info(
                    f"Setting mode for directory '{cert_path}' in store '{self.name}' "
                    f"to '{oct(self.dir_mode)}'"
                )
                cert_path.chmod(self.dir_mode)
        except OSError as error:
            raise StoreError(error) from error
        state_contents = cert.state.model_dump()
        entities = [
            # entity_type, contents
            [
                "key",
                state_contents["key"],
                self.key_mode,
            ],
            [
                "cert",
                state_contents["cert"],
                self.cert_mode,
            ],
            [
                "chain",
                self._join_certs(*state_contents["chain"]),
                self.cert_mode,
            ],
            [
                "fullchain",
                self._join_certs(*state_contents["fullchain"]),
                self.cert_mode,
            ],
        ]
        for entity_type, contents, mode in entities:
            # Update the entity if needed
            entity_path = cert_path.joinpath(f"{entity_type}.pem")
            try:
                if entity_path.exists() and entity_path.stat().st_mode & 0o777 != mode:
                    log.info(
                        f"Setting mode for '{entity_path}' in store '{self.name}' "
                        f"to '{oct(mode)}'"
                    )
                    entity_path.chmod(mode)
                if self._get_digest(contents) != self._get_digest(entity_path):
                    fd = os.open(
                        entity_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode
                    )
                    with os.fdopen(fd, "w") as file_handler:
                        os.fchmod(fd, mode)
                        file_handler.write(contents)
                    log.info(
                        f"Cert '{cert.name}' {entity_type} saved to '{entity_path}'"
                    )
            except OSError as error:
                raise StoreError(error) from error

    def _get_digest(self, obj: str | Path) -> str:
        """
        Get the sha256sum of either a str or Path object.
        """
        if isinstance(obj, str):
            return hashlib.sha256(obj.encode()).hexdigest()
        if not obj.exists():
            return ""
        with open(obj) as file_handler:
            return hashlib.sha256(
                "".join(file_handler.readlines()).encode()
            ).hexdigest()
