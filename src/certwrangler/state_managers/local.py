from __future__ import annotations

import json
import logging
import re
import textwrap
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional, Union

from cryptography.fernet import InvalidToken
from pydantic import Field

from certwrangler.exceptions import StateManagerError
from certwrangler.models import (
    Account,
    AccountState,
    Cert,
    CertState,
    Encryptor,
    StateManager,
)
from certwrangler.utils import XDG_DATA_HOME

log = logging.getLogger(__name__)

ENCRYPTION_HEADER = "-----BEGIN ENCRYPTED STATE-----"
ENCRYPTION_FOOTER = "-----END ENCRYPTED STATE-----"
ENCRYPTION_REGEX = re.compile(
    r"^\n*"
    rf"{ENCRYPTION_HEADER}\n+"
    r"(?P<metadata>([\w ]+: .+\n)*)?"
    r"\n*"
    r"(?P<data>([a-zA-Z0-9_=-]+\n)+)"
    rf"{ENCRYPTION_FOOTER}"
    r"\n*$"
)


def _is_encrypted(data: str) -> bool:
    """
    Simple check to see if the state is encrypted based on the presence of
    the encryption header and footer.
    """
    if re.match(ENCRYPTION_REGEX, data):
        return True
    return False


def _parse_encrypted_state(data: str) -> Dict[str, Any]:
    """
    Parses the encrypted state and returns a dict with the encrypted data
    and any discovered metadata tags.

    :raises ValueError: Raised if state file cannot be parsed.
    """
    match = re.match(ENCRYPTION_REGEX, data)
    if not match:
        raise ValueError("Could not parse encrypted state.")
    if match.group("metadata"):
        metadata = {
            key: value
            for key, value in [
                line.split(": ") for line in match.group("metadata").strip().split("\n")
            ]
        }
    else:
        metadata = {}
    data = "".join(match.group("data").strip().split("\n"))
    return {
        "metadata": metadata,
        "data": data.encode(),
    }


def _decrypt(data: str, encryptor: Encryptor) -> str:
    """
    Decrypt the encrypted state. Returns the decrypted contents of the
    data payload.
    """
    return encryptor.decrypt(_parse_encrypted_state(data)["data"]).decode()


def _encrypt(
    encryptor: Encryptor, data: str, metadata: Optional[Dict[str, str]] = None
) -> str:
    """
    Encrypts the contents of data using the provided encryptor. Can optionally
    embed a dict of additional metadata to the encrypted envelope.

    Note that the metadata is not encrypted and stored in plain text.
    """
    metadata_block = ""
    if metadata:
        metadata_block = "".join(
            sorted([f"{key}: {value}\n" for key, value in metadata.items()])
        )
    data_block = textwrap.fill(
        encryptor.encrypt(data.encode()).decode(),
        width=64,
        expand_tabs=False,
        replace_whitespace=False,
        fix_sentence_endings=False,
        break_long_words=True,
        drop_whitespace=False,
        break_on_hyphens=False,
    )
    return (
        f"{ENCRYPTION_HEADER}\n"
        f"{metadata_block}"
        f"\n"
        f"{data_block}\n"
        f"{ENCRYPTION_FOOTER}\n"
    )


def _list_entities(
    state_path_dir: Path, known_entities: List[str]
) -> Dict[str, Dict[str, Any]]:
    """
    Loops through the contents of the provided state_path_dir and compares
    the discovered entities to the provided known_entities list. Returns
    an inventory of discovered entities, including whether they're encrypted,
    the encryption metadata, if they're orphaned (not in known_entities),
    and their path.
    """
    entities = {}
    for state_path in state_path_dir.glob("*.json"):
        entity_name = state_path.name.rstrip(".json")
        entities[entity_name] = {
            "orphaned": entity_name not in known_entities,
            "encrypted": False,
            "encryption_metadata": {},
            "path": str(state_path.absolute()),
        }
        with open(state_path, "r") as file_handler:
            data = file_handler.read()
        if _is_encrypted(data):
            entities[entity_name]["encrypted"] = True
            entities[entity_name]["encryption_metadata"] = _parse_encrypted_state(data)[
                "metadata"
            ]
    return entities


class LocalStateManager(StateManager):
    """
    Local storage state manager driver.
    """

    driver: Literal["local"]
    base_path: Path = Field(
        default=Path(f"{XDG_DATA_HOME}/certwrangler"),
        alias="path",
        description="The base path for the state storage. Two subdirectories "
        "will be created under this path, 'accounts' and 'certs'. Defaults to "
        "'${XDG_DATA_HOME}/certwrangler' or '~/.local/share/certwrangler' "
        "if '${XDG_DATA_HOME}' is not set",
    )

    @property
    def certs_path(self) -> Path:
        """
        The path to the certs subdirectory based on base_path.
        """
        return self.base_path.joinpath("certs")

    @property
    def accounts_path(self) -> Path:
        """
        The path to the accounts subdirectory based on base_path.
        """
        return self.base_path.joinpath("accounts")

    def initialize(self) -> None:
        """
        Create the configured state storage directories based on the base_path.

        :raises StateManagerError: Raised on errors creating the state directories.
        """
        try:
            if not self.base_path.exists():
                log.info(f"Creating directory '{self.base_path}' for state storage.")
                self.base_path.mkdir(parents=True)
            if not self.accounts_path.exists():
                log.info(
                    f"Creating directory '{self.accounts_path}' for account state storage."
                )
                self.accounts_path.mkdir(parents=True)
            if not self.certs_path.exists():
                log.info(
                    f"Creating directory '{self.certs_path}' for cert state storage."
                )
                self.certs_path.mkdir(parents=True)
        except (OSError, IOError) as error:
            raise StateManagerError(error) from error

    def list(self) -> Dict[str, Dict[str, Any]]:
        """
        List all the state entities under management. Returns a dict of all
        the names of accounts and certs it discovers.

        :raises StateManagerError: Raised on errors reading the state.
        """
        try:
            return {
                "accounts": _list_entities(
                    self.accounts_path, list(self._config.accounts.keys())
                ),
                "certs": _list_entities(
                    self.certs_path, list(self._config.certs.keys())
                ),
            }
        except (OSError, IOError) as error:
            raise StateManagerError(error) from error

    def save(self, entity: Union[Account, Cert], encrypt: bool = True) -> None:
        """
        Save the provided entity's (Account or Cert object) state and by
        default will encrypt the contents if an encryptor is configured.

        :raises StateManagerError: Raised on errors writing the state.
        """
        try:
            if isinstance(entity.state, AccountState):
                state_path = self.accounts_path.joinpath(f"{entity.name}.json")
            if isinstance(entity.state, CertState):
                state_path = self.certs_path.joinpath(f"{entity.name}.json")
            data = entity.state.model_dump_json(indent=4)
            if encrypt and self.encryptor:
                data = _encrypt(
                    self.encryptor,
                    data,
                    metadata={"Fingerprint": str(self.encryptor.fingerprint)},
                )
            with open(state_path, "w") as file_handler:
                file_handler.write(data)
            log.debug(
                f"{entity.__class__.__name__} '{entity.name}' state saved to '{state_path}'"
            )
        except (OSError, IOError) as error:
            raise StateManagerError(error) from error

    def load(self, entity: Union[Account, Cert]) -> None:
        """
        Load and decrypt (if an encryptor is present) the state of the provided
        entity (Account or Cert object).

        :raises StateManagerError: Raised on errors reading, decoding, or
            decrypting the state.
        """
        try:
            if isinstance(entity, Account):
                state_path = self.accounts_path.joinpath(f"{entity.name}.json")
            if isinstance(entity, Cert):
                state_path = self.certs_path.joinpath(f"{entity.name}.json")
            if not state_path.exists():
                return
            state_class = type(entity.state)
            with open(state_path, "r") as file_handler:
                data = file_handler.read()
            if _is_encrypted(data):
                if self.encryptor is None:
                    raise StateManagerError(
                        f"Failed to load {entity.__class__.__name__} '{entity.name}': "
                        "State is encrypted and no encryption_keys present."
                    )
                data = _decrypt(data, self.encryptor)
            entity.state = state_class(**json.loads(data))
            log.debug(
                f"{entity.__class__.__name__} '{entity.name}' state loaded from '{state_path}'"
            )
        except (OSError, IOError, json.decoder.JSONDecodeError) as error:
            raise StateManagerError(error) from error
        except InvalidToken as error:
            raise StateManagerError(
                f"Failed to decrypt state for {entity.__class__.__name__} '{entity.name}'."
            ) from error

    def delete(
        self, entity_class: Union[Literal["account"], Literal["cert"]], entity_name: str
    ) -> None:
        """
        Delete the state for the provided entity_class and entity_name.

        :raises StateManagerError: Raised on errors deleting the state.
        """
        if entity_class == "account":
            state_path = self.accounts_path.joinpath(f"{entity_name}.json")
        if entity_class == "cert":
            state_path = self.certs_path.joinpath(f"{entity_name}.json")
        try:
            if state_path.exists():
                state_path.unlink()
        except (OSError, IOError) as error:
            raise StateManagerError(error) from error
