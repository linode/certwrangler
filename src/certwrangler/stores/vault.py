from __future__ import annotations

import abc
import logging
from pathlib import Path
from typing import Dict, Literal, Optional, Union

# hvac has no types, see: https://github.com/hvac/hvac/issues/800
import hvac  # type: ignore
from hvac.exceptions import InvalidPath, VaultError  # type: ignore
from pydantic import BaseModel, Field, HttpUrl, PrivateAttr
from requests.exceptions import RequestException

from certwrangler.exceptions import StoreError
from certwrangler.models import Cert, Store

log = logging.getLogger(__name__)


class BaseAuth(BaseModel, metaclass=abc.ABCMeta):
    """
    Base vault auth class.
    """

    @abc.abstractmethod
    def login(self, client: hvac.Client) -> None:
        """
        This should be overridden by subclasses to provide the login logic.
        """

        raise NotImplementedError


class AppRoleAuth(BaseAuth):
    """
    AppRole auth class.
    """

    method: Literal["approle"]
    mount_point: Optional[str] = Field(
        default=None, description="Optional mount point for the auth method."
    )
    role_id: str = Field(..., description="The AppRole role_id.")
    secret_id: str = Field(..., description="The AppRole secret_id.")

    def login(self, client: hvac.Client) -> None:
        """
        Login logic for AppRole auth.
        """

        kwargs = {
            "role_id": self.role_id,
            "secret_id": self.secret_id,
        }
        if self.mount_point:
            kwargs["mount_point"] = self.mount_point
        client.auth.approle.login(**kwargs)


class KubernetesAuth(BaseAuth):
    """
    Kubernetes auth class.
    """

    method: Literal["kubernetes"]
    mount_point: Optional[str] = Field(
        default=None, description="Optional mount point for the auth method."
    )
    role: str = Field(..., description="The name of the role.")
    token_path: str = Field(
        default="/var/run/secrets/kubernetes.io/serviceaccount/token",
        description="The path to the kubernetes service account token.",
    )

    def login(self, client: hvac.Client) -> None:
        """
        Login logic for kubernetes auth.
        """

        with open(self.token_path, "r") as file_handler:
            jwt = file_handler.read()
        kwargs = {
            "role": self.role,
            "jwt": jwt,
        }
        if self.mount_point:
            kwargs["mount_point"] = self.mount_point
        client.auth.kubernetes.login(**kwargs)


class TokenAuth(BaseAuth):
    """
    Token auth class.
    """

    method: Literal["token"]
    token: str = Field(..., description="The vault token.")

    def login(self, client: hvac.Client) -> None:
        """
        Login logic for token auth.
        """

        client.token = self.token


class VaultStore(Store):
    """
    Vault storage driver.
    """

    driver: Literal["vault"]
    server: HttpUrl = Field(..., description="The URI of the vault server.")
    ca_cert: Optional[Path] = Field(
        default=None,
        description="Optional path to a CA cert for requests to vault.",
    )
    mount_point: str = Field(..., description="Mount point of the secrets engine.")
    path: Path = Field(..., description="Path where secrets should be written.")
    version: Literal[1, 2] = Field(
        default=2, description="The version of the vault secrets engine."
    )
    auth: Union[AppRoleAuth, TokenAuth, KubernetesAuth] = Field(
        discriminator="method", description="The config for authenticating with vault."
    )

    _client: Optional[hvac.Client] = PrivateAttr(default=None)

    @property
    def client(self) -> hvac.Client:
        if self._client is None:
            self._client = hvac.Client(
                url=self.server,
                verify=self.ca_cert,
            )
        return self._client

    def initialize(self) -> None:
        """
        hvac will try to read the token from an $VAULT_TOKEN or ~/.vault_token.
        This explicitly clears out the token to ensure we read from config.
        """

        self.client.token = None

    def publish(self, cert: Cert) -> None:
        """
        Publish the cert to the configured location in vault.

        :raises StoreError: Raised on authentication failures or failures
            reading or writing to vault.
        """

        if not (cert.state.key and cert.state.cert):
            return
        try:
            if not self.client.is_authenticated():
                self.auth.login(self.client)
        except (RequestException, VaultError) as error:
            raise StoreError(error) from error
        if self.version == 1:
            read_secret = self._read_v1
            write_secret = self._write_v1
        elif self.version == 2:
            read_secret = self._read_v2
            write_secret = self._write_v2
        state_contents = cert.state.model_dump()
        proposed_secret = {
            "key": state_contents["key"],
            "cert": state_contents["cert"],
            "chain": self._join_certs(*state_contents["chain"]),
            "fullchain": self._join_certs(*state_contents["fullchain"]),
        }
        secret_path = self.path.joinpath(cert.name)
        if cert.store_key:
            secret_path = self.path.joinpath(cert.store_key)
        try:
            current_secret = read_secret(secret_path)
        except InvalidPath:
            # secret hasn't been created yet
            current_secret = {}
        except (RequestException, VaultError) as error:
            raise StoreError(error) from error
        if proposed_secret != current_secret:
            try:
                write_secret(secret_path, proposed_secret)
            except (RequestException, VaultError) as error:
                raise StoreError(error) from error
            log.info(
                f"Cert '{cert.name}' published to '{self.mount_point}/{secret_path}' in vault"
            )

    def _read_v1(self, path: Path) -> Dict[str, str]:
        """
        Read the contents of a secret from a v1 vault endpoint.
        """

        return self.client.secrets.kv.v1.read_secret(
            mount_point=self.mount_point,
            path=path,
        )["data"]

    def _write_v1(self, path: Path, secret: Dict[str, str]) -> None:
        """
        Write the contents of a secret to a v1 vault endpoint.
        """

        return self.client.secrets.kv.v1.create_or_update_secret(
            mount_point=self.mount_point,
            path=path,
            secret=secret,
        )

    def _read_v2(self, path: Path) -> Dict[str, str]:
        """
        Read the contents of a secret from a v2 vault endpoint.
        """

        return self.client.secrets.kv.v2.read_secret_version(
            mount_point=self.mount_point,
            path=path,
        )["data"]["data"]

    def _write_v2(self, path: Path, secret: Dict[str, str]) -> None:
        """
        Write the contents of a secret to a v1 vault endpoint.
        """

        return self.client.secrets.kv.v2.create_or_update_secret(
            mount_point=self.mount_point,
            path=path,
            secret=secret,
        )
