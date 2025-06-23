import os
from pathlib import Path

import pytest
from hvac.exceptions import InvalidPath, VaultError
from importlib_metadata import entry_points
from pydantic import ValidationError
from requests.exceptions import RequestException

from certwrangler.exceptions import StoreError
from certwrangler.stores.vault import AppRoleAuth, KubernetesAuth, TokenAuth, VaultStore


class TestVaultAppRoleAuth:
    """
    Tests for Vault Approle Auth
    """

    def test_approle_auth(self, store_vault_auth_approle_config, mocker):
        auth = AppRoleAuth(**store_vault_auth_approle_config)
        mount_point = "/secret/data/certwrangler"
        auth.mount_point = mount_point

        client = mocker.MagicMock()
        auth.login(client)

        assert client.auth.approle.login.call_args_list == [
            mocker.call(
                mount_point=mount_point,
                role_id=store_vault_auth_approle_config["role_id"],
                secret_id=store_vault_auth_approle_config["secret_id"],
            )
        ]


class TestVaultKubernetesAuth:
    """
    Tests for Vault KubernetesAuth
    """

    def test_kubernetes_auth(self, store_vault_auth_kubernetes_config, mocker):
        auth = KubernetesAuth(**store_vault_auth_kubernetes_config)
        mount_point = "/secret/data/certwrangler"
        auth.mount_point = mount_point

        mocker.patch(
            "certwrangler.stores.vault.open",
            mocker.mock_open(read_data="foo"),
        )
        client = mocker.MagicMock()
        auth.login(client)

        assert client.auth.kubernetes.login.call_args_list == [
            mocker.call(
                role=store_vault_auth_kubernetes_config["role"],
                jwt="foo",
                mount_point=mount_point,
            )
        ]


class TestVaultTokenAuth:
    """
    Tests for Vault TokenAuth
    """

    def test_token_login(self, store_vault_auth_token_config, mocker):
        auth = TokenAuth(**store_vault_auth_token_config)
        client = mocker.MagicMock()
        auth.login(client)

        assert auth.token == client.token


class TestVaultStore:
    """
    Tests for the VaultStore.
    """

    @pytest.fixture(autouse=True)
    def _mock_vault_client(self, mocker, click_ctx):
        """
        Autouse fixture that patches our calls to vault and brings in the click_ctx fixture.
        """
        self._mock_client = mocker.MagicMock()
        mocker.patch(
            "certwrangler.stores.vault.hvac.Client",
            mocker.MagicMock(return_value=self._mock_client),
        )

    def test_plugin(self):
        """
        Test we correctly see the VaultStore plugin.
        """
        # store_vault_config is ignored
        (plugin,) = entry_points(group="certwrangler.store", name="vault")
        assert plugin.load() == VaultStore

    @pytest.mark.parametrize(
        "field",
        (
            "server",
            "mount_point",
            "path",
        ),
    )
    def test_required_fields(self, store_vault_config, field):
        """
        Test that we raise a ValidationErorr if we're missing required fields using Token auth.
        """
        store_vault_config.pop(field)

        with pytest.raises(ValidationError):
            VaultStore(**store_vault_config)

    def test_initialize(self, store_vault):
        """
        Test that we can initalize the plugin and that token is cleared in env.
        """
        os.environ["VAULT_TOKEN"] = "a-very-secret-token"
        store_vault.initialize()

        assert not store_vault.client.token

    def test_unauthenticated_publish(self, store_vault, cert, cert_state, mocker):
        """
        Test that we attempt to login if we're not already authenticated
        """
        store_vault.auth = mocker.MagicMock()
        store_vault.client.is_authenticated = mocker.MagicMock(return_value=False)
        store_vault.publish(cert)

        store_vault.auth.login.assert_called()

    def test_publish_v1(self, store_vault, cert, mocker):
        """
        Test that we can publish to the vault store using the v1 methods.
        """
        cert.state.key = "test key"
        cert.state.cert = "test cert"
        mocker.patch(
            "certwrangler.models.CertState.model_dump",
            mocker.MagicMock(
                return_value={
                    "key": "test key\n",
                    "cert": "test cert\n",
                    "chain": [
                        "test intermediate 1\n",
                        "test intermediate 2\n",
                        "test ca\n",
                    ],
                    "fullchain": [
                        "test cert\n",
                        "test intermediate 1\n",
                        "test intermediate 2\n",
                        "test ca\n",
                    ],
                }
            ),
        )
        store_vault.version = 1
        store_vault.publish(cert)

        store_vault.client.is_authenticated.assert_called()
        store_vault.client.secrets.kv.v1.read_secret.assert_called()
        store_vault.client.secrets.kv.v1.create_or_update_secret.assert_called()
        assert store_vault.client.secrets.kv.v1.create_or_update_secret.call_args_list == [
            mocker.call(
                mount_point=store_vault.mount_point,
                path=Path("foo/test_cert"),
                secret={
                    "key": "test key\n",
                    "cert": "test cert\n",
                    "chain": "test intermediate 1\ntest intermediate 2\ntest ca\n",
                    "fullchain": "test cert\ntest intermediate 1\ntest intermediate 2\ntest ca\n",
                },
            )
        ]

    def test_publish_v2(self, store_vault, cert, cert_state, mocker):
        """
        Test that we can publish to the vault store using the v2 methods.
        """
        cert.state.key = "test key"
        cert.state.cert = "test cert"
        mocker.patch(
            "certwrangler.models.CertState.model_dump",
            mocker.MagicMock(
                return_value={
                    "key": "test key\n",
                    "cert": "test cert\n",
                    "chain": [
                        "test intermediate 1\n",
                        "test intermediate 2\n",
                        "test ca\n",
                    ],
                    "fullchain": [
                        "test cert\n",
                        "test intermediate 1\n",
                        "test intermediate 2\n",
                        "test ca\n",
                    ],
                }
            ),
        )
        store_vault.version = 2
        store_vault.publish(cert)

        store_vault.client.is_authenticated.assert_called()
        store_vault.client.secrets.kv.v2.read_secret_version.assert_called()
        store_vault.client.secrets.kv.v2.create_or_update_secret.assert_called()
        assert store_vault.client.secrets.kv.v2.create_or_update_secret.call_args_list == [
            mocker.call(
                mount_point=store_vault.mount_point,
                path=Path("foo/test_cert"),
                secret={
                    "key": "test key\n",
                    "cert": "test cert\n",
                    "chain": "test intermediate 1\ntest intermediate 2\ntest ca\n",
                    "fullchain": "test cert\ntest intermediate 1\ntest intermediate 2\ntest ca\n",
                },
            )
        ]

    def test_publish_no_state(self, store_vault, cert, mocker):
        """
        Test that we no-op if we don't have a cert and key in the state.
        """
        mocked_model_dump = mocker.patch("certwrangler.models.CertState.model_dump")
        store_vault.publish(cert)

        mocked_model_dump.assert_not_called()
        store_vault.client.secrets.kv.v2.create_or_update_secret.assert_not_called()

    def test_publish_auth_error(self, store_vault, cert, cert_state):
        store_vault.client.is_authenticated.side_effect = RequestException(
            "Request error"
        )
        with pytest.raises(StoreError, match="Request error"):
            store_vault.publish(cert)

        store_vault.client.is_authenticated.side_effect = VaultError("Vault error")
        with pytest.raises(StoreError, match="Vault error"):
            store_vault.publish(cert)

    def test_publish_read_error_v1(self, store_vault, cert, cert_state):
        """
        Test that StoreError is raised if there is an issue reading a secret
        """
        store_vault.version = 1
        store_vault.client.secrets.kv.v1.read_secret.side_effect = VaultError(
            "Read error"
        )
        with pytest.raises(StoreError, match="Read error"):
            store_vault.publish(cert)

    def test_publish_read_error_v2(self, store_vault, cert, cert_state):
        """
        Test that StoreError is raised if there is an issue reading a secret
        """
        store_vault.version = 2
        store_vault.client.secrets.kv.v2.read_secret_version.side_effect = VaultError(
            "Read error"
        )
        with pytest.raises(StoreError, match="Read error"):
            store_vault.publish(cert)

    def test_publish_write_error_v1(self, store_vault, cert, cert_state):
        """
        Test that a StoreError is raised if there is an issue writing a secret
        """
        store_vault.version = 1
        store_vault.client.secrets.kv.v1.create_or_update_secret.side_effect = (
            VaultError("Write error")
        )

        with pytest.raises(StoreError, match="Write error"):
            store_vault.publish(cert)

    def test_publish_write_error_v2(self, store_vault, cert, cert_state):
        """
        Test that a StoreError is raised if there is an issue writing a secret
        """
        store_vault.version = 2
        store_vault.client.secrets.kv.v2.create_or_update_secret.side_effect = (
            VaultError("Write error")
        )

        with pytest.raises(StoreError, match="Write error"):
            store_vault.publish(cert)

    def test_publish_invalid_path_error(self, store_vault, cert, cert_state, mocker):
        """
        Test that InvalidPath is raised if a bad path is passed to vault
        """
        store_vault._read_v2 = mocker.MagicMock(side_effect=InvalidPath("Invalid path"))
        store_vault.publish(cert)

        store_vault._read_v2.assert_called()

    def test_publish_store_key(self, store_vault, cert, cert_state, mocker):
        """
        Test that we publish vault path with a defined store_key if one is defined
        """
        cert.store_key = "dummy"
        store_vault._write_v2 = mocker.MagicMock()
        store_vault.publish(cert)

        store_vault._write_v2.assert_called()
        assert Path("foo/dummy") in store_vault._write_v2.call_args_list[0].args
