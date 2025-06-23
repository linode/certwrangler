import re
from pathlib import Path
from textwrap import dedent

import pytest
from cryptography.fernet import Fernet
from importlib_metadata import entry_points

from certwrangler.exceptions import StateManagerError
from certwrangler.models import Encryptor
from certwrangler.state_managers.local import (
    ENCRYPTION_FOOTER,
    ENCRYPTION_HEADER,
    LocalStateManager,
    _decrypt,
    _encrypt,
    _is_encrypted,
    _list_entities,
    _parse_encrypted_state,
)


def test__is_encrypted():
    """
    Test that we can detect an encrypted state file.
    """
    data = "this is data\ntest test test\nend test"
    assert not _is_encrypted(data)
    data = (
        "-----BEGIN ENCRYPTED STATE-----\n"
        "test test test not valid\n"
        "-----END ENCRYPTED STATE-----"
    )
    assert not _is_encrypted(data)
    data = (
        "\n\n-----BEGIN ENCRYPTED STATE-----\n"
        "test12test-test\n"
        "-----END ENCRYPTED STATE-----"
    )
    assert _is_encrypted(data)
    data = (
        "\n\n-----BEGIN ENCRYPTED STATE-----\n"
        "Here: have some metadata\n"
        "And More: even more metadata!\n"
        "\n"
        "test12test-test\n"
        "-----END ENCRYPTED STATE-----"
    )
    assert _is_encrypted(data)


def test__parse_encrypted_state():
    """
    Test that we can get the fingerprint metadata.
    """
    data = (
        "\n\n-----BEGIN ENCRYPTED STATE-----\n"
        "Fingerprint: actually a thumb\n"
        "\n"
        "test-test-test\n"
        "-----END ENCRYPTED STATE-----"
    )
    parsed = _parse_encrypted_state(data)
    assert parsed["metadata"]["Fingerprint"] == "actually a thumb"
    assert parsed["data"] == b"test-test-test"
    data = (
        "\n\n-----BEGIN ENCRYPTED STATE-----\n"
        "Fingerprint: actually a thumb\n"
        "More Metadata: more test!\n"
        "\n"
        "test-test-test\n"
        "-----END ENCRYPTED STATE-----"
    )
    parsed = _parse_encrypted_state(data)
    assert parsed["metadata"]["Fingerprint"] == "actually a thumb"
    assert parsed["metadata"]["More Metadata"] == "more test!"
    assert parsed["data"] == b"test-test-test"
    data = (
        "\n\n-----BEGIN ENCRYPTED STATE-----\n"
        "test-test-test\n"
        "-----END ENCRYPTED STATE-----"
    )
    parsed = _parse_encrypted_state(data)
    assert parsed["metadata"] == {}
    assert parsed["data"] == b"test-test-test"
    data = "\n\ndoes not compute\n"
    with pytest.raises(ValueError, match="Could not parse encrypted state."):
        _parse_encrypted_state(data)


def test__encrypt_and__decrypt():
    """
    Test that we can encrypt our data and decrypt it.
    """
    key = Fernet.generate_key()
    encryptor = Encryptor([Fernet(key)])
    metadata = {
        "Fingerprint": str(Encryptor.fingerprint),
        "How it Doing": "Pretty okay I guess",
    }
    encrypted_data = _encrypt(
        encryptor, "this is some test data, super secret", metadata
    )
    encrypted_lines = encrypted_data.strip().split("\n")
    assert encrypted_lines[0] == ENCRYPTION_HEADER
    assert encrypted_lines[-1] == ENCRYPTION_FOOTER
    assert encrypted_lines[1] == f"Fingerprint: {Encryptor.fingerprint}"
    assert encrypted_lines[2] == "How it Doing: Pretty okay I guess"
    assert encrypted_lines[3] == ""
    encrypted_string = "".join(encrypted_lines[4:-1])
    # make sure we only have valid urlsafe base64 characters.
    assert re.match(r"[a-zA-Z0-9_=-]+", encrypted_string)
    assert (
        encryptor.decrypt(encrypted_string.encode()).decode()
        == "this is some test data, super secret"
    )
    parsed = _parse_encrypted_state(encrypted_data)
    assert parsed["metadata"] == metadata
    assert parsed["data"] == encrypted_string.encode()
    assert _decrypt(encrypted_data, encryptor) == "this is some test data, super secret"


def test__list_entities(mocker):
    """
    Test that we can list state entities from a (fake) directory.
    """
    known_entities = []
    state_path_dir = mocker.MagicMock()
    state_path_dir.glob.return_value = [
        Path("/tmp/certwrangler/state/certs/test_entity.json")
    ]
    open_mock = mocker.patch(
        "certwrangler.state_managers.local.open",
        mocker.mock_open(
            read_data=dedent(
                """
                -----BEGIN ENCRYPTED STATE-----
                Fingerprint: actually a thumb

                test-test-test
                -----END ENCRYPTED STATE-----
                """
            ).strip()
        ),
    )
    entities = _list_entities(state_path_dir, known_entities)
    open_mock.assert_called_once_with(
        Path("/tmp/certwrangler/state/certs/test_entity.json"), "r"
    )
    assert entities == {
        "test_entity": {
            "orphaned": True,
            "encrypted": True,
            "encryption_metadata": {
                "Fingerprint": "actually a thumb",
            },
            "path": "/tmp/certwrangler/state/certs/test_entity.json",
        }
    }


class TestLocalStateManager:
    """
    Tests for the LocalStateManager.
    """

    def test_plugin(self):
        """
        Test we correctly see the LocalStateManager plugin.
        """
        (plugin,) = entry_points(group="certwrangler.state_manager", name="local")
        assert plugin.load() == LocalStateManager

    def test_properties(self, state_manager_local):
        assert (
            state_manager_local.accounts_path.as_posix()
            == "/tmp/certwrangler_state/accounts"
        )
        assert (
            state_manager_local.certs_path.as_posix() == "/tmp/certwrangler_state/certs"
        )

    def test_initialize(self, state_manager_local, mocker):
        """
        Test that we can initialize the plugin.
        """
        state_manager_local.base_path = mocker.MagicMock()
        state_manager_local.base_path.exists.return_value = False
        certs_path_mock = mocker.patch(
            "certwrangler.state_managers.local.LocalStateManager.certs_path"
        )
        certs_path_mock.exists.return_value = False
        accounts_path_mock = mocker.patch(
            "certwrangler.state_managers.local.LocalStateManager.accounts_path"
        )
        accounts_path_mock.exists.return_value = False
        state_manager_local.initialize()
        state_manager_local.base_path.exists.assert_called_once()
        state_manager_local.base_path.mkdir.assert_called_once_with(parents=True)
        certs_path_mock.exists.assert_called_once()
        certs_path_mock.mkdir.assert_called_once_with(parents=True)
        accounts_path_mock.exists.assert_called_once()
        accounts_path_mock.mkdir.assert_called_once_with(parents=True)

    def test_initialize_error(self, state_manager_local, mocker):
        """
        Test that we raise a StateManagerError if something breaks in initialization.
        """
        state_manager_local.base_path = mocker.MagicMock()
        state_manager_local.base_path.exists.return_value = False
        state_manager_local.base_path.mkdir.side_effect = OSError("That broke")
        with pytest.raises(StateManagerError, match="That broke"):
            state_manager_local.initialize()
        state_manager_local.base_path.mkdir.side_effect = IOError("Also broke")
        with pytest.raises(StateManagerError, match="Also broke"):
            state_manager_local.initialize()

    def test_list(self, config, state_manager_local, mocker):
        """
        Test that we can list entities in the state.
        """
        state_manager_local._config = config
        state_path_dir = mocker.MagicMock()
        state_path_dir.glob.return_value = [
            Path("/tmp/certwrangler/state/certs/test_entity.json")
        ]
        _list_entities_mock = mocker.patch(
            "certwrangler.state_managers.local._list_entities",
        )
        _list_entities_mock.return_value = {
            "test_entity": {
                "orphaned": True,
                "encrypted": True,
                "encryption_metadata": {
                    "Fingerprint": "actually a thumb",
                },
                "path": "/tmp/certwrangler/state/certs/test_entity.json",
            }
        }
        assert state_manager_local.list() == {
            "accounts": _list_entities_mock.return_value,
            "certs": _list_entities_mock.return_value,
        }

    def test_list_error(self, config, state_manager_local, mocker):
        """
        Test that we can list entities in the state.
        """
        state_manager_local._config = config
        state_path_dir = mocker.MagicMock()
        state_path_dir.glob.return_value = [
            Path("/tmp/certwrangler/state/certs/test_entity.json")
        ]
        _list_entities_mock = mocker.patch(
            "certwrangler.state_managers.local._list_entities",
        )
        _list_entities_mock.side_effect = OSError("That broke")
        with pytest.raises(StateManagerError, match="That broke"):
            state_manager_local.list()
        _list_entities_mock.side_effect = IOError("Also broke")
        with pytest.raises(StateManagerError, match="Also broke"):
            state_manager_local.list()

    def test_save_account(self, account, state_manager_local, mocker):
        """
        Test that we can save state for accounts.
        """
        open_mock = mocker.patch(
            "certwrangler.state_managers.local.open", mocker.mock_open()
        )
        account.state.key_size = 12345
        state_manager_local.save(account)
        open_mock.assert_called_once_with(
            Path("/tmp/certwrangler_state/accounts/test_account.json"), "w"
        )
        handler_mock = open_mock()
        handler_mock.write.assert_called_once_with(
            dedent(
                f"""
                {{
                    "registration": null,
                    "key": null,
                    "key_size": 12345,
                    "status": "new",
                    "_schema_version": {account.state._schema_version}
                }}
                """
            ).strip()
        )

    def test_save_cert(self, cert, state_manager_local, mocker):
        """
        Test that we can save state for certs.
        """
        open_mock = mocker.patch(
            "certwrangler.state_managers.local.open", mocker.mock_open()
        )
        cert.state.key_size = 12345
        state_manager_local.save(cert)
        open_mock.assert_called_once_with(
            Path("/tmp/certwrangler_state/certs/test_cert.json"), "w"
        )
        handler_mock = open_mock()
        handler_mock.write.assert_called_once_with(
            dedent(
                f"""
                {{
                    "url": null,
                    "key": null,
                    "key_size": 12345,
                    "cert": null,
                    "chain": null,
                    "csr": null,
                    "order": null,
                    "status": "new",
                    "_schema_version": {cert.state._schema_version},
                    "fullchain": null
                }}
                """
            ).strip()
        )

    def test_save_encryption(self, account, state_manager_local, mocker):
        """
        Test that we can save state with encryption.
        """
        account.state.key_size = 12345
        state_manager_local._encryptor = mocker.MagicMock()
        state_manager_local._encryptor.fingerprint = "no fingers"
        _encrypt_mock = mocker.patch("certwrangler.state_managers.local._encrypt")
        _encrypt_mock.return_value = "some encrypted data"
        open_mock = mocker.patch(
            "certwrangler.state_managers.local.open", mocker.mock_open()
        )
        handler_mock = open_mock()
        state_manager_local.save(account)
        _encrypt_mock.assert_called_once_with(
            state_manager_local._encryptor,
            dedent(
                f"""
                {{
                    "registration": null,
                    "key": null,
                    "key_size": 12345,
                    "status": "new",
                    "_schema_version": {account.state._schema_version}
                }}
                """
            ).strip(),
            metadata={"Fingerprint": "no fingers"},
        )
        handler_mock.write.assert_called_once_with("some encrypted data")

    def test_save_error(self, account, cert, state_manager_local, mocker):
        """
        Test that we raise a StateManagerError if we run into trouble
        while saving state.
        """
        open_mock = mocker.patch(
            "certwrangler.state_managers.local.open", mocker.mock_open()
        )
        open_mock.side_effect = OSError("That broke")
        with pytest.raises(StateManagerError, match="That broke"):
            state_manager_local.save(account)
        with pytest.raises(StateManagerError, match="That broke"):
            state_manager_local.save(cert)
        open_mock.side_effect = IOError("Also broke")
        with pytest.raises(StateManagerError, match="Also broke"):
            state_manager_local.save(account)
        with pytest.raises(StateManagerError, match="Also broke"):
            state_manager_local.save(cert)

    def test_load_account(self, account, state_manager_local, mocker):
        """
        Test that we can load state for accounts.
        """
        open_mock = mocker.patch(
            "certwrangler.state_managers.local.open",
            mocker.mock_open(
                read_data=dedent(
                    """
                    {
                        "registration": null,
                        "key": null,
                        "key_size": 12345
                    }
                    """
                ).strip()
            ),
        )
        accounts_path_mock = mocker.patch(
            "certwrangler.state_managers.local.LocalStateManager.accounts_path"
        )
        state_path = mocker.MagicMock()
        accounts_path_mock.joinpath.return_value = state_path
        # first simulate the state file not existing, should just no-op.
        state_path.exists.return_value = False
        state_manager_local.load(account)
        open_mock.assert_not_called()
        # then simulate it existing and returning data
        assert account.state.key_size is None
        state_path.exists.return_value = True
        state_manager_local.load(account)
        open_mock.assert_called_once_with(state_path, "r")
        assert account.state.key_size == 12345

    def test_load_cert(self, cert, state_manager_local, mocker):
        """
        Test that we can load state for certs.
        """
        open_mock = mocker.patch(
            "certwrangler.state_managers.local.open",
            mocker.mock_open(
                read_data=dedent(
                    """
                    {
                        "url": null,
                        "key": null,
                        "key_size": 12345,
                        "cert": null,
                        "intermediates": null,
                        "ca": null,
                        "csr": null,
                        "order": null
                    }
                    """
                ).strip()
            ),
        )
        certs_path_mock = mocker.patch(
            "certwrangler.state_managers.local.LocalStateManager.certs_path"
        )
        state_path = mocker.MagicMock()
        certs_path_mock.joinpath.return_value = state_path
        # first simulate the state file not existing, should just no-op.
        state_path.exists.return_value = False
        state_manager_local.load(cert)
        open_mock.assert_not_called()
        # then simulate it existing and returning data
        assert cert.state.key_size is None
        state_path.exists.return_value = True
        state_manager_local.load(cert)
        open_mock.assert_called_once_with(state_path, "r")
        assert cert.state.key_size == 12345

    def test_load_encryption(self, cert, state_manager_local, mocker):
        """
        Test that we can load state with encryption.
        """
        state_manager_local._encryptor = Encryptor(
            [Fernet(b"Ly6hr8-ZYLDZc4oCD59UFkJ5MNGTb7erAnkskksdBxg=")]
        )
        open_mock = mocker.patch(
            "certwrangler.state_managers.local.open",
            mocker.mock_open(
                read_data=dedent(
                    """
                    -----BEGIN ENCRYPTED STATE-----
                    Fingerprint: 756dd2c87036

                    gAAAAABmURDcC2b18qsuHmTTjtTrts1tn3ev1puMuynsLHVE4JyYpUkO6F6xIT5J
                    imGGHZDrzoGQyTTY1v2DBylGL5kNOPVBa89P4oCGUmjt4KtZhSwsRezZjLpn93Ua
                    3wGEPFHSfXP3xNEJ-u7SAa0IARuw9bmTLjlgSu8QVLNt5xMBCoKpYlMAmK76aEpz
                    43kzbNVMqZaaen8v1eSV3VCPbbyCesC7OGnMVISNb6T-E8kX7uecN3p9XiZtOCSU
                    zr5VNDZberC4oEJJo_pMjaxFaw0F-hvTWA==
                    -----END ENCRYPTED STATE-----
                    """
                ).strip()
            ),
        )
        certs_path_mock = mocker.patch(
            "certwrangler.state_managers.local.LocalStateManager.certs_path"
        )
        state_path = mocker.MagicMock()
        certs_path_mock.joinpath.return_value = state_path
        state_path.exists.return_value = True
        state_manager_local.load(cert)
        open_mock.assert_called_once_with(state_path, "r")
        assert cert.state.key_size == 12345

    def test_load_encryption_error(self, cert, state_manager_local, mocker):
        """
        Test that we raise StateManagerError when we load state with encryption
        and don't have keys and when we have an invalid key.
        """
        open_mock = mocker.patch(
            "certwrangler.state_managers.local.open",
            mocker.mock_open(
                read_data=dedent(
                    """
                    -----BEGIN ENCRYPTED STATE-----
                    Fingerprint: 756dd2c87036

                    gAAAAABmURDcC2b18qsuHmTTjtTrts1tn3ev1puMuynsLHVE4JyYpUkO6F6xIT5J
                    imGGHZDrzoGQyTTY1v2DBylGL5kNOPVBa89P4oCGUmjt4KtZhSwsRezZjLpn93Ua
                    3wGEPFHSfXP3xNEJ-u7SAa0IARuw9bmTLjlgSu8QVLNt5xMBCoKpYlMAmK76aEpz
                    43kzbNVMqZaaen8v1eSV3VCPbbyCesC7OGnMVISNb6T-E8kX7uecN3p9XiZtOCSU
                    zr5VNDZberC4oEJJo_pMjaxFaw0F-hvTWA==
                    -----END ENCRYPTED STATE-----
                    """
                ).strip()
            ),
        )
        certs_path_mock = mocker.patch(
            "certwrangler.state_managers.local.LocalStateManager.certs_path"
        )
        state_path = mocker.MagicMock()
        certs_path_mock.joinpath.return_value = state_path
        state_path.exists.return_value = True
        with pytest.raises(
            StateManagerError,
            match="Failed to load Cert 'test_cert': State is encrypted and no "
            "encryption_keys present.",
        ):
            state_manager_local.load(cert)
        open_mock.assert_called_once_with(state_path, "r")
        # Now test again with a bad key.
        open_mock.reset_mock()
        state_manager_local._encryptor = Encryptor(
            [Fernet(b"5N_L6HfTloIu3pjXHyhXXYsSCk6Of0iYM3GwJG83eAM=")]
        )
        with pytest.raises(
            StateManagerError,
            match="Failed to decrypt state for Cert 'test_cert'.",
        ):
            state_manager_local.load(cert)
        open_mock.assert_called_once_with(state_path, "r")

    def test_load_error(self, account, cert, state_manager_local, mocker):
        """
        Test that we raise a StateManagerError if we run into trouble
        while loading state.
        """
        state_manager_local.base_path = mocker.MagicMock()
        open_mock = mocker.patch(
            "certwrangler.state_managers.local.open", mocker.mock_open()
        )
        open_mock.side_effect = OSError("That broke")
        with pytest.raises(StateManagerError, match="That broke"):
            state_manager_local.load(account)
        with pytest.raises(StateManagerError, match="That broke"):
            state_manager_local.load(cert)
        open_mock.side_effect = IOError("Also broke")
        with pytest.raises(StateManagerError, match="Also broke"):
            state_manager_local.load(account)
        with pytest.raises(StateManagerError, match="Also broke"):
            state_manager_local.load(cert)

    def test_delete(self, state_manager_local, mocker):
        """
        Test that we can delete state.
        """
        certs_path_mock = mocker.patch(
            "certwrangler.state_managers.local.LocalStateManager.certs_path"
        )
        accounts_path_mock = mocker.patch(
            "certwrangler.state_managers.local.LocalStateManager.accounts_path"
        )
        account_state_path = mocker.MagicMock()
        cert_state_path = mocker.MagicMock()
        account_state_path.exists.return_value = True
        cert_state_path.exists.return_value = True
        accounts_path_mock.joinpath.return_value = account_state_path
        certs_path_mock.joinpath.return_value = cert_state_path
        # Test we can delete
        state_manager_local.delete("account", "test")
        account_state_path.unlink.assert_called_once()
        state_manager_local.delete("cert", "test")
        cert_state_path.unlink.assert_called_once()

    def test_delete_error(self, state_manager_local, mocker):
        """
        Test that we raise a StateManagerError if we run into trouble deleting.
        """
        certs_path_mock = mocker.patch(
            "certwrangler.state_managers.local.LocalStateManager.certs_path"
        )
        accounts_path_mock = mocker.patch(
            "certwrangler.state_managers.local.LocalStateManager.accounts_path"
        )
        account_state_path = mocker.MagicMock()
        cert_state_path = mocker.MagicMock()
        account_state_path.exists.return_value = True
        cert_state_path.exists.return_value = True
        accounts_path_mock.joinpath.return_value = account_state_path
        certs_path_mock.joinpath.return_value = cert_state_path
        account_state_path.unlink.side_effect = IOError("That broke")
        cert_state_path.unlink.side_effect = IOError("That broke")
        with pytest.raises(StateManagerError, match="That broke"):
            state_manager_local.delete("account", "test")
        with pytest.raises(StateManagerError, match="That broke"):
            state_manager_local.delete("cert", "test")
        account_state_path.unlink.side_effect = OSError("Also broke")
        cert_state_path.unlink.side_effect = OSError("Also broke")
        with pytest.raises(StateManagerError, match="Also broke"):
            state_manager_local.delete("account", "test")
        with pytest.raises(StateManagerError, match="Also broke"):
            state_manager_local.delete("cert", "test")
