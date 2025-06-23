from pathlib import Path

import pytest
from importlib_metadata import entry_points
from pydantic import ValidationError

from certwrangler.exceptions import StoreError
from certwrangler.stores.local import LocalStore


class TestLocalStore:
    """
    Tests for the LocalStore.
    """

    @pytest.fixture(autouse=True)
    def _mock_vault_client(self, mocker, click_ctx):
        """
        Autouse fixture that patches our calls to open and brings in the click_ctx fixture.
        """
        self._mock_open = mocker.patch(
            "certwrangler.stores.local.open", mocker.mock_open()
        )
        self._mock_path_exists = mocker.patch("certwrangler.stores.local.Path.exists")
        self._mock_path_mkdir = mocker.patch("certwrangler.stores.local.Path.mkdir")

    def test_plugin(self):
        """
        Test we correctly see the LocalStore plugin.
        """
        (plugin,) = entry_points(group="certwrangler.store", name="local")
        assert plugin.load() == LocalStore

    def test_required_fields(self, store_local_config):
        """
        Test that we raise a ValidationError if we're missing required fields.
        """
        store_local_config.pop("path")
        with pytest.raises(ValidationError):
            LocalStore(**store_local_config)

    def test_initialize(self, store_local):
        """
        Test that we can initialize the plugin.
        """
        self._mock_path_exists.return_value = False
        store_local.initialize()
        self._mock_path_exists.assert_called_once()
        self._mock_path_mkdir.assert_called_once_with(parents=True)

    def test_initialize_error(self, store_local):
        """
        Test that we raise a StoreError if something breaks in initialization.
        """
        self._mock_path_exists.return_value = False
        self._mock_path_mkdir.side_effect = OSError("That broke")
        with pytest.raises(StoreError, match="That broke"):
            store_local.initialize()
        self._mock_path_mkdir.side_effect = IOError("Also broke")
        with pytest.raises(StoreError, match="Also broke"):
            store_local.initialize()

    def test_publish(self, store_local, cert, mocker):
        """
        Test that we can publish to the local store.
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
        store_local._get_digest = mocker.MagicMock(side_effect=range(1, 100))
        self._mock_path_exists.return_value = False
        store_local.publish(cert)
        self._mock_path_exists.assert_called_once()
        self._mock_path_mkdir.assert_called_once_with(parents=True)
        assert self._mock_open.call_args_list == [
            mocker.call(Path("/tmp/certwrangler_store/test_cert/key.pem"), "w"),
            mocker.call(Path("/tmp/certwrangler_store/test_cert/cert.pem"), "w"),
            mocker.call(Path("/tmp/certwrangler_store/test_cert/chain.pem"), "w"),
            mocker.call(Path("/tmp/certwrangler_store/test_cert/fullchain.pem"), "w"),
        ]
        handler_mock = self._mock_open()
        assert handler_mock.write.call_args_list == [
            mocker.call("test key\n"),
            mocker.call("test cert\n"),
            mocker.call("test intermediate 1\ntest intermediate 2\ntest ca\n"),
            mocker.call(
                "test cert\ntest intermediate 1\ntest intermediate 2\ntest ca\n"
            ),
        ]

    def test_publish_no_state(self, store_local, cert, mocker):
        """
        Test that we no-op if we don't have a cert and key in the state.
        """
        mocked_model_dump = mocker.patch("certwrangler.models.CertState.model_dump")
        store_local.publish(cert)
        mocked_model_dump.assert_not_called()
        self._mock_open.assert_not_called()

    def test_publish_error(self, store_local, cert, mocker):
        """
        Test that we raise a StoreError if we run into trouble publishing.
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
        store_local._get_digest = mocker.MagicMock(side_effect=range(1, 100))
        # test that we can't create the cert's directory
        self._mock_path_exists.return_value = False
        self._mock_path_mkdir.side_effect = OSError("That broke")
        with pytest.raises(StoreError, match="That broke"):
            store_local.publish(cert)
        self._mock_path_mkdir.side_effect = IOError("Also broke")
        with pytest.raises(StoreError, match="Also broke"):
            store_local.publish(cert)
        self._mock_path_mkdir.side_effect = None
        # now test that we can't write to the file
        self._mock_open.side_effect = OSError("That broke")
        with pytest.raises(StoreError, match="That broke"):
            store_local.publish(cert)
        self._mock_open.side_effect = IOError("Also broke")
        with pytest.raises(StoreError, match="Also broke"):
            store_local.publish(cert)

    def test__get_digest(self, store_local, mocker):
        """
        Test that we can calculate a digest on existing files in the store.
        """
        # first test that we work with a string
        assert (
            store_local._get_digest("this is a test")
            == "2e99758548972a8e8822ad47fa1017ff72f06f3ff6a016851f45c398732bc50c"
        )
        # then test with a non-existing path to ensure we get an empty string back
        dummy_path = mocker.MagicMock()
        dummy_path.exists = mocker.MagicMock(return_value=False)
        assert store_local._get_digest(dummy_path) == ""
        # then simulate an actual file
        mocker.patch(
            "certwrangler.stores.local.open",
            mocker.mock_open(read_data="nom nom test data"),
        )
        dummy_path.exists = mocker.MagicMock(return_value=True)
        assert (
            store_local._get_digest(dummy_path)
            == "2f76b3417e9ebcfdff3fcb726278e6dd005874e92d2025cb1f8afe3744cb16a3"
        )
