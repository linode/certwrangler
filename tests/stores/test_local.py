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
    def _click_ctx(self, click_ctx):
        """
        Autouse fixture that brings in the click_ctx fixture.
        """

    @pytest.fixture
    def mock_fs(self, mocker):
        """
        Patches filesystem access for tests that shouldn't touch a real directory.
        """
        self._mock_open = mocker.patch(
            "certwrangler.stores.local.open", mocker.mock_open()
        )
        self._mock_path_exists = mocker.patch("certwrangler.stores.local.Path.exists")
        self._mock_path_mkdir = mocker.patch("certwrangler.stores.local.Path.mkdir")
        self._mock_path_stat = mocker.patch("certwrangler.stores.local.Path.stat")
        # Report the default dir_mode so we don't try to chmod anything.
        self._mock_path_stat.return_value.st_mode = 0o755

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

    def test_initialize(self, store_local, mock_fs):
        """
        Test that we can initialize the plugin.
        """
        self._mock_path_exists.return_value = False
        store_local.initialize()
        self._mock_path_exists.assert_called_once()
        self._mock_path_mkdir.assert_called_once_with(parents=True, mode=0o755)

    def test_initialize_updates_dir_mode(self, store_local, tmp_path):
        """
        Test that we correct the mode of a store directory that already exists.
        """
        store_local.path = tmp_path.joinpath("store")
        store_local.path.mkdir()
        store_local.path.chmod(0o777)
        store_local.initialize()
        assert store_local.path.stat().st_mode & 0o777 == 0o755

    def test_initialize_error(self, store_local, mock_fs):
        """
        Test that we raise a StoreError if something breaks in initialization.
        """
        self._mock_path_exists.return_value = False
        self._mock_path_mkdir.side_effect = OSError("That broke")
        with pytest.raises(StoreError, match="That broke"):
            store_local.initialize()
        self._mock_path_mkdir.side_effect = OSError("Also broke")
        with pytest.raises(StoreError, match="Also broke"):
            store_local.initialize()

    def test_publish(self, store_local, cert, tmp_path, mocker):
        """
        Test that we can publish to the local store.
        """
        store_local.path = tmp_path.joinpath("store")
        store_local.initialize()
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
        store_local.publish(cert)
        cert_path = store_local.path.joinpath("test_cert")
        assert cert_path.stat().st_mode & 0o777 == 0o755
        expected = {
            "key.pem": ("test key\n", 0o600),
            "cert.pem": ("test cert\n", 0o644),
            "chain.pem": (
                "test intermediate 1\ntest intermediate 2\ntest ca\n",
                0o644,
            ),
            "fullchain.pem": (
                "test cert\ntest intermediate 1\ntest intermediate 2\ntest ca\n",
                0o644,
            ),
        }
        for name, (contents, mode) in expected.items():
            entity_path = cert_path.joinpath(name)
            assert entity_path.read_text() == contents
            assert entity_path.stat().st_mode & 0o777 == mode

    def test_publish_updates_modes(self, store_local, cert, tmp_path, mocker):
        """
        Test that we correct modes on existing files even when the contents
        haven't changed.
        """
        store_local.path = tmp_path.joinpath("store")
        store_local.initialize()
        cert.state.key = "test key"
        cert.state.cert = "test cert"
        mocker.patch(
            "certwrangler.models.CertState.model_dump",
            mocker.MagicMock(
                return_value={
                    "key": "test key\n",
                    "cert": "test cert\n",
                    "chain": ["test ca\n"],
                    "fullchain": ["test cert\n", "test ca\n"],
                }
            ),
        )
        store_local.publish(cert)
        cert_path = store_local.path.joinpath("test_cert")
        cert_path.chmod(0o777)
        for name in ("key.pem", "cert.pem", "chain.pem", "fullchain.pem"):
            cert_path.joinpath(name).chmod(0o666)
        store_local.publish(cert)
        assert cert_path.stat().st_mode & 0o777 == 0o755
        assert cert_path.joinpath("key.pem").stat().st_mode & 0o777 == 0o600
        for name in ("cert.pem", "chain.pem", "fullchain.pem"):
            assert cert_path.joinpath(name).stat().st_mode & 0o777 == 0o644

    def test_publish_custom_modes(self, store_local_config, cert, tmp_path, mocker):
        """
        Test that we honor configured modes.
        """
        store = LocalStore(
            **{
                **store_local_config,
                "path": str(tmp_path.joinpath("store")),
                "cert_mode": "0640",
                "key_mode": "0400",
                "dir_mode": "0750",
            }
        )
        store._name = "test_store"
        store.initialize()
        cert.state.key = "test key"
        cert.state.cert = "test cert"
        mocker.patch(
            "certwrangler.models.CertState.model_dump",
            mocker.MagicMock(
                return_value={
                    "key": "test key\n",
                    "cert": "test cert\n",
                    "chain": ["test ca\n"],
                    "fullchain": ["test cert\n", "test ca\n"],
                }
            ),
        )
        store.publish(cert)
        cert_path = store.path.joinpath("test_cert")
        assert cert_path.stat().st_mode & 0o777 == 0o750
        assert cert_path.joinpath("key.pem").stat().st_mode & 0o777 == 0o400
        for name in ("cert.pem", "chain.pem", "fullchain.pem"):
            assert cert_path.joinpath(name).stat().st_mode & 0o777 == 0o640

    def test_publish_no_state(self, store_local, cert, mock_fs, mocker):
        """
        Test that we no-op if we don't have a cert and key in the state.
        """
        mocked_model_dump = mocker.patch("certwrangler.models.CertState.model_dump")
        store_local.publish(cert)
        mocked_model_dump.assert_not_called()
        self._mock_open.assert_not_called()

    def test_publish_error(self, store_local, cert, mock_fs, mocker):
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
        self._mock_path_mkdir.side_effect = OSError("Also broke")
        with pytest.raises(StoreError, match="Also broke"):
            store_local.publish(cert)
        self._mock_path_mkdir.side_effect = None
        # now test that we can't write to the file
        mock_os = mocker.patch("certwrangler.stores.local.os")
        mock_os.open.side_effect = OSError("That broke")
        with pytest.raises(StoreError, match="That broke"):
            store_local.publish(cert)
        mock_os.open.side_effect = OSError("Also broke")
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
