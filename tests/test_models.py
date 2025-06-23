import pytest
from pydantic import Field, ValidationError

from certwrangler.models import Account, CertState, StateModel


class TestStateModel:
    """
    Tests for StateModel class in models.py
    """

    def test__schema_version(self, click_ctx, mocker):
        """
        Test that the _schema_version is set correctly.
        """

        class TestState(StateModel):
            schema_migrations = []

        assert TestState()._schema_version == 0

        class TestState(StateModel):
            schema_migrations = [
                mocker.MagicMock(return_value={}),
            ]

        assert TestState()._schema_version == 1

        class TestState(StateModel):
            schema_migrations = [
                mocker.MagicMock(return_value={}),
                mocker.MagicMock(return_value={}),
                mocker.MagicMock(return_value={}),
                mocker.MagicMock(return_value={}),
            ]

        assert TestState()._schema_version == 4

    def test__handle_schema_migrations(self, click_ctx, mocker):
        """
        Test that the StateModel base class handles migrations correctly.
        """

        noop_migration = mocker.MagicMock(return_value={})

        def migrate_test_to_test_field(data):
            data["test_field"] = data.pop("test", None)
            return data

        class TestState(StateModel):
            schema_migrations = [noop_migration, migrate_test_to_test_field]
            test_field: str = Field(default="Test 123")

        # Test initializing with no data, this should bypass migrations.
        instance = TestState()
        assert instance.test_field == "Test 123"
        assert instance._migrated is False
        noop_migration.assert_not_called()

        # Test with no schema version, this should trigger all migrations to run.
        noop_migration.reset_mock()
        data = {"test": "yup, this is a test"}
        noop_migration.return_value = data
        instance = TestState(**data)
        assert instance.test_field == "yup, this is a test"
        assert instance._migrated is True
        noop_migration.assert_called_once()

        # Schema version 1 should skip the first migration, but run the second.
        noop_migration.reset_mock()
        data = {"test": "yup, this is a test", "_schema_version": 1}
        noop_migration.return_value = data
        instance = TestState(**data)
        assert instance.test_field == "yup, this is a test"
        assert instance._migrated is True
        noop_migration.assert_not_called()

        # Schema version 2 should skip the migrations.
        noop_migration.reset_mock()
        data = {"test_field": "yup, this is a test", "_schema_version": 2}
        noop_migration.return_value = data
        instance = TestState(**data)
        assert instance.test_field == "yup, this is a test"
        assert instance._migrated is False
        noop_migration.assert_not_called()


class TestAccount:
    """
    Tests for Account class in models.py
    """

    @pytest.mark.parametrize(
        "missing",
        [
            "emails",
        ],
    )
    def test_config_missing(self, click_ctx, missing, account_config):
        """
        Test that missing required config keys throw a ValidationError.
        """
        bad_config = account_config.copy()
        bad_config.pop(missing)

        with pytest.raises(
            ValidationError,
            match=(f"validation error for Account\n{missing}\n  Field required"),
        ):
            Account(**bad_config)

    def test_account_server_invalid_format(self, click_ctx, account_config):
        """
        Test that a url in the incorrect format will throw a ValueError.
        """
        bad_config = account_config.copy()
        bad_config["server"] = "ftt://not_an_acme_server.co"

        with pytest.raises(
            ValidationError,
            match=("URL scheme should be 'http' or 'https'"),
        ):
            Account(**bad_config)

    def test_account_state(self, click_ctx, account_config):
        """
        Test that .state = ._state.
        """
        account = Account(name="test_account", emails=["example@example.com"])
        assert account.state == account._state

        account.state = "random test string"
        assert account.state == account._state

    def test_duplicate_emails(self, click_ctx, account_config):
        """
        Test only one email is in the configuration file.
        """
        bad_config = account_config.copy()
        bad_config["emails"] = ["example@example.com", "example@example.com"]

        with pytest.raises(
            ValidationError,
            match=("Duplicate emails not allowed."),
        ):
            Account(**bad_config)


class TestCertState:
    """
    Tests for CertState
    """

    def test_fullchain(self):
        """
        Test that we compute the fullchain correctly.
        """
        # First test with an empty state, should return None
        cert_state = CertState()
        assert cert_state.fullchain is None
        # Now only populate the cert
        cert_state.cert = "test cert"
        assert cert_state.fullchain == ["test cert"]
        # and finally populate the chain
        cert_state.chain = ["intermediate cert", "ca cert"]
        assert cert_state.fullchain == ["test cert", "intermediate cert", "ca cert"]
