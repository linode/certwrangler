import json

import pytest
from click.exceptions import BadParameter
from click.testing import CliRunner

from certwrangler.exceptions import CertwranglerError
from certwrangler.shell import _validate_nameservers, cli, main


def test_cli_initialization():
    """
    Invoke the cli without arguments & options and ensure it runs successfully.
    """
    outcome = CliRunner().invoke(cli)
    assert outcome.exit_code == 0
    assert "The certwrangler management cli." in outcome.output


def test_main_calls_cli(mocker):
    """
    Test the main function and ensure it calls the cli function.
    """
    mock_cli = mocker.patch("certwrangler.shell.cli")
    main()
    mock_cli.assert_called_once()


def test_access_resource_lock(mocked_certwrangler_state):
    """
    Test the `run` command to ensure it acquires and releases the lock correctly.
    """
    outcome = CliRunner().invoke(cli, ["check-config"], obj=mocked_certwrangler_state)
    assert outcome.exit_code == 0
    mocked_certwrangler_state.lock.__enter__.assert_called_once()
    mocked_certwrangler_state.lock.__exit__.assert_called_once()


@pytest.mark.parametrize(
    "ip_addresses, expected_result",
    [
        (["192.168.1.1", "10.0.0.1"], True),
        (["192.168.2.2", "not_an_ip_addr"], False),
    ],
)
def test_validate_nameservers(ip_addresses, expected_result, click_ctx):
    """
    Test the _validate_nameservers function with valid/invalid ip address and ensure it behaves correctly.
    """
    params = {}
    if expected_result:
        assert _validate_nameservers(click_ctx, params, ip_addresses) == ip_addresses
    else:
        with pytest.raises(BadParameter):
            _validate_nameservers(click_ctx, params, ip_addresses)


def test_validate_nameservers_with_empty_list(click_ctx):
    """
    Test the _validate_nameservers function with empty lists and ensure it returns an empty list.
    """
    params = {}
    values = []
    assert _validate_nameservers(click_ctx, params, values) == []


def test_cli_with_nameservers(mocked_certwrangler_state):
    """
    Test the cli function and ensure that it correctly sets the nameserver when provided.
    """
    command = [
        "--config",
        "path/to/config",
        "--log-level",
        "debug",
        "--nameserver",
        "8.8.8.8",
        "check-config",
    ]
    outcome = CliRunner().invoke(cli, command, obj=mocked_certwrangler_state)
    # Assert that the command exited with code of 0 (success)
    assert outcome.exit_code == 0
    assert mocked_certwrangler_state.resolver.nameservers == ["8.8.8.8"]
    assert "✅ - Config file loaded successfully." in outcome.output


def test_cli_without_nameservers(mocked_certwrangler_state):
    """
    Test the cli function and it handles empty nameservers correctly.
    """
    command = ["--config", "path/to/config", "--log-level", "debug", "check-config"]
    outcome = CliRunner().invoke(cli, command, obj=mocked_certwrangler_state)
    # Assert that the command exited with a code of 0 (success)
    assert outcome.exit_code == 0
    assert mocked_certwrangler_state.resolver.nameservers.mock_calls == []


def test_cli_with_nameservers_default(mocked_certwrangler_state):
    """
    Test the cli function to ensure it does not modify resolver nameservers if nameservers is None.
    """
    mocked_certwrangler_state.resolver.nameservers = ["8.8.4.4"]
    command = ["--config", "path/to/config", "--log-level", "debug", "check-config"]
    outcome = CliRunner().invoke(cli, command, obj=mocked_certwrangler_state)
    # Assert that the command exited with a code of 0 (success)
    assert outcome.exit_code == 0
    assert mocked_certwrangler_state.resolver.nameservers == ["8.8.4.4"]


def test_daemon(mocked_certwrangler_state):
    """
    Test to daemon command and ensures it runs successfully.
    """
    outcome = CliRunner().invoke(cli, ["daemon"], obj=mocked_certwrangler_state)
    # Assert that the command exited with a code of 0 (success)
    assert outcome.exit_code == 0


def test_daemon_failure(mocked_certwrangler_state, caplog):
    """
    Test the daemon command and ensures it handles Certwrangler Error correctly.
    """
    mocked_certwrangler_state.daemon.run.side_effect = CertwranglerError("Daemon error")
    CliRunner().invoke(
        cli, ["daemon"], obj=mocked_certwrangler_state, catch_exceptions=False
    )
    # Assertions without the exit code check.
    assert "Daemon error" in caplog.text


def test_devshell(mocked_certwrangler_state):
    """
    Test to load the dev shell and ensures that it loads successfully.
    """
    outcome = CliRunner().invoke(cli, ["dev-shell"], obj=mocked_certwrangler_state)
    # Assert that the command exited with a code of 0 (success)
    assert outcome.exit_code == 0


def test_check_config_success(mocked_certwrangler_state):
    """
    Test to check-config command and ensures it loads the configuration successfully.
    """
    outcome = CliRunner().invoke(cli, ["check-config"], obj=mocked_certwrangler_state)
    # Assert that the command exited with a code of 0 (success)
    assert outcome.exit_code == 0
    # Assert that the output contains the success message
    assert "✅ - Config file loaded successfully." in outcome.output


def test_check_config_failure(mocked_certwrangler_state):
    """
    Test the mock load_config method to simulate a config load error.
    """
    mocked_certwrangler_state.load_config.side_effect = CertwranglerError(
        "Config error"
    )
    outcome = CliRunner().invoke(cli, ["check-config"], obj=mocked_certwrangler_state)
    # Assert that the command exited with a code of 1 (failure)
    assert outcome.exit_code == 1
    # Assert that the output contains the failure message
    assert "❌ - Config error" in outcome.output


def test_run_success(mocker, mocked_certwrangler_state):
    """
    Test the run command and it runs a single reconcile loop successfully.
    """
    mock_reconcile = mocker.patch("certwrangler.shell.reconcile_all", return_value=True)
    outcome = CliRunner().invoke(cli, ["run"], obj=mocked_certwrangler_state)
    # Assert that the command exited with a code of 0 (success)
    assert outcome.exit_code == 0
    mock_reconcile.assert_called_once()


def test_run_failure(mocked_certwrangler_state, caplog):
    """
    Test the run command and ensure it handles Certwrangler error correctly.
    """
    mocked_certwrangler_state.load_config.side_effect = CertwranglerError(
        "Config error"
    )
    CliRunner().invoke(
        cli, ["run"], obj=mocked_certwrangler_state, catch_exceptions=False
    )
    assert "Config error" in caplog.text


def test_run_unsuccessful_reconciliation(mocker, mocked_certwrangler_state):
    """
    Test the run command and ensure it handles unsuccessful reconciliation correctly.
    """
    mock_reconcile = mocker.patch(
        "certwrangler.shell.reconcile_all", return_value=False
    )
    outcome = CliRunner().invoke(cli, ["run"], obj=mocked_certwrangler_state)
    assert outcome.exit_code == 1
    mock_reconcile.assert_called_once()


def test_state_generate_key(mocked_certwrangler_state):
    """
    Test the generate-key functionality and ensure that the key is generated successfully.
    """
    outcome = CliRunner().invoke(
        cli, ["state", "generate-key"], obj=mocked_certwrangler_state
    )
    # Assert that the command exited with a code of 0 (success)
    assert outcome.exit_code == 0
    assert "Key:" in outcome.output
    assert "Fingerprint:" in outcome.output


def test_state_fingerprint_no_keys(mocked_certwrangler_state):
    """
    Test the state fingerprint command and ensure that it can handle the missing encryption keys.
    """
    outcome = CliRunner().invoke(
        cli, ["state", "fingerprint"], obj=mocked_certwrangler_state
    )
    # Assert that the command exited with a code of 1 (failure)
    assert outcome.exit_code == 1
    assert "No encryption keys defined." in outcome.output


def test_state_fingerprint_success(mocked_certwrangler_state, state_manager_encryptor):
    """
    Test the state fingerprint command and ensure that it outputs the correct fingerprint.
    """
    outcome = CliRunner().invoke(
        cli, ["state", "fingerprint"], obj=mocked_certwrangler_state
    )
    # Assert that the command exited with a code of 0 (success)
    assert outcome.exit_code == 0
    assert f"Fingerprint: {state_manager_encryptor.fingerprint}" in outcome.output


def test_state_list(mocked_certwrangler_state, mocker):
    """
    Test the state command with list and ensure that it lists the entities successfully.
    """
    mocker.patch(
        "certwrangler.state_managers.dummy.DummyStateManager.list",
        return_value={
            "accounts": {"test_account": {"orphaned": False}},
            "certs": {"test_cert": {"orphaned": False}},
        },
    )
    outcome = CliRunner().invoke(cli, ["state", "list"], obj=mocked_certwrangler_state)
    # Assert that the command exited with a code of 0 (success)
    assert outcome.exit_code == 0
    assert '"accounts": {\n' in outcome.output
    assert '"certs": {\n' in outcome.output


def test_state_list_orphaned(mocked_certwrangler_state, mocker):
    """
    Test the state command with list and --orphaned and ensure that it lists the orphaned entities successfully.
    """
    mocker.patch(
        "certwrangler.state_managers.dummy.DummyStateManager.list",
        return_value={
            "accounts": {"test_account": {"orphaned": True}},
            "certs": {"test_cert": {"orphaned": True}},
        },
    )
    outcome = CliRunner().invoke(
        cli, ["state", "list", "--orphaned"], obj=mocked_certwrangler_state
    )
    # Assert that the command exited with a code of 0 (success)
    assert outcome.exit_code == 0
    assert '"accounts": {\n' in outcome.output
    assert '"certs": {\n' in outcome.output

    # Test again with no orphans returned
    mocker.patch(
        "certwrangler.state_managers.dummy.DummyStateManager.list",
        return_value={
            "accounts": {"test_account": {"orphaned": False}},
            "certs": {"test_cert": {"orphaned": False}},
        },
    )
    outcome = CliRunner().invoke(
        cli, ["state", "list", "--orphaned"], obj=mocked_certwrangler_state
    )
    assert outcome.exit_code == 0
    assert '"accounts": {}' in outcome.output
    assert '"certs": {}' in outcome.output


def test_state_list_orphaned_failure(mocked_certwrangler_state, mocker):
    """
    Test the state command with list and --orphaned and ensure it handles the Certwrangler error properly.
    """
    mocker.patch(
        "certwrangler.state_managers.dummy.DummyStateManager.list",
        side_effect=CertwranglerError("List Error"),
    )
    outcome = CliRunner().invoke(
        cli, ["state", "list", "--orphaned"], obj=mocked_certwrangler_state
    )
    # Assert that the command exited with a code of 1.
    assert outcome.exit_code == 1
    assert "List Error" in outcome.output


def test_state_show_account_success(mocked_certwrangler_state, account, account_state):
    """
    Test state show account.
    """
    expected_output = json.loads(account.state.model_dump_json())
    outcome = CliRunner().invoke(
        cli, ["state", "show", "account", "test_account"], obj=mocked_certwrangler_state
    )
    assert outcome.exit_code == 0
    parsed_output = json.loads(outcome.output)
    assert parsed_output == expected_output


def test_state_show_account_failure(mocked_certwrangler_state):
    """
    Test state show account with a failure.
    """
    outcome = CliRunner().invoke(
        cli, ["state", "show", "account", "bad_account"], obj=mocked_certwrangler_state
    )
    assert outcome.exit_code == 1
    assert "Unable to find state for account named 'bad_account'." in outcome.output


def test_state_show_cert_success(mocked_certwrangler_state, cert, cert_state):
    """
    Test state show cert.
    """
    expected_output = json.loads(cert.state.model_dump_json())
    outcome = CliRunner().invoke(
        cli, ["state", "show", "cert", "test_cert"], obj=mocked_certwrangler_state
    )
    assert outcome.exit_code == 0
    parsed_output = json.loads(outcome.output)
    assert parsed_output == expected_output


def test_state_show_cert_failure(mocked_certwrangler_state):
    """
    Test state show account with a failure.
    """
    outcome = CliRunner().invoke(
        cli, ["state", "show", "cert", "bad_cert"], obj=mocked_certwrangler_state
    )
    assert outcome.exit_code == 1
    assert "Unable to find state for cert named 'bad_cert'." in outcome.output


def test_state_account_delete_success(mocked_certwrangler_state, mocker):
    """
    Test the state command with account and delete to ensure that it removes the account successfully.
    """
    mocker.patch(
        "certwrangler.state_managers.dummy.DummyStateManager.list",
        return_value={
            "accounts": {"test_account": {"orphaned": False}},
            "certs": {"test_cert": {"orphaned": False}},
        },
    )
    outcome = CliRunner().invoke(
        cli,
        ["state", "delete", "account", "test_account", "--yes"],
        obj=mocked_certwrangler_state,
    )
    # Assert that the command exited with a code of 0 (success)
    assert outcome.exit_code == 0
    assert "Deleted state for account 'test_account'." in outcome.output


def test_state_cert_delete_success(mocked_certwrangler_state, mocker):
    """
    Test the state command with cert and delete to ensure that it removes the account successfully.
    """
    mocker.patch(
        "certwrangler.state_managers.dummy.DummyStateManager.list",
        return_value={
            "accounts": {"test_account": {"orphaned": False}},
            "certs": {"test_cert": {"orphaned": False}},
        },
    )
    outcome = CliRunner().invoke(
        cli,
        ["state", "delete", "cert", "test_cert", "--yes"],
        obj=mocked_certwrangler_state,
    )
    # Assert that the command exited with a code of 0 (success)
    assert outcome.exit_code == 0
    assert "Deleted state for cert 'test_cert'." in outcome.output


def test_state_account_delete_failure(mocked_certwrangler_state, mocker):
    """
    Test the state command with account and delete, and ensure that it handles the deletion properly.
    """
    mocker.patch(
        "certwrangler.state_managers.dummy.DummyStateManager.list",
        return_value={
            "accounts": {"test_account": {"orphaned": False}},
            "certs": {"test_cert": {"orphaned": False}},
        },
    )
    mocker.patch(
        "certwrangler.state_managers.dummy.DummyStateManager.delete",
        side_effect=CertwranglerError("Delete account error"),
    )
    outcome = CliRunner().invoke(
        cli,
        ["state", "delete", "account", "test_account", "--yes"],
        obj=mocked_certwrangler_state,
    )
    # Assert that the command exited with a code of 0 (success)
    assert outcome.exit_code == 1
    assert "Delete account error" in outcome.output


def test_state_entity_not_found(mocked_certwrangler_state, mocker):
    """
    Test the state command with the entity that does not exist to ensure it handles correctly.
    """
    mocker.patch(
        "certwrangler.state_managers.dummy.DummyStateManager.list",
        return_value={
            "accounts": {"test_account": {"orphaned": False}},
            "certs": {"test_cert": {"orphaned": False}},
        },
    )
    outcome = CliRunner().invoke(
        cli,
        ["state", "delete", "account", "acc2", "--yes"],
        obj=mocked_certwrangler_state,
    )
    # Assert that the command exited with the code 1 (failure)
    assert outcome.exit_code == 1
    assert "Unable to find state for account named 'acc2'." in outcome.output


def test_state_user_abort_deletion(mocked_certwrangler_state, mocker):
    """
    Test the state command when the user aborts deletion by not confirming with 'yes'.
    """
    mocker.patch(
        "certwrangler.state_managers.dummy.DummyStateManager.list",
        return_value={
            "accounts": {"test_account": {"orphaned": False}},
            "certs": {"test_cert": {"orphaned": False}},
        },
    )
    mocked_input = mocker.patch("builtins.input", return_value="no")
    outcome = CliRunner().invoke(
        cli, ["state", "delete", "cert", "test_cert"], obj=mocked_certwrangler_state
    )
    # Verify that the input function was called exactly once
    mocked_input.assert_called_once()
    # Assert that the command exited with a code of 1.
    assert outcome.exit_code == 1
    assert "Aborted." in outcome.output


def test_state_cert_delete_failure(mocked_certwrangler_state, mocker):
    """
    Test the state command with cert and delete, and ensure that it handles the deletion properly.
    """
    mocker.patch(
        "certwrangler.state_managers.dummy.DummyStateManager.list",
        return_value={
            "accounts": {"test_account": {"orphaned": False}},
            "certs": {"test_cert": {"orphaned": False}},
        },
    )
    mocker.patch(
        "certwrangler.state_managers.dummy.DummyStateManager.delete",
        side_effect=CertwranglerError("Delete cert error"),
    )
    outcome = CliRunner().invoke(
        cli,
        ["state", "delete", "cert", "test_cert", "--yes"],
        obj=mocked_certwrangler_state,
    )
    # Assert that the command exited with a code of 0 (success)
    assert outcome.exit_code == 1
    assert "Delete cert error" in outcome.output


def test_state_encrypt(mocked_certwrangler_state, state_manager_encryptor):
    """
    Test the state encrypt command to ensure that it encrypts the state entities correctly.
    """
    outcome = CliRunner().invoke(
        cli, ["state", "encrypt"], obj=mocked_certwrangler_state
    )
    # Assert that the command exited with a code of 0 (success)
    assert outcome.exit_code == 0
    assert "Encrypting account" in outcome.output
    assert "Encrypting cert" in outcome.output


def test_state_encrypt_no_keys(mocked_certwrangler_state):
    """
    Test the state encrypt command and ensure that it can handle the missing encryption keys.
    """
    outcome = CliRunner().invoke(
        cli, ["state", "encrypt"], obj=mocked_certwrangler_state
    )
    # Assert that the command exited with a code of 1 (failure)
    assert outcome.exit_code == 1
    assert "No encryption keys defined." in outcome.output


def test_state_encrypt_failure(
    mocked_certwrangler_state, state_manager_encryptor, mocker
):
    """
    Test the state encrypt command and ensure that it handles the error properly.
    """
    mocker.patch(
        "certwrangler.state_managers.dummy.DummyStateManager.save",
        side_effect=CertwranglerError("Encrypt Error"),
    )
    outcome = CliRunner().invoke(
        cli, ["state", "encrypt"], obj=mocked_certwrangler_state
    )
    # Assert that the command exited with a code of 0 (success)
    assert outcome.exit_code == 1
    assert "Encrypt Error" in outcome.output


def test_state_decrypt(mocked_certwrangler_state, state_manager_encryptor):
    """
    Test the state decrypt command to ensure that it decrypts the state entities correctly.
    """
    outcome = CliRunner().invoke(
        cli, ["state", "decrypt"], obj=mocked_certwrangler_state
    )
    # Assert that the command exited with a code of 0 (success)
    assert outcome.exit_code == 0
    assert "Decrypting account" in outcome.output
    assert "Decrypting cert" in outcome.output


def test_state_decrypt_no_keys(mocked_certwrangler_state):
    """
    Test the state decrypt command and ensure that it can handle the missing encryption keys.
    """
    outcome = CliRunner().invoke(
        cli, ["state", "decrypt"], obj=mocked_certwrangler_state
    )
    # Assert that the command exited with a code of 1 (failure)
    assert outcome.exit_code == 1
    assert "No encryption keys defined." in outcome.output


def test_state_decrypt_failure(
    mocked_certwrangler_state, state_manager_encryptor, mocker
):
    """
    Test the state decrypt command and ensure that it handles the error properly.
    """
    mocker.patch(
        "certwrangler.state_managers.dummy.DummyStateManager.save",
        side_effect=CertwranglerError("Decrypt Error"),
    )
    outcome = CliRunner().invoke(
        cli, ["state", "decrypt"], obj=mocked_certwrangler_state
    )
    # Assert that the command exited with a code of 0 (success)
    assert outcome.exit_code == 1
    assert "Decrypt Error" in outcome.output
