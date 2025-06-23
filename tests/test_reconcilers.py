from certwrangler.exceptions import ControllerError
from certwrangler.models import AccountStatus, CertStatus
from certwrangler.reconcilers import reconcile_account, reconcile_all, reconcile_cert


def test_reconcile_account_no_account_state(mocker, account):
    account.state.key_size = account.key_size
    mock_account_controller = mocker.MagicMock()
    mocker.patch(
        "certwrangler.reconcilers.AccountController",
        return_value=mock_account_controller,
    )
    mock_state_manager = mocker.MagicMock()
    assert account.state.status == AccountStatus.new
    assert reconcile_account(account, mock_state_manager) is True
    mock_account_controller.create_key.assert_called_once()
    mock_account_controller.register.assert_called_once()
    assert account.state.status == AccountStatus.active


def test_reconcile_account_change_key(mocker, account, account_state):
    account_state.key_size = 128
    mock_account_controller = mocker.MagicMock()
    mocker.patch(
        "certwrangler.reconcilers.AccountController",
        return_value=mock_account_controller,
    )
    mock_state_manager = mocker.MagicMock()
    assert reconcile_account(account, mock_state_manager) is True
    mock_account_controller.change_key.assert_called_once()
    assert mock_account_controller.create_key.call_args_list == []


def test_reconcile_account_update_contacts(mocker, account, account_state):
    account.emails.append("test@example.com")
    mock_account_controller = mocker.MagicMock()
    mocker.patch(
        "certwrangler.reconcilers.AccountController",
        return_value=mock_account_controller,
    )
    mock_state_manager = mocker.MagicMock()
    assert reconcile_account(account, mock_state_manager) is True
    mock_account_controller.update_contacts.assert_called_once()


def test_reconcile_account_failure(mocker, account, caplog):
    mock_account_controller = mocker.MagicMock()
    mock_account_controller.create_key = mocker.MagicMock(
        side_effect=ControllerError("Something broke")
    )
    mocker.patch(
        "certwrangler.reconcilers.AccountController",
        return_value=mock_account_controller,
    )
    mock_state_manager = mocker.MagicMock()
    assert reconcile_account(account, mock_state_manager) is False
    assert "Failed to reconcile account" in caplog.text
    assert account.state.status == AccountStatus.new


def test_reconcile_cert_no_key(mocker, cert):
    cert.key_size = cert.state.key_size
    mock_cert_controller = mocker.MagicMock()

    def _mock_key_and_cert():
        cert.state.key = "dummy key"
        cert.state.cert = "dummy cert"

    mock_cert_controller.create_order.side_effect = _mock_key_and_cert
    mocker.patch(
        "certwrangler.reconcilers.CertController",
        return_value=mock_cert_controller,
    )
    mock_state_manager = mocker.MagicMock()
    assert cert.state.status == CertStatus.new
    assert reconcile_cert(cert, mock_state_manager) is True
    mock_cert_controller.create_key.assert_called_once()
    mock_cert_controller.create_order.assert_called_once()
    mock_cert_controller.process_order.assert_not_called()
    mock_cert_controller.publish.assert_called_once()
    assert cert.state.status == CertStatus.active


def test_reconcile_cert_key_change(mocker, cert, cert_state):
    cert.key_size = 128
    mock_cert_controller = mocker.MagicMock()
    mocker.patch(
        "certwrangler.reconcilers.CertController",
        return_value=mock_cert_controller,
    )
    mock_state_manager = mocker.MagicMock()
    assert reconcile_cert(cert, mock_state_manager) is True
    mock_cert_controller.create_key.assert_called_once()
    mock_cert_controller.create_order.assert_not_called()
    mock_cert_controller.process_order.assert_not_called()
    mock_cert_controller.publish.assert_called_once()


def test_reconcile_process_order(mocker, cert, cert_state):
    cert.key_size = cert.state.key_size
    cert.state.order = mocker.MagicMock()
    mock_cert_controller = mocker.MagicMock()
    mocker.patch(
        "certwrangler.reconcilers.CertController",
        return_value=mock_cert_controller,
    )
    mock_state_manager = mocker.MagicMock()
    assert reconcile_cert(cert, mock_state_manager) is True
    mock_cert_controller.create_key.assert_not_called()
    mock_cert_controller.create_order.assert_not_called()
    mock_cert_controller.process_order.assert_called_once()


def test_reconcile_cert_renewal(mocker, cert, cert_state):
    cert.key_size = cert.state.key_size
    cert.alt_names = ["example.com", "test.example.com"]
    mock_cert_controller = mocker.MagicMock()

    def mock_create_order():
        assert cert.state.status == CertStatus.renewing

    mock_cert_controller.create_order.side_effect = mock_create_order
    mocker.patch(
        "certwrangler.reconcilers.CertController",
        return_value=mock_cert_controller,
    )
    mock_state_manager = mocker.MagicMock()
    assert cert.state.status == CertStatus.active
    assert reconcile_cert(cert, mock_state_manager) is True
    mock_cert_controller.create_key.assert_not_called()
    mock_cert_controller.create_order.assert_called_once()
    mock_cert_controller.process_order.assert_not_called()
    mock_cert_controller.publish.assert_called_once()
    assert cert.state.status == CertStatus.active


def test_reconcile_cert_failure(mocker, cert, caplog):
    mock_cert_controller = mocker.MagicMock()
    mock_cert_controller.create_key = mocker.MagicMock(
        side_effect=ControllerError("Something broke")
    )
    mocker.patch(
        "certwrangler.reconcilers.CertController",
        return_value=mock_cert_controller,
    )
    mock_state_manager = mocker.MagicMock()
    assert reconcile_cert(cert, mock_state_manager) is False
    assert "Failed to reconcile cert" in caplog.text


def test_reconcile_all_account_failure(mocker, config, caplog):
    mocker.patch(
        "certwrangler.reconcilers.reconcile_account",
        return_value=False,
    )
    mocker.patch(
        "certwrangler.reconcilers.reconcile_cert",
        return_value=True,
    )
    assert reconcile_all(config) is False
    assert "Finished reconciliation with errors." in caplog.text


def test_reconcile_all_cert_failure(mocker, config, caplog):
    mocker.patch(
        "certwrangler.reconcilers.reconcile_account",
        return_value=True,
    )
    mocker.patch(
        "certwrangler.reconcilers.reconcile_cert",
        return_value=False,
    )
    assert reconcile_all(config) is False
    assert "Finished reconciliation with errors." in caplog.text


def test_reconcile_all_successful(mocker, config, caplog):
    mocker.patch(
        "certwrangler.reconcilers.reconcile_account",
        return_value=True,
    )
    mocker.patch(
        "certwrangler.reconcilers.reconcile_cert",
        return_value=True,
    )
    assert reconcile_all(config) is True
    assert "Finished reconciliation." in caplog.text
