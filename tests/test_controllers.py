import datetime
import json
import logging

import josepy as jose
import pytest
from acme import challenges as acme_challenges
from acme import client as acme_client
from acme import errors as acme_errors
from acme import messages as acme_messages
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtensionOID, NameOID

from certwrangler.controllers import (
    AccountController,
    AccountKeyChangeMessage,
    CertController,
    _get_acme_client,
)
from certwrangler.exceptions import ControllerError, SolverError, StoreError
from certwrangler.models import AccountState


def test__get_acme_client(account, mocker):
    """
    Test that we can build our client from an account.
    """
    # Mock out the external calls
    mocked_net = mocker.patch("certwrangler.controllers.acme_client.ClientNetwork")
    # Test that we raise an error if we don't have an account key.
    with pytest.raises(
        ControllerError, match="Unable to create client, no account key in state."
    ):
        _get_acme_client(account)
    # Now generate a key and try again
    new_key = jose.JWKRSA(
        key=rsa.generate_private_key(public_exponent=65537, key_size=account.key_size)
    )
    account.state = AccountState(key=new_key, key_size=account.key_size)
    account.state.registration = "test123"
    client = _get_acme_client(account)
    assert isinstance(client, acme_client.ClientV2)
    mocked_net.assert_called_once_with(
        account.state.key, account="test123", user_agent="certwrangler"
    )


class TestAccountController:
    """
    Tests for the AccountController.
    """

    def test___init__(self, mocker, account):
        """
        Test that we can initialize the controller.
        """
        mocker.patch("certwrangler.controllers.acme_client.ClientNetwork")
        state_manager_mock = mocker.MagicMock()
        account_controller = AccountController(account, state_manager_mock)
        assert account_controller.account == account
        assert account_controller._client is None
        state_manager_mock.load.assert_called_once_with(account)

    def test_client(self, account_controller, account):
        """
        Test that we can lazy load our client.
        """
        # accessing the client without a key on the account should raise
        with pytest.raises(
            ControllerError, match="Unable to create client, no account key in state."
        ):
            account_controller.client
        # make a key so we can access the client
        new_key = jose.JWKRSA(
            key=rsa.generate_private_key(
                public_exponent=65537, key_size=account.key_size
            )
        )
        account.state = AccountState(key=new_key, key_size=account.key_size)
        # then make sure we generate the client dynamically when it's requested
        assert account_controller._client is None
        assert isinstance(account_controller.client, acme_client.ClientV2)
        assert account_controller._client == account_controller.client

    def test_create_key(self, account_controller, account):
        """
        Test that we can create a new key for our account.
        """
        old_account_state = account.state
        assert account.state.key is None
        assert account_controller._client is None
        account_controller.create_key()
        account_controller.state_manager.save.assert_called_once_with(account)
        assert account.state.key is not None
        assert old_account_state != account.state
        assert isinstance(account_controller._client, acme_client.ClientV2)

    def test_register(self, account_controller, account, mocker):
        """
        Test that we can register an account.
        """
        account_controller.create_key()
        account_controller.state_manager.reset_mock()
        account_controller.client.new_account = mocker.MagicMock(
            return_value="test1234"
        )
        account_controller.register()
        account_controller.client.new_account.assert_called_once()
        reg = account_controller.client.new_account.call_args_list[0].args[0]
        assert isinstance(reg, acme_messages.NewRegistration)
        assert reg.contact == ("mailto:dummy_account@example.com",)
        assert reg.terms_of_service_agreed
        assert account.state.registration == "test1234"
        assert account_controller.client.net.account == "test1234"
        account_controller.state_manager.save.assert_called_once_with(account)

    def test_register_conflict(self, account_controller, mocker, caplog):
        """
        Test that if we try to register an existing account we defer to recovery.
        """
        caplog.set_level(logging.INFO)
        account_controller.create_key()
        account_controller.state_manager.reset_mock()
        account_controller.client.new_account = mocker.MagicMock(
            side_effect=acme_errors.ConflictError("uhoh")
        )
        account_controller.get_registration = mocker.MagicMock()
        account_controller.register()
        assert (
            "Registration exists for account 'test_account', recovering..."
            in caplog.text
        )
        account_controller.client.new_account.assert_called_once()
        account_controller.get_registration.assert_called_once()

    def test_get_registration(self, account_controller, account, mocker):
        """
        Test that we can retrieve our registration from the ACME server.
        """
        account_controller.create_key()
        account_controller.state_manager.reset_mock()
        account_controller.client.query_registration = mocker.MagicMock(
            return_value="test1234"
        )
        account_controller.get_registration()
        reg = account_controller.client.query_registration.call_args_list[0].args[0]
        assert isinstance(reg, acme_messages.RegistrationResource)
        assert account_controller.client.net.account == "test1234"
        assert account.state.registration == "test1234"
        account_controller.state_manager.save.assert_called_once_with(account)

    def test_change_key(self, account_state, account, account_controller, mocker):
        """
        Test that we can request a key change.
        """
        # save the old key, registration, and client
        old_key = account.state.key
        old_registration = account.state.registration
        old_client = account_controller.client
        # mock out all the external calls
        dummy_endpoint = "https://acme-staging-v02.api.example.com/acme/key-change"
        account_controller.client.directory = {"keyChange": dummy_endpoint}
        response_mock = mocker.MagicMock()
        response_mock.status_code = 200
        post_mock = mocker.MagicMock(return_value=response_mock)
        account_controller.client._post = post_mock
        account_controller.get_registration = mocker.MagicMock()
        # do the key change
        account_controller.change_key()
        new_key = account.state.key
        # verify that the key did change
        assert old_key != new_key
        # verify that we made the request to the right endpoint
        assert post_mock.call_args_list[0].args[0] == dummy_endpoint
        # verify that the inner message was signed by the new key
        inner_message = post_mock.call_args_list[0].args[1]
        assert inner_message.verify(new_key.public_key())
        # verify that the payload of the inner message is what we expect.
        payload = AccountKeyChangeMessage.from_json(json.loads(inner_message.payload))
        assert payload["account"] == old_registration.uri
        assert payload["oldKey"] == old_registration.body.key
        # verify that we saved our changes
        account_controller.state_manager.save.assert_called_once_with(account)
        # verify that we got a new client
        assert old_client != account_controller.client
        # and verify that we made the call to update the registration
        account_controller.get_registration.assert_called_once()

    def test_change_key_non_200(self, account_state, account_controller, mocker):
        """
        Test that we raise a controller error if the acme server doesn't respond as expected.
        """
        account_controller.client.directory = {
            "keyChange": "https://acme-staging-v02.api.example.com/acme/keychange"
        }
        response_mock = mocker.MagicMock()
        response_mock.status_code = 500
        response_mock.reason = "I just don't feel like it."
        account_controller.client._post = mocker.MagicMock(return_value=response_mock)
        with pytest.raises(ControllerError, match="I just don't feel like it."):
            account_controller.change_key()

    def test_change_key_no_registration(self, account_controller):
        """
        Test that we get an error if we try to change our key with no existing account.
        """
        with pytest.raises(ControllerError, match="No registration found."):
            account_controller.change_key()

    def test_update_contacts(self, account_state, account, account_controller, mocker):
        """
        Test that we can update the contacts on our account.
        """
        account_controller.client.update_registration = mocker.MagicMock(
            return_value="test1234"
        )
        account.emails.append("my_test_email@example.com")
        account_controller.update_contacts()
        message = account_controller.client.update_registration.call_args_list[0].args[
            0
        ]
        assert message.body["contact"] == (
            "mailto:dummy_account@example.com",
            "mailto:my_test_email@example.com",
        )
        assert account.state.registration == "test1234"
        account_controller.state_manager.save.assert_called_once_with(account)

    def test_update_contacts_no_registration(self, account_controller):
        """
        Test that we get an error if we try to change our key with no existing account.
        """
        with pytest.raises(ControllerError, match="No registration found."):
            account_controller.update_contacts()


class TestCertController:
    """
    Tests for the CertController.
    """

    def test___init__(self, mocker, cert):
        """
        Test that we can initialize the controller.
        """
        mocker.patch("certwrangler.controllers.acme_client.ClientNetwork")
        state_manager_mock = mocker.MagicMock()
        cert_controller = CertController(cert, state_manager_mock)
        assert cert_controller.cert == cert
        assert cert_controller._client is None
        state_manager_mock.load.assert_called_once_with(cert)

    def test_client(self, cert_controller, account):
        """
        Test that we can lazy load our client.
        """
        # make sure we generate the client dynamically when it's requested
        assert cert_controller._client is None
        assert isinstance(cert_controller.client, acme_client.ClientV2)
        assert cert_controller._client == cert_controller.client

    def test_create_key(self, cert_controller, cert):
        """
        Test that we can create a new key for our cert.
        """
        old_cert_state = cert.state
        assert cert.state.key is None
        assert cert_controller._client is None
        cert_controller.create_key()
        cert_controller.state_manager.save.assert_called_once_with(cert)
        assert cert.state.key is not None
        assert cert.state.key_size == cert.key_size
        assert old_cert_state != cert.state

    def test_create_order(self, cert_controller, cert, mocker):
        """
        Test that we can create an order object in our state.
        """
        cert_controller.create_key()
        cert_controller.state_manager.reset_mock()
        fake_csr = cert_controller._create_csr()
        cert_controller.client.new_order = mocker.MagicMock()
        cert_controller.process_order = mocker.MagicMock()
        cert_controller._create_csr = mocker.MagicMock(return_value=fake_csr)
        cert_controller.create_order()
        cert_controller._create_csr.assert_called_once()
        cert_controller.client.new_order.assert_called_once_with(
            fake_csr.public_bytes(serialization.Encoding.PEM)
        )
        assert isinstance(cert.state.order, mocker.MagicMock)
        cert_controller.process_order.assert_called_once()
        cert_controller.state_manager.save.assert_called_once_with(cert)

    def test_process_order_no_order(self, cert_controller, mocker):
        """
        Test that we raise an exception if no order is in the state.
        """
        cert_controller._update_order = mocker.MagicMock()
        with pytest.raises(ControllerError, match="No order found."):
            cert_controller.process_order()

    def test_process_order_STATUS_PENDING(
        self, cert_controller, cert, cert_state_order, mocker
    ):
        """
        Test that we can process a STATUS_PENDING order.
        """
        cert_controller._update_order = mocker.MagicMock()
        cert_controller.process_challenges = mocker.MagicMock()
        mocker.patch("acme.messages.Order.status", acme_messages.STATUS_PENDING)
        cert_controller.process_order()
        cert_controller.process_challenges.assert_called_once()

    def test_process_order_STATUS_READY(
        self, cert_controller, cert, cert_state_order, mocker
    ):
        """
        Test that we can process a STATUS_READY order.
        """
        cert_controller._update_order = mocker.MagicMock()
        cert_controller.finalize_order = mocker.MagicMock()
        mocker.patch("acme.messages.Order.status", acme_messages.STATUS_READY)
        cert_controller.process_order()
        cert_controller.finalize_order.assert_called_once()

    def test_process_order_STATUS_PROCESSING(
        self, cert_controller, cert, cert_state_order, mocker
    ):
        """
        Test that we can process a STATUS_PROCESSING order.
        """
        cert_controller._update_order = mocker.MagicMock()
        cert_controller.retrieve_cert = mocker.MagicMock()
        mocker.patch("acme.messages.Order.status", acme_messages.STATUS_PROCESSING)
        cert_controller.process_order()
        cert_controller.retrieve_cert.assert_called_once()

    def test_process_order_STATUS_VALID(
        self, cert_controller, cert, cert_state_order, mocker
    ):
        """
        Test that we can process a STATUS_VALID order.
        """
        cert_controller._update_order = mocker.MagicMock()
        cert_controller.retrieve_cert = mocker.MagicMock()
        mocker.patch("acme.messages.Order.status", acme_messages.STATUS_VALID)
        cert_controller.process_order()
        cert_controller.retrieve_cert.assert_called_once()

    def test_process_order_STATUS_INVALID(
        self, cert_controller, cert, cert_state_order, mocker
    ):
        """
        Test that we can process a STATUS_INVALID order.
        """
        cert_controller._update_order = mocker.MagicMock()
        cert_controller._fail_order = mocker.MagicMock()
        mocker.patch("acme.messages.Order.status", acme_messages.STATUS_INVALID)
        error_mock = mocker.MagicMock()
        error_mock.detail = "all out of certs today"
        mocker.patch("acme.messages.Order.error", error_mock)
        chall_mock = mocker.MagicMock()
        chall_mock.error.detail = "DNS also broke"
        auth_mock = mocker.MagicMock()
        auth_mock.body.challenges = [chall_mock]
        mocker.patch("acme.messages.OrderResource.authorizations", [auth_mock])
        cert_controller.process_order()
        cert_controller._fail_order.assert_called_once_with(
            "all out of certs today, DNS also broke"
        )

    def test_process_order_unknown_status(
        self, cert_controller, cert, cert_state_order, mocker
    ):
        """
        Test that we can process an order with an unknown status.
        """
        cert_controller._update_order = mocker.MagicMock()
        cert_controller._fail_order = mocker.MagicMock()
        mocked_status = mocker.MagicMock()
        mocked_status.name = "something broken"
        mocker.patch("acme.messages.Order.status", mocked_status)
        cert_controller.process_order()
        cert_controller._fail_order.assert_called_once_with(
            "Unknown order status 'something broken'"
        )

    def test_process_challenges(
        self, cert_controller, cert, cert_state_order, mocker, caplog
    ):
        """
        Test that we can process an order's challenges.
        """
        mocked_challenge_1 = mocker.MagicMock()
        mocked_challenge_1.response = mocker.MagicMock(return_value="dummy_response_1")
        mocked_challenge_2 = mocker.MagicMock()
        mocked_challenge_2.response = mocker.MagicMock(return_value="dummy_response_2")
        cert_controller._get_challenges = mocker.MagicMock(
            return_value=[
                ("example.com", mocked_challenge_1),
                ("www.example.com", mocked_challenge_2),
            ]
        )
        mock_solver = mocker.MagicMock()
        cert_controller._get_dns_records = mocker.MagicMock(
            return_value=[
                ("_acme-challenge", "example.com", "test123", mock_solver),
                ("_acme-challenge.www", "example.com", "test123", mock_solver),
            ]
        )
        wait_for_challenges_mock = mocker.MagicMock()
        mocker.patch(
            "certwrangler.controllers.wait_for_challenges", wait_for_challenges_mock
        )
        cert_controller.client.answer_challenge = mocker.MagicMock()
        mocker.patch(
            "acme.challenges.DNS01.response",
            mocker.MagicMock(return_value="dummy_response"),
        )
        cert_controller.client.poll_authorizations = mocker.MagicMock()
        cert_controller.finalize_order = mocker.MagicMock()
        cert_controller.process_challenges()
        cert_controller._get_dns_records.assert_called_once()
        assert mock_solver.create.call_args_list == [
            mocker.call("_acme-challenge", "example.com", "test123"),
            mocker.call("_acme-challenge.www", "example.com", "test123"),
        ]
        assert (
            "DNS records created for cert 'test_cert', waiting max 300 seconds..."
            in caplog.text
        )
        wait_for_challenges_mock.assert_called_once_with(
            [
                ("_acme-challenge.example.com", "test123"),
                ("_acme-challenge.www.example.com", "test123"),
            ],
            datetime.timedelta(seconds=300),
        )

        assert mock_solver.create.call_args_list == [
            mocker.call("_acme-challenge", "example.com", "test123"),
            mocker.call("_acme-challenge.www", "example.com", "test123"),
        ]
        assert cert_controller.client.answer_challenge.call_args_list == [
            mocker.call(mocked_challenge_1, "dummy_response_1"),
            mocker.call(mocked_challenge_2, "dummy_response_2"),
        ]
        cert_controller.finalize_order.assert_called_once()

    def test_process_challenges_ValidationError(
        self, cert_controller, cert, cert_state_order, mocker, caplog
    ):
        """
        Test that we raise a ControllerError if we timeout when waiting.
        """
        mocked_challenge_1 = mocker.MagicMock()
        mocked_challenge_1.response = mocker.MagicMock(return_value="dummy_response_1")
        mocked_challenge_2 = mocker.MagicMock()
        mocked_challenge_2.response = mocker.MagicMock(return_value="dummy_response_2")
        cert_controller._get_challenges = mocker.MagicMock(
            return_value=[
                ("example.com", mocked_challenge_1),
                ("www.example.com", mocked_challenge_2),
            ]
        )
        mock_solver = mocker.MagicMock()
        cert_controller._get_dns_records = mocker.MagicMock(
            return_value=[
                ("_acme-challenge", "example.com", "test123", mock_solver),
                ("_acme-challenge.www", "example.com", "test123", mock_solver),
            ]
        )
        mocker.patch("certwrangler.controllers.wait_for_challenges", mocker.MagicMock())
        cert_controller.client.answer_challenge = mocker.MagicMock()
        mocker.patch(
            "acme.challenges.DNS01.response",
            mocker.MagicMock(return_value="dummy_response"),
        )
        cert_controller.client.poll_authorizations = mocker.MagicMock(
            side_effect=acme_errors.ValidationError("This doesn't look right.")
        )
        with pytest.raises(
            ControllerError, match="Failed to validate challenges for cert 'test_cert'."
        ):
            cert_controller.process_challenges()

    def test_process_challenges_timeout(
        self, cert_controller, cert, cert_state_order, mocker, caplog
    ):
        """
        Test that we raise a ControllerError if we timeout when waiting.
        """
        mocked_challenge_1 = mocker.MagicMock()
        mocked_challenge_1.response = mocker.MagicMock(return_value="dummy_response_1")
        mocked_challenge_2 = mocker.MagicMock()
        mocked_challenge_2.response = mocker.MagicMock(return_value="dummy_response_2")
        cert_controller._get_challenges = mocker.MagicMock(
            return_value=[
                ("example.com", mocked_challenge_1),
                ("www.example.com", mocked_challenge_2),
            ]
        )
        mock_solver = mocker.MagicMock()
        cert_controller._get_dns_records = mocker.MagicMock(
            return_value=[
                ("_acme-challenge", "example.com", "test123", mock_solver),
                ("_acme-challenge.www", "example.com", "test123", mock_solver),
            ]
        )
        mocker.patch(
            "certwrangler.controllers.wait_for_challenges",
            mocker.MagicMock(
                side_effect=TimeoutError("DNS left in oven too long, burnt.")
            ),
        )
        with pytest.raises(ControllerError, match="DNS left in oven too long, burnt."):
            cert_controller.process_challenges()

    def test_process_challenges_no_order(self, cert_controller):
        """
        Test that we raise a ControllerError if we timeout when waiting.
        """
        with pytest.raises(ControllerError, match="No order found."):
            cert_controller.process_challenges()

    def test_process_challenges_SolverError(
        self, cert_controller, cert, cert_state_order, mocker, caplog
    ):
        """
        Test that we raise a ControllerError if we get a SolverError when
        creating our records.
        """
        mocked_challenge_1 = mocker.MagicMock()
        mocked_challenge_1.response = mocker.MagicMock(return_value="dummy_response_1")
        mocked_challenge_2 = mocker.MagicMock()
        mocked_challenge_2.response = mocker.MagicMock(return_value="dummy_response_2")
        cert_controller._get_challenges = mocker.MagicMock(
            return_value=[
                ("example.com", mocked_challenge_1),
                ("www.example.com", mocked_challenge_2),
            ]
        )
        mock_solver = mocker.MagicMock()
        mock_solver.create = mocker.MagicMock(
            side_effect=SolverError("I can't solve a single thing.")
        )
        cert_controller._get_dns_records = mocker.MagicMock(
            return_value=[
                ("_acme-challenge", "example.com", "test123", mock_solver),
                ("_acme-challenge.www", "example.com", "test123", mock_solver),
            ]
        )
        mocker.patch("certwrangler.controllers.SOLVER_METRICS")
        with pytest.raises(ControllerError, match="I can't solve a single thing."):
            cert_controller.process_challenges()

    def test_finalize_order(
        self, cert_controller, cert, cert_state_order, mocker, caplog
    ):
        """
        Test that we can finalize a successful order.
        """
        order = cert.state.order
        cert_controller.client.begin_finalization = mocker.MagicMock(
            return_value="dummy_order"
        )
        cert_controller.retrieve_cert = mocker.MagicMock()
        cert_controller.finalize_order()
        assert cert.state.order == "dummy_order"
        cert_controller.client.begin_finalization.assert_called_once_with(order)
        cert_controller.state_manager.save.assert_called_once_with(cert)
        cert_controller.retrieve_cert.assert_called_once()
        assert "Order finalized for cert 'test_cert'." in caplog.text

    def test_finalize_order_no_order(self, cert_controller):
        """
        Test that we raise a ControllerError if no order is in the state.
        """
        with pytest.raises(ControllerError, match="No order found."):
            cert_controller.finalize_order()

    def test_retrieve_cert(
        self, cert, cert_controller, cert_state_order, mocker, caplog
    ):
        """
        Test that we can load our certs from a completed order.
        """
        mocker.patch("acme.messages.Order.status", acme_messages.STATUS_VALID)
        mocker.patch("acme.messages.Order.certificate", "dummy_url")
        mocker.patch(
            "cryptography.x509.load_pem_x509_certificates",
            return_value=["cert", "intermediate_1", "intermediate_2", "ca_cert"],
        )
        order_mock = mocker.MagicMock()
        order_mock.body.certificate = "dummy_url"
        cert_controller.client.poll_finalization = mocker.MagicMock(
            return_value=order_mock
        )
        cert_controller.clean_up = mocker.MagicMock()
        cert_controller.retrieve_cert()
        cert_controller.client.poll_finalization.assert_called_once()
        cert_controller.state_manager.save.assert_called_once_with(cert)
        assert "Cert retrieved from ACME server for cert 'test_cert'." in caplog.text
        cert_controller.clean_up.assert_called_once()
        assert cert.state.cert == "cert"
        assert cert.state.chain == ["intermediate_1", "intermediate_2", "ca_cert"]
        assert cert.state.fullchain == [
            "cert",
            "intermediate_1",
            "intermediate_2",
            "ca_cert",
        ]
        assert cert.state.url == "dummy_url"

    def test_retrieve_cert_no_order(self, cert_controller):
        """
        Test that we raise a ControllerError if there is no order.
        """
        with pytest.raises(ControllerError, match="No order found."):
            cert_controller.retrieve_cert()

    def test_clean_up(self, cert_controller, cert, cert_state_order, mocker):
        """
        Test that we can clean up after an order.
        """
        mock_solver = mocker.MagicMock()
        cert_controller._get_dns_records = mocker.MagicMock(
            return_value=[
                ("_acme-challenge", "example.com", "test123", mock_solver),
                ("_acme-challenge.www", "example.com", "test123", mock_solver),
            ]
        )
        assert cert.state.order is not None
        cert_controller.clean_up()
        cert_controller._get_dns_records.assert_called_once_with(
            validate=False, completed=True
        )
        assert mock_solver.delete.call_args_list == [
            mocker.call("_acme-challenge", "example.com", "test123"),
            mocker.call("_acme-challenge.www", "example.com", "test123"),
        ]
        assert cert.state.order is None
        cert_controller.state_manager.save.assert_called_once_with(cert)

    def test_clean_up_SolverError(
        self, cert_controller, cert, cert_state_order, mocker, caplog
    ):
        """
        Test that we raise a ControllerError if we get a SolverError when
        cleaning up our records.
        """
        mock_solver = mocker.MagicMock()
        mock_solver.delete = mocker.MagicMock(
            side_effect=SolverError("I'm a failure, not a solver.")
        )
        cert_controller._get_dns_records = mocker.MagicMock(
            return_value=[
                ("_acme-challenge", "example.com", "test123", mock_solver),
                ("_acme-challenge.www", "example.com", "test123", mock_solver),
            ]
        )
        mocker.patch("certwrangler.controllers.SOLVER_METRICS")
        with pytest.raises(ControllerError, match="I'm a failure, not a solver."):
            cert_controller.clean_up()

    def test_publish(self, cert_controller, cert, cert_state, mocker):
        """
        Test that we can publish our cert to the stores.
        """
        mock_store_1 = mocker.MagicMock()
        mock_store_2 = mocker.MagicMock()
        mocker.patch(
            "certwrangler.models.Cert.stores",
            new_callable=mocker.PropertyMock(return_value=[mock_store_1, mock_store_2]),
        )
        cert_controller.publish()
        mock_store_1.publish.assert_called_once_with(cert)
        mock_store_2.publish.assert_called_once_with(cert)

    def test_publish_failure(self, cert_controller, cert, cert_state, mocker):
        """
        Test that we raise an exception if we fail to publish to one of the stores.
        """
        mock_store_1 = mocker.MagicMock()
        mock_store_1.publish = mocker.MagicMock(side_effect=StoreError("uhoh"))
        mock_store_2 = mocker.MagicMock()
        mocker.patch(
            "certwrangler.models.Cert.stores",
            new_callable=mocker.PropertyMock(return_value=[mock_store_1, mock_store_2]),
        )
        mocker.patch("certwrangler.controllers.STORE_METRICS")
        with pytest.raises(
            ControllerError, match="Failed to publish cert to all stores."
        ):
            cert_controller.publish()
        mock_store_1.publish.assert_called_once_with(cert)
        mock_store_2.publish.assert_called_once_with(cert)

    def test__create_csr(self, cert_controller, cert):
        """
        Test that we can create a CSR.
        """
        cert_controller.create_key()
        csr = cert_controller._create_csr()
        # Validate that our common name is correct
        assert (
            csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
            == cert.common_name
        )
        # Validate that our alt names are correct
        alt_names = [
            x.value
            for x in csr.extensions.get_extension_for_oid(
                ExtensionOID.SUBJECT_ALTERNATIVE_NAME
            ).value
        ]
        for name in [cert.common_name] + cert.alt_names:
            assert name in alt_names
        # Validate that our subject was set correctly
        assert (
            csr.subject.get_attributes_for_oid(NameOID.COUNTRY_NAME)[0]
            == cert.subject.country
        )
        assert (
            csr.subject.get_attributes_for_oid(NameOID.STATE_OR_PROVINCE_NAME)[0]
            == cert.subject.state_or_province
        )
        assert (
            csr.subject.get_attributes_for_oid(NameOID.LOCALITY_NAME)[0]
            == cert.subject.locality
        )
        assert (
            csr.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0]
            == cert.subject.organization
        )
        assert (
            csr.subject.get_attributes_for_oid(NameOID.ORGANIZATIONAL_UNIT_NAME)[0]
            == cert.subject.organizational_unit
        )
        # Validate that this was signed by our private key
        assert csr.public_key() == cert.state.key.public_key()

    def test__create_csr_no_key(self, cert_controller):
        """
        Test that we raise an exception if no key is present.
        """
        with pytest.raises(
            ControllerError, match="Unable to create CSR, no private key in state."
        ):
            cert_controller._create_csr()

    def test__update_order(self, cert_controller, cert, cert_state_order, mocker):
        """
        Test that we can get an updated order object from the acme server.
        """
        order_uri = cert.state.order.uri
        csr_pem = cert.state.order.csr_pem
        cert_controller.client._post_as_get = mocker.MagicMock()
        cert_controller.client._authzr_from_response = mocker.MagicMock(
            return_value="testtest"
        )
        body_mock = mocker.MagicMock()
        body_mock.authorizations = ["test_authz_url_1", "test_authz_url_2"]
        order_mock = mocker.MagicMock()
        order_mock.from_json = mocker.MagicMock(return_value=body_mock)
        mocker.patch("acme.messages.Order", order_mock)
        order_resource_mock = mocker.MagicMock()
        mocker.patch("acme.messages.OrderResource", order_resource_mock)
        cert_controller._update_order()
        assert isinstance(cert.state.order, mocker.MagicMock)
        # TODO: asserts around _post_as_get
        order_resource_mock.assert_called_once_with(
            body=body_mock,
            uri=order_uri,
            authorizations=["testtest", "testtest"],
            csr_pem=csr_pem,
        )
        cert_controller.state_manager.save.assert_called_once_with(cert)

    def test__update_order_no_order(self, cert_controller):
        """
        Test that we raise an exception if no order is in the state.
        """
        with pytest.raises(ControllerError, match="No order found."):
            cert_controller._update_order()

    def test__validate_authorizations(self, cert_controller, cert_state_order, mocker):
        """
        Test that we don't take any action if our authorizations are good.
        """
        cert_controller._fail_order = mocker.MagicMock()
        cert_controller._validate_authorizations()
        assert cert_controller._fail_order.call_args_list == []

    def test__validate_authorizations_no_order(self, cert_controller):
        """
        Test that we raise a ControllerError if we have no order.
        """
        with pytest.raises(ControllerError, match="No order found."):
            cert_controller._validate_authorizations()

    @pytest.mark.parametrize(
        "authz_status",
        [
            acme_messages.STATUS_DEACTIVATED,
            acme_messages.STATUS_REVOKED,
            acme_messages.STATUS_UNKNOWN,
        ],
    )
    def test__validate_authorizations_bad_statuses(
        self, cert_controller, cert_state_order, authz_status, mocker
    ):
        """
        Test that we fail the order if our authorization is in a bad status.
        """
        mocker.patch("acme.messages.Authorization.status", authz_status)
        cert_controller._fail_order = mocker.MagicMock()
        cert_controller._validate_authorizations()
        cert_controller._fail_order.assert_called_once_with(
            "Authorizations in invalid status, failing order."
        )

    @pytest.mark.parametrize(
        "authz_status",
        [
            acme_messages.STATUS_PENDING,
            acme_messages.STATUS_PROCESSING,
        ],
    )
    def test__get_challenges(
        self, cert_controller, cert_state_order, authz_status, mocker
    ):
        """
        Test that we can extract our challenges from an order.
        """
        mocker.patch("acme.messages.Authorization.status", authz_status)
        challenges = cert_controller._get_challenges()
        assert len(challenges) == 2
        for challenge in challenges:
            assert isinstance(challenge[1].chall, acme_challenges.DNS01)

    def test__get_challenges_no_order(self, cert_controller, cert):
        """
        Test that we raise an exception if no order is in the state.
        """
        with pytest.raises(ControllerError, match="No order found."):
            cert_controller._get_challenges()

    def test__get_challenges_completed(self, cert_controller, cert_state_order, mocker):
        """
        Test that we get omit completed challenges when completed is false
        and get all challenges when completed is true.
        """
        mocker.patch("acme.messages.Authorization.status", acme_messages.STATUS_VALID)
        assert len(cert_controller._get_challenges(completed=False)) == 0
        assert len(cert_controller._get_challenges(completed=True)) == 2

    def test__get_dns_records(
        self, cert_controller, solver, cert, cert_state_order, mocker
    ):
        """
        Test that we can extract the DNS records we need to create from an order.
        """
        solver.zones.append("example.test")
        mocker.patch(
            "acme.challenges.DNS01.validation", mocker.MagicMock(return_value="test123")
        )
        resolve_cname_mock = mocker.MagicMock(
            side_effect=[
                "_acme-challenge.example.test",
                "_acme-challenge.www.example.test",
            ]
        )
        mocker.patch("certwrangler.controllers.resolve_cname", resolve_cname_mock)
        resolve_zone_mock = mocker.MagicMock(return_value="example.test")
        mocker.patch("certwrangler.controllers.resolve_zone", resolve_zone_mock)
        assert cert_controller._get_dns_records() == [
            ("_acme-challenge", "example.test", "test123", solver),
            ("_acme-challenge.www", "example.test", "test123", solver),
        ]
        assert resolve_cname_mock.call_args_list == [
            mocker.call("_acme-challenge.example.com"),
            mocker.call("_acme-challenge.www.example.com"),
        ]
        assert resolve_zone_mock.call_args_list == [
            mocker.call("_acme-challenge.example.test"),
            mocker.call("_acme-challenge.www.example.test"),
        ]

    def test__get_dns_records_cnames(
        self, cert_controller, solver, cert, cert_state_order, mocker
    ):
        """
        Test that we don't follow cnames if configured as such.
        """
        cert.follow_cnames = False
        mocker.patch(
            "acme.challenges.DNS01.validation", mocker.MagicMock(return_value="test123")
        )
        resolve_cname_mock = mocker.MagicMock(
            side_effect=[
                "_acme-challenge.example.test",
                "_acme-challenge.www.example.test",
            ]
        )
        mocker.patch("certwrangler.controllers.resolve_cname", resolve_cname_mock)
        resolve_zone_mock = mocker.MagicMock(return_value="example.com")
        mocker.patch("certwrangler.controllers.resolve_zone", resolve_zone_mock)
        assert cert_controller._get_dns_records() == [
            ("_acme-challenge", "example.com", "test123", solver),
            ("_acme-challenge.www", "example.com", "test123", solver),
        ]
        assert resolve_cname_mock.call_args_list == []
        assert resolve_zone_mock.call_args_list == [
            mocker.call("_acme-challenge.example.com"),
            mocker.call("_acme-challenge.www.example.com"),
        ]

    def test__get_dns_records_completed(
        self, cert_controller, cert_state_order, mocker
    ):
        """
        Test that we don't get completed challenge DNS records when completed is false
        and get all challenge DNS records when completed is true.
        """
        mocker.patch(
            "certwrangler.controllers.resolve_zone",
            mocker.MagicMock(return_value="example.com"),
        )
        mocker.patch("acme.messages.Authorization.status", acme_messages.STATUS_VALID)
        assert len(cert_controller._get_dns_records(completed=False)) == 0
        assert len(cert_controller._get_dns_records(completed=True)) == 2

    def test__get_dns_records_resolve_cname_exception(
        self, cert_controller, cert, cert_state_order, mocker
    ):
        """
        Test that we raise a ControllerError if resolve_cname raises a ValueError.
        """
        mocker.patch(
            "certwrangler.controllers.resolve_cname",
            mocker.MagicMock(side_effect=ValueError("I broke it.")),
        )
        with pytest.raises(ControllerError, match="I broke it."):
            cert_controller._get_dns_records()

    def test__get_dns_records_resolve_zone_exception(
        self, cert_controller, cert, cert_state_order, mocker
    ):
        """
        Test that we raise a ControllerError if resolve_zone raises a ValueError.
        """
        mocker.patch(
            "certwrangler.controllers.resolve_zone",
            mocker.MagicMock(side_effect=ValueError("I broke it.")),
        )
        with pytest.raises(ControllerError, match="I broke it."):
            cert_controller._get_dns_records()

    def test__get_dns_records_no_solver(
        self, cert_controller, cert, cert_state_order, mocker
    ):
        """
        Test that we raise a ControllerError if there is no solver for the resolved zone.
        """
        mocker.patch(
            "certwrangler.controllers.resolve_zone",
            mocker.MagicMock(return_value="example.test"),
        )
        with pytest.raises(
            ControllerError, match="Unable to find solver for zone example.test."
        ):
            cert_controller._get_dns_records()

    def test__fail_order(self, cert_controller, cert, caplog, mocker):
        """
        Test that we can fail an order.
        """
        cert_controller.clean_up = mocker.MagicMock()
        with pytest.raises(ControllerError, match="no cert today"):
            cert_controller._fail_order("no cert today")
        assert "Removing invalid order for cert 'test_cert'." in caplog.text
        cert_controller.clean_up.assert_called_once()
