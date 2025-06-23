"""
This module handles all the logic around interacting with the ACME server and
processing ACME orders. It is highly recommended to read and understand
`RFC 8555 <https://datatracker.ietf.org/doc/html/rfc8555>`_ before making
changes to this code.
"""

import datetime
import logging
from typing import List, Optional, Tuple, Union

import josepy as jose
from acme import challenges as acme_challenges
from acme import client as acme_client
from acme import errors as acme_errors
from acme import jws as acme_jws
from acme import messages as acme_messages
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from certwrangler.dns import resolve_cname, resolve_zone, wait_for_challenges
from certwrangler.exceptions import ControllerError, SolverError, StoreError
from certwrangler.metrics import SOLVER_METRICS, STORE_METRICS
from certwrangler.models import (
    Account,
    AccountState,
    Cert,
    CertState,
    Solver,
    StateManager,
)

USER_AGENT = "certwrangler"
log = logging.getLogger(__name__)


class AccountKeyChangeMessage(acme_messages.ResourceBody):
    """
    Account Key change message since the acme library doesn't seem to have this.
    """

    oldKey: jose.JWK = jose.field("oldKey", decoder=jose.JWK.from_json)
    """
    The old public key.
    """

    account: str = jose.field("account")
    """
    The URI of the account.
    """


def _get_acme_client(account: Account) -> acme_client.ClientV2:
    """
    Creates an ACME client based on the key in the provided Account's state.

    :param account: The account object that the client will be created for.

    :returns: An ACME client object.

    :raises ControllerError: Raised if no account key is in the state.
    """
    if account.state.key is None:
        raise ControllerError("Unable to create client, no account key in state.")
    net = acme_client.ClientNetwork(
        account.state.key, account=account.state.registration, user_agent=USER_AGENT
    )
    acme_server = str(account.server)
    directory = acme_messages.Directory.from_json(net.get(acme_server).json())
    return acme_client.ClientV2(directory, net=net)


class AccountController:
    """
    Controller for ACME account operations.

    :param account: The account object that the controller will operate on.
    :param state_manager: The state manager object the controller will persist
        state to.
    """

    def __init__(self, account: Account, state_manager: StateManager) -> None:
        self.account = account
        self.state_manager = state_manager
        # Load to ensure we have the update state from the store.
        self.state_manager.load(self.account)
        self._client: Optional[acme_client.ClientV2] = None

    @property
    def client(self) -> acme_client.ClientV2:
        """
        Lazy loader for the ACME client.
        """

        if not self._client:
            self._client = _get_acme_client(self.account)
        return self._client

    def create_key(self) -> None:
        """
        Create a new key and reset the account state.
        """

        new_key = jose.JWKRSA(
            key=rsa.generate_private_key(
                public_exponent=65537, key_size=self.account.key_size
            )
        )
        self.account.state = AccountState(key=new_key, key_size=self.account.key_size)
        self.state_manager.save(self.account)
        self._client = _get_acme_client(self.account)

    def register(self) -> None:
        """
        Register a new account.
        """

        try:
            self.account.state.registration = self.client.new_account(
                acme_messages.NewRegistration.from_data(
                    email=",".join(self.account.emails), terms_of_service_agreed=True
                )
            )
            self.client.net.account = self.account.state.registration
            self.state_manager.save(self.account)
        except acme_errors.ConflictError:
            # Account already exists, so recover instead.
            log.info(
                f"Registration exists for account '{self.account.name}', recovering..."
            )
            self.get_registration()

    def get_registration(self) -> None:
        """
        Get registration for an existing account.
        """

        self.account.state.registration = self.client.query_registration(
            acme_messages.RegistrationResource.from_json({"body": {}, "uri": None})
        )
        self.client.net.account = self.account.state.registration
        self.state_manager.save(self.account)

    def change_key(self) -> None:
        """
        Change the account key.

        :raises ControllerError: Raised if no registration is in the state
            or if we get an invalid response from the ACME server.
        """

        if not self.account.state.registration:
            raise ControllerError("No registration found.")

        new_private_key = jose.JWKRSA(
            key=rsa.generate_private_key(
                public_exponent=65537, key_size=self.account.key_size
            )
        )

        # The certbot ACME library doesn't implement this call so we have to craft
        # it ourselves. The operation is described in RFC 8555 section 7.3.5:
        # https://datatracker.ietf.org/doc/html/rfc8555#section-7.3.5
        # The TL;DR is that we have an inner message containing the old public key and
        # account uri that's signed by the new key, encapsulated by an outer
        # message signed by the old key, showing that the holder(s) of both keys
        # consent to the change.

        inner_message = acme_jws.JWS.sign(
            AccountKeyChangeMessage.from_json(
                {
                    "account": self.account.state.registration.uri,
                    "oldKey": self.account.state.registration.body.key.to_json(),
                }
            )
            .json_dumps()
            .encode(),
            new_private_key,
            jose.RS256,
            None,
            url=self.client.directory["keyChange"],
            kid=None,
        )

        # The _post() method signs with the old key, completing the message.
        response = self.client._post(self.client.directory["keyChange"], inner_message)
        if response.status_code != 200:
            raise ControllerError(response.reason)
        # Now we reset our state with the new key.
        self.account.state = AccountState(
            key=new_private_key, key_size=self.account.key_size
        )
        self.state_manager.save(self.account)
        # Get a new client since the key changed.
        self._client = _get_acme_client(self.account)
        # Then get our new registration
        self.get_registration()

    def update_contacts(self) -> None:
        """
        Update the contact information on the account.

        :raises ControllerError: Raised if no registration is in the state.
        """

        if not self.account.state.registration:
            raise ControllerError("No registration found.")
        emails = tuple(
            (
                f"{self.account.state.registration.body.email_prefix}{email}"
                for email in self.account.emails
            )
        )
        self.account.state.registration = self.client.update_registration(
            self.account.state.registration.update(
                body=self.account.state.registration.body.update(contact=emails)
            )
        )
        self.state_manager.save(self.account)


class CertController:
    """
    Controller for ACME cert operations.

    :param cert: The cert object that the controller will operate on.
    :param state_manager: The state manager object the controller will persist
        state to.
    """

    def __init__(self, cert: Cert, state_manager: StateManager) -> None:
        self.cert = cert
        self.state_manager = state_manager
        # Load to ensure we have the update state from the store.
        self.state_manager.load(self.cert)
        self._client: Optional[acme_client.ClientV2] = None

    @property
    def client(self) -> acme_client.ClientV2:
        """
        Lazy loader for the ACME client.
        """

        if not self._client:
            self._client = _get_acme_client(self.cert.account)
        return self._client

    def create_key(self) -> None:
        """
        Create a new key and reset the cert state.
        """

        new_key = rsa.generate_private_key(
            public_exponent=65537, key_size=self.cert.key_size
        )
        self.cert.state = CertState(key=new_key, key_size=self.cert.key_size)
        self.state_manager.save(self.cert)

    def create_order(self) -> None:
        """
        Create a new CSR and submit an order request, then continue onto
        :meth:`process_order`.
        """

        self.cert.state.csr = self._create_csr()
        self.cert.state.order = self.client.new_order(
            self.cert.state.csr.public_bytes(serialization.Encoding.PEM)
        )
        log.info(f"Created order for cert '{self.cert.name}'.")
        self.state_manager.save(self.cert)
        self.process_order()

    def process_order(self) -> None:
        """
        Get the latest state of the order from the ACME server and process
        it based on the order's state:

        ``STATUS_PENDING``:
            Process any outstanding challenges with :meth:`process_challenges`.
        ``STATUS_READY``:
            Finalize the order with :meth:`finalize_order`.
        ``STATUS_PROCESSING`` or ``STATUS_VALID``:
            retrieve the cert with :meth:`retrieve_cert`.
        ``STATUS_INVALID``:
            collect any error messages from the challenges and :meth:`_fail_order`.
        ELSE:
            We shouldn't end up here, provide a less helpful error message and
            :meth:`_fail_order`.

        :raises ControllerError: Raised if no order is in the state.
        """
        self._update_order()
        if not self.cert.state.order:
            raise ControllerError("No order found.")
        order = self.cert.state.order
        if order.body.status == acme_messages.STATUS_PENDING:
            # Do the challenges
            self.process_challenges()
        elif order.body.status == acme_messages.STATUS_READY:
            self.finalize_order()
        elif order.body.status in [
            acme_messages.STATUS_PROCESSING,
            acme_messages.STATUS_VALID,
        ]:
            self.retrieve_cert()
        elif order.body.status == acme_messages.STATUS_INVALID:
            error = []
            if order.body.error:
                error.append(order.body.error.detail)
            for auth in order.authorizations:
                for chall in auth.body.challenges:
                    if chall.error:
                        error.append(chall.error.detail)
            # Order is invalid, kill it
            self._fail_order(", ".join(error))
        else:
            self._fail_order(f"Unknown order status '{order.body.status.name}'")

    def process_challenges(self) -> None:
        """
        Loops through the DNS challenges on the order and do the following:

        1. Create the requested TXT records using the solver for that zone.
        2. Wait until specified timeout for the records to resolve.
        3. Submit the challenges to the ACME server for authorization.
        4. Poll the ACME server for its validation.

        Once all that is complete, proceeds to :meth:`finalize_order`.

        :raises ControllerError: Raised if no order is in the state, if we hit
            a timeout, if we failed validation from the ACME server, or can be
            raised from :exc:`certwrangler.exceptions.SolverError`
            if a solver encounters a problem creating a DNS record.
        """
        if not self.cert.state.order:
            raise ControllerError("No order found.")
        challenges = self._get_challenges()
        # Create the TXT records
        dns_records = self._get_dns_records()
        for name, zone, token, solver in dns_records:
            try:
                solver.create(name, zone, token)
            except SolverError as error:
                SOLVER_METRICS[solver.name].counters["errors"].inc()
                raise ControllerError(error) from error
        wait_timeout = self.cert.wait_timeout
        log.info(
            f"DNS records created for cert '{self.cert.name}', waiting max {wait_timeout.seconds} seconds..."
        )
        try:
            wait_for_challenges(
                [(f"{name}.{zone}", token) for name, zone, token, _ in dns_records],
                wait_timeout,
            )
        except TimeoutError as error:
            raise ControllerError(error) from error
        log.info(f"Submitting challenges for validation for cert '{self.cert.name}'...")
        for _, challenge in challenges:
            self.client.answer_challenge(
                challenge, challenge.response(self.cert.account.state.key)
            )
        deadline = datetime.datetime.now() + datetime.timedelta(seconds=90)
        try:
            self.cert.state.order = self.client.poll_authorizations(
                self.cert.state.order, deadline
            )
        except acme_errors.ValidationError as error:
            raise ControllerError(
                f"Failed to validate challenges for cert '{self.cert.name}'."
            ) from error
        self.state_manager.save(self.cert)
        self.finalize_order()

    def finalize_order(self) -> None:
        """
        Submits the order to the ACME server for finalization, then
        continues onto :meth:`retrieve_cert`.

        :raises ControllerError: Raised if no order is in the state.
        """
        if not self.cert.state.order:
            raise ControllerError("No order found.")
        self.cert.state.order = self.client.begin_finalization(self.cert.state.order)
        self.state_manager.save(self.cert)
        log.info(f"Order finalized for cert '{self.cert.name}'.")
        self.retrieve_cert()

    def retrieve_cert(self) -> None:
        """
        Poll the order for finalization, then download and saves the cert
        to the Cert object's state. Continues onto :meth:`clean_up`.

        :raises ControllerError: Raised if no order is in the state.
        """
        if not self.cert.state.order:
            raise ControllerError("No order found.")
        deadline = datetime.datetime.now() + datetime.timedelta(seconds=90)
        self.cert.state.order = self.client.poll_finalization(
            self.cert.state.order, deadline
        )
        cert, *chain = x509.load_pem_x509_certificates(
            self.cert.state.order.fullchain_pem.encode()
        )
        self.cert.state.cert = cert
        self.cert.state.chain = chain
        self.cert.state.url = self.cert.state.order.body.certificate
        self.state_manager.save(self.cert)
        log.info(f"Cert retrieved from ACME server for cert '{self.cert.name}'.")
        self.clean_up()

    def clean_up(self) -> None:
        """
        Cleans up any TXT records we created then reset the order state.

        :raises ControllerError: Raised from :exc:`certwrangler.exceptions.SolverError`
            if any of the solvers encounter errors deleting the TXT records.
        """
        for name, zone, token, solver in self._get_dns_records(
            validate=False, completed=True
        ):
            try:
                solver.delete(name, zone, token)
            except SolverError as error:
                SOLVER_METRICS[solver.name].counters["errors"].inc()
                raise ControllerError(error) from error
        self.cert.state.order = None
        self.state_manager.save(self.cert)

    def publish(self) -> None:
        """
        Publish the cert to the stores.

        :raises ControllerError: Raised from :exc:`certwrangler.exceptions.StoreError`
            if any of the stores encounter errors publishing the cert.
        """
        failure = False
        for store in self.cert.stores:
            log.info(
                f"Ensuring cert '{self.cert.name}' is published to '{store.driver}' store '{store.name}'..."
            )
            try:
                store.publish(self.cert)
            except StoreError as error:
                failure = True
                STORE_METRICS[store.name].counters["errors"].inc()
                log.error(
                    f"Failed to publish cert '{self.cert.name}' to '{store.driver}' store '{store.name}': {error}"
                )
        if failure:
            raise ControllerError("Failed to publish cert to all stores.")

    def _create_csr(self) -> x509.CertificateSigningRequest:
        """
        Creates a CSR for the order.

        :raises ControllerError: Raised if no private key is in the state.
        """
        if self.cert.state.key is None:
            raise ControllerError("Unable to create CSR, no private key in state.")
        domains = []
        for domain in [self.cert.common_name] + self.cert.alt_names:
            domains.append(x509.DNSName(domain))
        subjects = [x509.NameAttribute(NameOID.COMMON_NAME, self.cert.common_name)]
        for subject in [
            self.cert.subject.country,
            self.cert.subject.state_or_province,
            self.cert.subject.locality,
            self.cert.subject.organization,
            self.cert.subject.organizational_unit,
        ]:
            if subject:
                subjects.append(subject)
        return (
            x509.CertificateSigningRequestBuilder()
            .subject_name(x509.Name(subjects))
            .add_extension(
                x509.SubjectAlternativeName(domains),
                critical=False,
            )
            .sign(self.cert.state.key, hashes.SHA256())
        )

    def _update_order(self) -> None:
        """
        Update the order status from the server in case it changed.

        :raises ControllerError: Raised if no order is in the state.
        """
        if not self.cert.state.order:
            raise ControllerError("No order found.")
        order_uri = self.cert.state.order.uri
        csr_pem = self.cert.state.order.csr_pem
        try:
            response = self.client._post_as_get(order_uri)
            body = acme_messages.Order.from_json(response.json())
            authorizations = []
            for uri in body.authorizations:
                authorizations.append(
                    self.client._authzr_from_response(
                        self.client._post_as_get(uri), uri=uri
                    )
                )
        except acme_messages.Error as error:
            self._fail_order(f"Failed to retrieve order from ACME server: {error}.")
        self.cert.state.order = acme_messages.OrderResource(
            body=body,
            uri=order_uri,
            authorizations=authorizations,
            csr_pem=csr_pem,
        )
        self.state_manager.save(self.cert)

    def _validate_authorizations(self) -> None:
        """
        Validates the authorizations on the order. Continues onto
        :meth:`_fail_order` if any authorizations are in the following
        statuses:

        - ``STATUS_DEACTIVATED``
        - ``STATUS_REVOKED``
        - ``STATUS_UNKNOWN``

        :raises ControllerError: Raised if no order is in the state.
        """
        if not self.cert.state.order:
            raise ControllerError("No order found.")
        errors = []
        for authz in self.cert.state.order.authorizations:
            if authz.body.status in [
                acme_messages.STATUS_DEACTIVATED,
                acme_messages.STATUS_REVOKED,
                acme_messages.STATUS_UNKNOWN,
            ]:
                errors.append(authz)
        if errors:
            self._fail_order("Authorizations in invalid status, failing order.")

    def _get_challenges(
        self, validate: bool = True, completed: bool = False
    ) -> List[Tuple[str, acme_messages.ChallengeBody]]:
        """
        Extracts the DNS challenges from the order.

        :param validate: Whether to verify the authorizations are in a valid
            state. If not, the order is failed.
        :param completed: Whether to return already completed challenges.

        :returns: A list of tuples containing (domain, :class:`acme.messages.ChallengeBody`).

        :raises ControllerError: Raised if no order is in the state.
        """
        if not self.cert.state.order:
            raise ControllerError("No order found.")
        # First check for any errors
        if validate:
            self._validate_authorizations()
        challenges = []
        # Now find the challenges
        for authz in self.cert.state.order.authorizations:
            domain = authz.body.identifier.value
            status = authz.body.status
            if completed or status in [
                acme_messages.STATUS_PENDING,
                acme_messages.STATUS_PROCESSING,
            ]:
                for challenge in authz.body.challenges:
                    if isinstance(challenge.chall, acme_challenges.DNS01):
                        challenges.append((domain, challenge))
        return challenges

    def _get_dns_records(
        self, validate: bool = True, completed: bool = False
    ) -> List[Tuple[str, str, str, Solver]]:
        """
        Compiles and returns the parts of a DNS records and associated
        :class:`certwrangler.models.Solver` instances for each of the
        challenges.

        :param validate: Whether to verify the authorizations are in a valid
            state. If not, the order is failed.
        :param completed: Whether to return already completed challenges.

        :returns: A list of tuples containing the name of the record,
            the DNS zone, the value of the TXT record, and the
            :class:`certwrangler.models.Solver` associated with the zone for
            each challenge on the order.

        :raises ControllerError: Raised if errors are encountered resolving
            DNS or if a :class:`certwrangler.models.Solver` isn't found for
            the zone.
        """
        dns_records = []
        challenges = self._get_challenges(validate=validate, completed=completed)
        for domain, challenge in challenges:
            challenge_name = f"_acme-challenge.{domain}"
            if self.cert.follow_cnames:
                try:
                    challenge_name = resolve_cname(challenge_name)
                except ValueError as error:
                    raise ControllerError(error) from error
            try:
                zone = resolve_zone(challenge_name)
            except ValueError as error:
                raise ControllerError(error) from error
            name = ".".join(challenge_name.split(".")[: -len(zone.split("."))])
            token = challenge.validation(self.cert.account.state.key)
            try:
                solver = self.cert.get_solver_for_zone(zone)
            except ValueError as error:
                raise ControllerError(error) from error
            dns_records.append((name, zone, token, solver))
        return dns_records

    def _fail_order(self, error: Optional[Union[Exception, str]] = None) -> None:
        """
        Cleans up any resources created as part of processing the order and
        removes the order from the cert's state.

        :param error: Optional error message or exception.

        :raises ControllerError: Raised after cleanup is performed. A message
            can be provided with the optional ``error`` parameter.
        """
        # Trash the order and try again on the next loop
        log.error(f"Removing invalid order for cert '{self.cert.name}'.")
        self.clean_up()
        raise ControllerError(error)
