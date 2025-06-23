import datetime
import os
from pathlib import Path

import click
import josepy as jose
import pytest
from acme import messages as acme_messages
from cryptography import x509
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from certwrangler.controllers import AccountController, CertController
from certwrangler.models import AccountStatus, CertStatus
from certwrangler.solvers.dummy import DummySolver
from certwrangler.solvers.edgedns import EdgeDNSSolver
from certwrangler.solvers.lexicon import LexiconSolver
from certwrangler.state_managers.dummy import DummyStateManager
from certwrangler.state_managers.local import LocalStateManager
from certwrangler.stores.dummy import DummyStore
from certwrangler.stores.local import LocalStore
from certwrangler.stores.vault import VaultStore
from certwrangler.utils import CertwranglerState

ONE_DAY = datetime.timedelta(1, 0, 0)


@pytest.fixture(scope="function")
def click_ctx(dummy_config_path):
    """
    Creates a fake click context for tests.
    This is needed for any tests against code that uses the click context,
    directly or indirectly. If you see this message when running your test:
        RuntimeError: There is no active click context.
    then you just need to include this fixture to make it magically work.

    By default this will set the config path on the CertwranglerState object
    to the dummy_config_path fixture. This can be changed by doing the following
    within your test:
        click_ctx.obj.config_path = new_config_path
    where new_config_path is a pathlib.Path object. Recommended to follow the
    pattern of dummy_config_path and setup a fixture to return that object.
    """

    command = click.Command("dummy_command")
    ctx = click.Context(command)
    with ctx:
        ctx.ensure_object(CertwranglerState)
        with ctx.obj.lock:
            ctx.obj.config_path = dummy_config_path
        yield ctx


@pytest.fixture(scope="function")
def mocked_certwrangler_state(click_ctx, mocker, config):
    """
    Returns a mocked out CertwranglerState.
    """
    state = mocker.MagicMock(spec=click_ctx.obj)
    state.config = config
    return state


@pytest.fixture
def dummy_config_path():
    """
    Return the path of the dummy config that only uses the dummy drivers.
    """
    return Path(
        os.path.join(os.path.dirname(__file__), "files/certwrangler_config_dummy.yaml")
    )


# Model config fixtures


@pytest.fixture(scope="function")
def account_config():
    return {
        "emails": ["dummy_account@example.com"],
        "server": "https://acme-staging-v02.api.example.com/directory",
        "key_size": "2048",
    }


@pytest.fixture(scope="function")
def subject_config():
    return {
        "country": "US",
        "state_or_province": "DevLandia",
        "locality": "Dev Town",
        "organization": "Example Org",
        "organizational_unit": "DevOps",
    }


@pytest.fixture(scope="function")
def cert_config():
    return {
        "account_name": "test_account",
        "subject_name": "test_subject",
        "store_names": ["test_store"],
        "common_name": "example.com",
        "alt_names": ["www.example.com"],
    }


# Solver config fixtures


@pytest.fixture(scope="function")
def solver_dummy_config():
    return {
        "driver": "dummy",
        "zones": ["example.com"],
    }


@pytest.fixture(scope="function")
def solver_edgedns_config():
    return {
        "driver": "edgedns",
        "zones": ["example.com"],
        "host": "dummyapi.example.com",
        "client_token": "kinda_secret",
        "client_secret": "actually_secret",
        "access_token": "just a token trying to live its best life",
    }


@pytest.fixture(scope="function")
def solver_lexicon_config():
    return {
        "driver": "lexicon",
        "provider_name": "test_provider",
        "provider_options": {"key": "value"},
        "zones": ["example.com"],
    }


# State Manager config fixtures


@pytest.fixture(scope="function")
def state_manager_dummy_config():
    return {
        "driver": "dummy",
    }


@pytest.fixture(scope="function")
def state_manager_local_config():
    return {
        "driver": "local",
        "path": "/tmp/certwrangler_state",
    }


# Store config fixtures


@pytest.fixture(scope="function")
def store_dummy_config():
    return {
        "driver": "dummy",
    }


@pytest.fixture(scope="function")
def store_local_config():
    return {
        "driver": "local",
        "path": "/tmp/certwrangler_store",
    }


@pytest.fixture(scope="function")
def store_vault_auth_token_config():
    return {"method": "token", "token": "sweetlittlelies"}


@pytest.fixture(scope="function")
def store_vault_auth_approle_config():
    return {"method": "approle", "role_id": "foo", "secret_id": "bar"}


@pytest.fixture(scope="function")
def store_vault_auth_kubernetes_config():
    return {"method": "kubernetes", "role": "kubernetes"}


@pytest.fixture(scope="function")
def store_vault_config(store_vault_auth_token_config):
    return {
        "name": "test_store",
        "driver": "vault",
        "server": "https://dummy-vault.local",
        "mount_point": "/secret/data/certwrangler",
        "path": "foo",
        "version": 2,
        "auth": store_vault_auth_token_config,
    }


# Model instance fixtures (dummy config file)


@pytest.fixture(scope="function")
def config(click_ctx):
    click_ctx.obj.load_config()
    return click_ctx.obj.config


@pytest.fixture(scope="function")
def state_manager(config):
    """
    Modifies the state manager to support encryption.
    """
    return config.state_manager


@pytest.fixture(scope="function")
def state_manager_encryptor(state_manager):
    """
    Adds a generated fernet key to the state manager to support encryption.
    """
    state_manager.encryption_keys = [Fernet(Fernet.generate_key())]
    return state_manager.encryptor


@pytest.fixture(scope="function")
def account(config):
    return config.accounts["test_account"]


@pytest.fixture(scope="function")
def account_state(account):
    """
    Create a fake registration object in the account state.
    """
    private_key = jose.JWKRSA(
        key=rsa.generate_private_key(public_exponent=65537, key_size=account.key_size)
    )
    regr = acme_messages.RegistrationResource(
        body=acme_messages.Registration.from_data(
            key=private_key.public_key(),
            email=",".join(account.emails),
            terms_of_service_agreed=True,
            status="valid",
        ),
        uri="https://acme-staging-v02.api.example.com/acme/acct/12345",
    )
    account.state.key = private_key
    account.state.key_size = account.key_size
    account.state.registration = regr
    account.state.status = AccountStatus.active
    return account.state


@pytest.fixture(scope="function")
def subject(config):
    return config.subjects["test_subject"]


@pytest.fixture(scope="function")
def solver(config):
    return config.solvers["test_solver"]


@pytest.fixture(scope="function")
def store(config):
    return config.stores["test_store"]


@pytest.fixture(scope="function")
def cert(config):
    return config.certs["test_cert"]


@pytest.fixture(scope="function")
def cert_state_order(cert, cert_controller, account_state):
    """
    Populate the cert state with a fake order object.
    """
    cert_controller.create_key()
    cert.state.csr = cert_controller._create_csr()
    cert_controller.state_manager.reset_mock()
    cert.state.order = acme_messages.OrderResource().from_json(
        {
            "body": {
                "identifiers": [
                    {"type": "dns", "value": "example.com"},
                    {"type": "dns", "value": "www.example.com"},
                ],
                "status": "pending",
                "authorizations": [
                    "https://acme-staging-v02.api.example.com/acme/authz-v3/11029233303",
                    "https://acme-staging-v02.api.example.com/acme/authz-v3/11029233313",
                ],
                "finalize": "https://acme-staging-v02.api.example.com/acme/finalize/127766434/14277827173",
                "expires": "2030-02-13T14:33:08Z",
            },
            "uri": "https://acme-staging-v02.api.example.com/acme/order/127766434/14277827173",
            "csr_pem": str(cert.state.csr.public_bytes(serialization.Encoding.PEM)),
            "authorizations": [
                {
                    "body": {
                        "identifier": {"type": "dns", "value": "example.com"},
                        "challenges": [
                            {
                                "url": "https://acme-staging-v02.api.example.com/acme/chall-v3/11029233303/gxojLw",
                                "status": "pending",
                                "token": "Nf2GNKs0HZT5WaVnaNxNGuB_2tvtIegZD5E4GqGNcxQ",
                                "type": "http-01",
                            },
                            {
                                "url": "https://acme-staging-v02.api.example.com/acme/chall-v3/11029233303/BREykA",
                                "status": "pending",
                                "token": "Nf2GNKs0HZT5WaVnaNxNGuB_2tvtIegZD5E4GqGNcxQ",
                                "type": "dns-01",
                            },
                            {
                                "url": "https://acme-staging-v02.api.example.com/acme/chall-v3/11029233303/Vu7N2g",
                                "status": "pending",
                                "token": "Nf2GNKs0HZT5WaVnaNxNGuB_2tvtIegZD5E4GqGNcxQ",
                                "type": "tls-alpn-01",
                            },
                        ],
                        "status": "pending",
                        "expires": "2030-02-13T14:33:08Z",
                    },
                    "uri": "https://acme-staging-v02.api.example.com/acme/authz-v3/11029233303",
                },
                {
                    "body": {
                        "identifier": {
                            "type": "dns",
                            "value": "www.example.com",
                        },
                        "challenges": [
                            {
                                "url": "https://acme-staging-v02.api.example.com/acme/chall-v3/11029233313/AeacIA",
                                "status": "pending",
                                "token": "pW4CK83IQMpwJwlgO4cZeH-8WeQU1tVOBT62UiRfzdc",
                                "type": "http-01",
                            },
                            {
                                "url": "https://acme-staging-v02.api.example.com/acme/chall-v3/11029233313/sGCw9A",
                                "status": "pending",
                                "token": "pW4CK83IQMpwJwlgO4cZeH-8WeQU1tVOBT62UiRfzdc",
                                "type": "dns-01",
                            },
                            {
                                "url": "https://acme-staging-v02.api.example.com/acme/chall-v3/11029233313/PQGX0w",
                                "status": "pending",
                                "token": "pW4CK83IQMpwJwlgO4cZeH-8WeQU1tVOBT62UiRfzdc",
                                "type": "tls-alpn-01",
                            },
                        ],
                        "status": "pending",
                        "expires": "2030-02-13T14:33:08Z",
                    },
                    "uri": "https://acme-staging-v02.api.example.com/acme/authz-v3/11029233313",
                },
            ],
        }
    )


@pytest.fixture(scope="function")
def cert_state(cert, account_state, cert_controller, fake_ca):
    """
    Populate the cert state with a fake cert, key, and ca info.
    """
    cert_controller.create_key()
    cert.state.csr = cert_controller._create_csr()
    cert_controller.state_manager.reset_mock()
    serial = x509.random_serial_number()
    cert.state.cert = (
        x509.CertificateBuilder()
        .subject_name(cert.state.csr.subject)
        .issuer_name(fake_ca["ca_cert"].subject)
        .not_valid_before(datetime.datetime.today() - ONE_DAY)
        .not_valid_after(datetime.datetime.today() + (ONE_DAY * 90))
        .serial_number(serial)
        .public_key(cert.state.csr.public_key())
        .add_extension(
            cert.state.csr.extensions.get_extension_for_class(
                x509.SubjectAlternativeName
            ).value,
            critical=False,
        )
        .sign(
            private_key=fake_ca["intermediate_key"],
            algorithm=hashes.SHA256(),
            backend=default_backend(),
        )
    )
    cert.state.chain = [fake_ca["intermediate_cert"], fake_ca["ca_cert"]]
    cert.state.url = f"https://acme-staging-v02.api.example.com/acme/cert/{serial}"
    cert.state.status = CertStatus.active


# Controller instance fixtures (dummy config file)


@pytest.fixture(scope="function")
def account_controller(account, mocker):
    """
    Return an instance of the account controller with a mocked state manager.
    """
    mocker.patch("certwrangler.controllers.acme_client.ClientNetwork")
    state_manager_mock = mocker.MagicMock()
    account_controller = AccountController(account, state_manager_mock)
    # reset the mock because the init function of the controller issues a load.
    state_manager_mock.reset_mock()
    return account_controller


@pytest.fixture(scope="function")
def cert_controller(account_state, cert, mocker):
    """
    Return an instance of the cert controller with a mocked state manager.
    """
    mocker.patch("certwrangler.controllers.acme_client.ClientNetwork")
    state_manager_mock = mocker.MagicMock()
    cert_controller = CertController(cert, state_manager_mock)
    # reset the mock because the init function of the controller issues a load.
    state_manager_mock.reset_mock()
    return cert_controller


# Plugin instance fixtures (stand alone)


@pytest.fixture(scope="function")
def solver_dummy(solver_dummy_config):
    solver = DummySolver(**solver_dummy_config)
    solver._name = "test_solver"
    return solver


@pytest.fixture(scope="function")
def solver_edgedns(solver_edgedns_config):
    solver = EdgeDNSSolver(**solver_edgedns_config)
    solver._name = "test_solver"
    return solver


@pytest.fixture(scope="function")
def solver_lexicon(solver_lexicon_config):
    solver = LexiconSolver(**solver_lexicon_config)
    solver._name = "test_solver"
    return solver


@pytest.fixture(scope="function")
def state_manager_dummy(state_manager_dummy_config):
    return DummyStateManager(**state_manager_dummy_config)


@pytest.fixture(scope="function")
def state_manager_local(state_manager_local_config):
    return LocalStateManager(**state_manager_local_config)


@pytest.fixture(scope="function")
def store_dummy(store_dummy_config):
    store = DummyStore(**store_dummy_config)
    store._name = "test_store"
    return store


@pytest.fixture(scope="function")
def store_local(store_local_config):
    store = LocalStore(**store_local_config)
    store._name = "test_store"
    return store


@pytest.fixture(scope="function")
def store_vault(store_vault_config):
    store = VaultStore(**store_vault_config)
    store._name = "test_store"
    return store


# Misc


@pytest.fixture
def fake_ca():
    """
    Create a fake CA with an intermediate.
    """

    ca_private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )
    ca_public_key = ca_private_key.public_key()
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Certwrangler Test CA")])
        )
        .issuer_name(
            x509.Name(
                [
                    x509.NameAttribute(NameOID.COMMON_NAME, "Certwrangler Test CA"),
                ]
            )
        )
        .not_valid_before(datetime.datetime.today() - ONE_DAY)
        .not_valid_after(datetime.datetime.today() + ONE_DAY)
        .serial_number(x509.random_serial_number())
        .public_key(ca_public_key)
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        )
        .sign(
            private_key=ca_private_key,
            algorithm=hashes.SHA256(),
            backend=default_backend(),
        )
    )
    intermediate_private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )
    intermediate_public_key = intermediate_private_key.public_key()
    intermediate_cert = (
        x509.CertificateBuilder()
        .subject_name(
            x509.Name(
                [
                    x509.NameAttribute(
                        NameOID.COMMON_NAME, "Certwrangler Test Intermediate CA"
                    )
                ]
            )
        )
        .issuer_name(
            x509.Name(
                [
                    x509.NameAttribute(
                        NameOID.COMMON_NAME, "Certwrangler Test Intermediate CA"
                    ),
                ]
            )
        )
        .not_valid_before(datetime.datetime.today() - ONE_DAY)
        .not_valid_after(datetime.datetime.today() + ONE_DAY)
        .serial_number(x509.random_serial_number())
        .public_key(intermediate_public_key)
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        )
        .sign(
            private_key=ca_private_key,
            algorithm=hashes.SHA256(),
            backend=default_backend(),
        )
    )

    return {
        "ca_key": ca_private_key,
        "ca_cert": ca_cert,
        "intermediate_key": intermediate_private_key,
        "intermediate_cert": intermediate_cert,
    }
