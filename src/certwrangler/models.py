"""
This module contains all the models used in certwrangler's config and state.
Note that the ``name`` field is automatically populated on loading of the
config based on the key of the object.
"""

from __future__ import annotations

import abc
import base64
import hashlib
import logging
from datetime import datetime, timedelta, timezone
from enum import Enum
from ipaddress import IPv4Address
from pathlib import Path
from typing import Any, Callable, ClassVar, Dict, List, Literal, Optional, Union

from cryptography import x509
from cryptography.fernet import MultiFernet
from cryptography.x509.oid import NameOID
from importlib_metadata import entry_points
from pydantic import (
    BaseModel,
    ConfigDict,
    EmailStr,
    Field,
    HttpUrl,
    IPvAnyAddress,
    ModelWrapValidatorHandler,
    PrivateAttr,
    computed_field,
    field_validator,
    model_validator,
)
from typing_extensions import Self

from certwrangler.dns import resolve_zone
from certwrangler.schema_migrations import (
    ACCOUNT_STATE_SCHEMA_MIGRATIONS,
    CERT_STATE_SCHEMA_MIGRATIONS,
)
from certwrangler.types import (
    X509CSR,
    CountryNameOID,
    Days,
    Domain,
    FernetKey,
    JWKRSAKey,
    LocalityOID,
    Order,
    OrganizationalUnitOID,
    OrganizationOID,
    Registration,
    RSAKey,
    StateOrProvinceOID,
    X509Certificate,
)

log = logging.getLogger(__name__)


class NamedModel(BaseModel):
    """
    Base class for models that have a name.

    The :attr:`_name` attribute is set by the :class:`Config` class as part of
    :meth:`Config.__post_populate` based on the key that the model was defined
    under.
    """

    _name: str = PrivateAttr()

    @property
    def name(self) -> str:
        return self._name


class StateModel(BaseModel):
    """
    Base class for models representing state.

    The :attr:`_migrated` attribute is set if the model schema was migrated.
    """

    schema_migrations: ClassVar[List[Callable[[Dict[str, Any]], Dict[str, Any]]]] = []

    _migrated: bool = PrivateAttr(default=False)

    @computed_field
    def _schema_version(self) -> int:
        """
        The version of the schema, which is based on how many schema migrations
        are defined on the model.
        """

        return len(self.schema_migrations)

    @model_validator(mode="wrap")
    @classmethod
    def _handle_schema_migrations(
        cls,
        data: Any,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Any:
        """
        Iterate through the defined schema_migrations callables to perform any
        needed migrations. This checks the incoming data for the current schema
        version to determine which migrations it should apply. This also instantiates
        the class and sets the _migrated variable to True if any of the migration
        callables were applied.

        The callables should mutate the data dict as needed to migrate the schema
        then return it.
        """

        if not isinstance(data, dict) or not data:
            return handler(data)
        migrated = False
        schema_version = data.get("_schema_version", 0)
        for migration in cls.schema_migrations[schema_version:]:
            data = migration(data)
            migrated = True
        instance = handler(data)
        instance._migrated = migrated
        return instance


class Solver(NamedModel, metaclass=abc.ABCMeta):
    """Base class for ACME challenge solver drivers."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    driver: str = Field(..., description="The name of the driver to use.")
    zones: List[Domain] = Field(
        ..., description="A list of DNS zones this solver should be used for."
    )

    @abc.abstractmethod
    def create(self, name: str, domain: str, content: str) -> None:
        """
        This should handle the logic of creating a TXT record.
        """
        raise NotImplementedError

    @abc.abstractmethod
    def delete(self, name: str, domain: str, content: str) -> None:
        """
        This should handle the logic of deleting a TXT record.
        """
        raise NotImplementedError

    def initialize(self) -> None:
        """
        Any driver specific initialization steps (creating resources, setting
        up clients, etc) should be placed here.
        """
        pass

    @field_validator("zones")
    @classmethod
    def __validate_zones(cls, values: List[Domain]) -> List[Domain]:
        """
        Validate that the configured zones have valid SOA records.

        :returns: A list of valid zones.

        :raises ValueError: Raised if a configured zone doesn't have an SOA record.
        """
        errors = []
        for zone in values:
            resolved_zone = resolve_zone(zone)
            if zone != resolved_zone:
                errors.append(f"Invalid zone, SOA for '{zone}' is '{resolved_zone}'.")
        if errors:
            raise ValueError(errors)
        return values


class Encryptor(MultiFernet):
    """
    This just adds the ability to generate a fingerprint of a fernet key.
    """

    @property
    def fingerprint(self) -> str:
        """
        Returns the fingerprint of the active encryption key.

        :returns: A string representing the fingerprint of the active key.
        """
        return hashlib.sha512(
            base64.urlsafe_b64encode(
                self._fernets[0]._signing_key + self._fernets[0]._encryption_key
            )
        ).hexdigest()[:12]


class StateManager(BaseModel, metaclass=abc.ABCMeta):
    """
    Base class for state manager drivers.
    """

    model_config = ConfigDict(arbitrary_types_allowed=True)

    driver: str = Field(..., description="The name of the driver to use.")
    encryption_keys: List[FernetKey] = Field(
        default_factory=list,
        description="An optional list of encryption keys to use to encrypt "
        "the state. Only the top-most key will be used for encryption "
        "operations, the additional keys are only used to decrypt the state "
        "in the case that a new key was added. New keys can be generated "
        "using the ``certwrangler state generate-key`` command.",
    )

    _config: Config = PrivateAttr()
    _encryptor: Optional[Encryptor] = PrivateAttr(default=None)

    @property
    def encryptor(self) -> Optional[Encryptor]:
        """
        This sets up and returns an Encryptor if ``encryption_keys`` are defined.

        :returns: The initialized :class:`Encryptor` if ``encryption_keys`` are
            defined, otherwise returns ``None``.
        """
        if not self._encryptor and self.encryption_keys:
            self._encryptor = Encryptor(self.encryption_keys)
        return self._encryptor

    def initialize(self) -> None:
        """
        Any driver specific initialization steps (creating resources, setting
        up clients, etc) should be placed here.
        """
        pass

    @abc.abstractmethod
    def list(self) -> Dict[str, Dict[str, Any]]:
        """
        Lists all the saved states for the given entity_class including encryption fingerprint.
        """
        raise NotImplementedError

    @abc.abstractmethod
    def save(self, entity: Union[Account, Cert], encrypt: bool = True) -> None:
        """
        Saves the state of the given entity.
        """
        raise NotImplementedError

    @abc.abstractmethod
    def load(self, entity: Union[Account, Cert]) -> None:
        """
        Loads the state of the given entity to memory.
        """
        raise NotImplementedError

    @abc.abstractmethod
    def delete(
        self, entity_class: Union[Literal["account"], Literal["cert"]], entity_name: str
    ) -> None:
        """
        Deletes the given entity_name from state.
        """
        raise NotImplementedError


class Store(NamedModel, metaclass=abc.ABCMeta):
    """
    Base class for store drivers.
    """

    model_config = ConfigDict(arbitrary_types_allowed=True)

    driver: str = Field(..., description="The name of the driver to use.")

    @abc.abstractmethod
    def publish(self, cert: Cert) -> None:
        """
        This should handle the logic of publishing the cert to the store.
        """
        raise NotImplementedError

    def initialize(self) -> None:
        """
        Any driver specific initialization steps (creating resources, setting
        up clients, etc) should be placed here.
        """
        pass

    @staticmethod
    def _join_certs(*certs: str) -> str:
        """
        Joins multiple certs together into a bundle.
        """
        return "\n".join([x.strip() for x in certs]) + "\n"


class AccountStatus(str, Enum):
    new = "new"
    active = "active"


class AccountState(StateModel):
    """
    Managed ACME account state.
    """

    model_config = ConfigDict(arbitrary_types_allowed=True)
    schema_migrations = ACCOUNT_STATE_SCHEMA_MIGRATIONS

    registration: Optional[Registration] = Field(
        None, description="The ACME registration record."
    )
    key: Optional[JWKRSAKey] = Field(None, description="The current RSA key.")
    key_size: Optional[int] = Field(
        None, description="The size of the current RSA key in bits."
    )
    status: AccountStatus = AccountStatus.new


class Account(NamedModel):
    """
    Managed ACME account definition.
    """

    model_config = ConfigDict(arbitrary_types_allowed=True)

    emails: List[EmailStr] = Field(
        ..., description="A list of email addresses for the account."
    )
    server: HttpUrl = Field(
        HttpUrl("https://acme-v02.api.letsencrypt.org/directory"),
        description="The URL of the ACME server.",
    )
    key_size: int = Field(2048, description="The desired size of the RSA key in bits")

    _state: AccountState = PrivateAttr(default_factory=AccountState)

    @property
    def state(self) -> AccountState:
        return self._state

    @state.setter
    def state(self, value: AccountState) -> None:
        self._state = value

    @field_validator("emails")
    @classmethod
    def __validate_unique_emails(cls, values: List[EmailStr]) -> List[EmailStr]:
        """
        Validates that all the configured emails are unique.
        """
        if len(set(values)) != len(values):
            raise ValueError("Duplicate emails not allowed.")
        return values


class Subject(NamedModel):
    """
    Cert subject.
    """

    model_config = ConfigDict(arbitrary_types_allowed=True)

    country: Optional[CountryNameOID] = Field(None, description="The country name OID.")
    state_or_province: Optional[StateOrProvinceOID] = Field(
        None, description="The state or province OID."
    )
    locality: Optional[LocalityOID] = Field(None, description="The locality OID.")
    organization: Optional[OrganizationOID] = Field(
        None, description="The organization OID."
    )
    organizational_unit: Optional[OrganizationalUnitOID] = Field(
        None, description="The organizational unit OID."
    )


class CertStatus(str, Enum):
    new = "new"
    active = "active"
    renewing = "renewing"


class CertState(StateModel):
    """
    Managed cert state.
    """

    model_config = ConfigDict(arbitrary_types_allowed=True)
    schema_migrations = CERT_STATE_SCHEMA_MIGRATIONS

    url: Optional[str] = Field(
        None, description="The URL of the cert retrieved from the ACME server."
    )
    key: Optional[RSAKey] = Field(None, description="The cert's RSA key.")
    key_size: Optional[int] = Field(
        None, description="The size of the RSA key in bits."
    )
    cert: Optional[X509Certificate] = Field(
        None, description="The cert returned by the ACME server."
    )
    chain: Optional[List[X509Certificate]] = Field(
        None, description="The chain of trust returned by the ACME server."
    )
    csr: Optional[X509CSR] = Field(
        None, description="The CSR generated to request the cert."
    )
    order: Optional[Order] = Field(
        None, description="The order if an order is currently active."
    )
    status: CertStatus = CertStatus.new

    @computed_field
    def fullchain(self) -> Optional[List[X509Certificate]]:
        """
        The full chain of trust including the leaf cert.
        """
        if not self.cert:
            return None
        if not self.chain:
            return [self.cert]
        return [self.cert, *self.chain]


class Cert(NamedModel):
    """
    Managed cert definition.
    """

    model_config = ConfigDict(arbitrary_types_allowed=True)

    common_name: Domain = Field(..., description="The common name for the cert.")
    account_name: str = Field(
        ...,
        description="The name of the configured ACME account the cert should "
        "be created under.",
    )
    store_names: List[str] = Field(
        ...,
        description="A list of the configured stores the cert should be "
        "published to.",
    )
    store_key: Optional[str] = Field(
        None,
        description="Optional sub-key the cert should be published to in the "
        "store. Currently only supported by the vault store driver.",
    )
    subject_name: str = Field(
        "default",
        description="The name of the configured subject the cert should be "
        "created with.",
    )
    alt_names: List[Domain] = Field(
        default_factory=list, description="A list of alternative names for the cert."
    )
    wait_timeout: timedelta = Field(
        default=timedelta(seconds=300), description="Wait timeout for DNS operations."
    )
    key_size: int = Field(2048, description="The desired size of the RSA key in bits.")
    follow_cnames: bool = Field(
        True, description="Whether to follow CNAMEs for DNS operations."
    )
    renewal_threshold: Days = Field(
        default=timedelta(days=30),
        description="How many days before a cert expires should it be renewed.",
    )

    _state: CertState = PrivateAttr(default_factory=CertState)
    _config: Config = PrivateAttr()

    @property
    def state(self) -> CertState:
        return self._state

    @state.setter
    def state(self, value: CertState) -> None:
        self._state = value

    @property
    def account(self) -> Account:
        """
        Returns the account object configured for the cert.

        :raises ValueError: Raised if the account can't be found in the config.
        """
        try:
            return self._config.accounts[self.account_name]
        except KeyError:
            raise ValueError(f"No account named '{self.account_name}'.")

    @property
    def stores(self) -> List[Store]:
        """
        Returns a list of the configured store objects.

        :raises ValueError: Raised if a store can't be found in the config.
        """
        stores = []
        errors = []
        for store_name in self.store_names:
            try:
                stores.append(self._config.stores[store_name])
            except KeyError:
                errors.append(f"No store named '{store_name}'.")
        if errors:
            raise ValueError(" ".join(errors))
        return stores

    @property
    def solvers(self) -> Dict[str, Solver]:
        """
        Returns the available solvers.
        """
        return self._config.solvers

    @property
    def subject(self) -> Subject:
        """
        Returns the subject object configured for the cert.

        :raises ValueError: Raised if a subject can't be found in the config.
        """
        try:
            return self._config.subjects[self.subject_name]
        except KeyError:
            raise ValueError(f"No subject named '{self.subject_name}'.")

    def get_solver_for_zone(self, zone: str) -> Solver:
        """
        Finds a solver for a given zone name.

        :raises ValueError: Raised if a solver for the zone can't be found in
            the config.
        """
        for solver in self.solvers.values():
            if zone in solver.zones:
                return solver
        raise ValueError(f"Unable to find solver for zone {zone}.")

    @field_validator("store_names")
    @classmethod
    def __validate_unique_stores(cls, values: List[str]) -> List[str]:
        """
        Validates that all the configured stores are unique.

        :raises ValueError: Raised if there are duplicate stores.
        """
        if len(set(values)) != len(values):
            raise ValueError("Duplicate stores not allowed.")
        return values

    @property
    def time_left(self) -> timedelta:
        """
        Returns the cert expiry as a :class:`datetime.timedelta`. If no cert is
        in the state it returns an empty :class:`datetime.timedelta`.

        :returns: A :class:`datetime.timedelta` representing the cert's expiry.
        """
        if not self.state.cert:
            return timedelta()
        return self.state.cert.not_valid_after_utc - datetime.now(timezone.utc)

    @property
    def needs_renewal(self) -> bool:
        """
        Check if a cert needs to be renewed by checking its expiry time is less
        than ``renewal_threshold``, or if it's ``common_name`` or
        ``alternative_names`` changed.

        We specifically don't check for the ``subject`` since apparently LE
        strips that out.

        :returns: A ``bool`` representing if the cert should be renewed.
        """
        if not self.state.cert:
            log.info(f"No cert present in state for cert '{self.name}'.")
            return True
        if self.time_left < self.renewal_threshold:
            log.info(
                f"Cert '{self.name}' expires in {self.time_left.days} days, "
                f"(threshold {self.renewal_threshold.days}).'"
            )
            return True
        state_common_name = self.state.cert.subject.get_attributes_for_oid(
            NameOID.COMMON_NAME
        )[0].value
        if self.common_name != state_common_name:
            log.info(f"Common name changed on cert '{self.name}'.")
            return True
        # This only works for certs with DNS alt names
        alt_names = sorted(
            self.state.cert.extensions.get_extension_for_class(
                x509.SubjectAlternativeName
            ).value.get_values_for_type(x509.general_name.DNSName)
        )
        if set([self.common_name] + self.alt_names) != set(alt_names):
            log.debug(
                f"'{set([self.common_name] + self.alt_names)}' does not equal '{set(alt_names)}'."
            )
            log.info(f"Alternative names changed on cert '{self.name}'.")
            return True
        return False


class ReconcilerConfig(BaseModel):
    """
    Config for the reconciler loop subsystem.
    """

    model_config = ConfigDict(arbitrary_types_allowed=True)

    interval: int = Field(60, description="Reconciler interval in seconds.")


class MetricsConfig(BaseModel):
    """
    Config for the metrics subsystem.
    """

    model_config = ConfigDict(arbitrary_types_allowed=True)

    mount: str = Field("/metrics", description="The mount-point for metrics.")


class HttpConfig(BaseModel):
    """
    Config for the HTTP subsystem.
    """

    model_config = ConfigDict(arbitrary_types_allowed=True)

    host: IPvAnyAddress = Field(
        IPv4Address("127.0.0.1"),
        description="Address the HTTP server should bind to.",
    )
    port: int = Field(6377, description="Port the HTTP server should listen on.")
    server_name: str = Field("certwrangler", description="Name of the HTTP server.")
    ssl_key_file: Optional[Path] = Field(None, description="Optional SSL key.")
    ssl_key_password: Optional[str] = Field(
        None, description="Optional SSL key password."
    )
    ssl_cert_file: Optional[Path] = Field(None, description="Optional SSL cert.")
    ssl_ca_certs_file: Optional[Path] = Field(None, description="Optional SSL CA cert.")

    @field_validator("ssl_key_file", "ssl_cert_file", "ssl_ca_certs_file")
    @classmethod
    def __validate_ssl_files_exist(cls, value: Optional[Path]) -> Optional[Path]:
        """
        Validates that the specified file exists.

        :raises ValueError: Raised if the file does not exist.
        """
        if value is not None and not value.expanduser().is_file():
            raise ValueError(f"File '{value}' does not exist.")
        return value

    @model_validator(mode="after")
    def __validate_ssl_options(self) -> HttpConfig:
        """
        Validate that we have both ``ssl_key_file`` and ``ssl_cert_file`` populated if
        either are set.

        :raises ValueError: Raised if either ``ssl_key_file`` or ``ssl_cert_file``
            is not set when the other is set.
        """
        if bool(self.ssl_key_file) != bool(self.ssl_cert_file):
            raise ValueError(
                "'ssl_key_file' and 'ssl_cert_file' are both required if either is set."
            )
        # TODO: additional validation that the cert, ca cert, key, and key password match.
        return self


class DaemonConfig(BaseModel):
    """
    Config for the daemon.
    """

    model_config = ConfigDict(arbitrary_types_allowed=True)

    reconciler: ReconcilerConfig = Field(
        default_factory=ReconcilerConfig, description="Config for the reconciler."
    )
    metrics: MetricsConfig = Field(
        default_factory=MetricsConfig, description="Config for metrics."
    )
    http: HttpConfig = Field(
        default_factory=HttpConfig, description="Config for the http server."
    )
    watchdog_interval: int = Field(
        30,
        description="Watchdog interval in seconds. The watchdog periodically "
        "checks to see if any of the daemon threads have died.",
    )


class Config(BaseModel):
    """
    The root config object for the application.

    This class is the root of the entire config tree of the application and is
    responsible for loading any of the plugins specified by sub-members in
    their configuration as well as triggering any initialization hooks that
    may be specified by the various plugins.
    """

    model_config = ConfigDict(arbitrary_types_allowed=True)

    daemon: DaemonConfig = Field(
        default_factory=DaemonConfig, description="Config for the daemon."
    )
    state_manager: StateManager = Field(
        ..., alias="state", description="Config for the state manager."
    )
    accounts: Dict[str, Account] = Field(..., description="Config for the accounts.")
    certs: Dict[str, Cert] = Field(..., description="Config for the certs.")
    solvers: Dict[str, Solver] = Field(..., description="Config for the solvers.")
    stores: Dict[str, Store] = Field(..., description="Config for the stores.")
    subjects: Dict[str, Subject] = Field(..., description="Config for the subjects.")

    @field_validator("solvers", mode="before")
    @classmethod
    def __load_solver_plugins(cls, values: Dict[str, Any]) -> Dict[str, Solver]:
        """
        Dynamically load solver plugins based on their driver key.

        :raises ValueError: Raised if the specified plugin can't be loaded.
        """
        for name, solver_config in values.items():
            try:
                (plugin,) = entry_points(
                    group="certwrangler.solver", name=solver_config["driver"]
                )
            except ValueError as error:
                raise ValueError(
                    f"No solver plugin named '{solver_config['driver']}'."
                ) from error
            values[name] = plugin.load()(**solver_config)
        return values

    @field_validator("state_manager", mode="before")
    @classmethod
    def __load_state_manager_plugin(cls, values: Dict[str, Any]) -> StateManager:
        """
        Dynamically load state_manager plugins based on their driver key.

        :raises ValueError: Raised if the specified plugin can't be loaded.
        """
        try:
            (plugin,) = entry_points(
                group="certwrangler.state_manager", name=values["driver"]
            )
        except ValueError as error:
            raise ValueError(
                f"No state_manager plugin named '{values['driver']}'."
            ) from error
        return plugin.load()(**values)

    @field_validator("stores", mode="before")
    @classmethod
    def __load_store_plugins(cls, values: Dict[str, Any]) -> Dict[str, Store]:
        """
        Dynamically load store plugins based on their driver key.

        :raises ValueError: Raised if the specified plugin can't be loaded.
        """
        for name, store_config in values.items():
            try:
                (plugin,) = entry_points(
                    group="certwrangler.store", name=store_config["driver"]
                )
            except ValueError as error:
                raise ValueError(
                    f"No store plugin named '{store_config['driver']}'."
                ) from error
            values[name] = plugin.load()(**store_config)
        return values

    @model_validator(mode="before")
    @classmethod
    def __pre_populate(cls, values: Dict[str, Any]) -> Dict[str, Any]:
        """
        Pre-populate the config data with some defaults.
        """
        # First pre-populate an empty default subject and state if we don't have one
        if not values.get("subjects"):
            values["subjects"] = {}
        if not values["subjects"].get("default"):
            values["subjects"]["default"] = {}
        if not values.get("state"):
            values["state"] = {"driver": "local"}
        return values

    @model_validator(mode="after")
    def __post_populate(self) -> Config:
        """
        Loops through the certs config and populates the reference to the root
        config object, which is needed to resolve foreign references.

        Also loops through all the objects and populates their name field
        based on their key.

        It then tries to resolve all references to account, subject, and stores
        on the cert object and will raise a ValueError if any references don't
        resolve.

        :raises ValueError: Raised if any references on sub-objects don't resolve.
        """
        errors = {}
        self.state_manager._config = self
        # Populate the name value
        for key in ["accounts", "certs", "solvers", "stores", "subjects"]:
            for name, entity in getattr(self, key).items():
                entity._name = name
        for cert in self.certs.values():
            cert._config = self
            cert_errors = []
            # make sure our dynamic attributes resolve
            for attr_name in ["account", "subject", "stores"]:
                try:
                    getattr(cert, attr_name)
                except ValueError as error:
                    cert_errors.append(str(error))
            if cert_errors:
                errors[cert.name] = " ".join(cert_errors)
        if errors:
            raise ValueError({"certs": errors})
        return self

    def initialize(self) -> None:
        """
        Initialize drivers and load state on stateful objects.
        """
        self.state_manager.initialize()
        for store in self.stores.values():
            store.initialize()
        for solver in self.solvers.values():
            solver.initialize()
        for account in self.accounts.values():
            self.state_manager.load(account)
            if account.state._migrated:
                log.info(
                    f"Account '{account.name}' state schema migrated, saving changes..."
                )
                self.state_manager.save(account)
                account.state._migrated = False
        for cert in self.certs.values():
            self.state_manager.load(cert)
            if cert.state._migrated:
                log.info(f"Cert '{cert.name}' state schema migrated, saving changes...")
                self.state_manager.save(cert)
                cert.state._migrated = False
