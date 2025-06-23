from datetime import timedelta
from typing import Any, Dict, Union

import josepy as jose
from acme import messages
from cryptography import fernet, x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.types import (
    CertificateIssuerPrivateKeyTypes,
)
from cryptography.x509.oid import NameOID
from pydantic import BeforeValidator, Field, PlainSerializer, WithJsonSchema
from typing_extensions import Annotated

# Cryptography Types

FernetKey = Annotated[
    fernet.Fernet,
    BeforeValidator(
        lambda value: fernet.Fernet(value) if isinstance(value, str) else value
    ),
    WithJsonSchema({"type": "string"}),
]


RSAKey = Annotated[
    CertificateIssuerPrivateKeyTypes,
    BeforeValidator(
        lambda value: (
            serialization.load_pem_private_key(value.encode(), password=None)
            if isinstance(value, str)
            else value
        )
    ),
    PlainSerializer(
        lambda value: value.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode()
    ),
    WithJsonSchema({"type": "string"}),
]


X509Certificate = Annotated[
    x509.Certificate,
    BeforeValidator(
        lambda value: (
            x509.load_pem_x509_certificate(value.encode())
            if isinstance(value, str)
            else value
        ),
    ),
    PlainSerializer(
        lambda value: value.public_bytes(serialization.Encoding.PEM).decode()
    ),
    WithJsonSchema({"type": "string"}),
]


X509CSR = Annotated[
    x509.CertificateSigningRequest,
    BeforeValidator(
        lambda value: (
            x509.load_pem_x509_csr(value.encode()) if isinstance(value, str) else value
        ),
    ),
    PlainSerializer(
        lambda value: value.public_bytes(serialization.Encoding.PEM).decode()
    ),
    WithJsonSchema({"type": "string"}),
]


JWKRSAKey = Annotated[
    jose.JWK,
    BeforeValidator(
        lambda value: (
            jose.JWKRSA.from_json(value) if isinstance(value, dict) else value
        ),
    ),
    PlainSerializer(lambda value: value.to_json()),
    WithJsonSchema({"type": "object"}),
]


# x509 OIDs


CountryNameOID = Annotated[
    x509.NameAttribute,
    BeforeValidator(
        lambda value: (
            x509.NameAttribute(NameOID.COUNTRY_NAME, value)
            if isinstance(value, str)
            else value
        ),
    ),
    PlainSerializer(lambda value: value.value),
    WithJsonSchema({"type": "string"}),
]


StateOrProvinceOID = Annotated[
    x509.NameAttribute,
    BeforeValidator(
        lambda value: (
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, value)
            if isinstance(value, str)
            else value
        ),
    ),
    PlainSerializer(lambda value: value.value),
    WithJsonSchema({"type": "string"}),
]

LocalityOID = Annotated[
    x509.NameAttribute,
    BeforeValidator(
        lambda value: (
            x509.NameAttribute(NameOID.LOCALITY_NAME, value)
            if isinstance(value, str)
            else value
        ),
    ),
    PlainSerializer(lambda value: value.value),
    WithJsonSchema({"type": "string"}),
]


OrganizationOID = Annotated[
    x509.NameAttribute,
    BeforeValidator(
        lambda value: (
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, value)
            if isinstance(value, str)
            else value
        ),
    ),
    PlainSerializer(lambda value: value.value),
    WithJsonSchema({"type": "string"}),
]


OrganizationalUnitOID = Annotated[
    x509.NameAttribute,
    BeforeValidator(
        lambda value: (
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, value)
            if isinstance(value, str)
            else value
        ),
    ),
    PlainSerializer(lambda value: value.value),
    WithJsonSchema({"type": "string"}),
]


# ACME Types


Registration = Annotated[
    messages.RegistrationResource,
    BeforeValidator(
        lambda value: (
            messages.RegistrationResource.from_json(value)
            if isinstance(value, dict)
            else value
        ),
    ),
    PlainSerializer(lambda value: value.to_json()),
    WithJsonSchema({"type": "object"}),
]


def _order_loader(
    value: Union[Dict[str, Any], messages.OrderResource],
) -> messages.OrderResource:
    """
    Deserializes a json representation of :class:`acme.messages.OrderResource`,
    including casting its sub-keys to the types it expects and deserializing
    any embedded :class:`acme.messages.AuthorizationResource` instances.
    """
    if isinstance(value, messages.OrderResource):
        return value
    body = messages.Order.from_json(value["body"])
    uri = value["uri"]
    csr_pem = bytes(value["csr_pem"], encoding="utf-8")
    fullchain_pem = value["fullchain_pem"] if value.get("fullchain_pem") else None
    authorizations = [
        messages.AuthorizationResource.from_json(auth)
        for auth in value["authorizations"]
    ]
    return messages.OrderResource(
        body=body,
        uri=uri,
        authorizations=authorizations,
        csr_pem=csr_pem,
        fullchain_pem=fullchain_pem,
    )


Order = Annotated[
    messages.OrderResource,
    BeforeValidator(_order_loader),
    PlainSerializer(lambda value: value.to_json()),
    WithJsonSchema({"type": "object"}),
]


# Generic types

Domain = Annotated[
    str,
    Field(
        # taken from https://github.com/python-validators/validators/blob/0.20.0/validators/domain.py#L5-L10
        pattern=r"^(?:(\*\.|[a-zA-Z0-9])"  # First character of the domain (including wildcard)
        r"(?:[a-zA-Z0-9-_]{0,61}[A-Za-z0-9])?\.)"  # Sub domain + hostname
        r"+[A-Za-z0-9][A-Za-z0-9-_]{0,61}"  # First 61 characters of the gTLD
        r"[A-Za-z]$"
    ),
]

Days = Annotated[
    timedelta,
    BeforeValidator(
        lambda value: timedelta(days=value) if isinstance(value, int) else value,
    ),
    PlainSerializer(lambda value: value.days),
]
