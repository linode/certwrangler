# Reconciliation Loop

When Certwrangler is run once (with the `run` subcommand), it runs through a single reconciliation loop. When run as a daemon, it runs reconciliation loops continuously, with a sleep interval in between each run. During each loop, the following steps run:

## Account reconciliation
Certwrangler loops through all the [accounts](./config.md#acme-accounts) listed in its configuration and ensures that each of them is registered on the remote ACME server. This ensures that it is able to request any new certs it needs to during the next step.

During this step, if the contact info or the default key size does not match that on the remote ACME server, we send a request to update it.

## Cert reconciliation
As above, Certwrangler loops through all [certs](./config.md#defining-certs) in its configuration and ensures that all of them exist and do not need to be rotated. If a cert does not yet exist, the configured key size has changed, or the cert is close enough to expiration (configurable via `renewal_threshold` in the cert config entry), Certwrangler will proceed with the certificate generation process:

- A new private key is generated for the certificate, if one does not already exist
  - If the requested key size has changed, a new private key is generated, as changing the key size of a certificate requires changing the key size of its private key as well
- A new ACME order is created. This is [part of the ACME protocol](https://datatracker.ietf.org/doc/html/rfc8555#section-7.1.3) and represents a request for a certificate that will be sent to the ACME server
- Certwrangler will attempt to process the [DNS-01](https://letsencrypt.org/docs/challenge-types/#dns-01-challenge) challenges that the ACME provider requires before it will generate the certificate
- Once the certificate has been generated, Certwrangler will store the certificate and its associated private key in all stores configured for that cert

If any of the above steps fail during reconciliation, they will be retried on the next reconciliation loop.
