# Configuration

Though it's not a desktop application, Certwrangler adheres to the [XDG Base Directory Specification](https://specifications.freedesktop.org/basedir-spec/basedir-spec-latest.html) by default. It will load its config from `${XDG_CONFIG_HOME}/certwrangler` (or `~/.config/certwrangler.yaml` if `${XDG_CONFIG_HOME}` is not set). The config location can be overridden by providing the `--config` option or the environment variable `${CERTWRANGLER_CONFIG}`.

## Defining certs
Certwrangler (whether running as a daemon or running once) will attempt to generate certs via ACME that are configured in its config file. The relevant section of the config file looks like this:

```yaml
certs:
  example.com:
    account_name: default
    subject_name: default
    store_names:
      - default
    common_name: example.com
    alt_names:
      - www.example.com
    key_size: 4096
    wait_timeout: 120
```

If this is the entire `certs` section of your config, Certwrangler will attempt to generate a single cert with a common name of `example.com` and a SAN of `www.example.com`.

### Cert reference

````{toggle}
```{eval-rst}
.. autopydantic_model:: certwrangler.models.Cert
   :no-index:
   :model-signature-prefix: cert
   :model-show-validator-summary: False
   :model-show-field-summary: False
   :no-undoc-members:
   :inherited-members: BaseModel
   :exclude-members: name, state, account, stores, solvers, subject, get_solver_for_zone, time_left, needs_renewal
   :model-erdantic-figure: False
   :no-show-inheritance:
   :no-private-members:
   :field-list-validators: False
```
````

## ACME accounts
Each cert is generated with an ACME account, each having an email address, ACME server URL, and keypair (with configurable key size) associated with it.
```yaml
accounts:
  default:
    emails:
      - this.is.me@example.com
    # This example is set to the staging environment for testing.
    # The default value is the Let's Encrypt production endpoint.
    server: https://acme-staging-v02.api.letsencrypt.org/directory
    key_size: 4096
```
The account to use can be specified on a per-certificate basis.

### ACME account reference

````{toggle}
```{eval-rst}
.. autopydantic_model:: certwrangler.models.Account
   :no-index:
   :model-signature-prefix: account
   :model-show-validator-summary: False
   :model-show-field-summary: False
   :no-undoc-members:
   :inherited-members: BaseModel
   :exclude-members: name, state
   :model-erdantic-figure: False
   :no-show-inheritance:
   :no-private-members:
   :field-list-validators: False
```
````

## ACME validation (solvers)
Certwrangler will always use ACME DNS-01 validation. Because it runs as a standalone daemon completely separate from the services it's generating certs for, it cannot use HTTP-01 validation.

Certwrangler will use a configured solver to complete the ACME challenge. Each solver is configured with a list of zones that it should be responsible for. Again from the example config:

```yaml
solvers:
  default:
    driver: lexicon
    zones:
      # List out the zones that this solver should be used for.
      # This should only be zones, as in an SOA record exists for this FQDN.
      - example.com
    provider_name: linode4
    provider_options:
      # This will pull the token from the LINODE_TOKEN environment variable
      auth_token: $LINODE_TOKEN
```

In this case, because the cert that was defined above is in the `example.com` zone, this `default` solver would be used. This solver is using the `linode4` provider, which means it will use the Linode API to create/update the required ACME challenge DNS records.

### EdgeDNS Solver Reference

````{toggle}
```{eval-rst}
.. autopydantic_model:: certwrangler.solvers.edgedns.EdgeDNSSolver
   :no-index:
   :model-signature-prefix: solver
   :model-show-validator-summary: False
   :model-show-field-summary: False
   :no-undoc-members:
   :inherited-members: BaseModel
   :exclude-members: name, create, delete, initialize, model_post_init
   :model-erdantic-figure: False
   :no-show-inheritance:
   :no-private-members:
   :field-list-validators: False
```
````

### Lexicon Solver Reference

Certwrangler has a [Lexicon](https://dns-lexicon.readthedocs.io/en/latest/introduction.html)-based solver backend to provide support for many DNS providers (including Linode's DNS Manager). A list of available providers along with their provider-specific options can be found in [the Lexicon configuration docs](https://dns-lexicon.readthedocs.io/en/latest/configuration_reference.html).

````{toggle}
```{eval-rst}
.. autopydantic_model:: certwrangler.solvers.lexicon.LexiconSolver
   :no-index:
   :model-signature-prefix: solver
   :model-show-validator-summary: False
   :model-show-field-summary: False
   :no-undoc-members:
   :inherited-members: BaseModel
   :exclude-members: name, create, delete, initialize, model_post_init
   :model-erdantic-figure: False
   :no-show-inheritance:
   :no-private-members:
   :field-list-validators: False
```
````

## Certificate storage
After generating a cert, Certwrangler will store the cert and its associated private key in one or more configurable `store`s.

```yaml
stores:
  # Example vault store.
  default:
    driver: vault
    server: http://localhost:8200
    mount_point: secret
    path: certwrangler
    auth:
      method: approle
      role_id: example_role_id
      secret_id: $CERTWRANGLER_SECRET_ID

  # An example local store for backing up our cert and keys
  backup:
    driver: local
    path: ./test_store
```

The Vault store is the most commonly used, as storing certs and keys there lets us allow other applications to read their certs/keys out of Vault.

If Certwrangler fails to write to any of its stores, it will retry the write on the next reconciliation loop until it is successful.

The stores used are configurable for any given cert in [the certs section of the config](#defining-certs). A cert may be published to multiple stores, and it is possible to define multiple instances of the same type of store with different names (for example, in case you wanted to publish the same cert to two different locations in Vault).

### Vault store reference

````{toggle}
```{eval-rst}
.. autopydantic_model:: certwrangler.stores.vault.VaultStore
   :no-index:
   :model-signature-prefix: store
   :model-show-validator-summary: False
   :model-show-field-summary: False
   :no-undoc-members:
   :inherited-members: BaseModel
   :exclude-members: name, client, initialize, publish
   :model-erdantic-figure: False
   :no-show-inheritance:
   :no-private-members:
   :field-list-validators: False
```
````

#### Authentication

Certwrangler must be configured with Vault credentials to use the Vault store. It currently supports AppRole, token, and Kubernetes authentication; see the sections below for configuration details for each.

##### AppRole

````{toggle}
```{eval-rst}
.. autopydantic_model:: certwrangler.stores.vault.AppRoleAuth
   :no-index:
   :model-signature-prefix: store
   :model-show-validator-summary: False
   :model-show-field-summary: False
   :no-undoc-members:
   :inherited-members: BaseModel
   :exclude-members: name, client, login
   :model-erdantic-figure: False
   :no-show-inheritance:
   :no-private-members:
   :field-list-validators: False
```
````

##### Token

````{toggle}
```{eval-rst}
.. autopydantic_model:: certwrangler.stores.vault.TokenAuth
   :no-index:
   :model-signature-prefix: store
   :model-show-validator-summary: False
   :model-show-field-summary: False
   :no-undoc-members:
   :inherited-members: BaseModel
   :exclude-members: name, client, login
   :model-erdantic-figure: False
   :no-show-inheritance:
   :no-private-members:
   :field-list-validators: False
```
````

##### Kubernetes

````{toggle}
```{eval-rst}
.. autopydantic_model:: certwrangler.stores.vault.KubernetesAuth
   :no-index:
   :model-signature-prefix: store
   :model-show-validator-summary: False
   :model-show-field-summary: False
   :no-undoc-members:
   :inherited-members: BaseModel
   :exclude-members: name, client, login
   :model-erdantic-figure: False
   :no-show-inheritance:
   :no-private-members:
   :field-list-validators: False
```
````

### Local store reference

````{toggle}
```{eval-rst}
.. autopydantic_model:: certwrangler.stores.local.LocalStore
   :no-index:
   :model-signature-prefix: store
   :model-show-validator-summary: False
   :model-show-field-summary: False
   :no-undoc-members:
   :inherited-members: BaseModel
   :exclude-members: name, initialize, publish
   :model-erdantic-figure: False
   :no-show-inheritance:
   :no-private-members:
   :field-list-validators: False
```
````

## Example Config

To see how this all fits together, `certwrangler.example.yaml` contains a complete example:

```{literalinclude} ../../../certwrangler.example.yaml
```
