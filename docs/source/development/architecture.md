# Architecture

## Models

Certwrangler makes extensive use of [Pydantic](https://docs.pydantic.dev/latest/) for the core data models of the application. Models are defined in [src/certwrangler/models.py](#certwrangler.models) and are used to parse and validate the config file, serialize the state of the application to disk, and provide a driver plugin architecture for different remote resources.

Broadly, there are three different type of models with some overlap between the types:

### Config models

```{list-table}
:header-rows: 1

*   - Model
    - Config Key
    - Description
*   - [Account](#certwrangler.models.Account)
    - accounts
    - Defines an ACME account.
*   - [Cert](#certwrangler.models.Cert)
    - certs
    - Defines an ACME cert that should be managed.
*   - [Subject](#certwrangler.models.Subject)
    - subjects
    - Defines a cert subject to be used when creating CSRs.
*   - [DaemonConfig](#certwrangler.models.DaemonConfig)
    - daemon
    - Defines configuration for the Certwrangler daemon.
```

Config models are models that directly correspond to the Certwrangler config schema. All config models are connected to the root [](#certwrangler.models.Config) class, which is the entry point for parsing the Certwrangler config.

{{ config_models_relationship_graph }}

With the exception of [driver models](#driver-models) (which are also represented in the config tree), config models are intentionally left lightweight and should not have methods outside of simple checks (like a check to determine [if a cert should be renewed](#certwrangler.models.Cert.needs_renewal)) or validator functions (like [validating non-duplicate entries](#certwrangler.models.Account.__validate_unique_emails)). Business logic should be handled elsewhere, like in the [controller classes](#certwrangler.controllers).

### Driver models

```{list-table}
:header-rows: 1

*   - Model
    - Config Key
    - Implementations
    - Description
*   - [Solver](#certwrangler.models.Solver)
    - solvers
    - - [DummySolver](#certwrangler.solvers.dummy.DummySolver)
      - [EdgeDNSSolver](#certwrangler.solvers.edgedns.EdgeDNSSolver)
      - [LexiconSolver](#certwrangler.solvers.lexicon.LexiconSolver)
    - Responsible for implementing the logic needed to solve ACME dns-01 challenges with different DNS providers.
*   - [StateManager](#certwrangler.models.StateManager)
    - state_manager
    - - [DummyStateManager](#certwrangler.state_managers.dummy.DummyStateManager)
      - [LocalStateManager](#certwrangler.state_managers.local.LocalStateManager)
    - Responsible for implementing the logic needed to save and load [state models](#state-models).
*   - [Store](#certwrangler.models.Store)
    - stores
    - - [DummyStore](#certwrangler.stores.dummy.DummyStore)
      - [LocalStore](#certwrangler.stores.local.LocalStore)
      - [VaultStore](#certwrangler.stores.vault.VaultStore)
    - Responsible for implementing the logic needed to publish a certificate and its key out to consuming services.
```

Certwrangler uses a plugin architecture for solvers, state managers, and stores. These models are used to parse the config as well as provide the implementation logic for the resources they describe. Plugins are exposed through python's entrypoint system (more information is available [here](https://packaging.python.org/en/latest/guides/creating-and-discovering-plugins/)) and are dynamically loaded when the config is parsed based on the `driver` key of the object in question.

The entrypoint groups and submodule locations for each of these classes are as follows:

```{list-table}
:header-rows: 1

*   - Base Class
    - Group
    - Directory
*   - [Solver](#certwrangler.models.Solver)
    - `certwrangler.solver`
    - `src/certwrangler/solvers/`
*   - [StateManager](#certwrangler.models.StateManager)
    - `certwrangler.state_manager`
    - `src/certwrangler/state_managers/`
*   - [Store](#certwrangler.models.Store)
    - `certwrangler.store`
    - `src/certwrangler/stores/`
```

The [](#certwrangler.models.Config) pydantic model has 3 field validators for each of the plugin base classes: [__load_solver_plugins()](#certwrangler.models.Config.__load_solver_plugins), [__load_state_manager_plugin()](#certwrangler.models.Config.__load_state_manager_plugin), and [__load_store_plugins()](#certwrangler.models.Config.__load_store_plugins). These validators run before the raw config for these objects are cast to their corresponding pydantic model types. These validators evaluate the `driver` key on each of the objects they're responsible for and tries to load a plugin corresponding to that name from the entrypoint group, and if successful, it casts the config to model of the plugin that it loaded.

New plugins classes should inherit from their respective base classes and should be exposed through their respective entrypoint group in `pyproject.toml`. The name of the entry point should match the `driver` literal of the plugin. An example of what this looks like in `pyproject.toml` is as follows:

```toml
[project.entry-points."certwrangler.solver"]
dummy = "certwrangler.solvers.dummy:DummySolver"
edgedns = "certwrangler.solvers.edgedns:EdgeDNSSolver"
lexicon = "certwrangler.solvers.lexicon:LexiconSolver"
[project.entry-points."certwrangler.state_manager"]
dummy = "certwrangler.state_managers.dummy:DummyStateManager"
local = "certwrangler.state_managers.local:LocalStateManager"
[project.entry-points."certwrangler.store"]
dummy = "certwrangler.stores.dummy:DummyStore"
local = "certwrangler.stores.local:LocalStore"
vault = "certwrangler.stores.vault:VaultStore"
```

When developing new driver plugins please follow the convention of adding two new fixtures to `tests/conftest.py` for the plugin, one that returns a dict representing a fake config for the new plugin, and a second that returns an initialized object from that config. The naming for the config fixture should follow this convention:

```
(solver|state_manager|store)_(driver_name)_config
```

and the naming for the initialized object fixture should follow this convention:

```
(solver|state_manager|store)_(driver_name)
```

So for example, if you were creating a new state manager plugin named vault, the fixtures would be:

```
state_manager_vault_config
```

and:

```
state_manager_vault
```

### State models

```{list-table}
:header-rows: 1

*   - Model
    - Description
*   - [AccountState](#certwrangler.models.AccountState)
    - Represents the current state of an [Account](#certwrangler.models.Account).
*   - [CertState](#certwrangler.models.CertState)
    - Represents the current state of an [Cert](#certwrangler.models.Cert).
```

The [](#certwrangler.models.Account) and [](#certwrangler.models.Cert) models also have corresponding state models, [](#certwrangler.models.AccountState) and [](#certwrangler.models.CertState). The state models are responsible for representing the actual state of the object in question, whereas the corresponding config models are responsible for representing the desired state of the object. Stateful model data is persisted to storage through a [state manager](#certwrangler.models.StateManager). During [config initialization](#certwrangler.models.Config.initialize) the configured state manager is used to load the state from disk.

## Reconcilers

Similar to how operators work in Kubernetes, Certwrangler is built around a concept of reconciliation. As mentioned in the previous section, both [](#certwrangler.models.Account) and [](#certwrangler.models.Cert) config models have corresponding [](#certwrangler.models.AccountState) and [](#certwrangler.models.CertState) state models. Similarly, there's a corresponding [account reconciler](#certwrangler.reconcilers.reconcile_account) and [cert reconciler](#certwrangler.reconcilers.reconcile_cert).

The job of the reconcilers is to compare the config of an object to its state and trigger the necessary actions to make the state match the desired state defined in the config. The details of how to bring the state in-line with the config is handled by the [controllers](#controllers). In short, the reconcilers are responsible for identifying what work needs to be done to bring an object's state into conformance with its config while the controllers are responsible for doing the work prescribed by the reconciler.

## Controllers

The controllers are responsible for implementing all the logic needed to be an ACME client and as such it is highly recommended to be familiar with [RFC 8555](https://datatracker.ietf.org/doc/html/rfc8555) before working with the controller code.

There are two controllers, [](#certwrangler.controllers.AccountController) and [](#certwrangler.controllers.CertController). Each instance of the controllers operate on a single [](#certwrangler.models.Account) or [](#certwrangler.models.Cert) object. The [](#certwrangler.controllers.AccountController) is responsible for all tasks around creating and managing the ACME account for the account object it manages. The [](#certwrangler.controllers.CertController) is responsible for all tasks around creating a processing ACME orders for the cert object it manages.

## Daemon

When running in [daemon mode](/usage/cli.md#certwrangler-daemon) Certwrangler will spin up separate threads for the reconciler (which it will run in an endless loop with a [configurable sleep interval](#certwrangler.models.ReconcilerConfig.interval) between runs) and the HTTP web server that serves metrics. The lifecycle of these threads is managed by the [Daemon class](#certwrangler.daemon.Daemon). This class is responsible for loading and initializing the config, starting and stopping the threads, and handling graceful restarts on SIGHUP and graceful shutdown on SIGINT or SIGTERM. More information can be found at [](#certwrangler.daemon).

## CLI and CertwranglerState

Certwrangler uses [click](https://click.palletsprojects.com/) for the [certwrangler cli](/usage/cli.md). One of the features of click is the ability to define an object on it's [context](inv:click#click.core.Context), which is globally available throughout the code. We make use of this to store some global data in the [](#certwrangler.utils.CertwranglerState) object and making it available whenever the click context is available. This object is responsible for setting up logging, loading the config, and holding references to other global level objects like the DNS [resolver](inv:dnspython#dns.resolver.Resolver) and [daemon](#certwrangler.daemon.Daemon).

For example, if you need the config you can access it like so:

```python
import click

config = click.get_current_context().obj.config
```

Or if you need the resolver:

```python
import click

resolver = click.get_current_context().obj.resolver
```
