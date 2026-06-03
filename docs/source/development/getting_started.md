# Development Getting Started

## Installation

This project is managed by `uv`, which can be installed through [these instructions](https://docs.astral.sh/uv/getting-started/installation/).

The dev dependencies can be installed like so:

```
uv sync
```

This will create a virtual environment under `.venv` that you can optionally activate like so:

```
. .venv/bin/activate
```

Alternatively, you can prefix your commands with `uv run`, example: `uv run certwrangler --help`.

Then copy `certwrangler.example.yaml` to `~/.config/certwrangler.yaml` and fill it out with your info.

The `certwrangler` CLI utility will be installed in the virtual environment, more information about the CLI can be found here: {doc}`/usage/cli`

## Pre-commit

This project uses [pre-commit](https://pre-commit.com/) to enforce style and typing standards on the code. To setup `pre-commit` to run before each commit, run the following:

```
uv run pre-commit install --install-hooks
```

## Bumping Dependencies

Github actions, pre-commit, and uv dependencies can be bumped by running the following:

```
uv run tox -m update
```

## Dev shell

If certwrangler is installed with the development dependency groups (the default when using `uv sync`) then you'll also have access to the `dev-shell` sub-command. This provides you with an IPython environment pre-loaded with the various certwrangler modules loaded, which is helpful for playing around with the various types to test out changes:

```
$ uv run certwrangler dev-shell
2026-06-02 15:23:16,490: INFO [certwrangler.utils, load_config(), line 128, thread MainThread] - Loading config from /home/<username>/.config/certwrangler.yaml
2026-06-02 15:23:16,587: INFO [certwrangler.utils, load_config(), line 151, thread MainThread] - Config loaded from '/home/<username>/.config/certwrangler.yaml'.
Welcome to certwrangler's development shell!
  Python 3.13.13 (main, May 10 2026, 19:26:54) [Clang 22.1.3 ] on linux.
Loaded certwrangler variables:
  ctx
  config
  controllers
  dns
  models
  reconcilers
Config loaded but not initialized, initialize with:
  config.initialize()
Tip: You can use Ctrl-O to force a new line in terminal IPython

In [1]:
```

## Project layout

<!--- You can generate the basis of file layout via the following command:
    tree -a --gitignore -F -L 1 -I '.git' --dirsfirst .
--->

```console
./
├── .github/                   <- GitHub Actions
├── .vscode/
├── docs/                      <- Docs
├── script/                    <- Scripts used in packaging
├── src/                       <- The certwrangler python module
├── tests/                     <- Tests
├── .gitignore
├── .pre-commit-config.yaml
├── certwrangler.example.yaml  <- Example config file
├── LICENSE
├── pyproject.toml
├── README.md
└── uv.lock
```

### Code layout

<!--- You can generate the basis of file layout via the following command:
    tree -a --gitignore -F -I '.git' --dirsfirst src
--->

```console
src/
├── certwrangler
│   ├── solvers                <- Solver plugins
│   │   ├── dummy.py
│   │   ├── edgedns.py
│   │   ├── __init__.py
│   │   └── lexicon.py
│   ├── state_managers         <- State manager plugins
│   │   ├── dummy.py
│   │   ├── __init__.py
│   │   └── local.py
│   ├── stores                 <- Store plugins
│   │   ├── dummy.py
│   │   ├── __init__.py
│   │   ├── local.py
│   │   └── vault.py
│   ├── controllers.py         <- Account and cert ACME controller code
│   ├── daemon.py              <- Daemon/threading manager
│   ├── dns.py                 <- Misc DNS functions
│   ├── exceptions.py          <- Exception definitions
│   ├── http.py                <- HTTP server for metrics
│   ├── __init__.py
│   ├── metrics.py             <- Metrics registry
│   ├── models.py              <- Core models
│   ├── reconcilers.py         <- Reconciler functions
│   ├── shell.py               <- CLI
│   ├── types.py               <- Type annotations for pydantic
│   └── utils.py               <- App state and misc constants
```
