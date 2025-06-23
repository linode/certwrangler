# Development Getting Started

## Installation

Create a virtual environment, clone the repo, then install with:

```
pip install -e .[dev]
```

Then copy `certwrangler.example.yaml` to `~/.config/certwrangler.yaml` and fill it out with your info.

Pip will also install the `certwrangler` CLI utility, more information about the CLI can be found here: {doc}`/usage/cli`

## Dev shell

If you installed with the `[dev]` extras then you'll also have access to the `dev-shell` sub-command. This provides you with an IPython environment pre-loaded with the various certwrangler modules loaded, which is helpful for playing around with the various types to test out changes:

```
$ certwrangler dev-shell
Welcome to certwrangler's development shell!
  Python 3.8.10 (default, Nov 22 2023, 10:22:35)
[GCC 9.4.0] on linux.
Loaded certwrangler variables:
  ctx
  config
  controllers
  dns
  models
  reconcilers
Config loaded but not initialized, initialize with:
  config.initialize()

In [1]:
```

## Project layout

<!--- You can generate the basis of file layout via the following command:
    tree -a --gitignore -F -L 1 -I '.git' --dirsfirst .
--->

```console
./
├── debian/                    <- Debian packaging
├── docs/                      <- Docs
├── .github/                   <- GitHub Actions
├── script/                    <- Scripts used in packaging
├── src/                       <- The certwrangler python module
├── tests/                     <- Tests
├── .vscode/
├── certwrangler.example.yaml  <- Example config file
├── Dockerfile
├── .flake8
├── .gitchangelog.debian.rc
├── .gitchangelog.debian.tpl
├── .gitignore
├── Jenkinsfile
├── .pre-commit-config.yaml
├── pyproject.toml
├── README.md
├── setup.py
└── tox.ini
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
