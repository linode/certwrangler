# Testing

## Tox

We use tox as our test runner. We have three different test suites configured in tox:

`test`
: Unit tests using pytest.

`style`
: Style checks using pre-commit and friends (black, flake8, etc).

`type`
: Type checks using mypy.

 You can run the full suite of tests like so:

```shell
uv run tox
```

Or target specific test suites with `-e`:

```shell
uv run tox -e style
```

## Style checks

All style checks are implemented through [pre-commit](https://pre-commit.com/). It is recommended to setup pre-commit locally so that style checks run automatically when making a commit, this can be done like so:

```shell
uv run pre-commit install
```

## Type checks

Type checks are implemented with mypy and the pydantic mypy plugin.

## Unit tests

Unit tests are located in `tests/`. Overall the directory structure mimics what's in `src/certwrangler/`:

```shell
tests/
├── files/
│   └── certwrangler_config_dummy.yaml
├── solvers/
│   ├── __init__.py
│   ├── test_dummy.py
│   └── test_edgedns.py
├── state_managers/
│   ├── __init__.py
│   ├── test_dummy.py
│   └── test_local.py
├── stores/
│   ├── __init__.py
│   ├── test_dummy.py
│   ├── test_local.py
│   └── test_vault.py
├── conftest.py
├── __init__.py
├── test_controllers.py
├── test_daemon.py
├── test_dns.py
├── test_http.py
├── test_metrics.py
├── test_models.py
├── test_reconcilers.py
└── test_shell.py
```

When running through tox with `tox -e test` you'll also get a coverage report at the end of the test run. This is useful when writing tests to get the line numbers of things you might've missed creating tests for. While 100% coverage is nice, it is sometimes not practical and not a hard requirement.

### Common fixtures

Fixtures are stored in `tests/conftest.py`. A few of the more common ones are documented here.

#### click_ctx

Creates a fake click context for tests. This is needed for any tests against code that uses the click context, directly or indirectly. If you see this message when running your test:

```
RuntimeError: There is no active click context.
```

then you just need to include this fixture to make it magically work.

By default this will set the config path on the CertwranglerState object to the dummy_config_path fixture. This can be changed by doing the following within your test:

```
click_ctx.obj.config_path = new_config_path
```

where new_config_path is a pathlib.Path object. Recommended to follow the pattern of dummy_config_path and setup a fixture to return that object.

#### config

This returns an uninitialized [Config](#certwrangler.models.Config) object loaded from the dummy config in `tests/files/certwrangler_config_dummy.yaml`. There are a few additional convenance fixtures that pluck objects off of this generated config tree, like `account`, `cert`, `subject`, `solver`, `state_manager`, and `store`.
