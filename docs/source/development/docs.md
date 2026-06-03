# Documentation

Certwrangler uses the [Sphinx](https://www.sphinx-doc.org) documentation framework. The documentation source files are under the `docs` directory.

Documentation can be built through tox like so:

```shell
uv run tox -e docs
```

The docs will be rendered to `docs/build/html`.

A development HTTP server with the docs can be launched on localhost with the following:

```shell
uv run tox -e docs-auto
```

This uses `sphinx-autobuild`, which will automatically rebuild the docs any time one of the source files for the docs is updated. This is useful for generating a live preview of the docs while making edits.
