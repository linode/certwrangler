import os
import sys
from datetime import datetime
from importlib.metadata import version as get_version
from textwrap import indent

import erdantic

# Dumb work-around for whatever is causing this:
# https://github.com/pydantic/pydantic/discussions/7763
import certwrangler.solvers.dummy  # noqa: F401
import certwrangler.solvers.edgedns  # noqa: F401
import certwrangler.solvers.lexicon  # noqa: F401
import certwrangler.state_managers.dummy  # noqa: F401
import certwrangler.state_managers.local  # noqa: F401
import certwrangler.stores.dummy  # noqa: F401
import certwrangler.stores.local  # noqa: F401
import certwrangler.stores.vault  # noqa: F401
from certwrangler.models import Config

sys.path.insert(0, os.path.abspath("_ext"))
from linkcode_res import linkcode_resolve  # noqa: E402, F401


def _make_erd(model):
    """
    Makes an a nice relationship graph for the models.
    """
    graphviz_dot = erdantic.to_dot(model, graph_attr={"label": ""}).replace("\t", "   ")
    return f"""
```{{eval-rst}}
.. graphviz::

{indent(graphviz_dot, "   ")}
```
"""


# Configuration file for the Sphinx documentation builder.
#
# For the full list of built-in configuration values, see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html

# -- Project information -----------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#project-information

project = "Certwrangler"
copyright = f"{datetime.now().year}, Akamai"
author = "Akamai Platform Services SREs"
release = get_version("certwrangler")

# -- General configuration ---------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#general-configuration

extensions = [
    "sphinx.ext.autodoc",
    "sphinx.ext.autosectionlabel",
    "sphinx.ext.autosummary",
    "sphinx.ext.githubpages",
    "sphinx.ext.graphviz",
    "sphinx.ext.intersphinx",
    "sphinx.ext.todo",
    "sphinx_copybutton",
    "sphinx_click",
    "sphinx_togglebutton",
    "sphinxcontrib.apidoc",
    "sphinxcontrib.autodoc_pydantic",
    "sphinx.ext.linkcode",
    "myst_parser",
]
myst_heading_anchors = 3
myst_enable_extensions = [
    "deflist",
    "substitution",
]
myst_substitutions = {
    "config_models_relationship_graph": _make_erd(Config),
}

intersphinx_mapping = {
    "acme": ("https://acme-python.readthedocs.io/en/stable", None),
    "click": ("https://click.palletsprojects.com/en/8.1.x", None),
    "cryptography": ("https://cryptography.io/en/stable", None),
    "dnspython": ("https://dnspython.readthedocs.io/en/stable", None),
    "josepy": ("https://josepy.readthedocs.io/en/stable", None),
    "pydantic": ("https://docs.pydantic.dev/latest", None),
    "python": ("https://docs.python.org/3", None),
    "requests": ("https://requests.readthedocs.io/en/stable/", None),
}

autosectionlabel_prefix_document = True

apidoc_output_dir = "development/api"
apidoc_module_dir = "../../src/certwrangler"
apidoc_toc_file = False
apidoc_separate_modules = True
apidoc_module_first = True
apidoc_extra_args = ["--remove-old"]

autodoc_default_options = {
    "members": True,
    "member-order": "bysource",
    "show-inheritance": True,
    "private-members": True,
    "undoc-members": True,
    "exclude-members": "_abc_impl,model_post_init",
    "no-value": True,
}

autodoc_pydantic_model_show_config_summary = False
autodoc_pydantic_model_erdantic_figure = True
autodoc_pydantic_model_erdantic_figure_collapsed = True

autosummary_generate = True

templates_path = ["_templates"]
exclude_patterns = []
todo_include_todos = False

# -- Options for HTML output -------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#options-for-html-output

html_theme = "sphinx_book_theme"

# Set link name generated in the top bar.
html_title = "Certwrangler"

# Theme options
html_theme_options = {
    "repository_url": "https://github.com/linode/certwrangler",
    "repository_provider": "github",
    "use_repository_button": True,
    "use_fullscreen_button": False,
    "show_navbar_depth": 1,
    "show_toc_level": 4,
}

graphviz_output_format = "svg"
