"""Configuration file for the Sphinx documentation builder."""

# -- Project information

from tmodbus import __version__ as tmodbus_version  # type: ignore[attr-defined]

project = "tModbus"
copyright = "2025, wlcrs"  # noqa: A001
author = "wlcrs"

release = tmodbus_version
version = tmodbus_version

# -- General configuration

extensions = [
    "sphinx.ext.doctest",
    "sphinx.ext.autodoc",
    "sphinx.ext.autosummary",
    "sphinx_rtd_theme",
    "sphinx.ext.intersphinx",
    "sphinx.ext.napoleon",
    "sphinxcontrib.mermaid",
]

autoclass_content = "both"

intersphinx_mapping = {
    "python": ("https://docs.python.org/3/", None),
}
intersphinx_disabled_domains = ["std"]

pygments_style = "sphinx"

# -- Options for HTML output

html_theme = "sphinx_rtd_theme"
