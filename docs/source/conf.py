# Configuration file for the Sphinx documentation builder.
#
# For the full list of built-in configuration values, see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html

# -- Project information -----------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#project-information

project = 'Caelestis-Eu Simulations Service'
copyright = '2023, Caelestis'
author = 'Barcelona Supercomputing Center (BSC)'

# -- General configuration ---------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#general-configuration

extensions = []

templates_path = ['_templates']
exclude_patterns = []



# -- Options for HTML output -------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#options-for-html-output

html_theme = 'alabaster'
html_static_path = ['_static']





import inspect
import os
import subprocess as subp
import sys


sys.path.insert(0, os.path.abspath('../../'))


extensions = [
    'sphinx.ext.autodoc',
    'sphinx.ext.intersphinx',
    'sphinx.ext.linkcode',
    'sphinx.ext.napoleon',
    'sphinx.ext.autosummary',
    'm2r',
]

napoleon_google_docstring = False
napoleon_use_param = False
napoleon_use_ivar = True

autodoc_mock_imports = ['pycompss']


templates_path = ['_templates']


source_suffix = '.rst'

# The encoding of source files.
# source_encoding = 'utf-8-sig'

# The master toctree document.
master_doc = 'index'




