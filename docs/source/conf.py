# Configuration file for the Sphinx documentation builder.
#
# For the full list of built-in configuration values, see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html

# -- Project information -----------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#project-information

project = 'Caelestis-Eu Simulations Service'
copyright = '2023, Caelestis'
author = 'Barcelona Supercomputing Center (BSC)'

autodoc_mock_imports = ['pycompss']


templates_path = ['_templates']


source_suffix = '.rst'

# The encoding of source files.
# source_encoding = 'utf-8-sig'

# The master toctree document.
master_doc = 'index'

pygments_style = 'sphinx'

# A list of ignored prefixes for module index sorting.
# modindex_common_prefix = []

# If true, keep warnings as "system message" paragraphs in the built documents.
# keep_warnings = False

# If true, `todo` and `todoList` produce output, else they produce nothing.
todo_include_todos = False

# -- Options for HTML output ----------------------------------------------

# The theme to use for HTML and HTML Help pages.  See the documentation for
# a list of builtin themes.
html_theme = 'scipy'

# Theme options are theme-specific and customize the look and feel of a theme
# further.  For a list of options available for each theme, see the
# documentation.
html_theme_options = {
    "edit_link": False,
    "sidebar": "right",
    "scipy_org_logo": False,
    "rootlinks": []
}

# Add any paths that contain custom themes here, relative to this directory.
html_theme_path = [os.path.join(os.pardir, 'scipy-sphinx-theme', '_theme')]




