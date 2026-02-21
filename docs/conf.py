# Sphinx configuration for secure-torch docs
# ReadTheDocs compatible

import os
import sys

sys.path.insert(0, os.path.abspath("../src"))

project = "secure-torch"
copyright = "2026, Avanish Kumar"
author = "Avanish Kumar"
release = "0.1.0"

extensions = [
    "sphinx.ext.autodoc",
    "sphinx.ext.napoleon",
    "sphinx.ext.viewcode",
    "sphinx.ext.intersphinx",
    "sphinx_autodoc_typehints",
    "myst_parser",
]

templates_path = ["_templates"]
exclude_patterns = ["_build", "Thumbs.db", ".DS_Store"]

# Furo theme — modern, dark-mode, ReadTheDocs compatible
html_theme = "furo"
html_static_path = ["_static"]
html_title = "secure-torch"
html_theme_options = {
    "sidebar_hide_name": False,
    "navigation_with_keys": True,
    "top_of_page_button": "edit",
    "source_repository": "https://github.com/Avanishk05/secure-torch/",
    "source_branch": "main",
    "source_directory": "docs/",
}

# MyST (Markdown) support
myst_enable_extensions = [
    "colon_fence",
    "deflist",
    "tasklist",
]

# Autodoc settings
autodoc_default_options = {
    "members": True,
    "undoc-members": False,
    "show-inheritance": True,
    "member-order": "bysource",
}
autodoc_typehints = "description"

# Intersphinx — link to Python and PyTorch docs
intersphinx_mapping = {
    "python": ("https://docs.python.org/3", None),
    "torch": ("https://pytorch.org/docs/stable", None),
}

# Napoleon — Google/NumPy docstring support
napoleon_google_docstring = True
napoleon_numpy_docstring = False
napoleon_include_init_with_doc = True
