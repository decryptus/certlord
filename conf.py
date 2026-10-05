from pathlib import Path
import yaml
metadata = yaml.safe_load((Path(__file__).resolve().parent / "setup.yml").read_text())
project = "CertLord"
version = release = metadata["release"]
author = metadata["author"]
copyright = metadata["copyright"]
extensions = ["myst_parser"]
source_suffix = {".rst": "restructuredtext", ".md": "markdown"}
master_doc = "index"
language = "en"
exclude_patterns = ["docs/_build", "docs/index.rst", "**/AGENTS.md"]
html_theme = "alabaster"
myst_heading_anchors = 4
include_patterns = ["index.rst", "docs/**", "MIGRATION.md"]
extensions.append("sphinxcontrib.mermaid")
myst_fence_as_directive = ["mermaid"]
