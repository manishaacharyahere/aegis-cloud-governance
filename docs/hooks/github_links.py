"""MkDocs hook: links from the docs to repository files outside docs/
(code, benchmarks, datasets, ADRs) are rewritten to GitHub URLs, so the same
Markdown works on GitHub and on the published site."""

from __future__ import annotations

import os
import posixpath
import re

REPO = "https://github.com/manishaacharyahere/aegis-cloud-governance"
LINK = re.compile(r"\]\(([^)\s#]+)(#[^)\s]*)?\)")
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def on_page_markdown(markdown: str, page, **_) -> str:
    base = posixpath.dirname(page.file.src_uri)

    def fix(m: re.Match) -> str:
        target, anchor = m.group(1), m.group(2) or ""
        if re.match(r"^[a-z]+:", target) or target.startswith("/"):
            return m.group(0)
        repo_path = posixpath.normpath(posixpath.join("docs", base, target))
        if repo_path.startswith("docs/") or repo_path == "docs":
            return m.group(0)  # stays inside the site
        kind = "tree" if os.path.isdir(os.path.join(ROOT, repo_path)) else "blob"
        return f"]({REPO}/{kind}/main/{repo_path}{anchor})"

    return LINK.sub(fix, markdown)
