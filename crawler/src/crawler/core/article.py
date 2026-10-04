"""Article body extraction, shared by every adapter that fetches a rendered HTML page."""

import trafilatura

# Below this, treat extraction as failed. Real security articles run to thousands of
# characters; a few hundred means the selectors missed or the page is a stub.
MIN_BODY_CHARS = 200


def extract_body(html: str) -> str:
    return trafilatura.extract(html, include_comments=False, include_tables=False) or ""
