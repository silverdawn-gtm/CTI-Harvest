import gzip
from pathlib import Path

from crawler.core.models import RawDocument

_EXTENSIONS = {
    "text/html": "html",
    "application/xhtml+xml": "html",
    "application/json": "json",
    "text/json": "json",
    "application/xml": "xml",
    "text/xml": "xml",
    "application/rss+xml": "xml",
    "application/pdf": "pdf",
    "text/csv": "csv",
    "text/plain": "txt",
}


class RawArchive:
    """Gzipped on-disk store of fetched bytes, so parsing can be redone without re-crawling."""

    def __init__(self, root: Path) -> None:
        self._root = Path(root)

    def store(self, raw: RawDocument) -> str:
        relative = self._relative_path(raw)
        target = self._root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(gzip.compress(raw.content))
        return relative

    def load(self, relative_path: str) -> bytes:
        return gzip.decompress((self._root / relative_path).read_bytes())

    def _relative_path(self, raw: RawDocument) -> str:
        mime = raw.content_type.split(";")[0].strip().lower()
        ext = _EXTENSIONS.get(mime, "bin")
        stamp = raw.fetched_at
        # Forward slashes, not os.sep, so archive paths stay portable if the data moves to Linux.
        return f"{raw.item.source}/{stamp:%Y}/{stamp:%m}/{raw.item.url_hash}.{ext}.gz"
