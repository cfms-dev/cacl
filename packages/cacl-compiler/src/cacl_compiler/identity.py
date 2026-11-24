import re
from uuid import UUID

_RFC9562_UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\Z"
)


def parse_canonical_uuid(raw: str) -> UUID | None:
    """Parse a strict 36-char hyphenated RFC 9562 UUID (version/variant agnostic)."""
    if not _RFC9562_UUID_RE.match(raw):
        return None
    return UUID(raw)
