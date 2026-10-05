"""Reports state relationships and the unverified anchor trust boundary."""
import json
from .contract import InputError, MAX_OUTPUT

LIMITATION = (
    "Anchors are separately supplied operator assertions, not authenticated by this tool. "
    "Valid relationships do not establish freshness, event truth/completeness, "
    "availability or absence of split views. Hash collision/second-preimage assumptions apply."
)


def visible(text: str) -> str:
    return text.encode("unicode_escape").decode("ascii")


def render(value: dict, format_name: str, *, generated_proof: bool = False) -> str:
    encoded = json.dumps(value, indent=2, ensure_ascii=True) + "\n"
    if format_name == "text":
        prefix = "Generated synthetic/unauthenticated data; no anchors updated.\n" if generated_proof else "MERKLE PROOF LAB\n"
        encoded = prefix + encoded
    if len(encoded.encode("utf-8")) > MAX_OUTPUT:
        raise InputError("output exceeds 256 KiB")
    return encoded
