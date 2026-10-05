"""Strict JSON envelopes; all identifiers and byte encodings are inert data."""
from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
import stat

ALGORITHM = "sha256-rfc9162"
MAX_TREE = 4096
MAX_ENTRY = 2048
MAX_TOTAL = 512 * 1024
MAX_PATH = 13
MAX_OUTPUT = 256 * 1024
COMMON = {"schema_version", "algorithm", "log_id"}
IDENTIFIER = re.compile(r"[A-Za-z0-9_.:-]{1,64}\Z")
HEX = re.compile(r"[0-9a-f]*\Z")


class InputError(ValueError):
    """Input is outside the versioned bounded contract."""


@dataclass(frozen=True)
class Entries:
    log_id: str
    values: tuple[bytes, ...]


@dataclass(frozen=True)
class Anchors:
    log_id: str
    heads: tuple[tuple[int, bytes], ...]

    def root(self, size: int) -> bytes:
        for head_size, digest in self.heads:
            if head_size == size:
                return digest
        raise InputError("required tree size has no supplied anchor")


@dataclass(frozen=True)
class Inclusion:
    log_id: str
    tree_size: int
    leaf_index: int
    leaf: bytes
    path: tuple[bytes, ...]


@dataclass(frozen=True)
class Consistency:
    log_id: str
    old_size: int
    new_size: int
    path: tuple[bytes, ...]


def bounded_integer(value: object, maximum: int = MAX_TREE) -> int:
    if type(value) is not int or not 0 <= value <= maximum:
        raise InputError(f"expected integer in 0..{maximum}")
    return value


def _hex(value: object, *, digest: bool = False) -> bytes:
    if type(value) is not str or len(value) > MAX_ENTRY * 2 or not HEX.fullmatch(value) or len(value) % 2:
        raise InputError("invalid bounded lowercase hex encoding")
    if digest and len(value) != 64:
        raise InputError("digest must be exactly 32 bytes")
    return bytes.fromhex(value)


def _fields(raw: object, fields: set[str]) -> dict:
    if type(raw) is not dict or set(raw) != fields:
        raise InputError("missing or unknown schema fields")
    return raw


def _pairs(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise InputError("duplicate JSON object key")
        result[key] = value
    return result


def _number(text: str) -> int:
    if len(text) > 10:
        raise InputError("numeric text exceeds 10 characters")
    return int(text)


def _reject_number(_text: str) -> None:
    raise InputError("only integer JSON numbers supported")


def _depth(text: str) -> None:
    depth, quoted, escaped = 0, False, False
    for char in text:
        if quoted:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
        elif char in "[{":
            depth += 1
            if depth > 8:
                raise InputError("JSON nesting exceeds 8")
        elif char in "}]":
            depth -= 1


def parse(data: bytes, kind: str) -> Entries | Anchors | Inclusion | Consistency:
    """Parse one explicit envelope kind with limits before decoding/hashing."""
    if kind not in ("entries", "anchors", "inclusion", "consistency"):
        raise InputError("unknown envelope kind")
    limit = 2 * 1024 * 1024 if kind == "entries" else 64 * 1024
    if len(data) > limit:
        raise InputError("input byte limit exceeded")
    try:
        text = data.decode("utf-8")
        _depth(text)
        raw = json.loads(text, object_pairs_hook=_pairs, parse_int=_number,
                         parse_float=_reject_number, parse_constant=_reject_number)
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise InputError("invalid UTF-8 JSON") from error
    extra = {"entries": {"entries_hex"}, "anchors": {"heads"},
             "inclusion": {"kind", "tree_size", "leaf_index", "leaf_hex", "path"},
             "consistency": {"kind", "old_size", "new_size", "path"}}[kind]
    raw = _fields(raw, COMMON | extra)
    if type(raw["schema_version"]) is not int or raw["schema_version"] != 1 or raw["algorithm"] != ALGORITHM:
        raise InputError("unsupported schema version or algorithm")
    log_id = raw["log_id"]
    if type(log_id) is not str or not IDENTIFIER.fullmatch(log_id):
        raise InputError("log_id must match [A-Za-z0-9_.:-], length 1..64")
    if kind == "entries":
        values = raw["entries_hex"]
        if type(values) is not list or len(values) > MAX_TREE:
            raise InputError("entries array exceeds 4096 or is not an array")
        decoded = tuple(_hex(value) for value in values)
        if sum(map(len, decoded)) > MAX_TOTAL:
            raise InputError("aggregate entry bytes exceed 512 KiB")
        return Entries(log_id, decoded)
    if kind == "anchors":
        heads = raw["heads"]
        if type(heads) is not list or len(heads) > 32:
            raise InputError("heads must be an array with at most 32 entries")
        sizes, result = set(), []
        for head in heads:
            head = _fields(head, {"size", "root_hex"})
            size = bounded_integer(head["size"])
            if size in sizes:
                raise InputError("ambiguous duplicate anchor size")
            sizes.add(size)
            result.append((size, _hex(head["root_hex"], digest=True)))
        return Anchors(log_id, tuple(result))
    if raw["kind"] != kind:
        raise InputError("proof kind does not match requested operation")
    path = raw["path"]
    if type(path) is not list or len(path) > MAX_PATH:
        raise InputError("path must be an array with at most 13 digests")
    path = tuple(_hex(value, digest=True) for value in path)
    if kind == "inclusion":
        return Inclusion(log_id, bounded_integer(raw["tree_size"]), bounded_integer(raw["leaf_index"], MAX_TREE - 1),
                         _hex(raw["leaf_hex"]), path)
    return Consistency(log_id, bounded_integer(raw["old_size"]), bounded_integer(raw["new_size"]), path)


def load(path: Path, kind: str) -> Entries | Anchors | Inclusion | Consistency:
    """Read regular files only, with bounded reads including post-stat growth."""
    if not stat.S_ISREG(path.stat().st_mode):
        raise InputError("input must be a regular file")
    limit = 2 * 1024 * 1024 if kind == "entries" else 64 * 1024
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0)
    with os.fdopen(os.open(path, flags), "rb") as handle:
        info = os.fstat(handle.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
            raise InputError("nonregular or oversized input")
        return parse(handle.read(limit + 1), kind)
