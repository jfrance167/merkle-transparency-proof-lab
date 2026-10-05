# RFC 9162 code components: Copyright (c) 2021 IETF Trust and identified authors.
# Revised BSD license: LICENSES/IETF-BSD-3-Clause.txt; source/changes: NOTICE.md.
"""SHA-256 RFC tree/proof algorithms, with explicit bounded public inputs."""
from dataclasses import dataclass
from functools import lru_cache
import hashlib
from .contract import InputError, MAX_ENTRY, MAX_PATH, MAX_TOTAL, MAX_TREE, bounded_integer


@dataclass(frozen=True)
class Result:
    status: str
    relationship: str
    reason: str


def leaf_hash(data: bytes) -> bytes:
    if type(data) is not bytes or len(data) > MAX_ENTRY:
        raise InputError("leaf must be bounded bytes")
    return hashlib.sha256(b"\x00" + data).digest()


def _digest(data: bytes) -> bytes:
    if type(data) is not bytes or len(data) != 32:
        raise InputError("expected 32-byte digest")
    return data


def node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + _digest(left) + _digest(right)).digest()


def empty_hash() -> bytes:
    return hashlib.sha256(b"").digest()


def _path(path: tuple[bytes, ...]) -> None:
    if type(path) is not tuple or len(path) > MAX_PATH:
        raise InputError("path must be a bounded tuple")
    for node in path:
        _digest(node)


def _tree(entries: tuple[bytes, ...]):
    if type(entries) is not tuple or len(entries) > MAX_TREE:
        raise InputError("entries must be a bounded tuple")
    if any(type(value) is not bytes or len(value) > MAX_ENTRY for value in entries):
        raise InputError("entries must be bounded bytes")
    if sum(map(len, entries)) > MAX_TOTAL:
        raise InputError("aggregate bytes exceed 512 KiB")

    @lru_cache(maxsize=2 * MAX_TREE)
    def digest(start: int, size: int) -> bytes:
        if size == 0:
            return empty_hash()
        if size == 1:
            return leaf_hash(entries[start])
        split = 1 << ((size - 1).bit_length() - 1)
        return node_hash(digest(start, split), digest(start + split, size - split))
    return digest


def root_hash(entries: tuple[bytes, ...]) -> bytes:
    return _tree(entries)(0, len(entries))


def inclusion_path(entries: tuple[bytes, ...], index: int) -> tuple[bytes, ...]:
    digest = _tree(entries)
    bounded_integer(index, MAX_TREE - 1)
    if index >= len(entries):
        raise InputError("index outside generated tree")

    def walk(start: int, size: int, offset: int) -> tuple:
        if size == 1:
            return ()
        split = 1 << ((size - 1).bit_length() - 1)
        if offset < split:
            return walk(start, split, offset) + (digest(start + split, size - split),)
        return walk(start + split, size - split, offset - split) + (digest(start, split),)
    return walk(0, len(entries), index)


def consistency_path(entries: tuple[bytes, ...], old_size: int) -> tuple[bytes, ...]:
    digest = _tree(entries)
    bounded_integer(old_size)
    if not 0 < old_size <= len(entries):
        raise InputError("generated consistency requires 0 < old_size <= tree size")

    def walk(start: int, size: int, old: int, complete: bool) -> tuple:
        if old == size:
            return () if complete else (digest(start, size),)
        split = 1 << ((size - 1).bit_length() - 1)
        if old <= split:
            return walk(start, split, old, complete) + (digest(start + split, size - split),)
        return walk(start + split, size - split, old - split, False) + (digest(start, split),)
    return walk(0, len(entries), old_size, True)


def verify_inclusion(index: int, size: int, leaf_digest: bytes, path: tuple[bytes, ...], root: bytes) -> Result:
    """Verify a digest-level indexed statement; CLI hashes raw leaf bytes once."""
    bounded_integer(index, MAX_TREE - 1)
    bounded_integer(size)
    _digest(leaf_digest)
    _digest(root)
    _path(path)
    if index >= size:
        return Result("invalid", "inclusion", "index outside tree")
    fn, sn, value = index, size - 1, leaf_digest
    for sibling in path:
        if sn == 0:
            return Result("invalid", "inclusion", "extra proof nodes")
        if fn & 1 or fn == sn:
            value = node_hash(sibling, value)
            if not fn & 1:
                while fn and not fn & 1:
                    fn >>= 1
                    sn >>= 1
        else:
            value = node_hash(value, sibling)
        fn >>= 1
        sn >>= 1
    if sn != 0:
        return Result("invalid", "inclusion", "missing proof nodes")
    if value != root:
        return Result("invalid", "inclusion", "root mismatch")
    return Result("valid", "inclusion", "indexed leaf matches supplied commitment")


def verify_consistency(old: int, new: int, path: tuple[bytes, ...], first: bytes, second: bytes) -> Result:
    """Verify both commitments; empty prior trees provide no history evidence."""
    bounded_integer(old)
    bounded_integer(new)
    _digest(first)
    _digest(second)
    _path(path)
    if new < old:
        return Result("invalid", "consistency", "shrinking tree")
    if old == 0:
        return Result("unsupported", "consistency", "empty prior tree supplies no meaningful history evidence")
    if old == new:
        if path or first != second:
            return Result("invalid", "identity-no-growth", "equal sizes require equal roots and empty path")
        return Result("valid", "identity-no-growth", "same positive-size commitment; no growth shown")
    if not path:
        return Result("invalid", "consistency", "missing proof nodes")
    fn, sn = old - 1, new - 1
    while fn & 1:
        fn >>= 1
        sn >>= 1
    if old & (old - 1) == 0:
        fr = sr = first
        remaining = path
    else:
        fr = sr = path[0]
        remaining = path[1:]
    for sibling in remaining:
        if sn == 0:
            return Result("invalid", "consistency", "extra proof nodes")
        if fn & 1 or fn == sn:
            fr = node_hash(sibling, fr)
            sr = node_hash(sibling, sr)
            while fn and not fn & 1:
                fn >>= 1
                sn >>= 1
        else:
            sr = node_hash(sr, sibling)
        fn >>= 1
        sn >>= 1
    if sn != 0:
        return Result("invalid", "consistency", "missing proof nodes")
    if fr != first or sr != second:
        return Result("invalid", "consistency", "one or both roots mismatch")
    return Result("valid", "consistency", "earlier committed history is a prefix of later history")
