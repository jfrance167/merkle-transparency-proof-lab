"""Offline CLI with separate anchors and exclusive, bounded output creation."""
import argparse
from pathlib import Path
import re
import sys
from .contract import ALGORITHM, InputError, load
from .report import LIMITATION, render, visible
from .tree import (consistency_path, inclusion_path, leaf_hash, root_hash,
                   verify_consistency, verify_inclusion)


def _argument_integer(text: str) -> int:
    if len(text) > 10 or not re.fullmatch(r"[0-9]+", text) or int(text) > 4096:
        raise argparse.ArgumentTypeError("expected ASCII integer 0..4096, <=10 digits")
    return int(text)


def _envelope(log_id: str) -> dict:
    return dict(schema_version=1, algorithm=ALGORITHM, log_id=log_id)


def operation(args) -> tuple[dict, int, bool]:
    """Return report/body, exit code and whether body is an untrusted proof."""
    name = args.command
    if name.startswith("verify-"):
        if args.input.samefile(args.anchors):
            raise InputError("proof and anchors must be separate files")
        kind = name.removeprefix("verify-")
        proof = load(args.input, kind)
        anchors = load(args.anchors, "anchors")
        if proof.log_id != anchors.log_id:
            raise InputError("proof log_id differs from supplied anchors")
        if kind == "inclusion":
            digest, root = leaf_hash(proof.leaf), anchors.root(proof.tree_size)
            result = verify_inclusion(proof.leaf_index, proof.tree_size, digest, proof.path, root)
            statement = dict(tree_size=proof.tree_size, leaf_index=proof.leaf_index,
                             leaf_hash_hex=digest.hex(), anchor_root_hex=root.hex())
        else:
            first, second = anchors.root(proof.old_size), anchors.root(proof.new_size)
            result = verify_consistency(proof.old_size, proof.new_size, proof.path, first, second)
            statement = dict(old_size=proof.old_size, new_size=proof.new_size,
                             old_anchor_hex=first.hex(), new_anchor_hex=second.hex())
        report = dict(report_version=1, algorithm=ALGORITHM, log_id=proof.log_id,
                      status=result.status, relationship=result.relationship, reason=result.reason,
                      statement=statement, anchor_authenticity_verified=False, limitation=LIMITATION)
        return report, {"valid":0,"invalid":1,"unsupported":3}[result.status], False
    entries = load(args.input, "entries")
    body = _envelope(entries.log_id)
    if name == "root":
        body.update(report_version=1, status="generated-commitment", tree_size=len(entries.values),
                    root_hex=root_hash(entries.values).hex(), anchor_authenticity_verified=False, limitation=LIMITATION)
        return body, 0, False
    if name == "prove-inclusion":
        path = inclusion_path(entries.values, args.index)
        body.update(kind="inclusion", tree_size=len(entries.values), leaf_index=args.index,
                    leaf_hex=entries.values[args.index].hex(), path=[node.hex() for node in path])
    else:
        if args.old_size == 0:
            return dict(report_version=1, status="unsupported", reason="empty prior tree supplies no meaningful history evidence",
                        anchor_authenticity_verified=False, limitation=LIMITATION), 3, False
        path = consistency_path(entries.values, args.old_size)
        body.update(kind="consistency", old_size=args.old_size, new_size=len(entries.values), path=[node.hex() for node in path])
    return body, 0, True


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Synthetic offline RFC Merkle proofs; anchors are not authenticated.")
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("root", "prove-inclusion", "prove-consistency", "verify-inclusion", "verify-consistency"):
        command = commands.add_parser(name)
        command.add_argument("input", type=Path)
        command.add_argument("--format", choices=("text","json"), default="text")
        command.add_argument("--output", type=Path, help="create new file only; refuse overwrite/aliases")
        if name.startswith("verify-"):
            command.add_argument("--anchors", type=Path, required=True)
        elif name == "prove-inclusion":
            command.add_argument("--index", type=_argument_integer, required=True)
        elif name == "prove-consistency":
            command.add_argument("--old-size", type=_argument_integer, required=True)
    args = parser.parse_args(argv)
    try:
        body, code, generated = operation(args)
        content = render(body, args.format, generated_proof=generated)
        if args.output:
            if args.output.exists():
                for source in (args.input, getattr(args,"anchors",None)):
                    if source is not None and args.output.samefile(source):
                        raise InputError("output aliases input evidence")
            with args.output.open("x", encoding="utf-8", newline="\n") as handle:
                handle.write(content)
        else:
            sys.stdout.write(content)
        if generated:
            print("Generated proof only; no roots authenticated or anchors updated.", file=sys.stderr)
        return code
    except (InputError, OSError, UnicodeError) as error:
        print("merkle-lab: " + visible(str(error)), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
