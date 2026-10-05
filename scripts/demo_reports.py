"""Generate fixed synthetic entries, proofs, operator anchors and reports.

Usage: python scripts/demo_reports.py [--check]
No user paths. Write mode overwrites only the fixed eight samples. --check reads
and verifies exact bytes. Sources are synthetic; no roots authenticated.
"""
import argparse
import json
from pathlib import Path
import sys
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from merkle_lab.contract import ALGORITHM
from merkle_lab.report import LIMITATION, render
from merkle_lab.tree import root_hash, leaf_hash, inclusion_path, consistency_path, verify_inclusion, verify_consistency


def artifacts() -> dict[str,str]:
    values=(b"synthetic event A",b"synthetic event B",b"synthetic event C",b"synthetic event D",b"synthetic event E")
    common=dict(schema_version=1,algorithm=ALGORITHM,log_id="synthetic-log")
    entries=dict(common,entries_hex=[value.hex() for value in values])
    roots={size:root_hash(values[:size]) for size in (0,3,5)}
    anchors=dict(common,heads=[dict(size=size,root_hex=root.hex()) for size,root in roots.items()])
    path=inclusion_path(values,1)
    inclusion=dict(common,kind="inclusion",tree_size=5,leaf_index=1,leaf_hex=values[1].hex(),path=[p.hex() for p in path])
    consistency=dict(common,kind="consistency",old_size=3,new_size=5,path=[p.hex() for p in consistency_path(values,3)])
    changed=dict(inclusion,leaf_hex=b"altered synthetic event".hex())
    unsupported=dict(consistency,old_size=0,path=[])
    statements=[]
    for case,digest in (("inclusion-valid",leaf_hash(values[1])),("inclusion-tampered",leaf_hash(b"altered synthetic event"))):
        result=verify_inclusion(1,5,digest,path,roots[5])
        statements.append(dict(case=case,status=result.status,relationship=result.relationship,reason=result.reason,
                               tree_size=5,leaf_index=1,leaf_hash_hex=digest.hex(),anchor_root_hex=roots[5].hex()))
    for case,old,new,proof in (("consistency-growth",3,5,consistency_path(values,3)),
                               ("equal-positive-heads",5,5,()),("empty-prior",0,5,())):
        result=verify_consistency(old,new,proof,roots[old],roots[new])
        statements.append(dict(case=case,status=result.status,relationship=result.relationship,reason=result.reason,
                               old_size=old,new_size=new,old_anchor_hex=roots[old].hex(),new_anchor_hex=roots[new].hex()))
    report=dict(report_version=1,anchor_authenticity_verified=False,limitation=LIMITATION,cases=statements)
    encode=lambda value:json.dumps(value,indent=2,ensure_ascii=True)+"\n"
    return {"entries.json":encode(entries),"operator-anchors.json":encode(anchors),"inclusion.json":encode(inclusion),
            "consistency.json":encode(consistency),"tampered-inclusion.json":encode(changed),
            "empty-prior.json":encode(unsupported),"demo-report.json":render(report,"json"),"demo-report.txt":render(report,"text")}


def main() -> int:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check",action="store_true")
    args=parser.parse_args()
    for name,content in artifacts().items():
        target=ROOT/"samples"/name
        if args.check:
            if not target.is_file() or target.read_bytes()!=content.encode("utf-8"):
                print("sample mismatch: "+name)
                return 1
        else:
            target.write_bytes(content.encode("utf-8"))
    print("eight synthetic artifacts verified" if args.check else "eight synthetic artifacts generated")
    return 0


if __name__=="__main__":raise SystemExit(main())
