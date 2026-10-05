import base64
import hashlib
import json
from pathlib import Path
import unittest
from merkle_lab.contract import InputError
from merkle_lab.tree import (empty_hash, leaf_hash, root_hash, inclusion_path, consistency_path,
                             verify_inclusion, verify_consistency)
from tests.oracle import tree, path

VECTORS = Path(__file__).parent / "vectors"


class TreeTests(unittest.TestCase):
    def test_source_provenance(self):
        manifest = json.loads((VECTORS/"manifest.json").read_text())
        self.assertEqual(len(manifest["records"]), 18)
        for record in manifest["records"]:
            data = (VECTORS/"original"/record["path"]).read_bytes()
            self.assertEqual(hashlib.sha256(data).hexdigest(), record["sha256"])
            self.assertEqual(len(data), record["bytes"])
            self.assertEqual(hashlib.sha1(b"blob "+str(len(data)).encode()+b"\0"+data,
                                         usedforsecurity=False).hexdigest(), record["git_blob_sha1"])

    def test_fixed_hasher_answers(self):
        # Independent fixed answers from pinned upstream hasher tests.
        self.assertEqual(empty_hash().hex(), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        self.assertEqual(leaf_hash(b"").hex(), "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d")
        self.assertEqual(leaf_hash(b"L123456").hex(), "395aa064aa4c29f7010acfe3f25db9485bbd4b91897b6ad7ad547639252b4d56")
        self.assertNotEqual(empty_hash(), leaf_hash(b""))

    def test_upstream_known_answers_and_negative_probes(self):
        count = positives = negatives = 0
        decode = lambda value: base64.b64decode(value, validate=True)
        for fixture in sorted((VECTORS/"original/testdata").rglob("*.json")):
            raw = json.loads(fixture.read_text())
            proof = tuple(decode(value) for value in raw["proof"] or [])
            with self.subTest(path=str(fixture)):
                try:
                    if "leafIdx" in raw:
                        result = verify_inclusion(raw["leafIdx"], raw["treeSize"], decode(raw["leafHash"]), proof, decode(raw["root"]))
                    else:
                        result = verify_consistency(raw["size1"], raw["size2"], proof, decode(raw["root1"]), decode(raw["root2"]))
                    bad = result.status != "valid"
                except InputError:
                    bad = True
                self.assertEqual(bad, raw["wantErr"])
            count += 1
            positives += not raw["wantErr"]
            negatives += raw["wantErr"]
        self.assertEqual((count, positives, negatives), (17, 10, 7))

    def test_independent_forest_all_small_trees_and_prefixes(self):
        for size in range(1, 33):
            entries = tuple(f"unique-record-{i}".encode() for i in range(size))
            oracle = tree(entries)
            self.assertEqual(root_hash(entries), oracle[2])
            for index in range(size):
                generated = inclusion_path(entries, index)
                self.assertEqual(generated, path(oracle, index))
                self.assertEqual(verify_inclusion(index, size, leaf_hash(entries[index]), generated, oracle[2]).status, "valid")
            for old in range(1, size+1):
                proof = consistency_path(entries, old)
                self.assertEqual(verify_consistency(old, size, proof, tree(entries[:old])[2], oracle[2]).status, "valid")

    def test_symbolic_rfc_seven_leaf_order(self):
        entries = tuple(f"d{i}".encode() for i in range(7))
        a,b,c,d,e,f,j = (leaf_hash(value) for value in entries)
        from merkle_lab.tree import node_hash
        g,h,i = node_hash(a,b),node_hash(c,d),node_hash(e,f)
        k,l = node_hash(g,h),node_hash(i,j)
        expected = {0:(b,h,l),3:(c,g,l),4:(f,j,k),6:(i,k)}
        for index, siblings in expected.items():
            self.assertEqual(inclusion_path(entries,index), siblings)
        self.assertEqual(consistency_path(entries,3),(c,d,g,l))
        self.assertEqual(consistency_path(entries,4),(l,))
        self.assertEqual(consistency_path(entries,6),(i,j,k))

    def test_false_statement_mutations(self):
        entries = (b"unique-a",b"unique-b",b"unique-c",b"unique-d",b"unique-e")
        root = tree(entries)[2]
        proof = inclusion_path(entries, 1)
        for index,size,digest,siblings,anchor in (
                (1,5,leaf_hash(b"changed"),proof,root), (2,5,leaf_hash(entries[1]),proof,root),
                (1,4,leaf_hash(entries[1]),proof,root), (1,5,leaf_hash(entries[1]),proof[:-1],root),
                (1,5,leaf_hash(entries[1]),proof+(b"x"*32,),root),
                (1,5,leaf_hash(entries[1]),tuple(reversed(proof)),root),
                (1,5,leaf_hash(entries[1]),proof,b"x"*32)):
            self.assertEqual(verify_inclusion(index,size,digest,siblings,anchor).status,"invalid")
        consistency = consistency_path(entries,3)
        for siblings,first,second in ((consistency[:-1],tree(entries[:3])[2],root),
                                     (consistency+(b"x"*32,),tree(entries[:3])[2],root),
                                     (consistency,b"x"*32,root), (consistency,tree(entries[:3])[2],b"x"*32)):
            self.assertEqual(verify_consistency(3,5,siblings,first,second).status,"invalid")

    def test_duplicates_and_empty_records_are_valid(self):
        entries = (b"",b"",b"same",b"same")
        root = root_hash(entries)
        for index in range(4):
            self.assertEqual(verify_inclusion(index,4,leaf_hash(entries[index]),inclusion_path(entries,index),root).status,"valid")
        # Two identical empty siblings make both indexed statements true.
        pair = (b"",b"")
        self.assertEqual(verify_inclusion(1,2,leaf_hash(b""),inclusion_path(pair,0),root_hash(pair)).status,"valid")

    def test_empty_equal_and_shrinking(self):
        root = leaf_hash(b"one")
        self.assertEqual(verify_inclusion(0,0,root,(),empty_hash()).status,"invalid")
        self.assertEqual(verify_consistency(0,0,(),empty_hash(),empty_hash()).status,"unsupported")
        self.assertEqual(verify_consistency(0,1,(),empty_hash(),root).status,"unsupported")
        self.assertEqual(verify_consistency(2,1,(),root,root).status,"invalid")
        result = verify_consistency(1,1,(),root,root)
        self.assertEqual((result.status,result.relationship),("valid","identity-no-growth"))
        self.assertEqual(verify_consistency(1,1,(root,),root,root).status,"invalid")
        self.assertEqual(verify_consistency(1,1,(),root,b"x"*32).status,"invalid")

    def test_split_views_and_stale_head_limit(self):
        # Individually accepted operator anchors can commit different histories.
        for entries in ((b"same",b"view-a"),(b"same",b"view-b")):
            self.assertEqual(verify_inclusion(1,2,leaf_hash(entries[1]),inclusion_path(entries,1),root_hash(entries)).status,"valid")
        self.assertNotEqual(root_hash((b"same",b"view-a")),root_hash((b"same",b"view-b")))
        self.assertEqual(verify_inclusion(0,1,leaf_hash(b"old"),(),leaf_hash(b"old")).status,"valid")

    def test_maximum_tree_and_public_api_bounds(self):
        entries=tuple(index.to_bytes(2,"big") for index in range(4096))
        oracle=tree(entries)[2]
        self.assertEqual(root_hash(entries),oracle)
        for index in (0,2047,2048,4095):
            self.assertEqual(verify_inclusion(index,4096,leaf_hash(entries[index]),inclusion_path(entries,index),oracle).status,"valid")
        proof=consistency_path(entries,4095)
        self.assertEqual(len(proof),13)
        self.assertEqual(verify_consistency(4095,4096,proof,tree(entries[:4095])[2],oracle).status,"valid")
        for bad in (True,-1,4097):
            with self.assertRaises(InputError):verify_consistency(bad,4096,(),oracle,oracle)
        with self.assertRaises(InputError):leaf_hash(b"x"*2049)
        with self.assertRaises(InputError):root_hash((b"",)*4097)
        with self.assertRaises(InputError):verify_inclusion(0,1,b"x",(),oracle)


if __name__ == "__main__":
    unittest.main()
