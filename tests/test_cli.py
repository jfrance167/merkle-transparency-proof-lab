from copy import deepcopy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from merkle_lab.contract import InputError
from merkle_lab.report import render
from merkle_lab.tree import leaf_hash, root_hash
from tests.test_contract import envelope, encode

ROOT = Path(__file__).resolve().parents[1]


class CliTests(unittest.TestCase):
    def setUp(self):
        temp_root=ROOT/".private/test-temp"
        temp_root.mkdir(parents=True,exist_ok=True)
        self.temp=tempfile.TemporaryDirectory(dir=temp_root)
        self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        self.entries=(b"one",b"two",b"three",b"four",b"five")
        self.source=self.root/"entries.json"
        raw=envelope();raw["entries_hex"]=[value.hex() for value in self.entries]
        self.source.write_bytes(encode(raw))
        self.anchors=self.root/"anchors.json"
        raw=envelope("anchors");raw["heads"]=[dict(size=size,root_hex=root_hash(self.entries[:size]).hex()) for size in (0,3,5)]
        self.anchors.write_bytes(encode(raw))
        self.proof=self.root/"proof.json"

    def call(self, *arguments):
        return subprocess.run([sys.executable,"-m","merkle_lab",*map(str,arguments)],cwd=ROOT,
                              capture_output=True,text=True,timeout=10,check=False)

    def generate(self, kind="inclusion"):
        options=("--index", "1") if kind=="inclusion" else ("--old-size", "3")
        process=self.call("prove-"+kind,self.source,*options,"--format","json")
        self.assertEqual(process.returncode,0,process.stderr)
        self.assertIn("no roots authenticated",process.stderr)
        self.proof.write_text(process.stdout,encoding="utf-8")
        return json.loads(process.stdout)

    def test_round_trip_both_relationships(self):
        for kind in ("inclusion","consistency"):
            self.generate(kind)
            process=self.call("verify-"+kind,self.proof,"--anchors",self.anchors,"--format","json")
            self.assertEqual(process.returncode,0,process.stderr)
            report=json.loads(process.stdout)
            self.assertFalse(report["anchor_authenticity_verified"])
            self.assertIn("split views",report["limitation"])
        process=self.call("root",self.source,"--format","json")
        self.assertEqual(json.loads(process.stdout)["status"],"generated-commitment")

    def test_tamper_and_repaired_control(self):
        original=self.generate()
        changed=deepcopy(original);changed["leaf_hex"]=b"changed".hex()
        self.proof.write_bytes(encode(changed))
        self.assertEqual(self.call("verify-inclusion",self.proof,"--anchors",self.anchors).returncode,1)
        self.proof.write_bytes(encode(original))
        self.assertEqual(self.call("verify-inclusion",self.proof,"--anchors",self.anchors).returncode,0)

    def test_anchor_ids_missing_and_duplicates(self):
        self.generate()
        for change in ("id","missing","duplicate"):
            raw=envelope("anchors")
            if change=="id":raw["log_id"]="other-log"
            elif change=="missing":raw["heads"]=[]
            else:raw["heads"]*=2
            self.anchors.write_bytes(encode(raw))
            self.assertEqual(self.call("verify-inclusion",self.proof,"--anchors",self.anchors).returncode,2)

    def test_same_file_and_hardlink_separation(self):
        self.generate()
        self.assertEqual(self.call("verify-inclusion",self.proof,"--anchors",self.proof).returncode,2)
        link=self.root/"alias.json"
        os.link(self.proof,link)
        self.assertEqual(self.call("verify-inclusion",self.proof,"--anchors",link).returncode,2)

    def test_exclusive_output_and_inputs_unchanged(self):
        self.generate()
        evidence={path:path.read_bytes() for path in (self.source,self.proof,self.anchors)}
        for target in evidence:
            self.assertEqual(self.call("verify-inclusion",self.proof,"--anchors",self.anchors,"--output",target).returncode,2)
        for path,data in evidence.items():self.assertEqual(path.read_bytes(),data)
        output=self.root/"report.json"
        self.assertEqual(self.call("verify-inclusion",self.proof,"--anchors",self.anchors,"--format","json","--output",output).returncode,0)
        content=output.read_bytes()
        self.assertEqual(self.call("root",self.source,"--output",output).returncode,2)
        self.assertEqual(output.read_bytes(),content)

    def test_unsupported_and_equal_identity(self):
        self.generate("consistency")
        raw=json.loads(self.proof.read_text());raw.update(old_size=0,path=[])
        self.proof.write_bytes(encode(raw))
        self.assertEqual(self.call("verify-consistency",self.proof,"--anchors",self.anchors).returncode,3)
        self.assertEqual(self.call("prove-consistency",self.source,"--old-size","0").returncode,3)
        raw.update(old_size=5,new_size=5,path=[]);self.proof.write_bytes(encode(raw))
        process=self.call("verify-consistency",self.proof,"--anchors",self.anchors,"--format","json")
        self.assertEqual(process.returncode,0)
        self.assertEqual(json.loads(process.stdout)["relationship"],"identity-no-growth")

    def test_input_errors_and_output_bound(self):
        for source in (self.root/"missing",self.root):
            process=self.call("root",source)
            self.assertEqual(process.returncode,2)
            self.assertNotIn("Traceback",process.stderr)
        self.source.write_bytes(b"x"*(2*1024*1024+1))
        self.assertEqual(self.call("root",self.source).returncode,2)
        with self.assertRaises(InputError):render({"message":"x"*(256*1024)},"json")
        self.assertEqual(self.call("prove-inclusion",self.source,"--index","9"*11).returncode,2)


if __name__ == "__main__":unittest.main()
