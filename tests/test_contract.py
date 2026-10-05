import json
import unittest
from merkle_lab.contract import InputError, parse


def envelope(kind="entries"):
    raw = dict(schema_version=1,algorithm="sha256-rfc9162",log_id="synthetic-log")
    if kind == "entries":
        raw["entries_hex"] = ["", "00"]
    elif kind == "anchors":
        raw["heads"] = [{"size":1,"root_hex":"00"*32}]
    elif kind == "inclusion":
        raw.update(kind=kind,tree_size=1,leaf_index=0,leaf_hex="",path=[])
    else:
        raw.update(kind=kind,old_size=1,new_size=2,path=["00"*32])
    return raw


def encode(raw):
    return json.dumps(raw).encode()


class ContractTests(unittest.TestCase):
    def reject(self, raw, kind="entries"):
        with self.assertRaises(InputError):
            parse(encode(raw),kind)

    def test_all_envelopes_and_identifier_allowlist(self):
        for kind in ("entries","anchors","inclusion","consistency"):
            self.assertEqual(parse(encode(envelope(kind)),kind).log_id,"synthetic-log")
            for bad in ("", "x"*65, "bad\nname", "bad name", "é", "<script>", True):
                raw=envelope(kind);raw["log_id"]=bad
                self.reject(raw,kind)

    def test_fields_keys_types_and_algorithm(self):
        for kind in ("entries","anchors","inclusion","consistency"):
            for operation in ("add","delete","version","algorithm"):
                raw=envelope(kind)
                if operation=="add":raw["unknown"]=0
                elif operation=="delete":del raw["log_id"]
                elif operation=="version":raw["schema_version"]=True
                else:raw["algorithm"]="sha1"
                self.reject(raw,kind)
        for text in (b'{"a":1,"a":2}',b'{"a":NaN}',b'{"a":1.0}',b'{"a":1e300}',b'{"a":12345678901}',b'\xff',b'\xef\xbb\xbf{}'):
            with self.assertRaises(InputError):parse(text,"entries")

    def test_sizes_boolean_and_proof_digests(self):
        for bad in (True,-1,4097,"1"):
            raw=envelope("consistency");raw["old_size"]=bad
            self.reject(raw,"consistency")
        for bad in (None,[""],["00"*31],["AA"*32],["gg"*32],["00"*32]*14):
            raw=envelope("inclusion");raw["path"]=bad
            self.reject(raw,"inclusion")
        for bad in ("0","FF","gg","00"*2049):
            raw=envelope("inclusion");raw["leaf_hex"]=bad
            self.reject(raw,"inclusion")

    def test_resource_bounds_and_inclusive_admission(self):
        raw=envelope();raw["entries_hex"]=["00"]*4096
        self.assertEqual(len(parse(encode(raw),"entries").values),4096)
        raw["entries_hex"].append("00");self.reject(raw)
        raw=envelope();raw["entries_hex"]=["00"*2048]*256
        self.assertEqual(sum(map(len,parse(encode(raw),"entries").values)),512*1024)
        raw["entries_hex"].append("00");self.reject(raw)
        for data,kind in ((b"["*9+b"]"*9,"entries"),(b" "*(2*1024*1024+1),"entries"),(b" "*(64*1024+1),"anchors")):
            with self.assertRaises(InputError):parse(data,kind)

    def test_anchor_uniqueness_and_count(self):
        raw=envelope("anchors");raw["heads"]*=2
        self.reject(raw,"anchors")
        raw["heads"]=[dict(size=i,root_hex="00"*32) for i in range(32)]
        self.assertEqual(len(parse(encode(raw),"anchors").heads),32)
        raw["heads"].append(dict(size=32,root_hex="00"*32));self.reject(raw,"anchors")


if __name__ == "__main__":unittest.main()
