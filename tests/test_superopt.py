import itertools
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import superopt
import verify


class ProofTests(unittest.TestCase):
    def setUp(self):
        self.source = bytes.fromhex("8018")
        self.cert, _, _ = superopt.optimize(self.source, 1, 5, 1000)

    def test_optimizer_and_standalone_verifier(self):
        self.assertEqual(self.cert["replacement"], "505f")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "proof.json"
            path.write_text(json.dumps(self.cert))
            result = subprocess.run(
                [sys.executable, str(ROOT / "verify.py"), str(path),
                 "--expect-source", self.source.hex(), "--expect-height", "1"],
                capture_output=True, text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("2 gas saved", result.stdout)

    def test_reject_forged_certificates(self):
        for key, value in {
            "replacement": "506001", "source": "8001", "entry_height": True,
            "source_gas": 900, "replacement_gas": 0, "fork": "paris",
            "max_entry_height": 1024, "format": "other", "normalized_stack_sha256": "0" * 64, "extra": None,
        }.items():
            with self.subTest(key=key):
                with self.assertRaises(ValueError):
                    verify.verify({**self.cert, key: value}, self.source, 1)

    def test_power_of_two_strength_reduction(self):
        for before, after in [("600202", "60011b"), ("60029004", "60011c"),
                              ("60049006", "600316"), ("60011b60021b", "60031b")]:
            with self.subTest(before=before):
                source, replacement = bytes.fromhex(before), bytes.fromhex(after)
                proof = verify.statement(source, replacement, 1, height_range=True)
                self.assertGreater(proof["source_gas"], proof["replacement_gas"])
        with self.assertRaises(ValueError):
            verify.statement(bytes.fromhex("600204"), bytes.fromhex("60011c"),
                             1, height_range=True)

    def test_range_certificate_lifts_to_evm_stack_limit(self):
        self.assertEqual(self.cert["max_entry_height"], 1023)
        verify.verify(self.cert, self.source, 1023)
        with self.assertRaises(ValueError):
            verify.verify(self.cert, self.source, 1024)
        data = bytes.fromhex(self.cert["replacement"])
        self.assertTrue(verify.same_stack(
            verify.replay(self.source, 1023)[0], verify.replay(data, 1023)[0],
        ))

    def test_range_rejects_more_stack_headroom_and_exact_still_works(self):
        source = bytes.fromhex("1919" * 3)
        replacement = bytes.fromhex("5f50")
        cert = verify.statement(source, replacement, 1)
        verify.verify(cert, source, 1)
        with self.assertRaisesRegex(ValueError, "headroom"):
            verify.statement(source, replacement, 1, height_range=True)

    def test_fail_closed(self):
        for code, height in [("5a", 0), ("60", 0), ("90", 1), ("5f", 1024), ("01", 1)]:
            with self.subTest(code=code), self.assertRaises(ValueError):
                verify.replay(bytes.fromhex(code), height)
        with self.assertRaises(ValueError):
            verify.statement(bytes.fromhex("9003"), bytes.fromhex("03"), 2)
        with self.assertRaises(ValueError):
            verify.statement(self.source, self.source, 1)
        with self.assertRaises(ValueError):
            json.loads('{"source":"8018","source":"8001"}',
                       object_pairs_hook=verify.unique_object)

    def test_enforce_byte_limit(self):
        source = bytes.fromhex("600160f81b")
        ordinary, _, _ = superopt.optimize(source, 0, 5, 1000)
        constrained, _, _ = superopt.optimize(source, 0, 5, 1000, True)
        self.assertGreater(len(bytes.fromhex(ordinary["replacement"])), len(source))
        self.assertIsNone(constrained)

    def test_search_matches_exhaustive_two_instruction_oracle(self):
        for hex_code, height in [("600202", 1), ("8018", 1), ("9001", 2),
                                  ("5f80", 0), ("6002600460021b01", 0)]:
            with self.subTest(source=hex_code):
                code = bytes.fromhex(hex_code)
                goal, source_gas, peak = verify.replay(code, height, verify.normal_v3)
                ops = superopt.alphabet(tuple(verify.decode(code)), goal)
                best = None
                for length in range(3):
                    for instructions in itertools.product(ops, repeat=length):
                        candidate = b"".join(instructions)
                        if len(candidate) > len(code):
                            continue
                        try:
                            after, cost, candidate_peak = verify.replay(
                                candidate, height, verify.normal_v3,
                            )
                        except ValueError:
                            continue
                        if candidate_peak > peak or not verify.same_stack(goal, after):
                            continue
                        if cost >= source_gas:
                            continue
                        score = (cost, len(candidate))
                        best = min(best, score) if best is not None else score
                cert, _, _ = superopt.optimize(code, height, 2, 100000, True)
                actual = None if cert is None else (
                    cert["replacement_gas"], len(bytes.fromhex(cert["replacement"])),
                )
                self.assertEqual(best, actual)

    def test_constant_chain_matches_documented_ebso_example(self):
        source = bytes.fromhex("600003600301")
        proof, _, _ = superopt.optimize(source, 1, 8, 1000)
        self.assertEqual(proof["replacement"], "600303")
        verify.verify(proof, source, 1)

    def test_stitch_certifies_full_window(self):
        source = bytes.fromhex("60a084901b166fffffffffffffffffffffffffffffffff")
        proof, _, status, _ = superopt.optimize_stitched(source, 4, 2, 1000, True)
        self.assertTrue(status.startswith(("stitched", "scheduled")))
        self.assertEqual(proof["source_gas"] - proof["replacement_gas"], 3)
        verify.verify(proof, source, 4)

    def test_size_certificate_accepts_equal_gas_and_rejects_increase(self):
        source = bytes.fromhex("610001")
        proof, _, _, _ = superopt.run_search(source, 0, 5, 20, True, False, True)
        self.assertEqual(proof["replacement"], "6001")
        self.assertEqual(proof["source_gas"], proof["replacement_gas"])
        verify.verify(proof, source, 0)
        with self.assertRaises(ValueError):
            verify.statement(bytes.fromhex("7f" + "00" * 32), bytes.fromhex("60008050"),
                             0, height_range=True, size=True)

    def test_additional_stack_tightens_certificate_range(self):
        source = bytes.fromhex("602081018490")
        proof, _, _, _ = superopt.run_search(source, 4, 8, 1000, True, True,
                                              extra_stack=1)
        self.assertEqual(proof["format"], verify.HEADROOM_FORMAT)
        self.assertEqual(proof["source_gas"] - proof["replacement_gas"], 3)
        self.assertEqual(proof["max_entry_height"], 1021)
        verify.verify(proof, source, 1021)
        with self.assertRaises(ValueError):
            verify.verify(proof, source, 1022)

    def test_state_budget(self):
        certificate, states, status = superopt.optimize(self.source, 1, 5, 1)
        self.assertIsNone(certificate)
        self.assertEqual((states, status), (1, "state_limit"))

    def test_deep_shared_symbolic_expression(self):
        code = bytes.fromhex("8002" * 23)
        stack, cost, _ = verify.replay(code, 1)
        other, _, _ = verify.replay(code, 1)
        self.assertTrue(verify.same_stack(stack, other))
        self.assertEqual(len(verify.stack_digest(stack)), 64)
        self.assertEqual(cost, 23 * 8)


if __name__ == "__main__":
    unittest.main()
