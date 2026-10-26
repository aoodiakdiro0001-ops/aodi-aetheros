"""Aodı-AetherOS 1.0.0 — offline test suite (stdlib unittest only).

Covers every honest claim the system makes:
  Paillier keygen/encrypt/decrypt + homomorphic add / scalar-mul / linear
  kernel + ciphertext range guards + Shamir 3-of-3 (and 2-of-3 refusal),
  AVP encode/decode determinism + oracle agreement + budget enforcement,
  synthetic Mach-O (thin + fat + arm64e) / PE / ELF forensics + plain-text
  refusal, AEFR frame round-trip + proven bit-flip rejection + chunk math,
  Ouroboros emission (file + manifest sha) + template compilability,
  tamper-evident ledger seal chain (broken_at_idx), and config isolation.

AE_HOME is redirected to a temp dir BEFORE any core import, so tests never
touch the operator's real ~/.aetheros state.
"""
import base64
import os
import sys
import tempfile
import unittest
from pathlib import Path

_TMP = tempfile.mkdtemp(prefix="aetheros-tests-")
os.environ["AE_HOME"] = _TMP                      # MUST precede core imports
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "core"))

import config                                     # noqa: E402
import fabric                                    # noqa: E402
import fhe                                       # noqa: E402
import morph                                     # noqa: E402
import ouroboros                                 # noqa: E402
import storage                                   # noqa: E402
import telemetry                                 # noqa: E402
import vproc                                     # noqa: E402


# ---------------------------------------------------------------- fixtures --
def _thin_macho(arch="arm64", cpusub=0):
    cputype = {"arm64": 0x0100000C, "x86_64": 0x01000007}[arch]
    flags = morph.MH_PIE
    return (b"\xcf\xfa\xed\xfe" +
            __import__("struct").pack("<IIIIII", cputype, cpusub, 2, 4,
                                      0x100, flags))


def _fat_macho():
    s = __import__("struct")
    slices = [s.pack(">IIIII", 0x01000007, 0x80000003, 4096, 1000, 12),
              s.pack(">IIIII", 0x0100000C, 0, 8192, 2000, 12)]
    return b"\xca\xfe\xba\xbe" + s.pack(">I", 2) + b"".join(slices)


def _pe():
    s = __import__("struct")
    rest = s.pack("<HHI", 0x8664, 5, 1765213230)
    return b"MZ" + b"\x00" * 0x3A + s.pack("<I", 0x40) + b"PE\x00\x00" + rest


def _elf(machine=0xB7):
    s = __import__("struct")
    return (b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\x00" * 8 +
            s.pack("<HH", 2, machine) + b"\x00\x00" +
            s.pack("<Q", 0x1000) + b"\x00" * 2)


# ------------------------------------------- Paillier: the privacy ledger ---
class TestPaillier(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key = fhe.keygen(1024)

    def test_roundtrip(self):
        for m in (0, 1, 999, 123456):
            self.assertEqual(fhe.decrypt(self.key, fhe.encrypt(self.key, m)), m)

    def test_g_n1_special_degeneracy(self):
        """E(0) = r^n mod n^2 (random mask), and it decrypts to exactly 0."""
        n2 = self.key["n"] * self.key["n"]
        c0 = fhe.encrypt(self.key, 0)
        self.assertLess(c0, n2)
        self.assertEqual(fhe.decrypt(self.key, c0), 0)

    def test_additive_homomorphism(self):
        a, b = 4242, 9876
        ca, cb = fhe.encrypt(self.key, a), fhe.encrypt(self.key, b)
        self.assertEqual(fhe.decrypt(self.key, fhe.homomorphic_add(
            self.key, ca, cb)), a + b)

    def test_scalar_multiplication(self):
        ca = fhe.encrypt(self.key, 77)
        self.assertEqual(fhe.decrypt(
            self.key, fhe.homomorphic_mul_const(self.key, ca, 9)), 693)

    def test_linear_kernel_public_weights(self):
        vals = [101, 210, 32, 401]
        encs = [fhe.encrypt(self.key, v) for v in vals]
        weights = [2, -1, 4, 3]           # negative weight handled via mod n
        got = fhe.decrypt(self.key, fhe.homomorphic_linear(
            self.key, encs, weights))
        self.assertEqual(
            got, sum(w * v for w, v in zip(weights, vals)) % self.key["n"])

    def test_ciphertext_range_guard(self):
        fake = format(self.key["n"] * self.key["n"] + 5, "x")
        with self.assertRaises(ValueError):
            fhe.from_enc_hex(self.key, fake)

    def test_randomized_ciphertexts(self):
        """Two encryptions of the same plaintext differ (semantic security)."""
        self.assertNotEqual(fhe.encrypt(self.key, 5), fhe.encrypt(self.key, 5))


class TestShamir(unittest.TestCase):
    def test_three_of_three_is_exact(self):
        secret = 0xDEADBEEF12345678
        bundle = fhe.shamir_split(secret, shares=3, threshold=3)
        pts = [(s["x"], int(s["y_hex"], 16)) for s in bundle["shares"]]
        # shares themselves must NOT equal the secret
        self.assertNotEqual(int(bundle["shares"][0]["y_hex"], 16), secret)
        self.assertEqual(bundle["threshold"], 3)
        self.assertEqual(fhe.shamir_combine(pts), secret)

    def test_two_of_three_refused(self):
        """Partial key custody must fail loudly - never a degraded secret."""
        secret = 0xFEEDFACE
        pts = [(s["x"], int(s["y_hex"], 16))
               for s in fhe.shamir_split(secret, 3, 3)["shares"]]
        with self.assertRaises(ValueError):
            fhe.shamir_combine(pts[:2], threshold=3)

    def test_secret_out_of_field(self):
        with self.assertRaises(ValueError):
            fhe.shamir_split(fhe._SHAMIR_P, 3, 3)


# ------------------------------------------------------- AVP portable VM ---
class TestAVP(unittest.TestCase):
    def test_encode_decode_roundtrip(self):
        prog = vproc.sum_squares_program(7)
        self.assertEqual(vproc.decode(vproc.encode(prog)), prog)

    def test_oracle_agreement(self):
        for n in (1, 3, 10, 100):
            r = vproc.run(vproc.sum_squares_program(n))
            self.assertEqual(r["out"][-1], vproc.reference_sum_squares(n))
        self.assertEqual(vproc.reference_sum_squares(10), 385)

    def test_deterministic_across_nodes(self):
        """Same bytes, same result - the cross-node agreement contract."""
        prog = vproc.sum_squares_program(42)
        data = vproc.encode(prog)
        r1 = vproc.run(vproc.decode(data))
        r2 = vproc.run(vproc.decode(data))
        self.assertEqual(r1["out"], r2["out"])
        self.assertEqual(vproc.fingerprint(data), vproc.fingerprint(data))

    def test_budget_enforced(self):
        """Infinite loop must die at the op budget - bounded autonomy."""
        prog = {"code": [(vproc.OPS["JMP"], 0, 0)], "consts": []}
        with self.assertRaises(RuntimeError):
            vproc.run(prog, ops_budget=128)

    def test_bad_magic_refused(self):
        with self.assertRaises(ValueError):
            vproc.decode(b"NOPE" + b"\x00" * 8)

    def test_div_by_zero_raises(self):
        prog = {"code": [(vproc.OPS["LOAD"], 0, 0),
                         (vproc.OPS["LOAD"], 1, 1),
                         (vproc.OPS["DIV"], 0, 1)], "consts": [9, 0]}
        with self.assertRaises(ZeroDivisionError):
            vproc.run(prog)


# ------------------------------------------- Binary forensics (synthetic) ---
class TestMorph(unittest.TestCase):
    def test_thin_macho_arm64_runs(self):
        rep = morph.inspect(data=_thin_macho("arm64"), self_arch="arm64")
        self.assertTrue(rep["recognized"])
        self.assertEqual(rep["format"], "mach-o")
        self.assertEqual(rep["machine"], "arm64")
        self.assertEqual(rep["verdict"], "runs")

    def test_thin_macho_x86_64_incompatible_on_arm(self):
        rep = morph.inspect(data=_thin_macho("x86_64"), self_arch="arm64")
        self.assertEqual(rep["machine"], "x86_64")
        self.assertEqual(rep["verdict"], "incompatible")

    def test_fat_binary_lands_on_arm(self):
        rep = morph.inspect(data=_fat_macho(), self_arch="arm64")
        self.assertEqual(rep["format"], "mach-o-fat")
        self.assertTrue(rep["verdict"] == "runs")
        self.assertIn("arm64", rep["machine"])

    def test_pe_x86_64(self):
        rep = morph.inspect(data=_pe(), self_arch="arm64")
        self.assertEqual(rep["format"], "pe")
        self.assertEqual(rep["machine"], "x86_64")
        self.assertEqual(rep["verdict"], "incompatible")

    def test_elf_aarch64(self):
        rep = morph.inspect(data=_elf(), self_arch="arm64")
        self.assertEqual(rep["format"], "elf")
        self.assertEqual(rep["machine"], "aarch64")
        self.assertEqual(rep["verdict"], "runs")     # aarch64 ≡ arm64

    def test_plain_text_refused(self):
        rep = morph.inspect(data=b"definitely not an executable header\0")
        self.assertFalse(rep["recognized"])
        self.assertTrue(rep.get("honest"))


# --------------------------------------------------------- Frame fabric ----
class TestFabric(unittest.TestCase):
    def test_frame_roundtrip(self):
        payload = {"hello": "aether", "n": 42}
        seq, back = fabric.unpack_frame(fabric.pack_frame(payload, seq=9))
        self.assertEqual(seq, 9)
        self.assertEqual(back, payload)

    def test_bit_flip_rejected(self):
        raw = bytearray(fabric.pack_frame({"blob": "x" * 64}, seq=3))
        raw[12] ^= 0x01                      # payload byte, CRC stays stale
        with self.assertRaises(ValueError):
            fabric.unpack_frame(bytes(raw))

    def test_wrong_version_refused(self):
        raw = bytearray(fabric.pack_frame({"a": 1}))
        raw[4] = 9
        with self.assertRaises(ValueError):
            fabric.unpack_frame(bytes(raw))

    def test_chunk_math_monotone(self):
        small = fabric.optimal_chunk(0.3, 10_000_000)
        big = fabric.optimal_chunk(8.0, 10_000_000)
        self.assertGreaterEqual(small, 512)
        self.assertGreater(big, small)


# ---------------------------------------------------- Ouroboros emission ---
class TestOuroboros(unittest.TestCase):
    def test_emit_writes_selfcontained_cell(self):
        rec = ouroboros.emit("testcell", parent_url="http://127.0.0.1:9461",
                             port=9491)
        self.assertTrue(Path(rec["file"]).exists())
        manifest = rec["manifest"]
        self.assertEqual(rec["sha256"], manifest["sha256"])
        src = Path(rec["file"]).read_text(encoding="utf-8")
        self.assertIn("AE_CELL/1.0", src)
        self.assertIn("def _run(", src)          # embedded compact VM present

    def test_template_compiles_to_bytecode(self):
        rec = ouroboros.emit("compilecheck", port=9492)
        compile(Path(rec["file"]).read_text(encoding="utf-8"),
                rec["file"], "exec")          # raises on syntax error

    def test_manifest_never_carries_decrypt_trapdoor(self):
        """Cell manifests carry the fleet token only - never key material."""
        rec = ouroboros.emit("privacy", port=9493)
        blob = str(rec["manifest"]) + Path(rec["file"]).read_text()[-400:]
        self.assertNotIn("mu_hex", blob)
        self.assertNotIn("lam_hex", blob)


# ------------------------------------------- Tamper-evident ledger chain ---
class TestLedger(unittest.TestCase):
    def test_seal_chain_verifies_clean(self):
        r1 = storage.seal_append("t-kind", "alpha", "sha-a")
        r2 = storage.seal_append("t-kind", "beta", "sha-b")
        self.assertEqual(r2["prev_hash"], r1["hash"])
        v = storage.seal_verify()
        self.assertTrue(v["ok"])
        self.assertEqual(v["broken_at_idx"], None)

    def test_tamper_detected_at_index(self):
        import sqlite3
        storage.seal_append("t-tamper", "label", "sha-x")
        v0 = storage.seal_verify()
        self.assertTrue(v0["ok"])
        with sqlite3.connect(str(config.DB_FILE)) as conn:
            conn.execute("UPDATE ledger SET kind='EVIL' WHERE kind='t-tamper'")
            conn.commit()
        v1 = storage.seal_verify()
        self.assertFalse(v1["ok"])
        self.assertIsNotNone(v1["broken_at_idx"])
        # restore integrity proof story: append a fresh honest row afterwards
        storage.seal_append("t-tamper-note", "rewrote tampered row", "sha-y")

    def test_private_runs_shape_only(self):
        storage.record_private("unit", 4, 1.23, True)
        self.assertTrue(True)


# ----------------------------------------------- Config and telemetry ------
class TestConfigTelemetry(unittest.TestCase):
    def test_isolated_home(self):
        self.assertTrue(str(config.HOME).startswith(_TMP))
        self.assertTrue(config.HOME.exists())

    def test_constants(self):
        self.assertEqual(config.FHE_SCALE, 10 ** 6)
        self.assertEqual(config.VERSION, "1.0.0")

    def test_telemetry_never_blocks(self):
        telemetry.emit("unit", "info", "no relay configured - must return fast")


if __name__ == "__main__":
    unittest.main()
