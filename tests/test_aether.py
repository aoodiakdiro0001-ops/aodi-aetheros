"""Offline test suite for Aodı-AetherOS (no network, no key files).

Run:  python3 tests/test_aether.py -v
"""
import json
import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "core"))

from aether import agent, mesh, orchestrator, paillier as he, vm  # noqa


class TestPaillier(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pk, cls.sk = he.generate_keypair(512)   # small = fast tests

    def test_roundtrip_and_sign(self):
        for m in (0, 1, 42, 123456789, -7, -99999):
            c = he.encrypt(self.pk, m)
            self.assertEqual(he.decrypt_signed(self.sk, c), m)

    def test_homomorphic_add_sub_scalar(self):
        a, b, k = 1234, -567, 7
        ca, cb = he.encrypt(self.pk, a), he.encrypt(self.pk, b)
        self.assertEqual(he.decrypt_signed(self.sk, he.add(self.pk, ca, cb)),
                         a + b)
        self.assertEqual(he.decrypt_signed(self.sk, he.sub(self.pk, ca, cb)),
                         a - b)
        self.assertEqual(
            he.decrypt_signed(self.sk, he.scalar_mul(self.pk, ca, k)), a * k)
        self.assertEqual(
            he.decrypt_signed(self.sk, he.add_many(self.pk, [ca, cb, ca])),
            a + b + a)

    def test_float_helpers(self):
        x, y = 12.5, -3.25
        cx, cy = he.enc_float(self.pk, x), he.enc_float(self.pk, y)
        total = he.add(self.pk, cx, cy)
        self.assertAlmostEqual(he.dec_float(self.sk, total), x + y, places=4)

    def test_rejects_non_int(self):
        with self.assertRaises(TypeError):
            he.encrypt(self.pk, 1.5)

    def test_key_serialization(self):
        pk2 = he.PublicKey.from_dict(self.pk.to_dict())
        sk2 = he.SecretKey.from_dict(self.sk.to_dict())
        m = 777
        self.assertEqual(he.decrypt_signed(sk2, he.encrypt(pk2, m)), m)


class TestVM(unittest.TestCase):
    def test_compile_and_plain_run(self):
        ir = vm.compile_expr("2 * x + y - 0.5", ["x", "y"])
        out = vm.run_plain_decoded(ir, [7, 3])
        self.assertAlmostEqual(out, 2 * 7 + 3 - 0.5, places=5)

    def test_fixed_point_mul_div(self):
        ir = vm.compile_expr("x * y", ["x", "y"])
        self.assertAlmostEqual(vm.run_plain_decoded(ir, [1.5, 4]), 6.0,
                               places=5)
        ir2 = vm.compile_expr("x / 4", ["x"])
        self.assertAlmostEqual(vm.run_plain_decoded(ir2, [10]), 2.5,
                               places=5)

    def test_compile_rejects_dangerous_input(self):
        for bad in ("__import__('os').system('ls')", "x.__class__",
                    "open('f')", "x ** 2", "f'{x}'", "lambda: 1"):
            with self.assertRaises(vm.CompileError, msg=bad):
                vm.compile_expr(bad, ["x"])

    def test_unknown_name_rejected(self):
        with self.assertRaises(vm.CompileError):
            vm.compile_expr("x + secret", ["x"])

    def test_he_compatible_matrix(self):
        ok = vm.compile_expr("3 * x + 10 * y - 5", ["x", "y"], scale=1)
        self.assertEqual(vm.check_he_compatible(ok), [])
        bad = vm.compile_expr("x * y", ["x", "y"], scale=1)
        self.assertTrue(vm.check_he_compatible(bad))
        div = vm.compile_expr("x / 2", ["x"], scale=1)
        self.assertTrue(vm.check_he_compatible(div))

    def test_he_execution_matches_plain(self):
        pk, sk = he.generate_keypair(512)
        cases = [("3 * a + 7 * b - 2", ["a", "b"], [11, -4]),
                 ("a + 100", ["a"], [5]),
                 ("100 - a", ["a"], [5]),
                 ("-a + b", ["a", "b"], [7, 3]),
                 ("a * 6", ["a"], [-2])]
        for expr, names, values in cases:
            ir = vm.compile_expr(expr, names, scale=1)
            self.assertEqual(vm.check_he_compatible(ir), [], expr)
            cts = [he.encrypt(pk, v) for v in values]
            out_ct = vm.run_he(pk, sk, ir, cts)
            he_val = he.decrypt_signed(sk, out_ct)
            plain = vm.run_plain(ir, values)
            self.assertEqual(he_val, plain, expr)
            self.assertEqual(he_val,
                             vm.run_plain(
                                 vm.compile_expr(expr, names, scale=1),
                                 values), expr)

    def test_he_rejects_non_homomorphic(self):
        pk, sk = he.generate_keypair(512)
        ir = vm.compile_expr("x * y", ["x", "y"], scale=1)
        cts = [he.encrypt(pk, 2), he.encrypt(pk, 3)]
        with self.assertRaises(vm.ExecError):
            vm.run_he(pk, sk, ir, cts)

    def test_he_rejects_scaling(self):
        pk, sk = he.generate_keypair(512)
        ir = vm.compile_expr("2 * x", ["x"])       # scale = 10^6
        with self.assertRaises(vm.ExecError):
            vm.run_he(pk, sk, ir, [he.encrypt(pk, 5)])

    def test_ir_json_roundtrip(self):
        ir = vm.compile_expr("x + 1", ["x"])
        ir2 = vm.ir_from_json(vm.ir_to_json(ir))
        self.assertEqual(ir2["ops"], ir["ops"])
        with self.assertRaises(vm.CompileError):
            vm.ir_from_json("not json")


class TestMesh(unittest.TestCase):
    def _nodes(self):
        return [{"id": "mac", "base_url": "http://127.0.0.1:1", "tags": []},
                {"id": "win", "base_url": "http://127.0.0.1:2",
                 "tags": ["gpu"]}]

    def test_dead_node_scores_infinite(self):
        s = mesh.score_node(self._nodes()[0], {"ok": False})
        self.assertEqual(s, float("inf"))

    def test_battery_penalty_and_tag_reward(self):
        n = self._nodes()[1]
        low = mesh.score_node(
            n, {"ok": True, "rtt_ms": 20.0,
                "status": {"load_1m": 0.5, "battery": 15, "tags": ["gpu"]}},
            job_tags=["gpu"])
        high = mesh.score_node(
            n, {"ok": True, "rtt_ms": 20.0,
                "status": {"load_1m": 0.5, "battery": 80, "tags": ["gpu"]}},
            job_tags=["gpu"])
        self.assertGreater(low, high)       # dying battery hurts more
        nomatch = mesh.score_node(
            n, {"ok": True, "rtt_ms": 20.0,
                "status": {"load_1m": 0.5, "battery": 80, "tags": ["gpu"]}},
            job_tags=["fpga"])
        self.assertGreater(nomatch, high)   # missing capability costs

    def test_schedule_orders_alive_first(self):
        nodes = self._nodes()
        probes = {"mac": {"ok": True, "rtt_ms": 5.0, "status": {"load_1m": 0.1}},
                  "win": {"ok": False}}
        ranked = mesh.schedule(nodes, probes, top_k=2)
        self.assertEqual(ranked[0]["node"]["id"], "mac")
        self.assertEqual(ranked[1]["score"], float("inf"))

    def test_run_verified_agreement(self):
        nodes = self._nodes()
        probes = {"mac": {"ok": True, "rtt_ms": 5.0, "status": {}},
                  "win": {"ok": True, "rtt_ms": 9.0, "status": {}}}
        out = mesh.run_verified(lambda n: 42, nodes, probes, redundancy=2)
        self.assertTrue(out["agreed"] and out["verified"])
        self.assertEqual(out["result"], 42)
        self.assertEqual(len(out["executions"]), 2)

    def test_run_verified_failover_and_disagreement(self):
        nodes = self._nodes()
        probes = {"mac": {"ok": True, "rtt_ms": 5.0, "status": {}},
                  "win": {"ok": True, "rtt_ms": 9.0, "status": {}}}

        def flaky(n):
            if n["id"] == "mac":
                raise RuntimeError("boom")
            return "ok-from-" + n["id"]

        out = mesh.run_verified(flaky, nodes, probes, redundancy=1)
        self.assertEqual(out["result"], "ok-from-win")
        self.assertFalse([e for e in out["executions"]
                          if e["node"] == "mac" and e["ok"]])
        # disagreement detection
        out2 = mesh.run_verified(lambda n: n["id"], nodes, probes,
                                 redundancy=2)
        self.assertFalse(out2["agreed"])

    def test_no_live_node_raises(self):
        nodes = self._nodes()
        probes = {"mac": {"ok": False}, "win": {"ok": False}}
        with self.assertRaises(RuntimeError):
            mesh.run_verified(lambda n: 1, nodes, probes)

    def test_topology_report(self):
        nodes = self._nodes()
        probes = {"mac": {"ok": True, "rtt_ms": 5.0,
                          "status": {"arch": "arm64", "load_1m": 0.2}},
                  "win": {"ok": False, "err": "down"}}
        rep = mesh.topology_report(nodes, probes)
        self.assertEqual((rep["up"], rep["total"]), (1, 2))
        self.assertEqual(rep["nodes"][0]["id"], "mac")


class TestAgent(unittest.TestCase):
    def test_status_fields_are_honest(self):
        st = agent.node_status("test-node", ["gpu"])
        self.assertEqual(st["id"], "test-node")
        self.assertTrue(st["battery"] is None
                        or 0 <= st["battery"] <= 100)   # honest null/real
        self.assertIsInstance(st["arch"], str)
        self.assertGreater(st["uptime_s"], -1)

    def test_execute_plain_job(self):
        ir = vm.compile_expr("2 * x + 1", ["x"])
        out = agent.execute_job({"mode": "plain", "ir": ir, "inputs": [10]})
        self.assertEqual(out["scaled"], int(2 * 10 * vm.SCALE + vm.SCALE))
        self.assertAlmostEqual(out["value"], 21.0, places=5)

    def test_execute_he_job_without_secret_key(self):
        pk, sk = he.generate_keypair(512)
        ir = vm.compile_expr("a + b", ["a", "b"], scale=1)
        cts = [he.encrypt(pk, 5), he.encrypt(pk, 7)]
        out = agent.execute_job({"mode": "he", "ir": ir, "pk": pk.to_dict(),
                                 "ciphertexts": [str(c) for c in cts]})
        self.assertIn("ciphertext", out)
        # the agent had NO sk: only the owner can decrypt
        self.assertEqual(
            he.decrypt_signed(sk, int(out["ciphertext"])), 12)

    def test_bad_jobs_rejected(self):
        with self.assertRaises(ValueError):
            agent.execute_job({"mode": "nope", "ir": {"ops": []}})
        with self.assertRaises(Exception):
            agent.execute_job({"mode": "plain"})   # missing ir


class TestOrchestrator(unittest.TestCase):
    def test_he_demo_local_roundtrip(self):
        pk, sk = he.generate_keypair(512)
        ir = orchestrator.compile_he("a + b", ["a", "b"])
        demo = orchestrator.he_demo(sk, pk, ir, [120, 42])
        self.assertEqual(demo["decrypted_result"], 162)
        self.assertIsNone(demo["remote_ciphertext_matches_local"])

    def test_keypair_file_roundtrip(self):
        pk, sk = he.generate_keypair(512)
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "k.json")
            orchestrator.save_keypair(path, pk, sk, 512)
            pk2, sk2 = orchestrator.load_keypair(path)
            self.assertEqual(he.decrypt_signed(sk2, he.encrypt(pk2, 9)), 9)
            mode = os.stat(path).st_mode & 0o777
            self.assertEqual(mode, 0o600)

    def test_dispatch_plain_local_server(self):
        """End-to-end: real HTTP agent on an ephemeral port."""
        import threading
        from http.server import ThreadingHTTPServer
        from aether.agent import Handler
        Handler.node_id, Handler.tags = "local-test", []
        srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        port = srv.server_address[1]
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()
        try:
            nodes = [{"id": "local-test",
                      "base_url": "http://127.0.0.1:%d" % port, "tags": []}]
            ir = vm.compile_expr("x * x + 1", ["x"])
            verdict = orchestrator.dispatch_plain(ir, [9], nodes,
                                                  redundancy=1)
            self.assertTrue(verdict["agreed"])
            self.assertEqual(len(verdict["executions"]), 1)
            self.assertAlmostEqual(verdict["decoded"], 82.0, places=5)
        finally:
            srv.shutdown()
            srv.server_close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
