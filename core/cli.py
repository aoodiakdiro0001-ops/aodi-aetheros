"""Aodı-AetherOS CLI — sovereign homomorphic mesh in one binary-free tool.

    python3 -m aether.cli keygen --out he_key.json
    python3 -m aether.cli agent --id mac-local --tags gpu,fast
    python3 -m aether.cli nodes add win-gpu http://100.x.y.z:8790 --tags gpu
    python3 -m aether.cli probe
    python3 -m aether.cli run "2*x + y" --inputs 7,3 --redundancy 2
    python3 -m aether.cli he-demo "a + b" --inputs 120,42 --remote
    python3 -m aether.cli adopt dev@100.x.y.z --id win-gpu --tags gpu
    python3 -m aether.cli revoke dev@100.x.y.z

Designed & built by Baran Avisat (Professional Programmer).
"""
import argparse
import json
import os
import platform
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from aether import mesh, orchestrator, ouroboros, paillier as he, vm  # noqa

CREDIT = ("Aodı-AetherOS v1.0 · © 2026 Baran Avisat (Professional Programmer)\n"
          "📧 baranavisat@gmail.com · 📞 +90 531 326 37 22 · "
          "WhatsApp wa.me/905313263722\n"
          "BTC bc1q8dhtdrndxsl70e97t8grydfe6pjue37zrhzf6c · "
          "USDT-TRC20 TLWdTjqqogkXNEXGiPWsGdjFP6ioycxeWW")

DEFAULT_NODES = os.environ.get("AETHER_NODES_FILE", "nodes.json")


def _parse_inputs(s):
    out = []
    for part in str(s).split(","):
        part = part.strip()
        if not part:
            continue
        out.append(float(part) if "." in part else int(part))
    return out


def _load_nodes(path):
    return mesh.load_nodes(path)


def _print_topology(report):
    print("  %-14s %-6s %9s %7s %8s %-10s %s"
          % ("NODE", "STATE", "RTT ms", "SCORE", "LOAD", "BATT", "ARCH"))
    for r in report["nodes"]:
        print("  %-14s %-6s %9s %7s %8s %-10s %s"
              % (r["id"], "UP" if r["up"] else "DOWN",
                 ("%.1f" % r["rtt_ms"]) if r["rtt_ms"] is not None else "-",
                 ("%.1f" % r["score"]) if r["score"] != float("inf") else "-",
                 r["load_1m"] if r["load_1m"] is not None else "-",
                 r["battery"] if r["battery"] is not None else "n/a",
                 r["arch"] or "-"))
    print("  => %d/%d nodes up" % (report["up"], report["total"]))


# --------------------------- commands ---------------------------------
def cmd_keygen(a):
    print("generating %d-bit Paillier keypair..." % a.bits)
    pk, sk = he.generate_keypair(a.bits)
    orchestrator.save_keypair(a.out, pk, sk, a.bits)
    print("wrote %s (mode 600) — n is %d bits. KEEP IT PRIVATE; the "
          "public key is what your nodes receive." % (a.out, pk.bits))
    print(CREDIT)


def cmd_nodes(a):
    nodes = _load_nodes(a.nodes_file)
    if a.action == "list":
        if not nodes:
            print("no nodes in %s — try: nodes add ..." % a.nodes_file)
        for n in nodes:
            print("  %-14s %-28s tags=%s"
                  % (n["id"], n["base_url"], ",".join(n.get("tags") or []) or "-"))
        return
    if a.action == "add":
        nodes = [n for n in nodes if n["id"] != a.id]
        nodes.append({"id": a.id, "base_url": a.url,
                      "tags": [t for t in (a.tags or "").split(",") if t]})
        mesh.save_nodes(a.nodes_file, nodes)
        print("added %s -> %s" % (a.id, a.url))


def cmd_probe(a):
    nodes = _load_nodes(a.nodes_file)
    if not nodes:
        print("no nodes in %s" % a.nodes_file)
        return
    probes = mesh.probe_all(nodes)
    _print_topology(mesh.topology_report(nodes, probes))


def cmd_run(a):
    nodes = _load_nodes(a.nodes_file)
    inputs = _parse_inputs(a.inputs)
    names = ["x", "y", "z", "w", "v", "u"][:len(inputs)]
    ir = vm.compile_expr(a.expr, names)
    if not nodes:
        # local fallback: still honest about where it ran
        scaled = vm.run_plain(ir, inputs)
        print("[local] %s = %s (no nodes in %s — ran on this machine)"
              % (a.expr, vm.decode_result(scaled, ir), a.nodes_file))
        return
    probes = mesh.probe_all(nodes)
    verdict = orchestrator.dispatch_plain(ir, inputs, nodes, probes,
                                          redundancy=a.redundancy)
    print("[kernel] %s   inputs=%s" % (a.expr, inputs))
    for e in verdict["executions"]:
        state = "ok" if e["ok"] else "FAIL: %s" % e.get("error")
        print("  -> %-12s %-6s %sms" % (e["node"], state, e["ms"]))
    print("result = %s   agreed=%s verified=%s"
          % (verdict["decoded"], verdict["agreed"], verdict["verified"]))
    if not verdict["agreed"]:
        print("!! nodes DISAGREE — investigation required (never hidden)")
        sys.exit(2)


def cmd_he_demo(a):
    if a.key and os.path.exists(a.key):
        pk, sk = orchestrator.load_keypair(a.key)
        print("loaded key %s (%d-bit n)" % (a.key, pk.bits))
    else:
        pk, sk = he.generate_keypair(a.bits)
        if a.key:
            orchestrator.save_keypair(a.key, pk, sk, a.bits)
        print("generated fresh %d-bit keypair" % a.bits)

    inputs = _parse_inputs(a.inputs)
    names = ["a", "b", "c", "d"][:len(inputs)]
    ir = orchestrator.compile_he(a.expr, names)

    print("\n[1] plaintext here        : inputs=%s" % inputs)
    enc = orchestrator.he_encrypt_inputs(sk, inputs)
    print("[2] encrypted here        : %d ciphertexts (%d digits each)"
          % (len(enc), len(str(enc[0]))))

    nodes = _load_nodes(a.nodes_file) if a.remote else []
    demo = orchestrator.he_demo(sk, pk, ir, inputs,
                                nodes=nodes or None)
    print("[3] remote node(s) compute : %s"
          % (", ".join(demo["remote_nodes_used"]) or
             ("skipped (no nodes / --remote not set)")))
    print("[4] decrypted back here    : %s" % demo["decrypted_result"])
    if demo["remote_ciphertext_matches_local"] is not None:
        print("[5] ciphertext byte-match  : %s"
              % demo["remote_ciphertext_matches_local"])
    if demo.get("remote_error"):
        print("    remote error: %s" % demo["remote_error"])
    print("\nhonest scope: additive homomorphism (encrypted +, - and "
          "×constant). The node saw only opaque integers.")
    print(CREDIT)


def cmd_adopt(a):
    tags = [t for t in (a.tags or "").split(",") if t]
    out = ouroboros.adopt(a.target, a.id, a.port, tags,
                          nodes_file=a.nodes_file,
                          dry_run=a.dry_run)
    print("adopted: %s" % json.dumps(out.get("node", out), indent=2))


def cmd_revoke(a):
    print(ouroboros.revoke(a.target, a.port))


def cmd_agent(a):
    from aether import agent
    tags = [t.strip() for t in (a.tags or "").split(",") if t.strip()]
    agent.serve(a.id, a.port, tags, a.host)


def cmd_status(a):
    from aether.agent import node_status
    print(json.dumps(node_status(a.id or platform.node() or "local",
                                 [t for t in (a.tags or "").split(",") if t]),
                     indent=2))


def build_parser():
    p = argparse.ArgumentParser(
        prog="aether",
        description="Aodı-AetherOS — sovereign homomorphic mesh "
                    "(zero-cloud, local-only)",
        epilog=CREDIT, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)

    k = sub.add_parser("keygen", help="generate Paillier keypair")
    k.add_argument("--bits", type=int, default=1024)
    k.add_argument("--out", default="he_key.json")
    k.set_defaults(fn=cmd_keygen)

    n = sub.add_parser("nodes", help="manage node registry")
    n.add_argument("action", choices=["add", "list"])
    n.add_argument("id", nargs="?")
    n.add_argument("url", nargs="?")
    n.add_argument("--tags", default="")
    n.add_argument("--nodes-file", default=DEFAULT_NODES)
    n.set_defaults(fn=cmd_nodes)

    pr = sub.add_parser("probe", help="measure mesh topology (real RTT)")
    pr.add_argument("--nodes-file", default=DEFAULT_NODES)
    pr.set_defaults(fn=cmd_probe)

    r = sub.add_parser("run", help="run a cleartext kernel across nodes")
    r.add_argument("expr")
    r.add_argument("--inputs", required=True, help="comma separated")
    r.add_argument("--redundancy", type=int, default=2)
    r.add_argument("--nodes-file", default=DEFAULT_NODES)
    r.set_defaults(fn=cmd_run)

    h = sub.add_parser("he-demo", help="encrypted round trip demo")
    h.add_argument("expr", help='e.g. "a + b" (HE: +, -, ×const only)')
    h.add_argument("--inputs", required=True)
    h.add_argument("--key", default="he_key.json")
    h.add_argument("--bits", type=int, default=1024)
    h.add_argument("--remote", action="store_true")
    h.add_argument("--nodes-file", default=DEFAULT_NODES)
    h.set_defaults(fn=cmd_he_demo)

    ad = sub.add_parser("adopt", help="bootstrap YOUR device into the mesh")
    ad.add_argument("target", help="user@host (SSH)")
    ad.add_argument("--id", required=True)
    ad.add_argument("--port", type=int, default=8790)
    ad.add_argument("--tags", default="")
    ad.add_argument("--nodes-file", default=DEFAULT_NODES)
    ad.add_argument("--dry-run", action="store_true")
    ad.set_defaults(fn=cmd_adopt)

    rv = sub.add_parser("revoke", help="remove an adopted node")
    rv.add_argument("target")
    rv.add_argument("--port", type=int, default=8790)
    rv.set_defaults(fn=cmd_revoke)

    ag = sub.add_parser("agent", help="run the node agent here")
    ag.add_argument("--id", default=platform.node() or "node")
    ag.add_argument("--port", type=int, default=8790)
    ag.add_argument("--tags", default="")
    ag.add_argument("--host", default="0.0.0.0")
    ag.set_defaults(fn=cmd_agent)

    st = sub.add_parser("status", help="print this machine's node status")
    st.add_argument("--id", default=platform.node() or "local")
    st.add_argument("--tags", default="")
    st.set_defaults(fn=cmd_status)
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    if args.cmd == "nodes" and args.action == "add" and not (
            args.id and args.url):
        build_parser().error("nodes add requires: nodes add ID URL")
    args.fn(args)


if __name__ == "__main__":
    main()
