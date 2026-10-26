"""Aodı-AetherOS 1.0.0 — core config & state (stdlib-only, zero deps)."""
import os
from pathlib import Path

VERSION = "1.0.0"
BRAND = "Aodı-AetherOS"

HOME = Path(os.environ.get("AE_HOME", str(Path.home() / ".aetheros")))
HOME.mkdir(parents=True, exist_ok=True)
DB_FILE = HOME / "aetheros.db"
KEY_DIR = HOME / "keys"
CELLS_DIR = HOME / "cells"
ARTIFACTS = HOME / "artifacts"

# Services (AetherOS binds its own address space)
DEFAULT_PORT = int(os.environ.get("AE_PORT", "9461"))          # hypervisor core
HUB_URL = os.environ.get("AE_HUB_URL", "http://127.0.0.1:9463")  # Go consensus hub
RELAY_URL = os.environ.get("AE_TELEGRAM_RELAY", "")             # optional notify

# Bounded autonomy (everything capped)
MAX_SPAWN_WAIT_S = int(os.environ.get("AE_SPAWN_WAIT", "10"))
MAX_CELLS = int(os.environ.get("AE_MAX_CELLS", "12"))
VM_OPS_BUDGET = int(os.environ.get("AE_VM_BUDGET", "4096"))
FHE_DEFAULT_BITS = int(os.environ.get("AE_FHE_BITS", "1024"))
FHE_SCALE = 10 ** 6           # fixed-point scale for the private linear kernel
FABRIC_BENCH_ITERS = int(os.environ.get("AE_FABRIC_ITERS", "400"))
MAX_MORPH_BYTES = 64 * 1024   # header-window forensics read cap

CONTACT = {
    "email": "baranavisat@gmail.com",
    "whatsapp": "+90 531 326 37 22",
    "whatsapp_url": "https://wa.me/905313263722",
    "github": "https://github.com/aoodiakdiro0001-ops",
    "btc": "bc1q8dhtdrndxsl70e97t8grydfe6pjue37zrhzf6c",
    "usdt": "TLWdTjqqogkXNEXGiPWsGdjFP6ioycxeWW",
}


def banner():
    return "\n".join([
        "=======================================================",
        f"  {BRAND} v{VERSION} — homomorphic neural hypervisor",
        "  paillier privacy · link-state consensus · avp vm",
        "  single-file self-replication · zero cloud",
        "=======================================================",
    ])


def save_json(path, data):
    import json
    path = Path(path)
    path.write_text(
        json.dumps(data, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")


def load_json(path, default=None):
    import json
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except Exception:
        return default
