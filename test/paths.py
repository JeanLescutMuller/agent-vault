"""Where the vault's tests find the code and where they write. Every path can be moved with the environment:
AV_REPO (this repo; default: the parent of test/), AV_RUNS (the run folders; default test/runs/, gitignored).
Reads and writes nothing itself."""
import os
import time

HERE = os.path.dirname(os.path.abspath(__file__))
AV = os.environ.get("AV_REPO") or os.path.dirname(HERE)
RUNS = os.environ.get("AV_RUNS") or os.path.join(HERE, "runs")
BW_STUB = os.path.join(HERE, "fakes", "bw_stub.py")


def run_dir(kind):
    """A fresh folder for one run: test/runs/<kind>-<YYYYmmdd-HHMMSS>/ (kept for reading afterwards)."""
    d = os.path.join(RUNS, f"{kind}-{time.strftime('%Y%m%d-%H%M%S')}")
    os.makedirs(d, exist_ok=True)
    return d
