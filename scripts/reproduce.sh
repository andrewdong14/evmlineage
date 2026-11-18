#!/usr/bin/env bash
# reproduce.sh — run every test suite and every measurement behind the paper,
# then regenerate results/results.tex.
#
#   scripts/reproduce.sh                  everything (about 20 minutes, 4 GB of memory)
#   RUNS=3 scripts/reproduce.sh           repeat the index run three times and
#                                         report the run-to-run spread of sealing
#   EVENTS=100000 scripts/reproduce.sh    smaller index run (0.6 GB)
#
# Needs: python3, cargo (Rust 1.75+), forge (Foundry) with forge-std in
# contracts/lib. anvil and cast are only needed for the optional devnet
# check. Run it on an otherwise idle machine: the engine benchmarks are
# timing measurements.
set -euo pipefail
cd "$(dirname "$0")/.."
EVENTS=${EVENTS:-1000000}
RUNS=${RUNS:-1}
WRITE_TX=${WRITE_TX:-200000}              # transactions of the write-path and payload runs
RETAIN_EVENTS=${RETAIN_EVENTS:-100000}    # events of the retention run
CHECKPOINTS=1000,3000,10000,30000,100000,300000,1000000
REPLAY_EVENTS=$(( EVENTS < 300032 ? EVENTS : 300032 ))

echo "== Python reference tests"
python3 agent/evm_lineage.py | tail -n 2
python3 agent/evm_lineage.py --vectors testvectors/conformance.json

echo "== Rust engine tests (unit + conformance)"
(cd engine && cargo test --release 2>&1 | grep "test result")

echo "== Contract tests"
(cd contracts && forge test | tail -n 3)

echo "== Engine benchmarks"
(cd engine && cargo build --release --quiet)
BENCH=engine/target/release/bench
rm -f results/index_run*.json
$BENCH hash --out results
for i in $(seq 1 "$RUNS"); do
  # --replay-max 0: the replay baseline would keep all payloads in memory
  $BENCH index --events "$EVENTS" --checkpoints "$CHECKPOINTS" --queries 300 \
               --retain 8 --replay-max 0 --out results
  cp results/index.json "results/index_run$i.json"
done
mv results/membership_fixture.json contracts/test/fixtures/membership_fixture.json

# Replay baseline: a shorter run of the same event stream that keeps the payloads.
mkdir -p results/replay
$BENCH index --events "$REPLAY_EVENTS" --checkpoints "$CHECKPOINTS" --queries 300 \
             --retain 8 --replay-max "$REPLAY_EVENTS" --out results/replay
mv results/replay/index.json results/index_replay.json
rm -f results/replay/membership_fixture.json
rmdir results/replay

$BENCH retain  --events "$RETAIN_EVENTS" --retains 1,2,4,8,16,32 --out results
$BENCH write   --tx "$WRITE_TX" --betas 1,2,4,8 --out results
$BENCH payload --tx "$WRITE_TX" --ws 64,128,256,512,1024,2048 --out results
$BENCH fixture --out contracts/test/fixtures

echo "== Gas report (each call is its own transaction)"
(cd contracts && forge test --isolate --match-contract GasTest | tail -n 3)
cp contracts/gas/gas-report.json results/

if command -v anvil >/dev/null && command -v cast >/dev/null; then
  echo "== Devnet check with a blob-carrying commit"
  python3 scripts/devnet_gas.py > /dev/null
  cp contracts/gas/devnet-report.json results/
else
  echo "== Devnet check skipped (anvil and cast not found); keeping results/devnet-report.json"
fi

echo "== Tool versions"
python3 - <<'PY'
import json, re, subprocess
def version(cmd):
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=30).stdout.strip()
        return out.splitlines()[0] if out else None
    except Exception:
        return None
tools = {name: version(cmd) for name, cmd in {
    "python": ["python3", "--version"], "rustc": ["rustc", "--version"],
    "cargo": ["cargo", "--version"], "forge": ["forge", "--version"],
    "anvil": ["anvil", "--version"], "cast": ["cast", "--version"]}.items()}
toml = open("contracts/foundry.toml").read()
m = re.search(r'solc(?:_version)?\s*=\s*"([^"]+)"', toml)
tools["solc"] = m.group(1) if m else None
json.dump(tools, open("results/toolchain.json", "w"), indent=2)
print(json.dumps(tools, indent=2))
PY

echo "== LaTeX macros"
python3 scripts/paper_numbers.py
