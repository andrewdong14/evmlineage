#!/usr/bin/env python3
"""
devnet_gas.py — commitRoot on a local Anvil devnet, with real transactions.

Cross-checks the Foundry gas test (contracts/test/Gas.t.sol) against
transaction receipts and exercises the one path that the test cannot: a
type-3 (EIP-4844) transaction that carries an epoch payload as a blob while
the contract checks the committed hash against BLOBHASH.

What it does
  1. starts `anvil --hardfork cancun`;
  2. deploys LineageAnchor, initialises it and stakes a committer;
  3. builds one real epoch with the Python reference (256 AE-TPCC events),
     giving a real EPSL root and a real payload;
  4. commits epochs without blobs and records gasUsed from the receipts;
  5. sends the payload once to learn its versioned blob hash, then commits
     the epoch root in a blob-carrying transaction with that hash, and
     checks that a wrong hash is rejected;
  6. writes contracts/gas/devnet-report.json.

Requirements: anvil, cast and forge (Foundry) on PATH. The two private keys
below are Anvil's published test keys; they hold no value anywhere.

    python3 scripts/devnet_gas.py
"""
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "agent"))
from evm_lineage import AeTpcc, Bcp, BlobPipeline, Epsl          # noqa: E402

PORT = int(os.environ.get("ANVIL_PORT", "8547"))
RPC  = f"http://127.0.0.1:{PORT}"
K0   = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"   # Anvil account 0
K1   = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"   # Anvil account 1
A0   = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
SINK = "0x000000000000000000000000000000000000dEaD"


def run(cmd, check=True, cwd=None):
    p = subprocess.run(cmd, capture_output=True, text=True, cwd=cwd)
    if check and p.returncode != 0:
        raise RuntimeError(f"{' '.join(cmd[:3])} ... failed:\n{p.stdout}\n{p.stderr}")
    return p


def send(to, sig, args, key, extra=()):
    cmd = ["cast", "send", to] + ([sig] if sig else []) + list(args) + \
          ["--rpc-url", RPC, "--private-key", key, "--json"] + list(extra)
    return json.loads(run(cmd).stdout)


def as_int(x):
    return int(x, 16) if isinstance(x, str) and x.startswith("0x") else int(x)


def main():
    anvil = subprocess.Popen(["anvil", "--hardfork", "cancun", "--port", str(PORT), "--silent"])
    try:
        for _ in range(100):
            if run(["cast", "block-number", "--rpc-url", RPC], check=False).returncode == 0:
                break
            time.sleep(0.1)
        else:
            raise RuntimeError("anvil did not start")

        out = run(["forge", "create", "src/LineageAnchor.sol:LineageAnchor", "--rpc-url", RPC,
                   "--private-key", K0, "--broadcast", "--json"], cwd=ROOT / "contracts").stdout
        anchor = json.loads(out[out.index("{"):])["deployedTo"]
        send(anchor, "initialise(address,uint256)", [A0, "100000000000000000"], K0)
        send(anchor, "registerCommitter()", [], K1, ["--value", "1ether"])

        # One real epoch from the reference implementation.
        epsl = Epsl()
        bcp = Bcp(epsl, BlobPipeline(keep_payloads=True), epoch_size=256)
        wl = AeTpcc(seed=42, beta=1)
        while bcp.committed_epochs < 5:
            ev = wl.next_event()
            bcp.write_direct(ev.sources, ev.targets, 0)
        commits = bcp.commits
        payload = bcp._blob.payload(4)

        # Epochs 0..3 without blobs (the data hash is the dry-run commitment).
        plain = []
        for c in commits[:4]:
            r = send(anchor, "commitRoot(bytes32,uint64,bytes32)",
                     ["0x" + c.root.hex(), str(c.epoch), "0x" + c.data_hash.hex()], K1)
            assert as_int(r["status"]) == 1
            plain.append(as_int(r["gasUsed"]))

        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
            f.write(payload)
            path = f.name
        # Learn the versioned hash of the blob that carries this payload.
        probe = send(SINK, None, [], K0, ["--blob", "--path", path])
        tx = json.loads(run(["cast", "tx", probe["transactionHash"], "--rpc-url", RPC, "--json"]).stdout)
        vhash = tx["blobVersionedHashes"][0]
        assert len(tx["blobVersionedHashes"]) == 1 and vhash.startswith("0x01")

        c = commits[4]
        wrong = run(["cast", "send", anchor, "commitRoot(bytes32,uint64,bytes32)",
                     "0x" + c.root.hex(), str(c.epoch), "0x" + c.data_hash.hex(),
                     "--rpc-url", RPC, "--private-key", K1, "--blob", "--path", path, "--json"],
                    check=False)
        rejected = wrong.returncode != 0 or as_int(json.loads(wrong.stdout)["status"]) == 0
        r = send(anchor, "commitRoot(bytes32,uint64,bytes32)",
                 ["0x" + c.root.hex(), str(c.epoch), vhash], K1, ["--blob", "--path", path])
        assert as_int(r["status"]) == 1
        stored = run(["cast", "call", anchor, "epochBlobHash(uint64)(bytes32)", str(c.epoch),
                      "--rpc-url", RPC]).stdout.strip()
        root_on_chain = run(["cast", "call", anchor, "epochRoot(uint64)(bytes32)", str(c.epoch),
                             "--rpc-url", RPC]).stdout.strip()
        os.unlink(path)

        report = {
            "chain": "anvil, hardfork cancun",
            "anvil_version": run(["anvil", "--version"]).stdout.split("\n")[0],
            "commit_gas_no_blob": plain,
            "commit_gas_with_blob": as_int(r["gasUsed"]),
            "blob_gas_used": as_int(r["blobGasUsed"]),
            "blob_gas_price_wei": as_int(r["blobGasPrice"]),
            "payload_bytes": len(payload),
            "payload_events": c.event_count,
            "blob_versioned_hash": vhash,
            "blob_hash_stored_matches": stored.lower() == vhash.lower(),
            "root_stored_matches": root_on_chain.lower() == "0x" + c.root.hex(),
            "wrong_blob_hash_rejected": rejected,
        }
        (ROOT / "contracts" / "gas").mkdir(exist_ok=True)
        (ROOT / "contracts" / "gas" / "devnet-report.json").write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps(report, indent=2))
    finally:
        anvil.terminate()
        anvil.wait()


if __name__ == "__main__":
    main()
