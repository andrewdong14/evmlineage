// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// Gas measurements for the paper's cost tables.
//
//   forge test --isolate --match-contract GasTest -vv
//
// With --isolate, forge executes every top-level call of a test as its own
// transaction, so the figures include the 21,000 intrinsic gas and calldata,
// and storage is cold at the start of each call, as it is on a live chain.
// Without --isolate the test is skipped. Results are written to
// gas/gas-report.json.
//
// Inputs (test/fixtures):
//   membership_fixture.json  membership proofs exported by the Rust engine at
//                            several index sizes (bench index)
//   events_fixture.json      a sample of committed AE-TPCC events
//                            (bench fixture), replayed against the baselines

import "forge-std/Test.sol";
import "../src/LineageAnchor.sol";
import "../src/LineageProxy.sol";
import "../src/baselines/OnChainLineage.sol";
import "../src/baselines/PerEventAnchor.sol";

contract GasTest is Test {
    address admin      = address(0xA11CE);
    address committer  = address(0xC0117);
    address challenger = address(0xBEEF);
    string constant OUT = "./gas/gas-report.json";
    string constant R   = "report";

    function _anchor() internal returns (LineageAnchor a) {
        a = new LineageAnchor();
        a.initialise(admin, 0.1 ether);
        vm.deal(committer, 10 ether);
        vm.prank(committer);
        a.registerCommitter{value: 1 ether}();
    }

    /// Gas of the last top-level call, net of refunds.
    function _used() internal view returns (uint256) {
        Vm.Gas memory g = vm.lastCallGas();
        uint256 refund = g.gasRefunded > 0 ? uint256(uint64(g.gasRefunded)) : 0;
        return uint256(g.gasTotalUsed) - refund;
    }

    /// Intrinsic gas of a transaction with this calldata (Cancun rules).
    function _intrinsic(bytes memory data) internal pure returns (uint256 gas_) {
        gas_ = 21_000;
        for (uint256 i = 0; i < data.length; i++) gas_ += data[i] == 0 ? 4 : 16;
    }

    function _root(uint256 i) internal pure returns (bytes32) { return keccak256(abi.encode("root", i)); }
    function _blob(uint256 i) internal pure returns (bytes32) { return keccak256(abi.encode("blob", i)); }

    function _pair(bytes32 a, bytes32 b) internal pure returns (bytes32) {
        return a < b ? keccak256(abi.encodePacked(a, b)) : keccak256(abi.encodePacked(b, a));
    }

    function testGasReport() public {
        // Isolation check: in isolation mode a state-changing call is a
        // transaction of its own and costs at least the intrinsic gas.
        LineageAnchor probe = _anchor();
        vm.prank(admin);
        probe.setRequireBlobs(false);
        if (vm.lastCallGas().gasTotalUsed < 21_000) {
            vm.skip(true, "run with --isolate to measure whole-transaction gas");
        }
        _commit();
        _prune();
        _slash();
        _multisig();
        _proxy();
        _verify();
        _baselines();
        string memory out = vm.serializeUint(R, "isolated", 1);
        vm.writeJson(out, OUT);
    }

    // ── commitRoot ──────────────────────────────────────────────────────

    function _commit() internal {
        LineageAnchor a = _anchor();
        vm.prank(committer);
        a.commitRoot(_root(0), 0, _blob(0));
        vm.serializeUint(R, "commit_first", _used());

        uint256 sum;
        uint256 lo = type(uint256).max;
        uint256 hi;
        for (uint64 e = 1; e <= 8; e++) {
            vm.prank(committer);
            a.commitRoot(_root(e), e, _blob(e));
            uint256 g = _used();
            sum += g;
            if (g < lo) lo = g;
            if (g > hi) hi = g;
        }
        vm.serializeUint(R, "commit_steady", sum / 8);
        vm.serializeUint(R, "commit_steady_min", lo);
        vm.serializeUint(R, "commit_steady_max", hi);
        vm.serializeUint(R, "commit_intrinsic", _intrinsic(
            abi.encodeCall(LineageAnchor.commitRoot, (_root(1), 1, _blob(1)))));
        // (A commit that carries its payload as a blob is measured on a
        // devnet with a real type-3 transaction: scripts/devnet_gas.sh.)
    }

    // ── commitPruneRoot ─────────────────────────────────────────────────

    function _prune() internal {
        LineageAnchor a = _anchor();
        vm.prank(committer);
        a.commitPruneRoot(0, _root(100));
        vm.serializeUint(R, "prune_first", _used());
        vm.prank(committer);
        a.commitPruneRoot(1, _root(101));
        vm.serializeUint(R, "prune_steady", _used());
    }

    // ── slash (two membership paths of 30 hashes each) ──────────────────

    function _slash() internal {
        LineageAnchor a = _anchor();
        bytes32 v  = keccak256("equivocating vertex");
        bytes32 dA = keccak256("record A");
        bytes32 dB = keccak256("record B");
        bytes32 lA = a.leafOf(v, dA);
        bytes32 lB = a.leafOf(v, dB);
        bytes32[] memory pA = new bytes32[](30);
        bytes32[] memory pB = new bytes32[](30);
        pA[0] = lB;
        pB[0] = lA;
        bytes32 node = _pair(lA, lB);
        for (uint256 i = 1; i < 30; i++) {
            bytes32 sib = keccak256(abi.encode("sibling", i));
            pA[i] = sib;
            pB[i] = sib;
            node = _pair(node, sib);
        }
        vm.prank(committer);
        a.commitRoot(node, 0, _blob(0));
        vm.deal(challenger, 1 ether);
        vm.prank(challenger);
        a.slash(v, dA, pA, dB, pB, 0);
        vm.serializeUint(R, "slash_two_paths_of_30", _used());
        require(a.isSlashed(committer), "slash must succeed");
    }

    // ── commit through the 3-of-5 multisig ──────────────────────────────

    function _multisig() internal {
        address[] memory owners = new address[](5);
        for (uint160 i = 0; i < 5; i++) owners[i] = address(0x1000 + i);
        LineageMultisig ms = new LineageMultisig(owners);
        LineageAnchor a = new LineageAnchor();
        a.initialise(admin, 0.1 ether);
        vm.deal(address(this), 1 ether);
        a.registerCommitterFor{value: 0.5 ether}(address(ms));

        uint256 total;
        for (uint64 e = 0; e < 2; e++) {           // epoch 0 warms up, epoch 1 is measured
            total = 0;
            bytes memory call_ = abi.encodeCall(LineageAnchor.commitRoot, (_root(e), e, _blob(e)));
            vm.prank(owners[0]);
            bytes32 id = ms.submit(address(a), call_);
            uint256 g = _used(); total += g;
            if (e == 1) vm.serializeUint(R, "multisig_submit", g);
            for (uint256 k = 0; k < 3; k++) {
                vm.prank(owners[k]);
                ms.approve(id);
                g = _used(); total += g;
                if (e == 1 && k == 1) vm.serializeUint(R, "multisig_approve", g);
            }
            vm.prank(owners[3]);
            ms.execute(id);
            g = _used(); total += g;
            if (e == 1) vm.serializeUint(R, "multisig_execute", g);
        }
        vm.serializeUint(R, "multisig_total", total);
        require(a.epochCommitter(1) == address(ms), "committed by the multisig");
    }

    // ── commit through the EIP-1967 proxy ───────────────────────────────

    function _proxy() internal {
        LineageAnchor impl = new LineageAnchor();
        LineageProxy proxy = new LineageProxy(
            address(impl), admin, abi.encodeCall(LineageAnchor.initialise, (admin, 0.1 ether)));
        LineageAnchor a = LineageAnchor(payable(address(proxy)));
        vm.deal(committer, 10 ether);
        vm.prank(committer);
        a.registerCommitter{value: 1 ether}();
        vm.prank(committer);
        a.commitRoot(_root(0), 0, _blob(0));
        vm.prank(committer);
        a.commitRoot(_root(1), 1, _blob(1));
        vm.serializeUint(R, "proxy_commit_steady", _used());
    }

    // ── verifyProof on proofs exported by the engine ────────────────────

    struct VerifyAcc {
        uint256[] events;
        uint256[] vertices;
        uint256[] pathLen;
        uint256[] intrinsic;
        uint256[] exec;
        uint256[] logTx;
        bytes32 lastRoot;
        uint64  epoch;
        bool    any;
    }

    function _verify() internal {
        string memory json = vm.readFile("./test/fixtures/membership_fixture.json");
        uint256 n = vm.parseJsonUint(json, ".count");
        uint256[] memory events = new uint256[](n);
        VerifyAcc memory acc;
        acc.events   = events;
        acc.vertices = new uint256[](n);
        acc.pathLen  = new uint256[](n);
        acc.intrinsic = new uint256[](n);
        acc.exec     = new uint256[](n);
        acc.logTx    = new uint256[](n);
        LineageAnchor a = _anchor();
        for (uint256 i = 0; i < n; i++) _verifyCase(a, json, i, acc);

        string memory V = "verify";
        vm.serializeUint(V, "events", acc.events);
        vm.serializeUint(V, "vertices", acc.vertices);
        vm.serializeUint(V, "path_len", acc.pathLen);
        vm.serializeUint(V, "log_intrinsic", acc.intrinsic);
        vm.serializeUint(V, "exec", acc.exec);
        string memory vjson = vm.serializeUint(V, "log_tx", acc.logTx);
        vm.serializeString(R, "verify", vjson);
    }

    function _verifyCase(LineageAnchor a, string memory json, uint256 i, VerifyAcc memory acc)
        internal
    {
        string memory k = string.concat(".cases[", vm.toString(i), "]");
        bytes32 root = vm.parseJsonBytes32(json, string.concat(k, ".root"));
        bytes32 leaf = vm.parseJsonBytes32(json, string.concat(k, ".leaf"));
        bytes32[] memory path = vm.parseJsonBytes32Array(json, string.concat(k, ".path"));
        acc.events[i]   = vm.parseJsonUint(json, string.concat(k, ".events"));
        acc.vertices[i] = vm.parseJsonUint(json, string.concat(k, ".vertices"));
        acc.pathLen[i]  = path.length;
        if (!acc.any || root != acc.lastRoot) {     // one epoch per distinct root
            if (acc.any) acc.epoch += 1;
            vm.prank(committer);
            a.commitRoot(root, acc.epoch, _blob(acc.epoch));
            acc.lastRoot = root;
            acc.any = true;
        }
        // The view function, as another contract would call it: execution
        // gas of the call frame with the root slot cold.
        vm.cool(address(a));
        bool ok = a.verifyProof(leaf, path, acc.epoch);
        acc.exec[i] = _used();
        require(ok, "engine proof must verify on-chain");
        // The same check as a transaction of its own (with an event).
        a.verifyProofAndLog(leaf, path, acc.epoch);
        acc.logTx[i] = _used();
        acc.intrinsic[i] = _intrinsic(
            abi.encodeCall(a.verifyProofAndLog, (leaf, path, acc.epoch)));
    }

    // ── baselines: the same events written on-chain ─────────────────────

    function _baselines() internal {
        string memory json = vm.readFile("./test/fixtures/events_fixture.json");
        uint256 n = vm.parseJsonUint(json, ".count");
        OnChainLineage full = new OnChainLineage();
        PerEventAnchor per  = new PerEventAnchor();
        uint256[4] memory f;      // total, min, max, edges
        uint256[3] memory p;      // total, min, max
        f[1] = type(uint256).max;
        p[1] = type(uint256).max;
        uint256 hashes;
        for (uint256 i = 0; i < n; i++) {
            string memory k = string.concat(".events[", vm.toString(i), "]");
            bytes32[] memory s = vm.parseJsonBytes32Array(json, string.concat(k, ".s"));
            bytes32[] memory t = vm.parseJsonBytes32Array(json, string.concat(k, ".t"));
            hashes += s.length + t.length;
            f[3] += s.length * t.length;
            full.record(s, t);
            uint256 g = _used();
            f[0] += g; if (g < f[1]) f[1] = g; if (g > f[2]) f[2] = g;
            per.record(s, t);
            g = _used();
            p[0] += g; if (g < p[1]) p[1] = g; if (g > p[2]) p[2] = g;
        }
        string memory B = "baseline";
        vm.serializeUint(B, "events", n);
        vm.serializeUint(B, "hashes", hashes);
        vm.serializeUint(B, "edges", f[3]);
        vm.serializeUint(B, "onchain_total", f[0]);
        vm.serializeUint(B, "onchain_min", f[1]);
        vm.serializeUint(B, "onchain_max", f[2]);
        vm.serializeUint(B, "perevent_total", p[0]);
        vm.serializeUint(B, "perevent_min", p[1]);
        string memory bjson = vm.serializeUint(B, "perevent_max", p[2]);
        vm.serializeString(R, "baseline", bjson);
    }
}
