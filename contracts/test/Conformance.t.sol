// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// Proofs produced by the off-chain layers must verify on the contract.
// The vectors come from the Python reference
// (python3 agent/evm_lineage.py --vectors testvectors/conformance.json);
// the Rust engine reproduces them byte for byte (engine/tests/conformance.rs).

import "forge-std/Test.sol";
import "../src/LineageAnchor.sol";

contract ConformanceTest is Test {
    address admin     = address(0xA11CE);
    address committer = address(0xC0117);
    string  json;

    function setUp() public {
        json = vm.readFile("../testvectors/conformance.json");
    }

    function _anchor() internal returns (LineageAnchor a) {
        a = new LineageAnchor();
        a.initialise(admin, 0.1 ether);
        vm.deal(committer, 1 ether);
        vm.prank(committer);
        a.registerCommitter{value: 0.2 ether}();
    }

    function testMembershipProofsVerifyOnChain() public {
        for (uint256 i = 0; i < 6; i++) {
            string memory k = string.concat(".evm.membership[", vm.toString(i), "]");
            uint64  epoch  = uint64(vm.parseJsonUint(json, string.concat(k, ".epoch")));
            bytes32 root   = vm.parseJsonBytes32(json, string.concat(k, ".root"));
            bytes32 vertex = vm.parseJsonBytes32(json, string.concat(k, ".vertex"));
            bytes32 digest = vm.parseJsonBytes32(json, string.concat(k, ".digest"));
            bytes32 leaf   = vm.parseJsonBytes32(json, string.concat(k, ".leaf"));
            bytes32[] memory path = vm.parseJsonBytes32Array(json, string.concat(k, ".path"));

            LineageAnchor a = _anchor();
            vm.prank(committer);
            a.commitRoot(root, epoch, bytes32(uint256(1)));
            assertEq(a.leafOf(vertex, digest), leaf, "leaf convention");
            assertTrue(a.verifyProof(leaf, path, epoch), "off-chain proof verifies on-chain");
            assertFalse(a.verifyProof(leaf ^ bytes32(uint256(1)), path, epoch));
            if (path.length > 0) {
                path[0] ^= bytes32(uint256(1));
                assertFalse(a.verifyProof(leaf, path, epoch));
            }
        }
    }

    function testPruneLogProofVerifiesOnChain() public {
        bytes32 root = vm.parseJsonBytes32(json, ".evm.prune.root");
        bytes32 leaf = vm.parseJsonBytes32(json, ".evm.prune.leaf");
        bytes32[] memory path = vm.parseJsonBytes32Array(json, ".evm.prune.path");
        LineageAnchor a = _anchor();
        vm.prank(committer);
        a.commitPruneRoot(0, root);
        assertTrue(a.verifyPruneProof(leaf, path, 0));
        assertFalse(a.verifyPruneProof(leaf ^ bytes32(uint256(1)), path, 0));
    }
}
