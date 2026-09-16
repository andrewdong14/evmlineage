// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// Foundry test suite for LineageAnchor.
// Run locally with:  cd contracts && forge test -vv
// (Not runnable in the authoring sandbox — verify before release.)

import "forge-std/Test.sol";
import "../src/LineageAnchor.sol";

contract LineageAnchorTest is Test {
    LineageAnchor anchor;
    address admin      = address(0xA11CE);
    address committer  = address(0xC0117);
    address challenger = address(0xBEEF);

    function setUp() public {
        anchor = new LineageAnchor();
        anchor.initialise(admin, 0.1 ether);
        vm.deal(committer, 1 ether);
        vm.deal(challenger, 1 ether);
        vm.prank(committer);
        anchor.registerCommitter{value: 0.5 ether}();
    }

    // ── Helpers mirroring the off-chain leaf/pair conventions ────────────

    function _pair(bytes32 a, bytes32 b) internal pure returns (bytes32) {
        return a < b ? keccak256(abi.encodePacked(a, b))
                     : keccak256(abi.encodePacked(b, a));
    }

    function _leaf(bytes32 vertexHash, bytes32 digest)
        internal pure returns (bytes32)
    {
        return keccak256(abi.encodePacked(vertexHash, digest));
    }

    // ── commitRoot / Invariant I2 ────────────────────────────────────────

    function testCommitSequentialEpochs() public {
        vm.startPrank(committer);
        anchor.commitRoot(bytes32(uint256(1)), 0, bytes32(uint256(0xB0)));
        anchor.commitRoot(bytes32(uint256(2)), 1, bytes32(uint256(0xB1)));
        vm.stopPrank();
        assertEq(anchor.latestEpoch(), 1);
        assertEq(anchor.epochRoot(0), bytes32(uint256(1)));
        assertEq(anchor.epochCommitter(0), committer);
    }

    function testRejectOutOfOrderEpoch() public {
        vm.startPrank(committer);
        anchor.commitRoot(bytes32(uint256(1)), 0, bytes32(uint256(0xB0)));
        vm.expectRevert(
            abi.encodeWithSelector(EpochOutOfOrder.selector, 1, 5));
        anchor.commitRoot(bytes32(uint256(9)), 5, bytes32(uint256(0xB5)));
        vm.stopPrank();
    }

    function testRejectRecommit() public {
        vm.startPrank(committer);
        anchor.commitRoot(bytes32(uint256(1)), 0, bytes32(uint256(0xB0)));
        vm.expectRevert(
            abi.encodeWithSelector(EpochAlreadyCommitted.selector, 0));
        anchor.commitRoot(bytes32(uint256(7)), 0, bytes32(uint256(0xB7)));
        vm.stopPrank();
    }

    function testRejectUnstakedCommitter() public {
        vm.prank(challenger);           // never registered
        vm.expectRevert(NotCommitter.selector);
        anchor.commitRoot(bytes32(uint256(1)), 0, bytes32(uint256(0xB0)));
    }

    // ── verifyProof ──────────────────────────────────────────────────────

    function testVerifyProofFourLeaves() public {
        // Tree over leaves L0..L3 with sorted-pair hashing.
        bytes32 l0 = keccak256("l0");
        bytes32 l1 = keccak256("l1");
        bytes32 l2 = keccak256("l2");
        bytes32 l3 = keccak256("l3");
        bytes32 n01 = _pair(l0, l1);
        bytes32 n23 = _pair(l2, l3);
        bytes32 root = _pair(n01, n23);

        vm.prank(committer);
        anchor.commitRoot(root, 0, bytes32(uint256(0xB0)));

        bytes32[] memory proof = new bytes32[](2);
        proof[0] = l1;
        proof[1] = n23;
        assertTrue(anchor.verifyProof(l0, proof, 0));

        proof[0] = l0;
        assertFalse(anchor.verifyProof(l1 ^ bytes32(uint256(1)), proof, 0));
    }

    // ── slash: sound equivocation proof ──────────────────────────────────

    function testSlashOnEquivocation() public {
        // Fraudulent root: SAME vertex v bound to two different digests.
        bytes32 v  = keccak256("vertex");
        bytes32 dA = keccak256("record-A");
        bytes32 dB = keccak256("record-B");
        bytes32 lA = _leaf(v, dA);
        bytes32 lB = _leaf(v, dB);
        bytes32 root = _pair(lA, lB);

        vm.prank(committer);
        anchor.commitRoot(root, 0, bytes32(uint256(0xB0)));

        bytes32[] memory pA = new bytes32[](1); pA[0] = lB;
        bytes32[] memory pB = new bytes32[](1); pB[0] = lA;

        uint256 balBefore = challenger.balance;
        vm.prank(challenger);
        anchor.slash(v, dA, pA, dB, pB, 0);
        assertTrue(anchor.isSlashed(committer));
        assertEq(anchor.stakeOf(committer), 0);
        assertEq(challenger.balance, balBefore + 0.5 ether);
    }

    function testCannotSlashHonestRootWithTwoLeaves() public {
        // Honest root over two DIFFERENT vertices: valid membership of two
        // distinct leaves must NOT be slashable (the bug this design fixes).
        bytes32 v1 = keccak256("vertex-1");
        bytes32 v2 = keccak256("vertex-2");
        bytes32 d1 = keccak256("record-1");
        bytes32 d2 = keccak256("record-2");
        bytes32 l1_ = _leaf(v1, d1);
        bytes32 l2_ = _leaf(v2, d2);
        bytes32 root = _pair(l1_, l2_);

        vm.prank(committer);
        anchor.commitRoot(root, 0, bytes32(uint256(0xB0)));

        bytes32[] memory p1 = new bytes32[](1); p1[0] = l2_;
        bytes32[] memory p2 = new bytes32[](1); p2[0] = l1_;

        // Claiming v1 equivocates with v2's digest fails: the recomputed
        // leaf keccak256(v1||d2) is not in the tree.
        vm.prank(challenger);
        vm.expectRevert(InvalidFraudProof.selector);
        anchor.slash(v1, d1, p1, d2, p2, 0);
    }

    function testSlashRequiresDistinctDigests() public {
        bytes32 v = keccak256("vertex");
        bytes32 d = keccak256("record");
        bytes32 l = _leaf(v, d);
        vm.prank(committer);
        anchor.commitRoot(l, 0, bytes32(uint256(0xB0)));   // 1-leaf tree
        bytes32[] memory empty = new bytes32[](0);
        vm.prank(challenger);
        vm.expectRevert(SelfEquivocationRequired.selector);
        anchor.slash(v, d, empty, d, empty, 0);
    }

    function testSlashUnknownEpochReverts() public {
        bytes32[] memory empty = new bytes32[](0);
        vm.prank(challenger);
        vm.expectRevert(abi.encodeWithSelector(UnknownCommitter.selector, 9));
        anchor.slash(bytes32(0), bytes32(0), empty, bytes32(uint256(1)), empty, 9);
    }
}
