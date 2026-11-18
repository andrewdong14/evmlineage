// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// Foundry tests for LineageAnchor, LineageProxy and LineageMultisig.
//   cd contracts && forge install foundry-rs/forge-std --no-git && forge test -vv

import "forge-std/Test.sol";
import "../src/LineageAnchor.sol";
import "../src/LineageProxy.sol";

contract LineageAnchorTest is Test {
    LineageAnchor anchor;
    address admin      = address(0xA11CE);
    address committer  = address(0xC0117);
    address challenger = address(0xBEEF);
    bytes32 constant BLOB = bytes32(uint256(0xB10B));

    function setUp() public {
        anchor = new LineageAnchor();
        anchor.initialise(admin, 0.1 ether);
        vm.deal(committer, 1 ether);
        vm.deal(challenger, 1 ether);
        vm.prank(committer);
        anchor.registerCommitter{value: 0.5 ether}();
    }

    // ── Helpers mirroring the off-chain conventions ─────────────────────

    function _pair(bytes32 a, bytes32 b) internal pure returns (bytes32) {
        return a < b ? keccak256(abi.encodePacked(a, b))
                     : keccak256(abi.encodePacked(b, a));
    }

    function _leaf(bytes32 vertexHash, bytes32 digest) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(keccak256(abi.encodePacked(vertexHash, digest))));
    }

    function _one(bytes32 x) internal pure returns (bytes32[] memory p) {
        p = new bytes32[](1);
        p[0] = x;
    }

    // ── commitRoot / Invariant I2 ───────────────────────────────────────

    function testCommitSequentialEpochs() public {
        vm.startPrank(committer);
        anchor.commitRoot(bytes32(uint256(1)), 0, BLOB);
        anchor.commitRoot(bytes32(uint256(2)), 1, BLOB);
        vm.stopPrank();
        assertEq(anchor.latestEpoch(), 1);
        assertEq(anchor.totalEpochs(), 2);
        assertEq(anchor.epochRoot(0), bytes32(uint256(1)));
        assertEq(anchor.epochBlobHash(1), BLOB);
        assertEq(anchor.epochCommitter(0), committer);
        assertEq(anchor.epochBlock(1), block.number);
        assertFalse(anchor.isDisputed(0));
    }

    function testRejectOutOfOrderEpoch() public {
        vm.startPrank(committer);
        anchor.commitRoot(bytes32(uint256(1)), 0, BLOB);
        vm.expectRevert(abi.encodeWithSelector(EpochOutOfOrder.selector, 1, 5));
        anchor.commitRoot(bytes32(uint256(9)), 5, BLOB);
        vm.stopPrank();
    }

    function testRejectRecommit() public {
        vm.startPrank(committer);
        anchor.commitRoot(bytes32(uint256(1)), 0, BLOB);
        vm.expectRevert(abi.encodeWithSelector(EpochAlreadyCommitted.selector, 0));
        anchor.commitRoot(bytes32(uint256(7)), 0, BLOB);
        vm.stopPrank();
    }

    function testRejectUnstakedCommitter() public {
        vm.prank(challenger);           // never registered
        vm.expectRevert(NotCommitter.selector);
        anchor.commitRoot(bytes32(uint256(1)), 0, BLOB);
    }

    function testRejectZeroRootAndZeroBlobHash() public {
        vm.startPrank(committer);
        vm.expectRevert(ZeroRoot.selector);
        anchor.commitRoot(bytes32(0), 0, BLOB);
        vm.expectRevert(InvalidBlobHash.selector);
        anchor.commitRoot(bytes32(uint256(1)), 0, bytes32(0));
        vm.stopPrank();
    }

    function testStorageSlotIsDerivedFromItsName() public {
        // The contract keeps its state at keccak256("evm_lineage.anchor.v2") - 1;
        // the struct's sixth slot packs the four uint64 counters.
        vm.prank(committer);
        anchor.commitRoot(bytes32(uint256(1)), 0, BLOB);
        bytes32 base = bytes32(uint256(keccak256("evm_lineage.anchor.v2")) - 1);
        uint256 counters = uint256(vm.load(address(anchor), bytes32(uint256(base) + 5)));
        assertEq(uint64(counters), 0);               // latestEpoch
        assertEq(uint64(counters >> 64), 1);         // totalEpochs
        assertEq(uint64(counters >> 192), 7 days);   // withdrawDelay
    }

    // ── verifyProof ─────────────────────────────────────────────────────

    function testVerifyProofFourLeaves() public {
        bytes32 l0 = keccak256("l0");
        bytes32 l1 = keccak256("l1");
        bytes32 l2 = keccak256("l2");
        bytes32 l3 = keccak256("l3");
        bytes32 n01 = _pair(l0, l1);
        bytes32 n23 = _pair(l2, l3);
        bytes32 root = _pair(n01, n23);

        vm.prank(committer);
        anchor.commitRoot(root, 0, BLOB);

        bytes32[] memory proof = new bytes32[](2);
        proof[0] = l1;
        proof[1] = n23;
        assertTrue(anchor.verifyProof(l0, proof, 0));
        assertTrue(anchor.verifyProofAndLog(l0, proof, 0));

        proof[0] = l0;
        assertFalse(anchor.verifyProof(l1 ^ bytes32(uint256(1)), proof, 0));
        vm.expectRevert(abi.encodeWithSelector(EpochNotCommitted.selector, 3));
        anchor.verifyProof(l0, proof, 3);
    }

    function testLeafOfIsDoubleHashed() public view {
        bytes32 v = keccak256("vertex");
        bytes32 d = keccak256("digest");
        assertEq(anchor.leafOf(v, d), _leaf(v, d));
        assertTrue(anchor.leafOf(v, d) != keccak256(abi.encodePacked(v, d)));
    }

    // ── slash ───────────────────────────────────────────────────────────

    function testSlashOnEquivocation() public {
        // Fraudulent root: the SAME vertex v bound to two different digests.
        bytes32 v  = keccak256("vertex");
        bytes32 dA = keccak256("record-A");
        bytes32 dB = keccak256("record-B");
        bytes32 lA = _leaf(v, dA);
        bytes32 lB = _leaf(v, dB);

        vm.prank(committer);
        anchor.commitRoot(_pair(lA, lB), 0, BLOB);

        uint256 balBefore = challenger.balance;
        vm.prank(challenger);
        anchor.slash(v, dA, _one(lB), dB, _one(lA), 0);
        assertTrue(anchor.isSlashed(committer));
        assertTrue(anchor.isDisputed(0));
        assertEq(anchor.stakeOf(committer), 0);
        assertEq(challenger.balance, balBefore + 0.25 ether);     // half is paid out
        assertEq(anchor.burnedStake(), 0.25 ether);               // half is burned
        assertEq(address(anchor).balance, 0.25 ether);

        // A slashed committer can neither commit nor be slashed twice.
        vm.prank(committer);
        vm.expectRevert(AlreadySlashed.selector);
        anchor.commitRoot(bytes32(uint256(2)), 1, BLOB);
        vm.prank(challenger);
        vm.expectRevert(AlreadySlashed.selector);
        anchor.slash(v, dA, _one(lB), dB, _one(lA), 0);
    }

    function testCannotSlashHonestRootWithTwoLeaves() public {
        // Honest root over two DIFFERENT vertices.
        bytes32 v1 = keccak256("vertex-1");
        bytes32 v2 = keccak256("vertex-2");
        bytes32 d1 = keccak256("record-1");
        bytes32 d2 = keccak256("record-2");
        bytes32 l1_ = _leaf(v1, d1);
        bytes32 l2_ = _leaf(v2, d2);

        vm.prank(committer);
        anchor.commitRoot(_pair(l1_, l2_), 0, BLOB);

        // v1 with v2's digest: the recomputed leaf is not in the tree.
        vm.prank(challenger);
        vm.expectRevert(InvalidFraudProof.selector);
        anchor.slash(v1, d1, _one(l2_), d2, _one(l1_), 0);
    }

    function testCannotSlashWithInteriorNode() public {
        // An honest tree over v1, v2 and a third "vertex" u whose hash an
        // attacker chose to equal the leaf label of v1. The interior node
        // over (leaf(v1), leaf(v2)) is keccak256(u || leaf(v2)) when
        // u < leaf(v2). With single-hashed leaves that node would pass as a
        // second record of u; with double-hashed leaves it does not.
        bytes32 v1 = keccak256("v1");
        bytes32 v2 = keccak256("v2");
        bytes32 l1_ = _leaf(v1, keccak256("d1"));
        bytes32 l2_ = _leaf(v2, keccak256("d2"));
        if (l1_ > l2_) { (l1_, l2_) = (l2_, l1_); }
        bytes32 u   = l1_;
        bytes32 dU  = keccak256("record of u");
        bytes32 lU  = _leaf(u, dU);
        bytes32 n12 = _pair(l1_, l2_);
        assertEq(n12, keccak256(abi.encodePacked(u, l2_)));       // the confusable node

        vm.prank(committer);
        anchor.commitRoot(_pair(n12, lU), 0, BLOB);

        // Honest record of u verifies ...
        assertTrue(anchor.verifyProof(lU, _one(n12), 0));
        // ... but (u, digest = leaf(v2)) is not a second record of u.
        vm.prank(challenger);
        vm.expectRevert(InvalidFraudProof.selector);
        anchor.slash(u, dU, _one(n12), l2_, _one(lU), 0);
        assertFalse(anchor.isSlashed(committer));
    }

    function testSlashRequiresDistinctDigests() public {
        bytes32 v = keccak256("vertex");
        bytes32 d = keccak256("record");
        vm.prank(committer);
        anchor.commitRoot(_leaf(v, d), 0, BLOB);   // 1-leaf tree
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

    // ── stake withdrawal ────────────────────────────────────────────────

    function testWithdrawalNeedsDelayAndStopsCommits() public {
        vm.startPrank(committer);
        anchor.commitRoot(bytes32(uint256(1)), 0, BLOB);
        vm.expectRevert(NoWithdrawalPending.selector);
        anchor.withdrawStake();
        anchor.requestWithdrawal();
        vm.expectRevert(WithdrawalPending.selector);
        anchor.commitRoot(bytes32(uint256(2)), 1, BLOB);
        uint64 unlocksAt = uint64(block.timestamp) + 7 days;
        vm.expectRevert(abi.encodeWithSelector(WithdrawalLocked.selector, unlocksAt));
        anchor.withdrawStake();
        vm.warp(unlocksAt);
        anchor.withdrawStake();
        vm.stopPrank();
        assertEq(committer.balance, 1 ether);
        assertEq(anchor.stakeOf(committer), 0);
    }

    function testStakeStaysSlashableDuringWithdrawalWindow() public {
        bytes32 v  = keccak256("vertex");
        bytes32 lA = _leaf(v, keccak256("A"));
        bytes32 lB = _leaf(v, keccak256("B"));
        vm.startPrank(committer);
        anchor.commitRoot(_pair(lA, lB), 0, BLOB);                // fraudulent root
        anchor.requestWithdrawal();                               // ... and run
        vm.stopPrank();
        vm.warp(block.timestamp + 6 days);
        vm.prank(challenger);
        anchor.slash(v, keccak256("A"), _one(lB), keccak256("B"), _one(lA), 0);
        vm.warp(block.timestamp + 2 days);
        vm.prank(committer);
        vm.expectRevert(NothingStaked.selector);
        anchor.withdrawStake();
        assertEq(committer.balance, 0.5 ether);
    }

    // ── prune-log roots ─────────────────────────────────────────────────

    function testPruneRoots() public {
        bytes32 e0 = keccak256("entry-0");
        bytes32 e1 = keccak256("entry-1");
        bytes32 e2 = keccak256("entry-2");
        bytes32 root = _pair(_pair(e0, e1), e2);                  // odd node promoted
        vm.startPrank(committer);
        vm.expectRevert(abi.encodeWithSelector(PruneBatchOutOfOrder.selector, 0, 1));
        anchor.commitPruneRoot(1, root);
        anchor.commitPruneRoot(0, root);
        vm.stopPrank();
        assertEq(anchor.pruneBatches(), 1);
        assertEq(anchor.pruneRoot(0), root);
        assertTrue(anchor.verifyPruneProof(e2, _one(_pair(e0, e1)), 0));
        bytes32[] memory p = new bytes32[](2);
        p[0] = e1; p[1] = e2;
        assertTrue(anchor.verifyPruneProof(e0, p, 0));
        assertFalse(anchor.verifyPruneProof(e1, _one(e2), 0));
        vm.expectRevert(abi.encodeWithSelector(PruneBatchNotCommitted.selector, 4));
        anchor.verifyPruneProof(e0, p, 4);
        vm.prank(challenger);
        vm.expectRevert(NotCommitter.selector);
        anchor.commitPruneRoot(1, root);
    }

    // ── payload commitment and blobs ────────────────────────────────────

    function testBlobHashMustMatchCarriedBlobs() public {
        bytes32 h0 = bytes32(uint256(0x01) << 248 | uint256(0xAAAA));
        bytes32 h1 = bytes32(uint256(0x01) << 248 | uint256(0xBBBB));
        bytes32[] memory one = new bytes32[](1);
        one[0] = h0;
        vm.blobhashes(one);
        vm.startPrank(committer);
        vm.expectRevert(BlobHashMismatch.selector);
        anchor.commitRoot(bytes32(uint256(1)), 0, BLOB);
        anchor.commitRoot(bytes32(uint256(1)), 0, h0);

        bytes32[] memory two = new bytes32[](2);
        two[0] = h0; two[1] = h1;
        vm.blobhashes(two);
        vm.expectRevert(BlobHashMismatch.selector);
        anchor.commitRoot(bytes32(uint256(2)), 1, h0);
        anchor.commitRoot(bytes32(uint256(2)), 1, keccak256(abi.encodePacked(h0, h1)));
        vm.stopPrank();
        assertEq(anchor.epochBlobHash(1), keccak256(abi.encodePacked(h0, h1)));
    }

    function testRequireBlobs() public {
        vm.prank(admin);
        anchor.setRequireBlobs(true);
        assertTrue(anchor.blobsRequired());
        vm.prank(committer);
        vm.expectRevert(BlobRequired.selector);
        anchor.commitRoot(bytes32(uint256(1)), 0, BLOB);
    }

    // ── administration ──────────────────────────────────────────────────

    function testPauseAndAdmin() public {
        vm.expectRevert(NotAdmin.selector);
        anchor.pause();
        vm.prank(admin);
        anchor.pause();
        vm.prank(committer);
        vm.expectRevert(Paused.selector);
        anchor.commitRoot(bytes32(uint256(1)), 0, BLOB);
        vm.startPrank(admin);
        anchor.unpause();
        anchor.setWithdrawDelay(1 days);
        anchor.setMinStake(1 ether);
        vm.stopPrank();
        assertEq(anchor.withdrawDelay(), 1 days);
        vm.prank(committer);                                      // stake is now too small
        vm.expectRevert(NotCommitter.selector);
        anchor.commitRoot(bytes32(uint256(1)), 0, BLOB);
        vm.expectRevert(AlreadyInitialised.selector);
        anchor.initialise(admin, 1);
    }

    // ── multisig committer behind the proxy ─────────────────────────────

    function testMultisigCommitsThroughProxy() public {
        address[] memory owners = new address[](5);
        for (uint160 i = 0; i < 5; i++) owners[i] = address(0x1000 + i);
        LineageMultisig ms = new LineageMultisig(owners);

        LineageAnchor impl = new LineageAnchor();
        LineageProxy proxy = new LineageProxy(
            address(impl), address(ms),
            abi.encodeCall(LineageAnchor.initialise, (address(ms), 0.1 ether)));
        LineageAnchor a = LineageAnchor(payable(address(proxy)));
        assertEq(a.admin(), address(ms));

        // Anyone can stake for the multisig, which cannot attach value itself.
        vm.deal(address(this), 1 ether);
        a.registerCommitterFor{value: 0.3 ether}(address(ms));
        assertEq(a.stakeOf(address(ms)), 0.3 ether);

        bytes memory call_ = abi.encodeCall(LineageAnchor.commitRoot,
                                            (bytes32(uint256(0xCAFE)), 0, BLOB));
        vm.prank(owners[0]);
        bytes32 id = ms.submit(address(a), call_);
        vm.prank(owners[0]); ms.approve(id);
        vm.prank(owners[1]); ms.approve(id);
        vm.prank(owners[2]);
        vm.expectRevert("below threshold");
        ms.execute(id);
        vm.prank(owners[2]); ms.approve(id);
        vm.prank(owners[3]); ms.execute(id);

        assertEq(a.epochRoot(0), bytes32(uint256(0xCAFE)));
        assertEq(a.epochCommitter(0), address(ms));

        // The implementation's own storage is untouched, and only the proxy
        // admin (the multisig) can upgrade.
        assertEq(impl.totalEpochs(), 0);
        LineageAnchor impl2 = new LineageAnchor();
        vm.expectRevert("not admin");
        proxy.upgradeTo(address(impl2));
        vm.prank(address(ms));
        proxy.upgradeTo(address(impl2));
        assertEq(proxy.implementation(), address(impl2));
        assertEq(a.epochRoot(0), bytes32(uint256(0xCAFE)));       // state survives the upgrade
    }
}
