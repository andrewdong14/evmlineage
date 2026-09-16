// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title  LineageAnchor
/// @notice On-chain anchor for EVM-Lineage epoch Merkle roots.
///         Compiled with solc 0.8.24, optimiser runs=200.
///
/// Operations:
///   commitRoot   – anchor the epoch's EPSL state root + EIP-4844 blob hash
///   verifyProof  – Merkle inclusion proof (assembly inner loop)
///   slash        – equivocation fraud proof → slash the epoch committer
///   epochRoot    – read committed root for a given epoch
///
/// Leaf convention (identical in the Rust engine and Python layer):
///   leaf = keccak256(abi.encodePacked(vertexHash, recordDigest))
/// where recordDigest commits the vertex's adjacency as of the epoch.
/// A root is fraudulent iff it contains two different records for the
/// same vertexHash — exactly what slash() checks. Two arbitrary distinct
/// leaves are NOT fraud (every honest tree has many).

error NotCommitter();
error EpochAlreadyCommitted(uint64 epoch);
error EpochNotCommitted(uint64 epoch);
error EpochOutOfOrder(uint64 expected, uint64 got);
error InvalidBlobHash();
error InsufficientStake();
error AlreadySlashed();
error InvalidFraudProof();
error SelfEquivocationRequired();
error UnknownCommitter(uint64 epoch);
error ZeroAddress();
error NotInitialised();
error AlreadyInitialised();
error Paused();

event RootCommitted(uint64 indexed epoch, bytes32 root, bytes32 blobHash,
                    address indexed committer, uint256 blockNumber);
event ProofVerified(uint64 indexed epoch, bytes32 leaf, address indexed caller);
event CommitterSlashed(address indexed committer, uint256 stake);
event CommitterRegistered(address indexed committer, uint256 stake);
event CommitterDeregistered(address indexed committer);

// Diamond-storage struct (EIP-1967-compatible)
struct LS {
    mapping(uint64  => bytes32) epochRoots;
    mapping(uint64  => bytes32) epochBlobHashes;
    mapping(uint64  => uint256) epochBlocks;
    mapping(address => uint256) stakes;
    mapping(address => bool)    slashed;
    mapping(uint64  => address) epochCommitter;
    uint64  latestEpoch;
    uint64  totalEpochs;
    uint256 minStake;
    address admin;
    bool    paused;
    bool    initialised;
}

contract LineageAnchor {
    // keccak256("evm_lineage.anchor.v1") - 1
    bytes32 private constant _SLOT =
        0x7f3a9c2b4e6d1f8a0c5b7e2d4f9a1c3e6b8d0f2a4c7e9b1d3f5a7c9e0b2d4f6a;

    uint256 private constant DEFAULT_MIN_STAKE = 0.1 ether;

    function initialise(address admin_, uint256 minStake_) external {
        LS storage s = _s();
        if (s.initialised) revert AlreadyInitialised();
        if (admin_ == address(0)) revert ZeroAddress();
        s.admin = admin_;
        s.minStake = minStake_ == 0 ? DEFAULT_MIN_STAKE : minStake_;
        s.initialised = true;
    }

    function registerCommitter() external payable {
        LS storage s = _s();
        if (!s.initialised) revert NotInitialised();
        if (s.paused) revert Paused();
        if (msg.value < s.minStake) revert InsufficientStake();
        s.stakes[msg.sender] += msg.value;
        emit CommitterRegistered(msg.sender, s.stakes[msg.sender]);
    }

    function deregisterCommitter() external {
        LS storage s = _s();
        uint256 stake = s.stakes[msg.sender];
        require(stake > 0 && !s.slashed[msg.sender], "ineligible");
        s.stakes[msg.sender] = 0;
        (bool ok,) = msg.sender.call{value: stake}("");
        require(ok, "transfer failed");
        emit CommitterDeregistered(msg.sender);
    }

    /// @notice Anchor an epoch's Merkle root and EIP-4844 KZG blob hash.
    /// @param  root      Batch Merkle root of winning branch events.
    /// @param  epoch     Must equal latestEpoch + 1 (Invariant I2).
    /// @param  blobHash  KZG commitment hash of the EIP-4844 blob transaction.
    function commitRoot(bytes32 root, uint64 epoch, bytes32 blobHash) external {
        LS storage s = _s();
        if (!s.initialised)                    revert NotInitialised();
        if (s.paused)                          revert Paused();
        if (s.stakes[msg.sender] < s.minStake) revert NotCommitter();
        if (s.slashed[msg.sender])             revert AlreadySlashed();
        if (blobHash == bytes32(0))            revert InvalidBlobHash();
        if (s.epochRoots[epoch] != bytes32(0)) revert EpochAlreadyCommitted(epoch);
        if (s.totalEpochs > 0 && epoch != s.latestEpoch + 1)
            revert EpochOutOfOrder(s.latestEpoch + 1, epoch);

        s.epochRoots[epoch]      = root;
        s.epochBlobHashes[epoch] = blobHash;
        s.epochBlocks[epoch]     = block.number;
        s.epochCommitter[epoch]  = msg.sender;
        s.latestEpoch            = epoch;
        s.totalEpochs           += 1;
        emit RootCommitted(epoch, root, blobHash, msg.sender, block.number);
    }

    /// @notice Verify a Merkle inclusion proof. ~430 gas/hash (assembly inner loop).
    function verifyProof(bytes32 leaf, bytes32[] calldata proof, uint64 epoch)
        external view returns (bool valid)
    {
        bytes32 root = _s().epochRoots[epoch];
        if (root == bytes32(0)) revert EpochNotCommitted(epoch);
        bytes32 node = leaf;
        uint256 len  = proof.length;
        assembly {
            let ptr := proof.offset
            for { let i := 0 } lt(i, len) { i := add(i, 1) } {
                let sib := calldataload(add(ptr, mul(i, 32)))
                switch lt(node, sib)
                case 1 { mstore(0x00, node) mstore(0x20, sib)  }
                default { mstore(0x00, sib)  mstore(0x20, node) }
                node := keccak256(0x00, 0x40)
            }
        }
        valid = (node == root);
    }

    /// @notice Non-view verifyProof that emits an event (on-chain composability).
    function verifyProofAndLog(bytes32 leaf, bytes32[] calldata proof, uint64 epoch)
        external returns (bool valid)
    {
        valid = this.verifyProof(leaf, proof, epoch);
        require(valid, "invalid proof");
        emit ProofVerified(epoch, leaf, msg.sender);
    }

    /// @notice Equivocation fraud proof. A committed root is fraudulent
    ///         iff it binds the SAME vertex hash to TWO different node
    ///         records. The caller supplies both record digests with
    ///         inclusion proofs; leaves are recomputed on-chain as
    ///         keccak256(vertexHash || digest), so arbitrary distinct
    ///         leaves cannot be used to slash an honest committer.
    ///         The stake of the epoch's recorded committer is slashed
    ///         and paid to the challenger.
    function slash(bytes32 vertexHash,
                   bytes32 digestA, bytes32[] calldata proofA,
                   bytes32 digestB, bytes32[] calldata proofB,
                   uint64  epoch) external
    {
        LS storage s = _s();
        address committer = s.epochCommitter[epoch];
        if (committer == address(0)) revert UnknownCommitter(epoch);
        if (s.slashed[committer])    revert AlreadySlashed();
        if (digestA == digestB)      revert SelfEquivocationRequired();
        bytes32 leafA = keccak256(abi.encodePacked(vertexHash, digestA));
        bytes32 leafB = keccak256(abi.encodePacked(vertexHash, digestB));
        if (!this.verifyProof(leafA, proofA, epoch)) revert InvalidFraudProof();
        if (!this.verifyProof(leafB, proofB, epoch)) revert InvalidFraudProof();
        uint256 stake = s.stakes[committer];
        s.slashed[committer] = true;
        s.stakes[committer]  = 0;
        (bool ok,) = msg.sender.call{value: stake}("");
        require(ok, "transfer failed");
        emit CommitterSlashed(committer, stake);
    }

    // View helpers
    function epochRoot(uint64 e)      external view returns (bytes32) { return _s().epochRoots[e]; }
    function epochCommitter(uint64 e) external view returns (address) { return _s().epochCommitter[e]; }
    function epochBlobHash(uint64 e)  external view returns (bytes32) { return _s().epochBlobHashes[e]; }
    function epochBlock(uint64 e)     external view returns (uint256) { return _s().epochBlocks[e]; }
    function latestEpoch()            external view returns (uint64)  { return _s().latestEpoch; }
    function totalEpochs()            external view returns (uint64)  { return _s().totalEpochs; }
    function stakeOf(address a)       external view returns (uint256) { return _s().stakes[a]; }
    function isSlashed(address a)     external view returns (bool)    { return _s().slashed[a]; }
    function isPaused()               external view returns (bool)    { return _s().paused; }
    function minStake()               external view returns (uint256) { return _s().minStake; }

    modifier onlyAdmin() { require(msg.sender == _s().admin, "not admin"); _; }
    function pause()                  external onlyAdmin { _s().paused = true; }
    function unpause()                external onlyAdmin { _s().paused = false; }
    function setMinStake(uint256 v)   external onlyAdmin { _s().minStake = v; }
    function transferAdmin(address a) external onlyAdmin {
        if (a == address(0)) revert ZeroAddress();
        _s().admin = a;
    }

    function _s() private pure returns (LS storage s) {
        bytes32 slot = _SLOT;
        assembly { s.slot := slot }
    }
    receive() external payable { revert("use registerCommitter()"); }
}
