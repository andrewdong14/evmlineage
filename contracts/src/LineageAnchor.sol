// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// LineageAnchor — on-chain anchor for EVM-Lineage epoch roots.
// Compile with solc 0.8.24 or later, EVM version cancun (BLOBHASH), optimiser
// runs = 200 (see foundry.toml).
//
// Operations
//   commitRoot        anchor the EPSL root of an epoch and the commitment to
//                     its payload (the versioned blob hash when the commit
//                     transaction carries the payload as blobs)
//   verifyProof       membership of a leaf under an epoch root
//   slash             equivocation fraud proof against an epoch root
//   commitPruneRoot   anchor the Merkle root of a prune-log batch
//   verifyPruneProof  membership of a prune-log entry
//
// Leaf convention (identical in the Rust engine and the Python layer):
//   leaf = keccak256(keccak256(abi.encodePacked(vertexHash, recordDigest)))
// Interior nodes are keccak256 of a sorted 64-byte pair. A leaf is the hash
// of a 32-byte value and an interior node the hash of a 64-byte value, so an
// interior node can never be presented as a leaf. Without the outer hash an
// interior node over (a, b) would pass as a record of vertex a with digest b
// and slash() could be turned against an honest committer.
//
// A root is fraudulent if it holds two different records for the same
// vertexHash; that is exactly what slash() checks.

error NotCommitter();
error EpochAlreadyCommitted(uint64 epoch);
error EpochNotCommitted(uint64 epoch);
error EpochOutOfOrder(uint64 expected, uint64 got);
error ZeroRoot();
error InvalidBlobHash();
error BlobHashMismatch();
error BlobRequired();
error InsufficientStake();
error AlreadySlashed();
error InvalidFraudProof();
error SelfEquivocationRequired();
error UnknownCommitter(uint64 epoch);
error PruneBatchOutOfOrder(uint64 expected, uint64 got);
error PruneBatchNotCommitted(uint64 index);
error WithdrawalPending();
error NoWithdrawalPending();
error WithdrawalLocked(uint64 unlocksAt);
error NothingStaked();
error TransferFailed();
error ZeroAddress();
error NotAdmin();
error NotInitialised();
error AlreadyInitialised();
error Paused();

event RootCommitted(uint64 indexed epoch, bytes32 root, bytes32 blobHash,
                    address indexed committer);
event PruneRootCommitted(uint64 indexed index, bytes32 root, address indexed committer);
event ProofVerified(uint64 indexed epoch, bytes32 leaf, address indexed caller);
event CommitterSlashed(address indexed committer, uint64 indexed epoch,
                       address indexed challenger, uint256 reward, uint256 burned);
event CommitterRegistered(address indexed committer, uint256 stake);
event WithdrawalRequested(address indexed committer, uint64 unlocksAt);
event CommitterWithdrawn(address indexed committer, uint256 stake);

struct Committer {
    uint128 stake;
    uint64  withdrawRequestedAt;   // 0 = active
    bool    slashed;
}

struct EpochMeta {
    address committer;
    uint64  blockNumber;
    bool    disputed;              // set by a successful slash()
}

// Namespaced storage, so the contract can sit behind LineageProxy.
struct LS {
    mapping(uint64  => bytes32)   epochRoots;
    mapping(uint64  => bytes32)   epochBlobHashes;
    mapping(uint64  => EpochMeta) epochMeta;
    mapping(address => Committer) committers;
    mapping(uint64  => bytes32)   pruneRoots;
    uint64  latestEpoch;
    uint64  totalEpochs;
    uint64  pruneBatches;
    uint64  withdrawDelay;         // seconds
    uint256 minStake;
    uint256 burned;                // slashed stake that stays locked here
    address admin;
    bool    paused;
    bool    initialised;
    bool    requireBlobs;
}

contract LineageAnchor {
    bytes32 private constant _SLOT =
        bytes32(uint256(keccak256("evm_lineage.anchor.v2")) - 1);

    uint256 private constant DEFAULT_MIN_STAKE      = 0.1 ether;
    uint64  private constant DEFAULT_WITHDRAW_DELAY = 7 days;
    /// Share of a slashed stake paid to the challenger, in basis points.
    /// The rest is burned: a committer who slashes itself through a second
    /// account still loses half of its stake.
    uint256 public  constant SLASH_REWARD_BPS       = 5_000;

    function initialise(address admin_, uint256 minStake_) external {
        LS storage s = _s();
        if (s.initialised) revert AlreadyInitialised();
        if (admin_ == address(0)) revert ZeroAddress();
        s.admin         = admin_;
        s.minStake      = minStake_ == 0 ? DEFAULT_MIN_STAKE : minStake_;
        s.withdrawDelay = DEFAULT_WITHDRAW_DELAY;
        s.initialised   = true;
    }

    // ── Committer registry ───────────────────────────────────────────────

    function registerCommitter() external payable { _register(msg.sender); }

    /// Stake on behalf of another account, e.g. a multisig wallet that
    /// cannot attach value to its calls.
    function registerCommitterFor(address committer) external payable {
        if (committer == address(0)) revert ZeroAddress();
        _register(committer);
    }

    function _register(address who) private {
        LS storage s = _s();
        if (!s.initialised) revert NotInitialised();
        if (s.paused) revert Paused();
        Committer storage c = s.committers[who];
        if (c.slashed) revert AlreadySlashed();
        if (c.withdrawRequestedAt != 0) revert WithdrawalPending();
        uint256 stake = uint256(c.stake) + msg.value;
        if (stake < s.minStake) revert InsufficientStake();
        c.stake = uint128(stake);
        emit CommitterRegistered(who, stake);
    }

    /// Start leaving. The committer can no longer commit, and its stake
    /// stays slashable until the withdrawal delay has passed, so every root
    /// it committed can be challenged for at least that long.
    function requestWithdrawal() external {
        LS storage s = _s();
        Committer storage c = s.committers[msg.sender];
        if (c.stake == 0) revert NothingStaked();
        if (c.withdrawRequestedAt != 0) revert WithdrawalPending();
        c.withdrawRequestedAt = uint64(block.timestamp);
        emit WithdrawalRequested(msg.sender, uint64(block.timestamp) + s.withdrawDelay);
    }

    function withdrawStake() external {
        LS storage s = _s();
        Committer storage c = s.committers[msg.sender];
        if (c.withdrawRequestedAt == 0) revert NoWithdrawalPending();
        uint64 unlocksAt = c.withdrawRequestedAt + s.withdrawDelay;
        if (block.timestamp < unlocksAt) revert WithdrawalLocked(unlocksAt);
        uint256 stake = c.stake;
        if (stake == 0) revert NothingStaked();          // slashed in the meantime
        c.stake = 0;
        c.withdrawRequestedAt = 0;
        (bool ok,) = msg.sender.call{value: stake}("");
        if (!ok) revert TransferFailed();
        emit CommitterWithdrawn(msg.sender, stake);
    }

    // ── Epoch roots ──────────────────────────────────────────────────────

    /// @notice Anchor the EPSL root of `epoch` and the commitment to its payload.
    /// @param  root      EPSL root after sealing `epoch` (Invariant I1).
    /// @param  epoch     Must equal latestEpoch + 1 (Invariant I2).
    /// @param  blobHash  Commitment to the epoch payload. If the transaction
    ///                   carries blobs, it must be the versioned hash of the
    ///                   single blob, or keccak256 of the concatenated
    ///                   versioned hashes when there are several.
    function commitRoot(bytes32 root, uint64 epoch, bytes32 blobHash) external {
        LS storage s = _s();
        if (!s.initialised) revert NotInitialised();
        if (s.paused) revert Paused();
        _checkCommitter(s);
        if (root == bytes32(0)) revert ZeroRoot();
        if (blobHash == bytes32(0)) revert InvalidBlobHash();
        if (s.epochRoots[epoch] != bytes32(0)) revert EpochAlreadyCommitted(epoch);
        if (s.totalEpochs > 0 && epoch != s.latestEpoch + 1)
            revert EpochOutOfOrder(s.latestEpoch + 1, epoch);

        bytes32 carried = _carriedBlobCommitment();
        if (carried != bytes32(0)) {
            if (carried != blobHash) revert BlobHashMismatch();
        } else if (s.requireBlobs) {
            revert BlobRequired();
        }

        s.epochRoots[epoch]      = root;
        s.epochBlobHashes[epoch] = blobHash;
        s.epochMeta[epoch]       = EpochMeta(msg.sender, uint64(block.number), false);
        s.latestEpoch            = epoch;
        s.totalEpochs           += 1;
        emit RootCommitted(epoch, root, blobHash, msg.sender);
    }

    function _checkCommitter(LS storage s) private view {
        Committer storage c = s.committers[msg.sender];
        if (c.slashed) revert AlreadySlashed();
        if (c.withdrawRequestedAt != 0) revert WithdrawalPending();
        if (c.stake < s.minStake) revert NotCommitter();
    }

    /// Commitment to the blobs of the current transaction: zero if there
    /// are none, the versioned hash if there is one, and keccak256 of the
    /// concatenated versioned hashes otherwise.
    function _carriedBlobCommitment() private view returns (bytes32) {
        bytes32 first = blobhash(0);
        if (first == bytes32(0)) return bytes32(0);
        bytes32 second = blobhash(1);
        if (second == bytes32(0)) return first;
        bytes memory all = abi.encodePacked(first, second);
        for (uint256 i = 2; ; ++i) {
            bytes32 h = blobhash(i);
            if (h == bytes32(0)) break;
            all = abi.encodePacked(all, h);
        }
        return keccak256(all);
    }

    /// @notice Membership of `leaf` under the root of `epoch`: fold the
    ///         sibling path with the sorted-pair keccak hash.
    function verifyProof(bytes32 leaf, bytes32[] calldata proof, uint64 epoch)
        public view returns (bool valid)
    {
        bytes32 root = _s().epochRoots[epoch];
        if (root == bytes32(0)) revert EpochNotCommitted(epoch);
        return _fold(leaf, proof) == root;
    }

    /// @notice verifyProof that reverts on failure and emits an event, for
    ///         contracts that act on a lineage proof.
    function verifyProofAndLog(bytes32 leaf, bytes32[] calldata proof, uint64 epoch)
        external returns (bool valid)
    {
        valid = verifyProof(leaf, proof, epoch);
        require(valid, "invalid proof");
        emit ProofVerified(epoch, leaf, msg.sender);
    }

    function _fold(bytes32 node, bytes32[] calldata proof) private pure returns (bytes32) {
        uint256 len = proof.length;
        assembly ("memory-safe") {
            let ptr := proof.offset
            for { let i := 0 } lt(i, len) { i := add(i, 1) } {
                let sib := calldataload(add(ptr, shl(5, i)))
                switch lt(node, sib)
                case 1  { mstore(0x00, node) mstore(0x20, sib)  }
                default { mstore(0x00, sib)  mstore(0x20, node) }
                node := keccak256(0x00, 0x40)
            }
        }
        return node;
    }

    /// Leaf of the record `digest` of vertex `vertexHash`.
    function leafOf(bytes32 vertexHash, bytes32 digest) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(keccak256(abi.encodePacked(vertexHash, digest))));
    }

    /// @notice Equivocation fraud proof. The caller shows that the root of
    ///         `epoch` holds two different record digests for the same
    ///         vertex. Leaves are recomputed here from (vertexHash, digest),
    ///         so two unrelated leaves, or an interior node, cannot be used
    ///         against an honest committer. The epoch is marked disputed,
    ///         the committer loses its stake: SLASH_REWARD_BPS of it goes to
    ///         the challenger, the rest is burned.
    function slash(bytes32 vertexHash,
                   bytes32 digestA, bytes32[] calldata proofA,
                   bytes32 digestB, bytes32[] calldata proofB,
                   uint64  epoch) external
    {
        LS storage s = _s();
        EpochMeta storage m = s.epochMeta[epoch];
        address committer = m.committer;
        if (committer == address(0)) revert UnknownCommitter(epoch);
        Committer storage c = s.committers[committer];
        if (c.slashed)          revert AlreadySlashed();
        if (digestA == digestB) revert SelfEquivocationRequired();
        bytes32 root = s.epochRoots[epoch];
        if (_fold(leafOf(vertexHash, digestA), proofA) != root) revert InvalidFraudProof();
        if (_fold(leafOf(vertexHash, digestB), proofB) != root) revert InvalidFraudProof();

        uint256 stake  = c.stake;
        uint256 reward = stake * SLASH_REWARD_BPS / 10_000;
        c.slashed  = true;
        c.stake    = 0;
        m.disputed = true;
        s.burned  += stake - reward;
        (bool ok,) = msg.sender.call{value: reward}("");
        if (!ok) revert TransferFailed();
        emit CommitterSlashed(committer, epoch, msg.sender, reward, stake - reward);
    }

    // ── Prune-log batch roots ────────────────────────────────────────────

    /// @notice Anchor the Merkle root of prune-log batch `index`
    ///         (batches are committed in sequence, starting at 0).
    function commitPruneRoot(uint64 index, bytes32 root) external {
        LS storage s = _s();
        if (!s.initialised) revert NotInitialised();
        if (s.paused) revert Paused();
        _checkCommitter(s);
        if (root == bytes32(0)) revert ZeroRoot();
        if (index != s.pruneBatches) revert PruneBatchOutOfOrder(s.pruneBatches, index);
        s.pruneRoots[index] = root;
        s.pruneBatches = index + 1;
        emit PruneRootCommitted(index, root, msg.sender);
    }

    /// @notice Membership of a prune-log entry: leaf = keccak256(96-byte entry).
    function verifyPruneProof(bytes32 leaf, bytes32[] calldata proof, uint64 index)
        external view returns (bool)
    {
        bytes32 root = _s().pruneRoots[index];
        if (root == bytes32(0)) revert PruneBatchNotCommitted(index);
        return _fold(leaf, proof) == root;
    }

    // ── Views ────────────────────────────────────────────────────────────

    function epochRoot(uint64 e)      external view returns (bytes32) { return _s().epochRoots[e]; }
    function epochBlobHash(uint64 e)  external view returns (bytes32) { return _s().epochBlobHashes[e]; }
    function epochCommitter(uint64 e) external view returns (address) { return _s().epochMeta[e].committer; }
    function epochBlock(uint64 e)     external view returns (uint256) { return _s().epochMeta[e].blockNumber; }
    function isDisputed(uint64 e)     external view returns (bool)    { return _s().epochMeta[e].disputed; }
    function latestEpoch()            external view returns (uint64)  { return _s().latestEpoch; }
    function totalEpochs()            external view returns (uint64)  { return _s().totalEpochs; }
    function pruneRoot(uint64 i)      external view returns (bytes32) { return _s().pruneRoots[i]; }
    function pruneBatches()           external view returns (uint64)  { return _s().pruneBatches; }
    function stakeOf(address a)       external view returns (uint256) { return _s().committers[a].stake; }
    function isSlashed(address a)     external view returns (bool)    { return _s().committers[a].slashed; }
    function withdrawalRequestedAt(address a) external view returns (uint64) {
        return _s().committers[a].withdrawRequestedAt;
    }
    function isPaused()               external view returns (bool)    { return _s().paused; }
    function minStake()               external view returns (uint256) { return _s().minStake; }
    function withdrawDelay()          external view returns (uint64)  { return _s().withdrawDelay; }
    function burnedStake()            external view returns (uint256) { return _s().burned; }
    function blobsRequired()          external view returns (bool)    { return _s().requireBlobs; }
    function admin()                  external view returns (address) { return _s().admin; }

    // ── Administration ───────────────────────────────────────────────────

    modifier onlyAdmin() { if (msg.sender != _s().admin) revert NotAdmin(); _; }
    function pause()                      external onlyAdmin { _s().paused = true; }
    function unpause()                    external onlyAdmin { _s().paused = false; }
    function setMinStake(uint256 v)       external onlyAdmin { _s().minStake = v; }
    function setWithdrawDelay(uint64 v)   external onlyAdmin { _s().withdrawDelay = v; }
    function setRequireBlobs(bool v)      external onlyAdmin { _s().requireBlobs = v; }
    function transferAdmin(address a)     external onlyAdmin {
        if (a == address(0)) revert ZeroAddress();
        _s().admin = a;
    }

    function _s() private pure returns (LS storage s) {
        bytes32 slot = _SLOT;
        assembly ("memory-safe") { s.slot := slot }
    }

    receive() external payable { revert("use registerCommitter()"); }
}
