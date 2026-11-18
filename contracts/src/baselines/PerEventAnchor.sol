// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title PerEventAnchor — baseline: one transaction per lineage event.
/// @notice The event's inputs and outputs travel as calldata and are emitted
///         as a log; the contract folds a digest of the event into a running
///         hash chain. This is the cheapest way to make every event
///         tamper-evident without batching: one storage update per event and
///         no on-chain index (queries replay the logs). Used only as a
///         baseline for the gas comparison.
contract PerEventAnchor {
    bytes32 public head;
    uint64  public count;

    event Lineage(uint64 indexed id, bytes32[] sources, bytes32[] targets);

    function record(bytes32[] calldata sources, bytes32[] calldata targets) external {
        head = keccak256(abi.encodePacked(head, keccak256(abi.encodePacked(sources)),
                                          keccak256(abi.encodePacked(targets))));
        emit Lineage(count++, sources, targets);
    }
}
