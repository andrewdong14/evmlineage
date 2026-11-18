// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title OnChainLineage — baseline: the lineage graph in contract storage.
/// @notice Every event writes one storage slot per edge (the parent list of
///         each output), so lineage can be read and proven with ordinary
///         storage proofs. Used only to measure what full on-chain storage
///         costs; it is not part of EVM-Lineage.
contract OnChainLineage {
    mapping(bytes32 => bytes32[]) private _parents;
    uint256 public events;

    event Recorded(uint256 indexed id, uint256 sources, uint256 targets);

    function record(bytes32[] calldata sources, bytes32[] calldata targets) external {
        uint256 ns = sources.length;
        uint256 nt = targets.length;
        for (uint256 j = 0; j < nt; ++j) {
            bytes32[] storage p = _parents[targets[j]];
            for (uint256 i = 0; i < ns; ++i) {
                p.push(sources[i]);
            }
        }
        emit Recorded(events++, ns, nt);
    }

    function parentsOf(bytes32 item) external view returns (bytes32[] memory) {
        return _parents[item];
    }
}
