// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title LineageProxy — EIP-1967 transparent upgradeable proxy
contract LineageProxy {
    bytes32 private constant _IMPL  =
        0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;
    bytes32 private constant _ADMIN =
        0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103;

    event Upgraded(address indexed impl);

    constructor(address impl_, address admin_, bytes memory data_) {
        _store(_IMPL,  bytes32(uint256(uint160(impl_))));
        _store(_ADMIN, bytes32(uint256(uint160(admin_))));
        if (data_.length > 0) {
            (bool ok,) = impl_.delegatecall(data_);
            require(ok, "init failed");
        }
    }

    modifier onlyAdmin() {
        require(msg.sender == address(uint160(uint256(_load(_ADMIN)))), "not admin");
        _;
    }

    function upgradeTo(address impl_) external onlyAdmin {
        require(impl_.code.length > 0, "not a contract");
        _store(_IMPL, bytes32(uint256(uint160(impl_))));
        emit Upgraded(impl_);
    }

    function upgradeToAndCall(address impl_, bytes calldata data_) external onlyAdmin {
        require(impl_.code.length > 0, "not a contract");
        _store(_IMPL, bytes32(uint256(uint160(impl_))));
        (bool ok,) = impl_.delegatecall(data_);
        require(ok, "call failed");
        emit Upgraded(impl_);
    }

    function implementation() external view returns (address) {
        return address(uint160(uint256(_load(_IMPL))));
    }

    function _store(bytes32 slot, bytes32 v) internal { assembly { sstore(slot, v) } }
    function _load(bytes32 slot) internal view returns (bytes32 v) { assembly { v := sload(slot) } }

    fallback() external payable {
        address impl = address(uint160(uint256(_load(_IMPL))));
        assembly {
            calldatacopy(0, 0, calldatasize())
            let r := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch r case 0 { revert(0, returndatasize()) } default { return(0, returndatasize()) }
        }
    }
    receive() external payable {}
}

/// @title LineageMultisig — minimal 3-of-5 multisig that can act as the
///        committer (and as the proxy admin). Stake it with
///        LineageAnchor.registerCommitterFor(address(multisig)); it can
///        receive the stake back through withdrawStake().
contract LineageMultisig {
    uint8 public constant THRESHOLD  = 3;
    uint8 public constant MAX_OWNERS = 5;

    address[MAX_OWNERS] public owners;
    uint8 public ownerCount;

    mapping(bytes32 => mapping(address => bool)) public approved;
    mapping(bytes32 => uint8)  public approvalCount;
    mapping(bytes32 => bool)   public executed;
    mapping(bytes32 => address) public txTarget;
    mapping(bytes32 => bytes)   public txData;

    event Submitted(bytes32 indexed txHash);
    event Approved(bytes32 indexed txHash, address indexed owner);
    event Executed(bytes32 indexed txHash);

    constructor(address[] memory owners_) {
        require(owners_.length <= MAX_OWNERS, "too many owners");
        ownerCount = uint8(owners_.length);
        for (uint8 i = 0; i < ownerCount; i++) owners[i] = owners_[i];
    }

    modifier onlyOwner() {
        bool found;
        for (uint8 i = 0; i < ownerCount; i++)
            if (owners[i] == msg.sender) { found = true; break; }
        require(found, "not owner");
        _;
    }

    function submit(address target, bytes calldata data) external onlyOwner returns (bytes32 h) {
        h = keccak256(abi.encode(target, data, block.number));
        txTarget[h] = target;
        txData[h]   = data;
        emit Submitted(h);
    }

    function approve(bytes32 h) external onlyOwner {
        require(txTarget[h] != address(0), "unknown tx");
        require(!approved[h][msg.sender], "already approved");
        require(!executed[h], "already executed");
        approved[h][msg.sender] = true;
        approvalCount[h]++;
        emit Approved(h, msg.sender);
    }

    function execute(bytes32 h) external onlyOwner {
        require(!executed[h], "already executed");
        require(approvalCount[h] >= THRESHOLD, "below threshold");
        executed[h] = true;
        (bool ok,) = txTarget[h].call(txData[h]);
        require(ok, "execution failed");
        emit Executed(h);
    }

    function isReady(bytes32 h) external view returns (bool) {
        return approvalCount[h] >= THRESHOLD && !executed[h];
    }

    receive() external payable {}
}
