// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract GaslessForwarder is EIP712 {
    using ECDSA for bytes32;

    struct ForwardRequest {
        address from;
        address to;
        bytes data;
        uint256 nonce;
    }

    bytes32 private constant _TYPEHASH =
        keccak256("ForwardRequest(address from,address to,bytes data,uint256 nonce)");

    mapping(address => uint256) public nonces;

    event TransactionForwarded(
        address indexed from,
        address indexed to,
        bytes data,
        uint256 nonce
    );

    constructor() EIP712("GaslessForwarder", "1") {}

    function execute(
        address from,
        address to,
        bytes calldata data,
        uint256 nonce,
        bytes calldata signature
    ) external {
        // Validate input parameters
        require(from != address(0), "Invalid sender address");
        require(to != address(0), "Invalid recipient address");
        require(nonces[from] == nonce, "Invalid nonce");

        // Verify signature
        bytes32 structHash = keccak256(
            abi.encode(_TYPEHASH, from, to, keccak256(data), nonce)
        );
        bytes32 digest = _hashTypedDataV4(structHash);
        address signer = digest.recover(signature);
        require(signer == from, "Invalid signature");

        // Update nonce before execution to prevent reentrancy
        nonces[from]++;

        // Execute transaction
        (bool success, ) = to.call(data);
        require(success, "Execution failed");

        emit TransactionForwarded(from, to, data, nonce);
    }
}