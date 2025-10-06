// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract MetaTxExample {
    using ECDSA for bytes32;

    string public constant NAME = "MetaTxExample";
    string public constant VERSION = "1";

    bytes32 private constant META_TRANSACTION_TYPEHASH =
        keccak256("MetaTransaction(uint256 nonce,address from,bytes functionSignature)");

    mapping(address => uint256) public nonces;

    event MetaTransactionExecuted(address user, address relayer, bytes functionSignature);

    function executeMetaTransaction(
        address userAddress,
        bytes calldata functionSignature,
        bytes calldata signature
    ) external payable returns (bytes memory) {
        uint256 nonce = nonces[userAddress];
        bytes32 digest = keccak256(
            abi.encodePacked(
                "\x19\x01",
                _domainSeparator(),
                keccak256(abi.encode(META_TRANSACTION_TYPEHASH, nonce, userAddress, keccak256(functionSignature)))
            )
        );

        address signer = digest.recover(signature);
        require(signer == userAddress, "MetaTx: Invalid signature");

        nonces[userAddress]++;

        (bool success, bytes memory returndata) = address(this).call(abi.encodePacked(functionSignature, userAddress));
        require(success, "MetaTx: Function call failed");

        emit MetaTransactionExecuted(userAddress, msg.sender, functionSignature);

        return returndata;
    }

    function _domainSeparator() internal view returns (bytes32) {
        return keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256(bytes(NAME)),
                keccak256(bytes(VERSION)),
                block.chainid,
                address(this)
            )
        );
    }
}
