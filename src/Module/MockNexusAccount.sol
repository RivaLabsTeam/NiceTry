// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {PackedUserOperation} from "@openzeppelin/contracts/interfaces/draft-IERC4337.sol";
import {RotatingECDSAValidator} from "src/Module/RotatingECDSAValidator.sol";

contract MockNexusAccount {
    RotatingECDSAValidator public validator;

    constructor(address _validator) {
        validator = RotatingECDSAValidator(_validator);
    }

    function installValidator(bytes calldata initData) external {
        validator.onInstall(initData);
    }

    function uninstallValidator() external {
        validator.onUninstall("");
    }

    function validateUserOp(
        PackedUserOperation memory userOp,
        bytes32 userOpHash
    ) external returns (uint256) {
        require(
            validator.isInitialized(address(this)),
            "MockNexus: validator not installed"
        );
        return validator.validateUserOp(userOp, userOpHash);
    }

    function isValidSignature(bytes32 hash, bytes calldata sig)
        external
        view
        returns (bytes4)
    {
        return validator.isValidSignatureWithSender(address(this), hash, sig);
    }

    receive() external payable {}
}