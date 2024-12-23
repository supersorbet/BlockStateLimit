// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import {Ownable} from "solady/src/auth/Ownable.sol";
import {LibBit} from "solady/src/utils/LibBit.sol";
import {SafeTransferLib} from "solady/src/utils/SafeTransferLib.sol";
import {LibZip} from "solady/src/utils/LibZip.sol";
import {IAntiMevStrategy} from "../interfaces/IAntiMevStrategy.sol";
import {IPair} from "../interfaces/IPair.sol";
import {IUniswapV2Factory} from "../interfaces/IUniswapV2Factory.sol";
import {IUniswapV3Factory} from "../interfaces/IUniswapV3Factory.sol";
import {IPoolV3} from "../interfaces/IPoolV3.sol";

/// @title DirectionalBlockLimitCheck
/// @author [@supersorbet]
/// @notice Strat to prevent sandwich attacks by enforcing directional transaction limits
/// @dev Implements MEV protecc thru per-block directional transaction constraints
contract DirectionalBlockLimit is Ownable, IAntiMev {

    error ExceededBlockDirectionLimit(address account);
    /// @notice Thrown when non-token contract attempts to call protected functions
    error UnauthorizedCaller();
    /// @notice Thrown when factory version is not 2 (V2) or 3 (V3)
    error InvalidFactoryVersion(uint8 version);
    /// @notice Thrown when zero address is provided where not allowed
    error InvalidAddress();
    /// @notice Thrown when target address contains no code
    error NotAContract(address target);
    /// @notice Thrown when attempting to use non-whitelisted factory
    error FactoryNotWhitelisted(address factory);
    /// @notice Thrown when pair contract validation fails
    error InvalidPairContract(address pair);
    /// @notice Thrown when array lengths don't match in batch operations
    error ArrayLengthMismatch();

    /// @dev Factory configuration data structure - packed for gas efficiency
    struct FactoryInfo {
        bool isWhitelisted;
        uint8 version;
    }
    /// @notice Protected token contract address
    address public immutable token;
    /// @dev Tracks transfer directions per block using bit flags
    /// @dev bit 0 (0x01) = outgoing, bit 1 (0x02) = incoming
    mapping(bytes32 accountHash => uint8 directions) private blockDirections;
    /// @notice Protection-exempt addresses mapping
    mapping(address account => bool isExempt) public protectedAccounts;
    /// @notice DEX factory configurations
    mapping(address factory => FactoryInfo factoryInfo) public factoryInfos;
    /// @dev Constants for bit operations
    uint8 private constant OUTGOING_BIT = 0x01;
    uint8 private constant INCOMING_BIT = 0x02;

    /// @notice Initializes the protection strategy
    /// @param _token Protected token address
    constructor(address _token) {
        if (_token == address(0)) revert InvalidAddress();
        token = _token;
    }

    /// @notice Processes transfers with MEV protection
    /// @param _from Source address
    /// @param _to Destination address
    /// @param _amount Transfer amount
    /// @param _isTaxing Whether transfer is part of taxation
    /// @dev Enforces directional limits unless address is exempt
    function onTransfer(
        address _from,
        address _to,
        uint256 _amount,
        bool _isTaxing
    ) external override onlyToken {
        /// @solidity memory-safe-assembly
        assembly {
            if or(
                or(iszero(iszero(_isTaxing)), eq(_from, _to)),
                iszero(_amount)
            ) {
                return(0, 0)
            }
        }
        bool fromIsExempt = protectedAccounts[_from];
        bool toIsExempt = protectedAccounts[_to];
        if (!fromIsExempt) {
            fromIsExempt = _isValidPair(_from);
        }
        if (!toIsExempt) {
            toIsExempt = _isValidPair(_to);
        }
        if (!fromIsExempt) {
            _processDirection(_from, OUTGOING_BIT, INCOMING_BIT);
        }
        if (!toIsExempt) {
            _processDirection(_to, INCOMING_BIT, OUTGOING_BIT);
        }
    }

    /// @dev Process direction for an address using inline assembly
    /// @param account Address to process
    /// @param allowedBit Bit flag for allowed direction
    /// @param blockedBit Bit flag for blocked direction
    function _processDirection(
        address account,
        uint8 allowedBit,
        uint8 blockedBit
    ) private {
        /// @solidity memory-safe-assembly
        assembly {
            mstore(0x00, account)
            mstore(0x20, number())
            let key := keccak256(0x00, 0x40)
            let slot := add(blockDirections.slot, key)
            let direction := sload(slot)
            if and(direction, blockedBit) {
                //revert w ExceededBlockDirectionLimit
                mstore(0x00, 0x8b68f4c3)
                mstore(0x04, account)
                revert(0x00, 0x24)
            }
            sstore(slot, or(direction, allowedBit))
        }
    }

    /// @dev Validates if address is a legitimate DEX pair using optimized checks
    /// @param _target Address to validate
    /// @return isValidPair True if address is valid DEX pair
    function _isValidPair(
        address _target
    ) private view returns (bool isValidPair) {
        /// @solidity memory-safe-assembly
        assembly {
            if iszero(extcodesize(_target)) {
                isValidPair := 0
                return(0, 32)
            }
            let ptr := mload(0x40)
            mstore(ptr, 0xc45a0155) //factory()

            let success := staticcall(gas(), _target, ptr, 0x04, 0x00, 0x20)

            if iszero(success) {
                isValidPair := 0
                return(0, 32)
            }

            let factory := mload(0x00)
            mstore(0x00, factory)
            mstore(0x20, factoryInfos.slot)
            let factorySlot := keccak256(0x00, 0x40)
            let isWhitelisted := sload(factorySlot)

            if iszero(isWhitelisted) {
                isValidPair := 0
                return(0, 32)
            }

            let version := shr(248, sload(add(factorySlot, 1)))
            mstore(ptr, 0x0dfe1681) //token0()

            success := staticcall(gas(), _target, ptr, 0x04, 0x00, 0x20)
            if iszero(success) {
                isValidPair := 0
                return(0, 32)
            }
            let token0 := mload(0x00)

            mstore(ptr, 0xd21220a7) //token1()
            success := staticcall(gas(), _target, ptr, 0x04, 0x00, 0x20)
            if iszero(success) {
                isValidPair := 0
                return(0, 32)
            }
            let token1 := mload(0x00)

            switch version
            case 2 {
                mstore(ptr, 0xe6a43905) //getPair
                mstore(add(ptr, 0x04), token0)
                mstore(add(ptr, 0x24), token1)

                success := staticcall(gas(), factory, ptr, 0x44, 0x00, 0x20)

                if and(success, eq(mload(0x00), _target)) {
                    isValidPair := 1
                    return(0x00, 32)
                }
            }
            case 3 {
                //validate v3
                mstore(ptr, 0xddca3f43) //fee()
                success := staticcall(gas(), _target, ptr, 0x04, 0x00, 0x20)

                if success {
                    let fee := mload(0x00)
                    mstore(ptr, 0x1698ee82) //getPool
                    mstore(add(ptr, 0x04), token0)
                    mstore(add(ptr, 0x24), token1)
                    mstore(add(ptr, 0x44), fee)

                    success := staticcall(gas(), factory, ptr, 0x64, 0x00, 0x20)

                    if and(success, eq(mload(0x00), _target)) {
                        isValidPair := 1
                        return(0x00, 32)
                    }
                }
            }
            default {
                isValidPair := 0
                return(0x00, 32)
            }
        }
    }

    /// @dev Helper to get pair tokens using optimized calls
    /// @param pair Address of the pair contract
    /// @return token0 First token address
    /// @return token1 Second token address
    function _getPairTokens(
        address pair
    ) private view returns (address token0, address token1) {
        try IPair(pair).token0() returns (address _token0) {
            token0 = _token0;
            try IPair(pair).token1() returns (address _token1) {
                token1 = _token1;
            } catch {
                token1 = address(0);
            }
        } catch {
            token0 = address(0);
            token1 = address(0);
        }
    }

    /// @dev Validates pair based on factory version
    /// @param factory Factory address
    /// @param token0 First token
    /// @param token1 Second token
    /// @param pair Pair address
    /// @param version Factory version
    /// @return isValid True if pair is valid
    function _validatePairByVersion(
        address factory,
        address token0,
        address token1,
        address pair,
        uint8 version
    ) private view returns (bool isValid) {
        if (version == 2) {
            return IUniswapV2Factory(factory).getPair(token0, token1) == pair;
        } else if (version == 3) {
            try IPoolV3(pair).fee() returns (uint24 fee) {
                return
                    IUniswapV3Factory(factory).getPool(token0, token1, fee) ==
                    pair;
            } catch {
                return false;
            }
        }
        return false;
    }

    /// @dev Updates protection exemption status
    /// @param _account Address to update
    /// @param _isExempt Exemption status
    function _setProteccExemption(address _account, bool _isExempt) private {
        /// @solidity memory-safe-assembly
        assembly {
            if iszero(_account) {
                mstore(0x00, 0xe6c4247b) //InvalidAddress
                revert(0x00, 0x04)
            }
            sstore(add(protectedAccounts.slot, _account), _isExempt)

            let ptr := mload(0x40)
            mstore(ptr, _account)
            mstore(add(ptr, 0x20), _isExempt)
            log2(
                ptr,
                0x40,
                0xf279e026fe11b6dbd1006f8d5e601df1f5cdaac5c1c1f2d42a18c86b3ace7978,
                _account
            )
        }
    }

    /// @notice Updates protection exemption for an address
    /// @param _account Address to update
    /// @param _isExempt Exemption status
    function setProteccExemption(
        address _account,
        bool _isExempt
    ) external onlyOwner {
        _setProteccExemption(_account, _isExempt);
    }

    /// @notice Batch updates protection exemptions
    /// @param _accounts Addresses to update
    /// @param _isExempt Exemption statuses
    function setProteccExemptions(
        address[] calldata _accounts,
        bool[] calldata _isExempt
    ) external onlyOwner {
        if (_accounts.length != _isExempt.length) revert ArrayLengthMismatch();

        for (uint256 i; i < _accounts.length; ) {
            _setProteccExemption(_accounts[i], _isExempt[i]);
            unchecked {
                ++i;
            }
        }
    }

    modifier onlyToken() {
        if (msg.sender != token) revert UnauthorizedCaller();
        _;
    }
    /// @notice Emitted when DEX factory whitelist status changes
    event FactoryWhitelistUpdated(
        address indexed factory,
        uint8 version,
        bool isWhitelisted
    );
    /// @notice Emitted when address protection status changes
    event ProtectionExemptionUpdated(address indexed account, bool isExempt);
}
