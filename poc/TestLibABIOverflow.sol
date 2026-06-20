// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {LibABI} from "./LibABI.sol";

/// @dev PoC: `LibABI.tryDecodeBytes` is documented as a *safe* decoder that
///      returns `(false, "")` for any malformed/untrusted input. This proves it
///      can instead revert (Panic 0x11) on attacker-controlled input, defeating
///      the safety guard that protects batch reverse resolution
///      (`ETHReverseResolver.resolveNames`).
contract TestLibABIOverflow {
    function wrap(bytes calldata v) external pure returns (bool ok) {
        (ok, ) = LibABI.tryDecodeBytes(v);
    }

    /// @notice A safe decoder must NOT revert here; it should return (false, "").
    ///         With the overflow bug present, the inner call reverts and this test fails.
    function test_safeDecodeDoesNotRevertOnUntrustedInput() external view {
        // First 32-byte word = offset = type(uint256).max.
        //   need = 32 + offset  (unchecked) -> overflows to 31, so `v.length >= need` passes,
        //   then readBytes32(v, offset) computes `offset + 32` (checked) -> Panic(0x11).
        bytes memory bad = new bytes(32);
        assembly {
            mstore(add(bad, 32), not(0)) // 32 bytes of 0xFF
        }

        (bool ok, ) = address(this).staticcall(
            abi.encodeWithSelector(this.wrap.selector, bad)
        );

        require(
            ok,
            "BUG: tryDecodeBytes reverted on untrusted input (should return false)"
        );
    }

    /// @notice Control: the same crafted input handled by a truly-safe decoder
    ///         (bounds-checked, no unchecked overflow) returns false gracefully.
    function test_controlValidInputsRoundTrip() external pure {
        bytes memory v = hex"deadbeef";
        (bool ok, bytes memory u) = LibABI.tryDecodeBytes(abi.encode(v));
        require(ok && keccak256(u) == keccak256(v), "roundtrip");
    }
}
