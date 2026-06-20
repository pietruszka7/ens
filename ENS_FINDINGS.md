# ENS `ens-contracts` — Security Findings (Immunefi)

- **Target program:** ENS (Immunefi) — https://immunefi.com/bug-bounty/ens/
- **Repository:** `ensdomains/ens-contracts`
- **Version reviewed:** `v1.7.0` (latest mainnet-eligible release at time of review)
- **Date:** 2026-06-20
- **Reviewer:** BB hunt

---

## Finding #1 — `LibABI.tryDecodeBytes` reverts (Panic) on untrusted input, defeating its safety guarantee (batch reverse-resolution DoS)

| | |
|---|---|
| **Severity (self-assessed)** | Low (possibly Medium — DoS of public batch reverse resolution) |
| **Status** | **Confirmed with working PoC** |
| **Component** | `contracts/utils/LibABI.sol` |
| **Impact** | A single address can permanently brick `ETHReverseResolver.resolveNames([...])` batches that include it, defeating the exact safety mechanism `tryDecodeBytes` exists to provide. |

### Root cause

```solidity
// contracts/utils/LibABI.sol
function tryDecodeBytes(bytes memory v) internal pure returns (bool ok, bytes memory value) {
    unchecked {
        uint256 need = 32;
        if (v.length >= need) {
            uint256 offset = uint256(bytes32(v));   // attacker-controlled
            need += offset;                          // <-- unchecked overflow
            if (v.length >= need) {                  // passes when `need` wraps to a small value
                uint256 size = uint256(BytesUtils.readBytes32(v, offset)); // offset+32 (CHECKED) => Panic
                if (v.length >= need + size) {
                    return (true, BytesUtils.substring(v, offset + 32, size));
                }
            }
        }
    }
}
```

The function is documented as a **safe** decoder that returns `(false, "")` for any
malformed input. However, `need += offset` runs inside `unchecked`, so a large
`offset` overflows `need` to a small number, passing the `v.length >= need` guard.
Execution then reaches `BytesUtils.readBytes32(v, offset)`, which computes
`off + 32` in **checked** arithmetic (it is a separate, non-`unchecked` function),
triggering `Panic(0x11)` instead of returning `false`.

### Trigger input

`v = 0xFF × 32` (32 bytes, all `0xFF`):
- `offset = uint256(bytes32(v)) = type(uint256).max`
- `need = 32 + offset` wraps to `31`; `v.length (32) >= 31` ✅
- `readBytes32(v, offset)` → `offset + 32` overflows (checked) → **Panic(0x11)**

### Impact path

`ETHReverseResolver._resolveName` decodes the **untrusted** return value of an
arbitrary resolver:

```solidity
// contracts/reverseResolver/ETHReverseResolver.sol
(bool ok, bytes memory v) = resolver.staticcall{gas: 100_000}(
    abi.encodeCall(INameResolver.name, (node))
);
if (ok) {
    (ok, v) = LibABI.tryDecodeBytes(v);   // <-- reverts (Panic) on crafted return data
}
if (!ok) return "";                       // intended graceful path is bypassed
```

The resolver for `{addr}.addr.reverse` is set **by the owner of that address**.
An attacker points their own reverse node at a malicious contract whose
`name(node)` returns the crafted bytes. Then any call to the public batch helper:

```solidity
ETHReverseResolver.resolveNames([alice, attacker, bob])  // used by indexers / UIs
```

reverts in full (the Panic propagates out of the per-address loop), so `alice`
and `bob` fail to resolve as well. `tryDecodeBytes` was specifically introduced to
prevent one malicious resolver from reverting batch resolution — the overflow
defeats that guarantee.

The single-name path (`AbstractReverseResolver.resolve` → `name()`) also reverts,
but that is self-grief; the batch path is what affects third parties.

### Proof of Concept (runs against v1.7.0)

`contracts/utils/TestLibABIOverflow.sol`:

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {LibABI} from "./LibABI.sol";

contract TestLibABIOverflow {
    function wrap(bytes calldata v) external pure returns (bool ok) {
        (ok, ) = LibABI.tryDecodeBytes(v);
    }

    // A safe decoder must NOT revert here; it should return (false, "").
    function test_safeDecodeDoesNotRevertOnUntrustedInput() external view {
        bytes memory bad = new bytes(32);
        assembly { mstore(add(bad, 32), not(0)) } // 32 bytes of 0xFF
        (bool ok, ) = address(this).staticcall(
            abi.encodeWithSelector(this.wrap.selector, bad)
        );
        require(ok, "BUG: tryDecodeBytes reverted on untrusted input (should return false)");
    }
}
```

Result (`vitest`):

```
Tests  1 failed | 1 passed
 ✗ test_safeDecodeDoesNotRevertOnUntrustedInput
     reverted with reason 'BUG: tryDecodeBytes reverted on untrusted input (should return false)'
```

The failing test proves `tryDecodeBytes` reverts where a safe decoder must return `(false, "")`.

### Recommended fix

Remove the overflow before using `offset`, e.g.:

```solidity
uint256 offset = uint256(bytes32(v));
if (offset > v.length - 32) return (false, ""); // v.length >= 32 already checked
uint256 size = uint256(BytesUtils.readBytes32(v, offset));
if (size > v.length - 32 - offset) return (false, "");
return (true, BytesUtils.substring(v, offset + 32, size));
```

(or move the whole body out of `unchecked` and rely on checked arithmetic +
explicit comparisons that never add attacker-controlled values to constants).

---

## Finding #2 — `abi.encodePacked` hash ambiguity in `L2ReverseRegistrar` signed messages

| | |
|---|---|
| **Severity (self-assessed)** | Low |
| **Status** | Analysis (not yet PoC'd) |
| **Component** | `contracts/reverseRegistrar/L2ReverseRegistrar.sol` |
| **Impact** | A holder of a victim's valid multi-coinType signature can replay it as a different `(name, coinTypes)` tuple, corrupting the victim's L2 reverse record. |

### Root cause

```solidity
// setNameForAddrWithSignature (and setNameForOwnableWithSignature)
bytes32 message = keccak256(
    abi.encodePacked(
        address(this),
        this.setNameForAddrWithSignature.selector,
        addr,
        signatureExpiry,
        name,        // dynamic (string)
        coinTypes    // dynamic (uint256[])
    )
).toEthSignedMessageHash();
```

`name` and `coinTypes` are two **adjacent dynamic types** in `abi.encodePacked`,
so the boundary between them is ambiguous (classic Solidity `encodePacked`
collision). Given a valid signature over `(name1, [c0, c1])`, an attacker can
submit `(name2 = name1 ++ <32-byte c0>, [c1])`: the packed bytes are identical,
so the hash and signature stay valid, as long as the contract's own `coinType`
remains present in the supplied array (enforced by `validCoinTypes`).

### Impact

The attacker sets the victim's L2 reverse record to a corrupted name
(victim's intended name + 32 trailing bytes). The attacker cannot inject an
arbitrary readable name, and the victim did sign *something* — hence Low. Still,
a signature should bind to exactly one `(name, coinTypes)` tuple.

Note: `DefaultReverseRegistrar.setNameForAddrWithSignature` has only **one** trailing
dynamic field (`name`) and is therefore **not** affected.

### Recommended fix

Use `abi.encode` (not `abi.encodePacked`) for the signed message, or hash the
dynamic fields separately (`keccak256(bytes(name))`, `keccak256(abi.encode(coinTypes))`).

---

## Scope / coverage notes

Reviewed in depth (no Medium+ issue found in these): `ETHRegistrarController`,
`BaseRegistrarImplementation`, `NameWrapper` + `ERC1155Fuse`, resolver profiles
(`PublicResolver`/`DataResolver`/`ResolverBase`/`Multicallable`), parsing utils
(`NameCoder`/`HexUtils`/`ENSIP19`/`BytesUtils`/`LibMem`), CCIP-Read stack
(`CCIPReader`/`CCIPBatcher`/`ResolverCaller`/`AbstractUniversalResolver`), DNSSEC
(`DNSSECImpl`, `RSAPKCS1Verify` [hardened in v1.7.0], `P256Precompile` [fails closed],
`DNSClaimChecker`, `OffchainDNSResolver`), `Root`/security controllers,
`MigrationHelper`, `ERC20Recoverable`.
