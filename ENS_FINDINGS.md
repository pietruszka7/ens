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

---

## Finding #3 — WITHDRAWN (FALSE POSITIVE: documented intended behavior)

> **Do NOT report.** Verification against `contracts-v2/README.md` shows this is
> explicitly documented, intended design — not a vulnerability.
>
> README "Transfer Behavior": *"Existing roles delegated to other accounts remain
> intact unless explicitly revoked. Example: If Alice granted Bob ROLE_SET_RESOLVER
> and transfers the name to Charlie, Charlie becomes the new admin but Bob keeps his
> resolver permission."* The team also deliberately blocked **admin**-role
> delegation specifically "to prevent … retaining control after a transfer",
> while accepting regular-role persistence as a documented tradeoff.
>
> The PoC (`poc/ResidualAccessPoC.t.sol`) faithfully demonstrates this behavior,
> but it is by-design and therefore out of scope / not payable. Kept here only as
> a record of the (correct) verification that rejected it.

<details>
<summary>Original (incorrect) write-up — kept for transparency</summary>

| | |
|---|---|
| **Severity (self-assessed)** | ~~High~~ → **N/A (intended behavior)** |
| **Status** | PoC passes, but confirmed **false positive** (documented design) |
| **Repo / scope** | `ensdomains/contracts-v2` |
| **Component** | `contracts/src/registry/PermissionedRegistry.sol` |

### Summary

When a name (ERC1155 token) is transferred/sold, `_update()` → `_transferRoles()`
moves only the **previous owner's** roles to the new owner. It does **not**
increment `eacVersionId`, so the EAC *resource* is unchanged, and any role the
previous owner delegated to a **third party** (e.g. an alt wallet) on that
resource **persists after the sale**. The seller therefore keeps `ROLE_SET_RESOLVER`
/ `ROLE_SET_SUBREGISTRY` control over a name the buyer now owns.

This matches `AUDIT_README.md` "Key Area of Concern #3 — Name transfer safety:
ensuring ownership state is fully reset on transfer … preventing previous owners
from retaining access (cf. CVE-2020-5232)", and breaks the documented invariant
"the token owner is the sole controller of their name."

### Root cause

`eacVersionId` (which forms the EAC resource id) is only bumped in `unregister()`
and on re-registration of an expired name — **never on transfer**:

```solidity
function _update(address from, address to, uint256[] memory tokenIds, uint256[] memory amounts) internal override {
    super._update(from, to, tokenIds, amounts);
    if (to != address(0) && from != address(0)) {
        for (uint256 i; i < tokenIds.length; ++i) {
            uint256 tokenId = tokenIds[i];
            if (!hasRoles(tokenId, RegistryRolesLib.ROLE_CAN_TRANSFER_ADMIN, from)) {
                revert TransferDisallowed(tokenId, from);
            } else if (amounts[i] > 0) {
                _transferRoles(getResource(tokenId), from, to, false); // only moves `from`'s roles
            }
        }
    }
}
```

`_transferRoles` reads `_roles[resource][srcAccount]` only — third-party delegatee
entries on the same `resource` are never touched, and `resource` does not change.

### Attack

1. Alice registers `premium.eth` (gets `ROLE_SET_RESOLVER` + `ROLE_SET_RESOLVER_ADMIN`
   + `ROLE_CAN_TRANSFER_ADMIN`, i.e. `ETHRegistrar.REGISTRATION_ROLE_BITMAP`).
2. Before listing, Alice grants `ROLE_SET_RESOLVER` to her alt wallet `aliceAlt`
   (allowed because she holds the corresponding admin role).
3. Alice sells the name to Carol via `safeTransferFrom`.
4. Carol owns the token and Alice holds no roles — **but `aliceAlt` still holds
   `ROLE_SET_RESOLVER`** on the (unchanged) resource.
5. `aliceAlt` calls `setResolver(tokenId, maliciousResolver)`; resolution of
   Carol's name now points wherever the seller chooses → addresses returned for
   `premium.eth` can be the seller's, redirecting funds.

The seller cannot reclaim the NFT itself (`ROLE_UNREGISTER` and
`ROLE_CAN_TRANSFER_ADMIN` are admin-position roles and cannot be delegated), but
retains full control of the name's resolver and subregistry — i.e. everything
that determines what the name resolves to.

### Proof of Concept

`poc/ResidualAccessPoC.t.sol` (drop into `contracts/test/unit/registry/` of a built
`contracts-v2` checkout, then `forge test --match-path test/unit/registry/ResidualAccessPoC.t.sol -vv`):

```
[PASS] test_PoC_delegatedRoleSurvivesSale_sellerHijacksBuyersResolver()
```

The test asserts: after the sale Carol owns the token, Alice has no roles, **but
`aliceAlt` still has `ROLE_SET_RESOLVER`**, and `aliceAlt` successfully rewrites
the resolver of the name Carol just bought.

### Recommended fix

On transfer, give the name a fresh permission scope just like re-registration —
increment `eacVersionId` in `_update()` so all prior delegatee roles on the old
resource are abandoned (the new owner is re-granted the registration roles). Or
explicitly clear all assignees of the resource on transfer. Document the chosen
behaviour as part of the transfer-safety invariant.

</details>

---

## ENSv2 (`ensdomains/contracts-v2`) — review notes

In-scope per Immunefi (`contracts-v2/releases`). Reviewed at HEAD `5677359`
(2026-05-19, pre-release / no tags). Fresh, less-audited code — prioritised.

**Reviewed in depth (no clearly-exploitable Medium+ found):**
- `EnhancedAccessControl` + `EACBaseRolesLib` — nybble-packed role/count bitmap;
  carry/borrow overflow & underflow guards (`_hasZeroNybbles`) verified correct;
  admin-role grant model (`_getSettableRoles`) consistent.
- `PermissionedRegistry` + `LibLabel` + `ERC1155Singleton` — dual version counters
  (eac/token); `withVersion` truncates lower 32 bits of the labelhash (cross-name
  collision needs a 224-bit partial keccak collision → infeasible); token
  regeneration on role change; role transfer on ERC1155 transfer gated by
  `ROLE_CAN_TRANSFER_ADMIN`; expired/re-register increments eacVersion → fresh
  permission scope (old roles orphaned, not leaked).
- `ETHRegistrar` — commit-reveal binds owner; name goes to committed owner;
  RESERVED status blocks front-running migration; checked arithmetic on expiry.
- Migration (`AbstractWrapperReceiver`, `Locked`/`UnlockedMigrationController`,
  `LockedWrapperReceiver`, `WrapperRegistry`, `LibMigration`) — `node ==
  namehash(parentNode, keccak(label))` binds label to the transferred token;
  `onlyWrapper`; you can only migrate names you control in v1.
- `PermissionedResolver` + `PermissionedResolverLib` — `onlyPartRoles` 2×2
  resource model; `resolve()`/aliasing/`ResolverProfileRewriterLib` are
  **read-only** (staticcall, public data) so node-rewrite parser-differentials
  are not a write-auth bypass.
- `UserRegistry` — thin self-owned proxy.

**Observations (low / informational, not confirmed payable):**
1. `PermissionedResolver.multicallWithNodeCheck(node, calls)` ignores `node` and
   forwards to `multicall(calls)`. In ENSv1 this enforced that every sub-call
   targets `node` (defence-in-depth when a privileged caller forwards
   user-supplied data). In v2 it is a no-op. Mitigated because every setter
   re-checks `onlyPartRoles(node, ...)`, and no in-scope v2 contract forwards
   attacker data through it — but it is a defence-in-depth regression / footgun
   for any future integrator that relies on the historical semantics.
2. All of v2's authorization (`_msgSender()` via `HCAContext`) trusts
   `HCA_FACTORY.getAccountOwner()`. If the (external, not-in-this-repo) HCA
   factory can be made to report an attacker-controlled HCA as owned by a victim,
   it is full impersonation (Critical). The factory implementation should be
   reviewed separately — it is the single largest trust dependency in v2.

**Not yet reviewed (remaining v2 surface that could still hide a payable bug):**
`UniversalResolverV2` + `UpgradableUniversalResolverProxy`, the DNS resolvers
(`DNSTLDResolver`, `DNSAliasResolver`, `DNSTXTResolver`, `DNSTXTParserLib`),
`AbstractMirrorResolver`/`ENSV1Resolver`/`ENSV2Resolver`, `StandardRentPriceOracle`
+ `LibHalving`, reverse registrars, `LibISO8601`/`LibString`, the `hca/*Upgradeable`
variants, and `VerifiableFactory` proxy/salt interactions.

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
