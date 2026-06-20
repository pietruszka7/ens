# ENS Smart Contracts — Total Security Review

**Scope:** Immunefi ENS program — on-chain smart contracts
**Targets reviewed:**
- `ensdomains/ens-contracts` @ **v1.7.0** (latest mainnet-eligible release)
- `ensdomains/contracts-v2` (ENSv2 / Namechain) @ `5677359` (pre-release, audit-fix `ffe4a73`+)

**Reviewer:** BB hunt · **Date:** 2026-06-20
**Methods:** manual review (entire contract set) · differential fuzzing (vitest/viem) · Foundry PoCs · Slither static analysis · `cloc`/diff vs prior versions.

> PoC required for all severities (Immunefi rule). Confirmed findings below ship with runnable PoCs in `poc/`.

---

## 1. Severity summary

| # | Title | Target | Severity | Status |
|---|-------|--------|----------|--------|
| 1 | `LibABI.tryDecodeBytes` reverts (Panic) on untrusted input → batch reverse-resolution DoS | v1.7.0 | **Low** | ✅ Confirmed (PoC) |
| 2 | `abi.encodePacked` hash ambiguity in `L2ReverseRegistrar` signed message | v1.7.0 | **Low** | Analysis. **Fixed in v2.** |
| 3 | ~~Delegated roles survive name transfer~~ | v2 | ~~High~~ | ❌ **False positive — documented intended behavior. Do NOT report.** |

**No Medium+/critical vulnerability was confirmed** in either codebase. v1.7.0 is hardened and multiply-audited; the v2 core is fresh but carefully constructed, with a coherent role/version model and strong bindings in migration and signatures.

---

## 2. Confirmed findings

### 2.1 (Low, PoC) `LibABI.tryDecodeBytes` — unchecked overflow defeats "safe decode"
`contracts/utils/LibABI.sol`. `need += offset` runs in an `unchecked` block with an
attacker-controlled `offset`; a large value overflows `need` so the bound check
passes, then `BytesUtils.readBytes32(v, offset)` (checked arithmetic in a separate
function) reverts with `Panic(0x11)` instead of returning `(false, "")`.

Impact: `ETHReverseResolver._resolveName` decodes the **untrusted** return value of an
arbitrary resolver via this function. A single address that points its own
`{addr}.addr.reverse` resolver at a contract returning `0xFF*32` bricks
`ETHReverseResolver.resolveNames([...])` batches that include it — defeating the very
safety guard `tryDecodeBytes` exists to provide. PoC: `poc/TestLibABIOverflow.sol`
(`test_safeDecodeDoesNotRevertOnUntrustedInput` fails, proving the revert).
Fix: bound-check `offset` before use / drop the `unchecked`.

### 2.2 (Low) `L2ReverseRegistrar` encodePacked ambiguity — v1.7.0 only
`contracts/reverseRegistrar/L2ReverseRegistrar.sol` (v1.7.0). The signed message
`keccak256(abi.encodePacked(addr, this, selector, expiry, name, coinTypes))` places two
adjacent dynamic fields (`name`, `coinTypes`), allowing a byte-shift collision that lets
a holder of a valid signature corrupt a victim's L2 reverse record. **ENSv2's rewritten
`L2ReverseRegistrar` is not affected** — it uses a human-readable EIP-191 message where
variable fields are separated by fixed-length fields, plus a monotonic `inceptionOf`
replay fence. (Reverse records are cosmetic → Low.)

---

## 3. False positive (verified & rejected)

### 3.1 v2 delegated roles surviving transfer — **intended, documented**
A Foundry PoC showed that EAC roles a name owner delegates (e.g. `ROLE_SET_RESOLVER`)
persist after the ERC1155 name is transferred, letting a seller retain resolver control
via a pre-delegated alt wallet. **This is explicitly documented as intended** in
`contracts-v2/README.md` ("Transfer Behavior": *"If Alice granted Bob `ROLE_SET_RESOLVER`
and transfers the name to Charlie, Charlie becomes the new admin but Bob keeps his
resolver permission"*). The team deliberately blocks **admin**-role delegation to prevent
retained *admin* control, and accepts regular-role persistence as a tradeoff. **Not a
vulnerability; not reportable.** Recorded here as evidence the FP-check worked.

---

## 4. Component review matrix

### ens-contracts v1.7.0
| Component | Verdict |
|---|---|
| `ETHRegistrarController`, `BaseRegistrarImplementation` | Clean — commitment binds all params, `_mint` (no callback) ⇒ no reentrancy, refunds via `transfer` |
| `NameWrapper`, `ERC1155Fuse` | Audited production code; fuse/expiry/grace logic intact |
| `SignatureUtils`, reverse registrars | 1 Low (2.2); replay bounded by 1h expiry + idempotent `_setName` |
| Resolvers (`PublicResolver`, `DataResolver`, `Multicallable`, `ResolverBase`) | Setters correctly `authorised(node)` |
| Parsing (`NameCoder`, `HexUtils`, `ENSIP19`, `BytesUtils`, `LibMem`) | Fuzzed: namehash ✔, encode/decode bijective ✔, reverseName↔parse ✔ |
| CCIP-Read / `UniversalResolver` / `ResolverCaller` | View-only; reverse flow has `ReverseAddressMismatch` forward-verification |
| DNSSEC (`DNSSECImpl`, RSA, P256, `DNSClaimChecker`, `OffchainDNSResolver`) | RSA **hardened** (full PKCS#1 v1.5), P256 fails-closed, gated by anchor trust root |
| `Root`/security controllers, `MigrationHelper`, `ERC20Recoverable`, `ENSRegistry(+Fallback)` | Correct access control; trust-root canonical |

### contracts-v2 (ENSv2)
| Component | Verdict |
|---|---|
| `EnhancedAccessControl`, `EACBaseRolesLib` | Nybble-packed role/count; carry/borrow guards verified |
| `PermissionedRegistry`, `LibLabel`, `ERC1155Singleton` | Dual version counters; transfer/regeneration model coherent (see §3.1 FP) |
| `ETHRegistrar`, `StandardRentPriceOracle`, `LibHalving` | Commit-reveal binds owner; premium math sound (decay→0, no underflow); ceil rounding prevents underpay |
| Migration (`AbstractWrapperReceiver`, `Locked`/`Unlocked` controllers, `WrapperRegistry`, `LibMigration`) | `node == namehash(parent, keccak(label))` binds label↔token; `onlyWrapper`; can only migrate names you control |
| `PermissionedResolver` + aliasing + `ResolverProfileRewriterLib` | Node-rewrite is **read-only** (staticcall, public data) ⇒ parser-differential ≠ write bypass |
| `L2ReverseRegistrar` (v2) | Replay fence (`inceptionOf`) + non-ambiguous EIP-191 message; **improves on v1.7.0** |
| `LibRegistry` traversal, DNS resolvers, `DNSTXTParserLib` | View; circular-subregistry/gas bound is a documented design decision; DNS input is DNSSEC/zone-owner controlled |
| `UserRegistry`, security controllers | Thin self-owned UUPS proxies |

---

## 5. Observations (informational — not payable)

- **`PermissionedResolver.multicallWithNodeCheck(node, calls)`** ignores `node` (no-op vs
  ENSv1's enforced node check). Mitigated by per-setter `onlyPartRoles`; a defence-in-depth
  regression for any future integrator relying on the historical semantics.
- **HCA Factory trust:** all v2 authorization (`_msgSender()` via `HCAContext`) trusts
  `HCA_FACTORY.getAccountOwner()`. The factory (`rhinestone-external/ens-modules`) is
  **out of scope** (separate Rhinestone audit) and its source is private — but it is the
  single largest trust dependency: a flaw there would be full impersonation.
- v1.7.0 `LibABI` self-grief single-resolution path (same root cause as 2.1).

---

## 6. Trust assumptions / out of scope (per `contracts-v2/doc/AUDIT_README.md`)

- HCA Factory (Rhinestone) — out of scope, trusted.
- ENSv1 contracts, DNSSEC oracle — trusted data sources.
- Unruggable Gateways — CCIP-Read transport.
- Test/deploy scripts, vendored ENSv1 — out of scope.
- `verifiable-factory` is separately in scope (not reviewed here in depth).

---

## 7. Tooling & reproduction

- v1.7.0: `bun install && bun run compile`; PoCs/fuzz in `poc/` run via `npx vitest run`.
- v2: foundry + submodules; `forge build`; PoC `poc/ResidualAccessPoC.t.sol` via `forge test`.
- Static analysis: Slither 0.11.5 over key entry points (no new serious findings; only known FPs: `arbitrary-send` with guards, `incorrect-shift` heuristic on verified masks).

---

## 8. Bottom line

Two **Low** findings (one PoC-confirmed) and several informational notes; one tempting
High candidate **correctly rejected as documented intended behavior**. The ENS on-chain
surface — both the hardened v1.7.0 and the fresh v2 core — is robust against the classes
probed here (theft, freezing, takeover, mispricing, signature replay, parser differentials,
residual access). The highest remaining-risk areas are the **out-of-scope HCA factory**
and any future-released v2 code; both warrant dedicated review when accessible.
