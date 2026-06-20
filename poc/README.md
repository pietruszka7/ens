# PoC & coverage artifacts

Reproducible against a clean checkout of `ensdomains/ens-contracts` at tag `v1.7.0`.

Setup:
```bash
git clone https://github.com/ensdomains/ens-contracts && cd ens-contracts
git checkout v1.7.0
bun install && bun run compile
```

## `TestLibABIOverflow.sol` — Finding #1 PoC (confirmed)
Copy to `contracts/utils/TestLibABIOverflow.sol`, add a one-line test wrapper
`test/utils/TestLibABIOverflow.test.ts`:
```ts
import { runSolidityTests } from '../fixtures/runSolidityTests.js'
await runSolidityTests('TestLibABIOverflow')
```
Run: `npx vitest run test/utils/TestLibABIOverflow.test.ts`

Expected: `test_safeDecodeDoesNotRevertOnUntrustedInput` **fails** with
`BUG: tryDecodeBytes reverted on untrusted input (should return false)` —
proving `LibABI.tryDecodeBytes` reverts (Panic 0x11) on `0xFF*32` instead of
returning `(false, "")`.

## `FuzzNameCoder.test.ts` — coverage (passes, no bug)
Differential fuzz of `NameCoder.namehash` vs a raw-bytes reference namehash
(400+ random cases + max-length labels). Rules out a namehash correctness bug.

## `FuzzRoundTrip.test.ts` — coverage (passes, no bug)
- `ENSIP19.reverseName` → `NameCoder.encode` → `ENSIP19.parse` round-trips for
  random addresses across ETH / default / EVM / non-EVM coin types.
- `NameCoder.decode(encode(name)) == name` bijectivity on random byte-labels.

Both copy into `test/utils/` and run with `npx vitest run`.
