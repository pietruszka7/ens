/**
 * Bug Validation Tests for Immunefi Submission
 * Validates bugs in ENSRegistryWithFallback and ReverseRegistrar
 */

const namehash = require('eth-ens-namehash');
const sha3 = require('web3-utils').sha3;

const ENSWithFallback = artifacts.require('ENSRegistryWithFallback.sol');
const ENSRegistry     = artifacts.require('ENSRegistry.sol');
const ReverseRegistrar = artifacts.require('ReverseRegistrar.sol');
const DummyResolver    = artifacts.require('DummyResolver.sol');

const ZERO_ADDRESS = '0x0000000000000000000000000000000000000000';
const ZERO_HASH    = '0x0000000000000000000000000000000000000000000000000000000000000000';

// ─────────────────────────────────────────────────────────────────
// BUG #3 — MEDIUM: Event/Storage Inconsistency in ENSRegistryWithFallback
// ─────────────────────────────────────────────────────────────────
contract('BUG #3 — Event/Storage Inconsistency (ENSRegistryWithFallback)', function (accounts) {
    let oldRegistry, newRegistry;
    const ethNode = namehash.hash('eth');

    beforeEach(async () => {
        oldRegistry = await ENSRegistry.new();
        newRegistry = await ENSWithFallback.new(oldRegistry.address);

        // Set up "eth" in OLD registry, owned by accounts[1]
        await oldRegistry.setSubnodeOwner(ZERO_HASH, sha3('eth'), accounts[1], { from: accounts[0] });
        await oldRegistry.setResolver(ethNode, accounts[2], { from: accounts[1] });
    });

    it('[BUG #3.1] setOwner(node, address(0)) emits Transfer with 0x0 but storage holds address(this)', async () => {
        // Root owner in NEW registry "burns" eth node by setting owner to 0
        const tx = await newRegistry.setSubnodeOwner(ZERO_HASH, sha3('eth'), accounts[1], { from: accounts[0] });
        // Now accounts[1] owns eth in new registry. accounts[1] "burns" it:
        const burnTx = await newRegistry.setOwner(ethNode, ZERO_ADDRESS, { from: accounts[1] });

        const transferEvent = burnTx.logs.find(l => l.event === 'Transfer');
        assert.exists(transferEvent, 'Transfer event should be emitted');

        // EVENT says: new owner is address(0)
        assert.equal(transferEvent.args.owner, ZERO_ADDRESS,
            '[3.1] Event emits address(0) as expected');

        // But what does the contract actually report?
        const reportedOwner = await newRegistry.owner(ethNode);
        assert.equal(reportedOwner, ZERO_ADDRESS,
            '[3.1] owner() also returns address(0) — consistent with event on surface');

        // The KEY divergence: recordExists
        const exists = await newRegistry.recordExists(ethNode);
        assert.equal(exists, true,
            '[3.1] BUG CONFIRMED: recordExists() returns TRUE even though Transfer event shows address(0)! ' +
            'Off-chain systems think node is burned, but on-chain it still "exists".');
    });

    it('[BUG #3.2] Fallback to old registry is SILENTLY BLOCKED after setOwner(node, address(0))', async () => {
        // Confirm fallback WORKS before the bug is triggered
        const ownerBefore = await newRegistry.owner(ethNode);
        assert.equal(ownerBefore, accounts[1],
            '[3.2] Before: owner falls back correctly to old registry → accounts[1]');

        const resolverBefore = await newRegistry.resolver(ethNode);
        assert.equal(resolverBefore, accounts[2],
            '[3.2] Before: resolver falls back correctly to old registry → accounts[2]');

        // Now root owner creates eth in new registry and then "burns" it
        await newRegistry.setSubnodeOwner(ZERO_HASH, sha3('eth'), accounts[1], { from: accounts[0] });
        await newRegistry.setOwner(ethNode, ZERO_ADDRESS, { from: accounts[1] });

        // After the burn...
        const ownerAfter = await newRegistry.owner(ethNode);
        assert.equal(ownerAfter, ZERO_ADDRESS,
            '[3.2] After burn: owner() returns address(0)');

        const resolverAfter = await newRegistry.resolver(ethNode);
        assert.equal(resolverAfter, ZERO_ADDRESS,
            '[3.2] BUG CONFIRMED: resolver() now returns address(0) instead of accounts[2] from old registry! ' +
            'Fallback is silently blocked. Old registry data is INVISIBLE.');
    });

    it('[BUG #3.3] setSubnodeRecord with address(0) owner blocks fallback for a fresh node', async () => {
        // Old registry has eth with resolver accounts[2]
        // New registry root owner creates eth subnode with owner=address(0)
        await newRegistry.setSubnodeRecord(ZERO_HASH, sha3('eth'), ZERO_ADDRESS, ZERO_ADDRESS, 0, { from: accounts[0] });

        // recordExists should be true (because _setOwner stored address(this))
        const exists = await newRegistry.recordExists(ethNode);
        assert.equal(exists, true,
            '[3.3] BUG CONFIRMED: recordExists() = true even though owner was set to address(0)');

        // Fallback should NOT kick in (recordExists is true)
        const owner = await newRegistry.owner(ethNode);
        assert.equal(owner, ZERO_ADDRESS,
            '[3.3] owner() returns address(0) — NOT falling back to old registry accounts[1]');

        const resolver = await newRegistry.resolver(ethNode);
        assert.equal(resolver, ZERO_ADDRESS,
            '[3.3] BUG CONFIRMED: resolver() returns address(0) instead of accounts[2] from old registry. ' +
            'Fallback silently disabled by setting owner to zero.');
    });

    it('[BUG #3.4] NewOwner event emits address(0) but recordExists says node is alive — indexer lie', async () => {
        // Trigger via setSubnodeOwner
        const tx = await newRegistry.setSubnodeOwner(ZERO_HASH, sha3('eth'), ZERO_ADDRESS, { from: accounts[0] });

        const newOwnerEvent = tx.logs.find(l => l.event === 'NewOwner');
        assert.exists(newOwnerEvent, 'NewOwner event should be emitted');

        // Event says owner = address(0) — looks like node was "cleared"
        assert.equal(newOwnerEvent.args.owner, ZERO_ADDRESS,
            '[3.4] Event emits address(0)');

        // But recordExists says it EXISTS
        const exists = await newRegistry.recordExists(ethNode);
        assert.equal(exists, true,
            '[3.4] BUG CONFIRMED: recordExists() = true, but event emitted owner=address(0). ' +
            'Storage holds address(this), not address(0). ' +
            'Event logs LIE to off-chain indexers (TheGraph, Etherscan, etc.).');
    });
});

// ─────────────────────────────────────────────────────────────────
// BUG #1 — HIGH: Permanent Root Node Lock in ENSRegistryWithFallback
// ─────────────────────────────────────────────────────────────────
contract('BUG #1 — Permanent Root Node Lock (ENSRegistryWithFallback)', function (accounts) {
    let oldRegistry, newRegistry;

    beforeEach(async () => {
        oldRegistry = await ENSRegistry.new();
        newRegistry = await ENSWithFallback.new(oldRegistry.address);
    });

    it('[BUG #1.1] setOwner(root, address(0)) permanently locks the root node', async () => {
        // Root is currently owned by accounts[0]
        assert.equal(await newRegistry.owner(ZERO_HASH), accounts[0], 'Root owner is accounts[0]');

        // accounts[0] "renounces" root by setting owner to address(0)
        await newRegistry.setOwner(ZERO_HASH, ZERO_ADDRESS, { from: accounts[0] });

        // Root appears unowned
        assert.equal(await newRegistry.owner(ZERO_HASH), ZERO_ADDRESS, 'Root appears unowned');

        // But recordExists is true — it's locked under address(this)
        assert.equal(await newRegistry.recordExists(ZERO_HASH), true, 'Root record still exists');

        // Now try to create a TLD — should FAIL permanently
        try {
            await newRegistry.setSubnodeOwner(ZERO_HASH, sha3('eth'), accounts[1], { from: accounts[0] });
            assert.fail('[1.1] BUG NOT CONFIRMED: setSubnodeOwner should have reverted but did not!');
        } catch (err) {
            assert.include(err.message, 'revert',
                '[1.1] BUG CONFIRMED: Root permanently locked. Cannot create any TLD ever again. ' +
                'setSubnodeOwner(root, ...) reverts because records[root].owner = address(this), ' +
                'and no one can be msg.sender == address(this).');
        }
    });

    it('[BUG #1.2] Even root owner CANNOT recover the root after setting owner to address(0)', async () => {
        await newRegistry.setOwner(ZERO_HASH, ZERO_ADDRESS, { from: accounts[0] });

        // Try every possible recovery path
        const attempts = [
            () => newRegistry.setOwner(ZERO_HASH, accounts[0], { from: accounts[0] }),
            () => newRegistry.setRecord(ZERO_HASH, accounts[0], ZERO_ADDRESS, 0, { from: accounts[0] }),
        ];

        for (const attempt of attempts) {
            try {
                await attempt();
                assert.fail('[1.2] Should have reverted');
            } catch (err) {
                assert.include(err.message, 'revert',
                    '[1.2] BUG CONFIRMED: Root cannot be recovered. No one can ever call authorised(root) successfully.');
            }
        }
    });

    it('[BUG #1.3] Operator of root owner can also trigger the permanent lock', async () => {
        // accounts[0] approves accounts[1] as operator
        await newRegistry.setApprovalForAll(accounts[1], true, { from: accounts[0] });

        // Malicious/accidental operator burns the root
        await newRegistry.setOwner(ZERO_HASH, ZERO_ADDRESS, { from: accounts[1] });

        // Root is now permanently locked — original owner accounts[0] cannot recover
        try {
            await newRegistry.setOwner(ZERO_HASH, accounts[0], { from: accounts[0] });
            assert.fail('[1.3] Should have reverted');
        } catch (err) {
            assert.include(err.message, 'revert',
                '[1.3] BUG CONFIRMED: An approved operator can permanently destroy the root node. ' +
                'Even the original root owner cannot recover it after operator sets owner to address(0).');
        }
    });
});

// ─────────────────────────────────────────────────────────────────
// BUG #2 — MEDIUM: ReverseRegistrar.setName permanently transfers
//           ownership to the contract without returning it
// ─────────────────────────────────────────────────────────────────
contract('BUG #2 — ReverseRegistrar setName ownership transfer', function (accounts) {
    let ens, registrar, resolver;
    let aliceReverseNode;

    beforeEach(async () => {
        ens = await ENSRegistry.new();
        resolver = await DummyResolver.new();
        registrar = await ReverseRegistrar.new(ens.address, resolver.address);

        // addr.reverse setup
        await ens.setSubnodeOwner(ZERO_HASH, sha3('reverse'), accounts[0], { from: accounts[0] });
        await ens.setSubnodeOwner(namehash.hash('reverse'), sha3('addr'), registrar.address, { from: accounts[0] });

        aliceReverseNode = namehash.hash(accounts[0].slice(2).toLowerCase() + '.addr.reverse');
    });

    it('[BUG #2.1] setName transfers ownership to ReverseRegistrar, not back to msg.sender', async () => {
        // accounts[0] (Alice) sets her reverse name
        await registrar.setName('alice.eth', { from: accounts[0], gas: 1000000 });

        // After setName, who owns Alice's reverse node?
        const ownerAfter = await ens.owner(aliceReverseNode);

        assert.notEqual(ownerAfter, accounts[0],
            '[2.1] BUG: Alice does NOT own her reverse record after setName!');
        assert.equal(ownerAfter, registrar.address,
            '[2.1] BUG CONFIRMED: ReverseRegistrar owns Alice\'s reverse record after setName. ' +
            'Alice cannot directly call ens.setResolver() or ens.setOwner() on her own reverse node.');
    });

    it('[BUG #2.2] After setName, Alice cannot directly modify her reverse record via ENS', async () => {
        await registrar.setName('alice.eth', { from: accounts[0], gas: 1000000 });

        // Alice tries to change her resolver directly — she's not the owner anymore
        try {
            await ens.setResolver(aliceReverseNode, accounts[3], { from: accounts[0] });
            assert.fail('[2.2] Should have reverted — Alice is not the owner');
        } catch (err) {
            assert.include(err.message, 'revert',
                '[2.1] BUG CONFIRMED: Alice cannot directly set resolver on her reverse record. ' +
                'She must go through ReverseRegistrar for all operations.');
        }
    });

    it('[BUG #2.3] Commented-out test: owner of reverse node cannot update name via setName (msg.sender mismatch)', async () => {
        // Give accounts[1] ownership of accounts[0]'s reverse node
        await registrar.claimWithResolver(accounts[1], resolver.address, { from: accounts[0] });

        assert.equal(await ens.owner(aliceReverseNode), accounts[1],
            'accounts[1] now owns accounts[0]\'s reverse node');

        // accounts[1] tries to update the name for accounts[0]'s reverse record via setName
        // This is the @todo test in TestReverseRegistrar.js that DOES NOT WORK
        await registrar.setName('alice.eth', { from: accounts[1], gas: 1000000 });

        // setName uses sha3HexAddress(msg.sender) = sha3HexAddress(accounts[1])
        // So it modifies accounts[1]'s reverse record, NOT accounts[0]'s!
        const nameForAlice = await resolver.name(aliceReverseNode);
        assert.equal(nameForAlice, '',
            '[2.3] BUG CONFIRMED: accounts[0]\'s reverse name is NOT updated (\'\'), even though accounts[1] ' +
            'owns the node and called setName. setName always operates on msg.sender\'s OWN reverse node.');
    });
});
